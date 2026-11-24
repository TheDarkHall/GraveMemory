/*
 * gravememory_shared.h - definitions shared between the gravememory launcher
 *               (gravememory.exe) and the in-lsass dump DLL
 *               (gravememorydll*.dll).
 *
 * AUTHORIZED USE ONLY - for auditing systems you own or have explicit
 * written permission to assess.
 */
#ifndef GMSHARED_H
#define GMSHARED_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* well-known names                                                   */
/* ------------------------------------------------------------------ */

#define GM_DMP_NAME     L"gravememory.dmp"
#define GM_STATUS_NAME  L"gravememory.dmp.status"
#define GM_RESULT_NAME  L"gravememory.dmp.result"
#define GM_LOG_NAME     L"gravememory.dmp.log"
#define GM_JSON_NAME    L"gravememory.json"
#define GM_TXT_NAME     L"hashes.txt"

#define GM_EXPORT_NAME  "DumpHashes"

#ifdef _WIN64
#define GM_DLL_NAME L"gravememorydll64.dll"
#else
#define GM_DLL_NAME L"gravememorydll32.dll"
#endif

/* exit codes reported by the remote injection stub (GetExitCodeThread) */
#define GM_STUB_OK           0x00000000u
#define GM_STUB_BADARGS      0xFFFFFFFEu
#define GM_STUB_LOADFAIL     0xFFFFFFFFu
#define GM_STUB_GETPROCFAIL  0xFFFFFFFCu

/* ------------------------------------------------------------------ */
/* function pointer typedefs used by the remote stub                  */
/* ------------------------------------------------------------------ */

typedef HMODULE (WINAPI *GM_LOADLIBRARYW_T)(LPCWSTR);
typedef FARPROC (WINAPI *GM_GETPROCADDRESS_T)(HMODULE, LPCSTR);
typedef BOOL (WINAPI *GM_FREELIBRARY_T)(HMODULE);

/* ------------------------------------------------------------------ */
/* argument block copied into lsass behind the stub code.             */
/* layout must be identical in exe and dll - keep it in this header.  */
/* ------------------------------------------------------------------ */

typedef struct {
    GM_LOADLIBRARYW_T   pLoadLibraryW;
    GM_GETPROCADDRESS_T pGetProcAddress;
    GM_FREELIBRARY_T    pFreeLibrary;
    wchar_t dllPath[MAX_PATH + 1];
    char    exportName[64];
    wchar_t dumpFolder[MAX_PATH + 1];
} GM_REMOTE_ARGS;

/* ------------------------------------------------------------------ */
/* small shared helpers                                               */
/* ------------------------------------------------------------------ */

#ifdef _MSC_VER
#define GM_FN static __inline
#else
#define GM_FN static inline __attribute__((unused))
#endif

/* join directory + filename; dir may have trailing backslashes */
GM_FN void GM_JoinPath(const wchar_t *dir, const wchar_t *name,
                         wchar_t *out, size_t cap)
{
    wchar_t clean[MAX_PATH + 1];
    size_t l;
    wchar_t sep[2] = L"\\";

    _snwprintf(clean, MAX_PATH, L"%s", dir);
    clean[MAX_PATH] = 0;
    l = wcslen(clean);
    while (l > 3 && clean[l - 1] == L'\\') {
        clean[l - 1] = 0;
        l--;
    }
    _snwprintf(out, cap - 1, L"%s%s%s", clean, sep, name);
    out[cap - 1] = 0;
}

/* GraveMemory secure file: SYSTEM full control, Administrators read|delete */
GM_FN HANDLE GM_CreateSecureFile(const wchar_t *path)
{
    typedef BOOL (WINAPI *SETSDC_T)(PSECURITY_DESCRIPTOR,
                                    SECURITY_DESCRIPTOR_CONTROL,
                                    SECURITY_DESCRIPTOR_CONTROL);
    PSECURITY_DESCRIPTOR psd = NULL;
    PACL pacl = NULL;
    PSID psidSystem = NULL, psidAdmins = NULL;
    SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
    SECURITY_ATTRIBUTES sa;
    HMODULE hAdv;
    SETSDC_T pSetSDC;
    HANDLE h;

    if (!AllocateAndInitializeSid(&sia, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0,
                                  0, 0, 0, 0, &psidSystem))
        return INVALID_HANDLE_VALUE;
    if (!AllocateAndInitializeSid(&sia, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &psidAdmins)) {
        FreeSid(psidSystem);
        return INVALID_HANDLE_VALUE;
    }

    pacl = (PACL)malloc(sizeof(ACL) + 128);
    if (!pacl || !InitializeAcl(pacl, sizeof(ACL) + 128, ACL_REVISION))
        goto fail;
    if (!AddAccessAllowedAce(pacl, ACL_REVISION, FILE_ALL_ACCESS, psidSystem))
        goto fail;
    if (!AddAccessAllowedAce(pacl, ACL_REVISION, FILE_GENERIC_READ | DELETE,
                             psidAdmins))
        goto fail;

    psd = (PSECURITY_DESCRIPTOR)malloc(SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (!psd || !InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION))
        goto fail;
    if (!SetSecurityDescriptorDacl(psd, TRUE, pacl, FALSE))
        goto fail;

    hAdv = GetModuleHandleW(L"advapi32.dll");
    if (hAdv) {
        pSetSDC = (SETSDC_T)GetProcAddress(hAdv, "SetSecurityDescriptorControl");
        if (pSetSDC)
            pSetSDC(psd, SE_DACL_AUTO_INHERIT_REQ, 0);
    }

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = psd;
    sa.bInheritHandle = FALSE;

    h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    FreeSid(psidSystem);
    FreeSid(psidAdmins);
    free(pacl);
    free(psd);
    return h;

fail:
    if (psidSystem)
        FreeSid(psidSystem);
    if (psidAdmins)
        FreeSid(psidAdmins);
    free(pacl);
    free(psd);
    return INVALID_HANDLE_VALUE;
}

/* write an ANSI/UTF-8 text file with the GraveMemory ACL */
GM_FN int GM_WriteAnsiSecure(const wchar_t *path, const char *content)
{
    HANDLE h = GM_CreateSecureFile(path);
    DWORD written = 0;
    size_t len = strlen(content);
    BOOL ok;
    if (h == INVALID_HANDLE_VALUE)
        return 1;
    ok = len == 0 ||
         (WriteFile(h, content, (DWORD)len, &written, NULL) &&
          written == (DWORD)len);
    CloseHandle(h);
    return ok ? 0 : 1;
}

/* write a plain ANSI file (no ACL) - used by the launcher side */
GM_FN int GM_WriteAnsiPlain(const wchar_t *path, const char *content)
{
    HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written = 0;
    size_t len = strlen(content);
    BOOL ok;
    if (h == INVALID_HANDLE_VALUE)
        return 1;
    ok = len == 0 ||
         (WriteFile(h, content, (DWORD)len, &written, NULL) &&
          written == (DWORD)len);
    CloseHandle(h);
    return ok ? 0 : 1;
}

/* append one ANSI line to a plain log file (best effort, never fatal) */
GM_FN void GM_AppendLog(const wchar_t *logPath, const char *line)
{
    HANDLE h;
    DWORD written = 0;
    size_t len;
    char buf[1024];

    if (!logPath || !logPath[0])
        return;
    len = strlen(line);
    if (len > 900)
        len = 900;
    memcpy(buf, line, len);
    if (len == 0 || buf[len - 1] != '\n') {
        buf[len++] = '\r';
        buf[len++] = '\n';
    }

    h = CreateFileW(logPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return;
    SetFilePointer(h, 0, NULL, FILE_END);
    WriteFile(h, buf, (DWORD)len, &written, NULL);
    CloseHandle(h);
}

/* timestamped log line */
GM_FN void GM_LogFmt(const wchar_t *logPath, const char *fmt, ...)
{
    char line[1024];
    char tstamp[64];
    SYSTEMTIME st;
    va_list ap;

    GetLocalTime(&st);
    _snprintf(tstamp, sizeof(tstamp) - 1,
              "[%04u-%02u-%02u %02u:%02u:%02u.%03u] ",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
              st.wMilliseconds);
    tstamp[sizeof(tstamp) - 1] = 0;

    va_start(ap, fmt);
    _vsnprintf(line, sizeof(line) - 1, fmt, ap);
    va_end(ap);
    line[sizeof(line) - 1] = 0;

    {
        char full[1100];
        _snprintf(full, sizeof(full) - 1, "%s%s", tstamp, line);
        full[sizeof(full) - 1] = 0;
        GM_AppendLog(logPath, full);
    }
}

#endif /* GMSHARED_H */
