https://github.com/DylanDavis1/DSCourier

# DSCourier BOF

Pure-C Beacon Object File that abuses the **WinGet Configuration** COM surface
(`Microsoft.Management.Configuration`) to apply a DSC YAML on the target —
**without spawning `winget.exe`**, **without a .NET runtime in the beacon**,
and **without dropping the YAML to disk**.

Compatible with **Cobalt Strike 4.9+** (tested on 4.12).

## Process tree

```
svchost.exe (DCOMLaunch)
  └── WindowsPackageManagerServer.exe
        └── ConfigurationRemotingServer.exe
              └── pwsh.exe   (only when the YAML invokes a PSDscResource)
```

No child of the beacon process. Everything happens via DCOM.

## Layout

```
bof/
├── beacon.h          CS 4.x BOF API (generic subset)
├── dscourier.h       COM / WinRT vtable layouts (from the IDL)
├── dscourier.c       the BOF itself
├── iids.h            WinRT IIDs (generated once from the winmd, committed)
├── Makefile          MinGW-w64 build (x64 + x86)
├── dscourier.cna     Aggressor script for Cobalt Strike
├── dscourier.x64.o   prebuilt x64 object
└── dscourier.x86.o   prebuilt x86 object
```

## Build

Only required if you want to rebuild from source.

### Prerequisites

- MinGW-w64 (`x86_64-w64-mingw32-gcc`). A 32-bit compiler
  (`i686-w64-mingw32-gcc`) is nice but optional — if your distro is
  x64-multilib, set `CC32` to the x64 compiler with `-m32`.
- GNU make (Git Bash / MSYS2).

### Commands

```bash
cd bof

# Distros with both compilers:
make

# x64 compiler with multilib only:
make CC32="x86_64-w64-mingw32-gcc -m32"
```

Outputs: `dscourier.x64.o`, `dscourier.x86.o` in `bof/`.

### Rebuilding `iids.h`

`iids.h` is derived once from `Microsoft.Management.Configuration.winmd`
via CsWinRT reflection and committed. The IIDs it contains are stable across
WinGet Configuration releases. If you ever need to regenerate, see the
commit history for the original `gen_iids/` helper, or extract with PowerShell:

```powershell
[System.Reflection.Assembly]::LoadFrom("WindowsPackageManager Interop.dll")
[Microsoft.Management.Configuration.IConfigurationStatics].GUID
# ...etc
```

## Loading into Cobalt Strike

Copy to the operator machine:

- `dscourier.cna`
- `dscourier.x64.o`
- `dscourier.x86.o`

Then: **Cobalt Strike → Script Manager → Load → `dscourier.cna`**.

The BOF is matched against beacon architecture automatically via
`barch($bid)`.

## Usage

| Command | Purpose |
|---|---|
| `dscourier-check [-elevated] [-v]` | Probe the COM surface only (no ApplySet). |
| `dscourier-apply <path.yaml> [-elevated] [-v]` | Read YAML from the teamserver operator filesystem and apply. |
| `dscourier-apply-b64 <base64> [-elevated] [-v]` | Apply YAML supplied as base64 on the command line. |

### Flags

- `-elevated` / `-e` — use the `Elevation:Administrator!new:{CLSID}` COM
  moniker. Requires the beacon token to already be elevated
  (split-token admin). Returns `E_ACCESSDENIED` otherwise.
- `-v` / `-verbose` — print per-unit progress and the COM binding trace.
  By default only the final `[+] ApplySet: N units applied` or failure line
  is emitted.

### Example session

```text
beacon> dscourier-check
[+] WinGet Configuration reachable

beacon> dscourier-apply-b64 <base64-of-your-yaml>
[+] ApplySet: 3 units applied

beacon> dscourier-apply C:\ops\install.yaml -elevated -v
[*] ConfigurationStaticFunctions bound
[*] pwsh factory ready
[*] YAML parsed, applying...
[+] InstallFirefox
[+] InstallEverything
[+] RunPostInstallScript
[+] ApplySet: 3 units applied
```

## OPSEC notes

- **No attribution string** — the BOF does not call `put_Caller`, so the
  Configuration telemetry path never sees "DSCourier" or any other
  operator-chosen identifier. (The original C# tool did.)
- **Telemetry off** — `put_GenerateTelemetryEvents(FALSE)` is set on every
  processor; no events go to Microsoft's telemetry pipeline.
- **Quiet by default** — success/failure summary only. Operator must
  explicitly opt into verbose output with `-v`.
- **No disk I/O on target** — the YAML is a BOF arg, re-wrapped in
  `InMemoryRandomAccessStream`, consumed by `OpenConfigurationSet`.
- **No extra modules in beacon** — pure DFR against `ole32`, `combase`,
  `kernel32`, `user32`. All of these are typically already loaded.
- **Visible artifacts** are unchanged from legitimate `winget configure`
  usage: the DCOM activation spawns `WindowsPackageManagerServer.exe`
  (and its child `ConfigurationRemotingServer.exe`). This *is* the technique.
- **x86 BOF on x64 Windows**: beacon must itself run in an x86 process.

## Flag/bit layout (wire format)

`bof_pack "iib"`:

| Field  | Type  | Meaning |
|--------|-------|---------|
| mode   | int32 | 0 = apply, 1 = check |
| flags  | int32 | bit0 = elevated, bit1 = verbose |
| yaml   | bin   | UTF-8 bytes (ignored when mode = 1) |

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `0x80040154 REGDB_E_CLASSNOTREG` | WinGet not installed / service not registered. `dscourier-check` surfaces this first. |
| `0x80070005 E_ACCESSDENIED` with `-elevated` | Beacon token is not elevated. |
| `0x800706BA RPC_S_SERVER_UNAVAILABLE` | `WindowsPackageManagerServer` not running / crashed. Check Event Log. |
| `dscourier-apply: empty or unreadable` | The YAML path is wrong or zero-byte on the operator side. |
| `missing dscourier.<arch>.o` | Copy both `.o` files next to `dscourier.cna` on the operator machine. |

## Reference

- Microsoft PM Configuration IDL:
  `winget-cli/src/Microsoft.Management.Configuration/Microsoft.Management.Configuration.idl`
- CLSID used: `{73D763B7-2937-432F-A97A-D98A4A596126}` (`ConfigurationStaticFunctions`)
- IAsyncInfo polling interval: `100 ms` (see `DS_ASYNC_POLL_MS` in `dscourier.c`)
- Factory/store timeouts: `60 s` / `10 s` (`DS_ASYNC_TIMEOUT_FACTORY_MS`, `DS_ASYNC_TIMEOUT_STORE_MS`)
