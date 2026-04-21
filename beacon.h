/*
 * beacon.h — Cobalt Strike 4.x Beacon Object File (BOF) API
 *
 * Generic public header. Compatible with Cobalt Strike 4.9+ (including 4.12).
 * Source: derived from the public HelpSystems/Fortra BOF template (MIT).
 *
 * Only the subset that DSCourier BOF actually uses is declared here; feel
 * free to drop in the full header from your CS install if preferred.
 */
#ifndef _BEACON_H
#define _BEACON_H

#include <windows.h>

/* ---------- data parser ---------- */
typedef struct {
    char *original; /* the original buffer [so we can free it] */
    char *buffer;   /* current pointer into our buffer */
    int   length;   /* remaining length of data */
    int   size;     /* total size of this buffer */
} datap;

DECLSPEC_IMPORT void    BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT int     BeaconDataInt(datap *parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap *parser);
DECLSPEC_IMPORT int     BeaconDataLength(datap *parser);
DECLSPEC_IMPORT char  * BeaconDataExtract(datap *parser, int *size);

/* ---------- output formatter ---------- */
typedef struct {
    char *original; /* the original buffer [so we can free it] */
    char *buffer;   /* current pointer into our buffer */
    int   length;   /* remaining length of data */
    int   size;     /* total size of this buffer */
} formatp;

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp *format, int maxsz);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp *format);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp *format);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp *format, char *text, int len);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp *format, char *fmt, ...);
DECLSPEC_IMPORT char *  BeaconFormatToString(formatp *format, int *size);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp *format, int value);

/* ---------- output ---------- */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

DECLSPEC_IMPORT void   BeaconPrintf(int type, char *fmt, ...);
DECLSPEC_IMPORT void   BeaconOutput(int type, char *data, int len);

/* ---------- token ---------- */
DECLSPEC_IMPORT BOOL   BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void   BeaconRevertToken(void);
DECLSPEC_IMPORT BOOL   BeaconIsAdmin(void);

/* ---------- spawn+inject ---------- */
DECLSPEC_IMPORT void   BeaconGetSpawnTo(BOOL x86, char *buffer, int length);
DECLSPEC_IMPORT void   BeaconInjectProcess(HANDLE hProc, int pid, char *payload,
                                           int p_len, int p_offset, char *arg, int a_len);
DECLSPEC_IMPORT void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION *pInfo,
                                                    char *payload, int p_len, int p_offset,
                                                    char *arg, int a_len);
DECLSPEC_IMPORT BOOL   BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken,
                                                   STARTUPINFO *sInfo, PROCESS_INFORMATION *pInfo);
DECLSPEC_IMPORT void   BeaconCleanupProcess(PROCESS_INFORMATION *pInfo);

DECLSPEC_IMPORT BOOL   toWideChar(char *src, wchar_t *dst, int max);

/*
 * Dynamic Function Resolution (DFR)
 *
 * CS requires Win32 APIs to be accessed through the DFR symbol-name
 * convention so the beacon loader can resolve them at load time:
 *
 *     LIBRARYNAME$FunctionName(args...)
 *
 * Example: OLE32$CoCreateInstance(...).
 *
 * DSCourier BOF follows this convention for every import.
 */

#endif /* _BEACON_H */
