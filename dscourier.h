/*
 * dscourier.h — COM/WinRT vtable layouts for the WinGet Configuration API
 *
 * These are derived directly from:
 *   winget-cli/src/Microsoft.Management.Configuration/Microsoft.Management.Configuration.idl
 *
 * Method order follows IDL declaration order. WinRT property accessors
 * appear in the vtable as (get, set) pairs in declaration order, after
 * IInspectable's three methods (GetIids / GetRuntimeClassName / GetTrustLevel).
 *
 * IIDs are NOT defined in this file — see iids.h which is generated at build
 * time from the actual Microsoft.Management.Configuration.winmd on the dev
 * machine (see gen_iids/gen_iids.cs).
 */

#ifndef _DSCOURIER_H
#define _DSCOURIER_H

#include <windows.h>
#include <unknwn.h>

/* ---------- WinRT primitives ---------- */

#ifndef __HSTRING__
#define __HSTRING__
struct HSTRING__ { int unused; };
typedef struct HSTRING__ *HSTRING;
typedef struct HSTRING_HEADER { void *Reserved[5]; } HSTRING_HEADER;
#endif

typedef enum AsyncStatus {
    AsyncStatus_Started   = 0,
    AsyncStatus_Completed = 1,
    AsyncStatus_Canceled  = 2,
    AsyncStatus_Error     = 3
} AsyncStatus;

typedef enum TrustLevel {
    BaseTrust     = 0,
    PartialTrust  = 1,
    FullTrust     = 2
} TrustLevel;

/* ---------- IInspectable ---------- */
typedef struct IInspectable IInspectable;
typedef struct IInspectableVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IInspectable*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IInspectable*);
    ULONG   (STDMETHODCALLTYPE *Release)(IInspectable*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IInspectable*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IInspectable*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IInspectable*, TrustLevel*);
} IInspectableVtbl;
struct IInspectable { const IInspectableVtbl *lpVtbl; };

/* ---------- IAsyncInfo ---------- */
typedef struct IAsyncInfo IAsyncInfo;
typedef struct IAsyncInfoVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IAsyncInfo*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IAsyncInfo*);
    ULONG   (STDMETHODCALLTYPE *Release)(IAsyncInfo*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IAsyncInfo*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IAsyncInfo*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IAsyncInfo*, TrustLevel*);
    HRESULT (STDMETHODCALLTYPE *get_Id)(IAsyncInfo*, UINT32*);
    HRESULT (STDMETHODCALLTYPE *get_Status)(IAsyncInfo*, AsyncStatus*);
    HRESULT (STDMETHODCALLTYPE *get_ErrorCode)(IAsyncInfo*, HRESULT*);
    HRESULT (STDMETHODCALLTYPE *Cancel)(IAsyncInfo*);
    HRESULT (STDMETHODCALLTYPE *Close)(IAsyncInfo*);
} IAsyncInfoVtbl;
struct IAsyncInfo { const IAsyncInfoVtbl *lpVtbl; };

/* ---------- IAsyncOperation<IInspectable>  (generic shape, GetResults returns IInspectable*) ---------- */
typedef struct IAsyncOperation IAsyncOperation;
typedef struct IAsyncOperationVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IAsyncOperation*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IAsyncOperation*);
    ULONG   (STDMETHODCALLTYPE *Release)(IAsyncOperation*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IAsyncOperation*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IAsyncOperation*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IAsyncOperation*, TrustLevel*);
    HRESULT (STDMETHODCALLTYPE *put_Completed)(IAsyncOperation*, void*);
    HRESULT (STDMETHODCALLTYPE *get_Completed)(IAsyncOperation*, void**);
    HRESULT (STDMETHODCALLTYPE *GetResults)(IAsyncOperation*, void**);
} IAsyncOperationVtbl;
struct IAsyncOperation { const IAsyncOperationVtbl *lpVtbl; };

/* ---------- IConfigurationStatics ---------- */
/* Default interface of ConfigurationStaticFunctions (CLSID 73D763B7-2937-432F-A97A-D98A4A596126) */
typedef struct IConfigurationStatics IConfigurationStatics;
typedef struct IConfigurationStaticsVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IConfigurationStatics*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IConfigurationStatics*);
    ULONG   (STDMETHODCALLTYPE *Release)(IConfigurationStatics*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IConfigurationStatics*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IConfigurationStatics*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IConfigurationStatics*, TrustLevel*);
    /* IDL order: */
    HRESULT (STDMETHODCALLTYPE *CreateConfigurationUnit)(IConfigurationStatics*, void** unit);
    HRESULT (STDMETHODCALLTYPE *CreateConfigurationSet)(IConfigurationStatics*, void** set);
    HRESULT (STDMETHODCALLTYPE *CreateConfigurationSetProcessorFactoryAsync)(IConfigurationStatics*, HSTRING handler, IAsyncOperation** op);
    HRESULT (STDMETHODCALLTYPE *CreateConfigurationProcessor)(IConfigurationStatics*, IInspectable* factory, IInspectable** processor);
    HRESULT (STDMETHODCALLTYPE *get_IsConfigurationAvailable)(IConfigurationStatics*, BOOL* value);
    HRESULT (STDMETHODCALLTYPE *EnsureConfigurationAvailableAsync)(IConfigurationStatics*, void** op);
} IConfigurationStaticsVtbl;
struct IConfigurationStatics { const IConfigurationStaticsVtbl *lpVtbl; };

/* ---------- IConfigurationProcessor (default interface of ConfigurationProcessor) ---------- */
/* IDL field/method order for ConfigurationProcessor runtimeclass:
 *   event Diagnostics                      (add_Diagnostics, remove_Diagnostics)
 *   property MinimumLevel                  (get, put)
 *   property Caller                        (get, put)
 *   property ActivityIdentifier            (get, put)
 *   property GenerateTelemetryEvents       (get, put)
 *   event ConfigurationChange              (add_, remove_)
 *   GetConfigurationHistory / Async
 *   OpenConfigurationSet / Async
 *   CheckForConflicts / Async
 *   GetSetDetails / Async
 *   GetUnitDetails / Async
 *   ApplySet / Async
 *   TestSet / Async
 *   GetUnitSettings / Async
 *
 * WinRT maps this to a single IConfigurationProcessor interface in declaration order.
 */
typedef struct IConfigurationProcessor IConfigurationProcessor;
typedef struct IConfigurationProcessorVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IConfigurationProcessor*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IConfigurationProcessor*);
    ULONG   (STDMETHODCALLTYPE *Release)(IConfigurationProcessor*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IConfigurationProcessor*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IConfigurationProcessor*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IConfigurationProcessor*, TrustLevel*);

    HRESULT (STDMETHODCALLTYPE *add_Diagnostics)(IConfigurationProcessor*, void*, INT64*);
    HRESULT (STDMETHODCALLTYPE *remove_Diagnostics)(IConfigurationProcessor*, INT64);
    HRESULT (STDMETHODCALLTYPE *get_MinimumLevel)(IConfigurationProcessor*, int*);
    HRESULT (STDMETHODCALLTYPE *put_MinimumLevel)(IConfigurationProcessor*, int);
    HRESULT (STDMETHODCALLTYPE *get_Caller)(IConfigurationProcessor*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *put_Caller)(IConfigurationProcessor*, HSTRING);
    HRESULT (STDMETHODCALLTYPE *get_ActivityIdentifier)(IConfigurationProcessor*, GUID*);
    HRESULT (STDMETHODCALLTYPE *put_ActivityIdentifier)(IConfigurationProcessor*, GUID);
    HRESULT (STDMETHODCALLTYPE *get_GenerateTelemetryEvents)(IConfigurationProcessor*, BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_GenerateTelemetryEvents)(IConfigurationProcessor*, BOOL);
    HRESULT (STDMETHODCALLTYPE *add_ConfigurationChange)(IConfigurationProcessor*, void*, INT64*);
    HRESULT (STDMETHODCALLTYPE *remove_ConfigurationChange)(IConfigurationProcessor*, INT64);

    HRESULT (STDMETHODCALLTYPE *GetConfigurationHistory)(IConfigurationProcessor*, void** vec);
    HRESULT (STDMETHODCALLTYPE *GetConfigurationHistoryAsync)(IConfigurationProcessor*, void** op);

    HRESULT (STDMETHODCALLTYPE *OpenConfigurationSet)(IConfigurationProcessor*, IInspectable* input_stream, IInspectable** open_result);
    HRESULT (STDMETHODCALLTYPE *OpenConfigurationSetAsync)(IConfigurationProcessor*, IInspectable* input_stream, void** op);

    HRESULT (STDMETHODCALLTYPE *CheckForConflicts)(IConfigurationProcessor*, IInspectable*, BOOL, void**);
    HRESULT (STDMETHODCALLTYPE *CheckForConflictsAsync)(IConfigurationProcessor*, IInspectable*, BOOL, void**);

    HRESULT (STDMETHODCALLTYPE *GetSetDetails)(IConfigurationProcessor*, IInspectable*, int, void**);
    HRESULT (STDMETHODCALLTYPE *GetSetDetailsAsync)(IConfigurationProcessor*, IInspectable*, int, void**);

    HRESULT (STDMETHODCALLTYPE *GetUnitDetails)(IConfigurationProcessor*, IInspectable*, int, void**);
    HRESULT (STDMETHODCALLTYPE *GetUnitDetailsAsync)(IConfigurationProcessor*, IInspectable*, int, void**);

    HRESULT (STDMETHODCALLTYPE *ApplySet)(IConfigurationProcessor*, IInspectable* set, int flags, IInspectable** apply_result);
    HRESULT (STDMETHODCALLTYPE *ApplySetAsync)(IConfigurationProcessor*, IInspectable*, int, void**);

    HRESULT (STDMETHODCALLTYPE *TestSet)(IConfigurationProcessor*, IInspectable*, void**);
    HRESULT (STDMETHODCALLTYPE *TestSetAsync)(IConfigurationProcessor*, IInspectable*, void**);

    HRESULT (STDMETHODCALLTYPE *GetUnitSettings)(IConfigurationProcessor*, IInspectable*, void**);
    HRESULT (STDMETHODCALLTYPE *GetUnitSettingsAsync)(IConfigurationProcessor*, IInspectable*, void**);
} IConfigurationProcessorVtbl;
struct IConfigurationProcessor { const IConfigurationProcessorVtbl *lpVtbl; };

/* ---------- IOpenConfigurationSetResult ---------- */
/* runtimeclass OpenConfigurationSetResult — default interface properties, all {get;} */
typedef struct IOpenConfigurationSetResult IOpenConfigurationSetResult;
typedef struct IOpenConfigurationSetResultVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IOpenConfigurationSetResult*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IOpenConfigurationSetResult*);
    ULONG   (STDMETHODCALLTYPE *Release)(IOpenConfigurationSetResult*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IOpenConfigurationSetResult*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IOpenConfigurationSetResult*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IOpenConfigurationSetResult*, TrustLevel*);
    HRESULT (STDMETHODCALLTYPE *get_Set)(IOpenConfigurationSetResult*, IInspectable**);
    HRESULT (STDMETHODCALLTYPE *get_ResultCode)(IOpenConfigurationSetResult*, HRESULT*);
    HRESULT (STDMETHODCALLTYPE *get_Field)(IOpenConfigurationSetResult*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *get_Value)(IOpenConfigurationSetResult*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *get_Line)(IOpenConfigurationSetResult*, UINT32*);
    HRESULT (STDMETHODCALLTYPE *get_Column)(IOpenConfigurationSetResult*, UINT32*);
} IOpenConfigurationSetResultVtbl;
struct IOpenConfigurationSetResult { const IOpenConfigurationSetResultVtbl *lpVtbl; };

/* ---------- IApplyConfigurationSetResult ---------- */
/* runtimeclass ApplyConfigurationSetResult — UnitResults (IVectorView<ApplyConfigurationUnitResult>), ResultCode */
typedef struct IApplyConfigurationSetResult IApplyConfigurationSetResult;
typedef struct IApplyConfigurationSetResultVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IApplyConfigurationSetResult*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IApplyConfigurationSetResult*);
    ULONG   (STDMETHODCALLTYPE *Release)(IApplyConfigurationSetResult*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IApplyConfigurationSetResult*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IApplyConfigurationSetResult*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IApplyConfigurationSetResult*, TrustLevel*);
    HRESULT (STDMETHODCALLTYPE *get_UnitResults)(IApplyConfigurationSetResult*, IInspectable** vector_view);
    HRESULT (STDMETHODCALLTYPE *get_ResultCode)(IApplyConfigurationSetResult*, HRESULT*);
} IApplyConfigurationSetResultVtbl;
struct IApplyConfigurationSetResult { const IApplyConfigurationSetResultVtbl *lpVtbl; };

/* ---------- IApplyConfigurationUnitResult (runtimeclass) ---------- */
typedef struct IApplyConfigurationUnitResult IApplyConfigurationUnitResult;
typedef struct IApplyConfigurationUnitResultVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IApplyConfigurationUnitResult*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IApplyConfigurationUnitResult*);
    ULONG   (STDMETHODCALLTYPE *Release)(IApplyConfigurationUnitResult*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IApplyConfigurationUnitResult*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IApplyConfigurationUnitResult*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IApplyConfigurationUnitResult*, TrustLevel*);
    HRESULT (STDMETHODCALLTYPE *get_Unit)(IApplyConfigurationUnitResult*, IInspectable**);
    HRESULT (STDMETHODCALLTYPE *get_State)(IApplyConfigurationUnitResult*, int*);
    HRESULT (STDMETHODCALLTYPE *get_PreviouslyInDesiredState)(IApplyConfigurationUnitResult*, BOOL*);
    HRESULT (STDMETHODCALLTYPE *get_RebootRequired)(IApplyConfigurationUnitResult*, BOOL*);
    HRESULT (STDMETHODCALLTYPE *get_ResultInformation)(IApplyConfigurationUnitResult*, IInspectable**);
} IApplyConfigurationUnitResultVtbl;
struct IApplyConfigurationUnitResult { const IApplyConfigurationUnitResultVtbl *lpVtbl; };

/* ---------- IConfigurationUnit (default interface of ConfigurationUnit runtimeclass) ---------- */
typedef struct IConfigurationUnit IConfigurationUnit;
typedef struct IConfigurationUnitVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IConfigurationUnit*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IConfigurationUnit*);
    ULONG   (STDMETHODCALLTYPE *Release)(IConfigurationUnit*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IConfigurationUnit*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IConfigurationUnit*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IConfigurationUnit*, TrustLevel*);
    HRESULT (STDMETHODCALLTYPE *get_Type)(IConfigurationUnit*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *put_Type)(IConfigurationUnit*, HSTRING);
    HRESULT (STDMETHODCALLTYPE *get_InstanceIdentifier)(IConfigurationUnit*, GUID*);
    HRESULT (STDMETHODCALLTYPE *get_Identifier)(IConfigurationUnit*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *put_Identifier)(IConfigurationUnit*, HSTRING);
    /* we don't use the rest */
} IConfigurationUnitVtbl;
struct IConfigurationUnit { const IConfigurationUnitVtbl *lpVtbl; };

/* ---------- IConfigurationUnitResultInformation ---------- */
typedef struct IConfigurationUnitResultInformation IConfigurationUnitResultInformation;
typedef struct IConfigurationUnitResultInformationVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IConfigurationUnitResultInformation*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IConfigurationUnitResultInformation*);
    ULONG   (STDMETHODCALLTYPE *Release)(IConfigurationUnitResultInformation*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IConfigurationUnitResultInformation*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IConfigurationUnitResultInformation*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IConfigurationUnitResultInformation*, TrustLevel*);
    HRESULT (STDMETHODCALLTYPE *get_ResultCode)(IConfigurationUnitResultInformation*, HRESULT*);
    HRESULT (STDMETHODCALLTYPE *get_Description)(IConfigurationUnitResultInformation*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *get_Details)(IConfigurationUnitResultInformation*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *get_ResultSource)(IConfigurationUnitResultInformation*, int*);
} IConfigurationUnitResultInformationVtbl;
struct IConfigurationUnitResultInformation { const IConfigurationUnitResultInformationVtbl *lpVtbl; };

/* ---------- IVectorView<T> (generic vector-view accessor) ---------- */
/* We just need Size and GetAt (returning IInspectable*). */
typedef struct IVectorView IVectorView;
typedef struct IVectorViewVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IVectorView*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IVectorView*);
    ULONG   (STDMETHODCALLTYPE *Release)(IVectorView*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IVectorView*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IVectorView*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IVectorView*, TrustLevel*);
    HRESULT (STDMETHODCALLTYPE *GetAt)(IVectorView*, UINT32 index, IInspectable** item);
    HRESULT (STDMETHODCALLTYPE *get_Size)(IVectorView*, UINT32* size);
    HRESULT (STDMETHODCALLTYPE *IndexOf)(IVectorView*, IInspectable*, UINT32*, BOOL*);
    HRESULT (STDMETHODCALLTYPE *GetMany)(IVectorView*, UINT32, UINT32, IInspectable**, UINT32*);
} IVectorViewVtbl;
struct IVectorView { const IVectorViewVtbl *lpVtbl; };

/* ---------- WinRT stream interfaces ---------- */
/* These IIDs are part of Windows.Storage.Streams and are stable/public. */

typedef struct IRandomAccessStream IRandomAccessStream;
typedef struct IOutputStream IOutputStream;
typedef struct IInputStream IInputStream;
typedef struct IBuffer IBuffer;
typedef struct IDataWriter IDataWriter;

/* Windows.Storage.Streams.IOutputStream — we just need Release (via IInspectable cast)
 * plus WriteAsync / FlushAsync / Close. We only hold it while feeding the DataWriter. */
typedef struct IOutputStreamVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IOutputStream*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IOutputStream*);
    ULONG   (STDMETHODCALLTYPE *Release)(IOutputStream*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IOutputStream*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IOutputStream*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IOutputStream*, TrustLevel*);
    HRESULT (STDMETHODCALLTYPE *WriteAsync)(IOutputStream*, IBuffer*, void**);
    HRESULT (STDMETHODCALLTYPE *FlushAsync)(IOutputStream*, void**);
    HRESULT (STDMETHODCALLTYPE *Close)(IOutputStream*);
} IOutputStreamVtbl;
struct IOutputStream { const IOutputStreamVtbl *lpVtbl; };

/* Windows.Storage.Streams.IInputStream — read-only shape; we only pass it through */
typedef struct IInputStreamVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IInputStream*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IInputStream*);
    ULONG   (STDMETHODCALLTYPE *Release)(IInputStream*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IInputStream*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IInputStream*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IInputStream*, TrustLevel*);
    HRESULT (STDMETHODCALLTYPE *ReadAsync)(IInputStream*, IBuffer*, UINT32, int options, void** op);
} IInputStreamVtbl;
struct IInputStream { const IInputStreamVtbl *lpVtbl; };

/* Windows.Storage.Streams.IRandomAccessStream — gives us GetInputStreamAt/GetOutputStreamAt + seek */
typedef struct IRandomAccessStreamVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IRandomAccessStream*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IRandomAccessStream*);
    ULONG   (STDMETHODCALLTYPE *Release)(IRandomAccessStream*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IRandomAccessStream*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IRandomAccessStream*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IRandomAccessStream*, TrustLevel*);
    /* IClosable */
    HRESULT (STDMETHODCALLTYPE *Close)(IRandomAccessStream*);
    /* IInputStream */
    HRESULT (STDMETHODCALLTYPE *ReadAsync)(IRandomAccessStream*, IBuffer*, UINT32, int, void**);
    /* IOutputStream */
    HRESULT (STDMETHODCALLTYPE *WriteAsync)(IRandomAccessStream*, IBuffer*, void** op);
    HRESULT (STDMETHODCALLTYPE *FlushAsync)(IRandomAccessStream*, void** op);
    /* IRandomAccessStream */
    HRESULT (STDMETHODCALLTYPE *get_Size)(IRandomAccessStream*, UINT64*);
    HRESULT (STDMETHODCALLTYPE *put_Size)(IRandomAccessStream*, UINT64);
    HRESULT (STDMETHODCALLTYPE *GetInputStreamAt)(IRandomAccessStream*, UINT64 position, IInputStream** stream);
    HRESULT (STDMETHODCALLTYPE *GetOutputStreamAt)(IRandomAccessStream*, UINT64 position, IOutputStream** stream);
    HRESULT (STDMETHODCALLTYPE *get_Position)(IRandomAccessStream*, UINT64*);
    HRESULT (STDMETHODCALLTYPE *Seek)(IRandomAccessStream*, UINT64 position);
    HRESULT (STDMETHODCALLTYPE *CloneStream)(IRandomAccessStream*, IRandomAccessStream**);
    HRESULT (STDMETHODCALLTYPE *get_CanRead)(IRandomAccessStream*, BOOL*);
    HRESULT (STDMETHODCALLTYPE *get_CanWrite)(IRandomAccessStream*, BOOL*);
} IRandomAccessStreamVtbl;
struct IRandomAccessStream { const IRandomAccessStreamVtbl *lpVtbl; };

/* Windows.Storage.Streams.IDataWriter — we use it to push the YAML bytes into the stream */
typedef struct IDataWriterVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDataWriter*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IDataWriter*);
    ULONG   (STDMETHODCALLTYPE *Release)(IDataWriter*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IDataWriter*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IDataWriter*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IDataWriter*, TrustLevel*);
    HRESULT (STDMETHODCALLTYPE *get_UnstoredBufferLength)(IDataWriter*, UINT32*);
    HRESULT (STDMETHODCALLTYPE *get_UnicodeEncoding)(IDataWriter*, int*);
    HRESULT (STDMETHODCALLTYPE *put_UnicodeEncoding)(IDataWriter*, int);
    HRESULT (STDMETHODCALLTYPE *get_ByteOrder)(IDataWriter*, int*);
    HRESULT (STDMETHODCALLTYPE *put_ByteOrder)(IDataWriter*, int);
    HRESULT (STDMETHODCALLTYPE *WriteByte)(IDataWriter*, BYTE);
    HRESULT (STDMETHODCALLTYPE *WriteBytes)(IDataWriter*, UINT32 count, BYTE* bytes);
    HRESULT (STDMETHODCALLTYPE *WriteBuffer)(IDataWriter*, IBuffer* buffer);
    HRESULT (STDMETHODCALLTYPE *WriteBufferRange)(IDataWriter*, IBuffer*, UINT32, UINT32);
    HRESULT (STDMETHODCALLTYPE *WriteBoolean)(IDataWriter*, BOOL);
    HRESULT (STDMETHODCALLTYPE *WriteGuid)(IDataWriter*, GUID);
    HRESULT (STDMETHODCALLTYPE *WriteInt16)(IDataWriter*, INT16);
    HRESULT (STDMETHODCALLTYPE *WriteInt32)(IDataWriter*, INT32);
    HRESULT (STDMETHODCALLTYPE *WriteInt64)(IDataWriter*, INT64);
    HRESULT (STDMETHODCALLTYPE *WriteUInt16)(IDataWriter*, UINT16);
    HRESULT (STDMETHODCALLTYPE *WriteUInt32)(IDataWriter*, UINT32);
    HRESULT (STDMETHODCALLTYPE *WriteUInt64)(IDataWriter*, UINT64);
    HRESULT (STDMETHODCALLTYPE *WriteSingle)(IDataWriter*, float);
    HRESULT (STDMETHODCALLTYPE *WriteDouble)(IDataWriter*, double);
    HRESULT (STDMETHODCALLTYPE *WriteDateTime)(IDataWriter*, INT64);
    HRESULT (STDMETHODCALLTYPE *WriteTimeSpan)(IDataWriter*, INT64);
    HRESULT (STDMETHODCALLTYPE *WriteString)(IDataWriter*, HSTRING, UINT32*);
    HRESULT (STDMETHODCALLTYPE *MeasureString)(IDataWriter*, HSTRING, UINT32*);
    HRESULT (STDMETHODCALLTYPE *get_MeasureStringEncoding)(IDataWriter*, int*);
    HRESULT (STDMETHODCALLTYPE *StoreAsync)(IDataWriter*, void** op);
    HRESULT (STDMETHODCALLTYPE *FlushAsync)(IDataWriter*, void** op);
    HRESULT (STDMETHODCALLTYPE *DetachBuffer)(IDataWriter*, IBuffer**);
    HRESULT (STDMETHODCALLTYPE *DetachStream)(IDataWriter*, IOutputStream**);
} IDataWriterVtbl;
struct IDataWriter { const IDataWriterVtbl *lpVtbl; };

/* IDataWriterFactory for activation with a backing IOutputStream */
typedef struct IDataWriterFactory IDataWriterFactory;
typedef struct IDataWriterFactoryVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDataWriterFactory*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IDataWriterFactory*);
    ULONG   (STDMETHODCALLTYPE *Release)(IDataWriterFactory*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IDataWriterFactory*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IDataWriterFactory*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IDataWriterFactory*, TrustLevel*);
    HRESULT (STDMETHODCALLTYPE *CreateDataWriter)(IDataWriterFactory*, IOutputStream*, IDataWriter**);
} IDataWriterFactoryVtbl;
struct IDataWriterFactory { const IDataWriterFactoryVtbl *lpVtbl; };

/* IActivationFactory — generic WinRT activation */
typedef struct IActivationFactory IActivationFactory;
typedef struct IActivationFactoryVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IActivationFactory*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IActivationFactory*);
    ULONG   (STDMETHODCALLTYPE *Release)(IActivationFactory*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IActivationFactory*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IActivationFactory*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IActivationFactory*, TrustLevel*);
    HRESULT (STDMETHODCALLTYPE *ActivateInstance)(IActivationFactory*, IInspectable**);
} IActivationFactoryVtbl;
struct IActivationFactory { const IActivationFactoryVtbl *lpVtbl; };

/* ---------- CLSID ---------- */
/* ConfigurationStaticFunctions classic-COM CLSID (same for prod & dev) */
static const GUID CLSID_ConfigurationStaticFunctions =
    { 0x73D763B7, 0x2937, 0x432F, { 0xA9, 0x7A, 0xD9, 0x8A, 0x4A, 0x59, 0x61, 0x26 } };

/* ---------- well-known WinRT IIDs (stable, from Windows SDK) ---------- */
static const GUID IID_IInspectable_ =
    { 0xAF86E2E0, 0xB12D, 0x4C6A, { 0x9C, 0x5A, 0xD7, 0xAA, 0x65, 0x10, 0x1E, 0x90 } };
static const GUID IID_IAsyncInfo_ =
    { 0x00000036, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID IID_IActivationFactory_ =
    { 0x00000035, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
/* Windows.Storage.Streams.IInputStream */
static const GUID IID_IInputStream_ =
    { 0x905A0FE2, 0xBC53, 0x11DF, { 0x8C, 0x49, 0x00, 0x1E, 0x4F, 0xC6, 0x86, 0xDA } };
/* Windows.Storage.Streams.IOutputStream */
static const GUID IID_IOutputStream_ =
    { 0x905A0FE6, 0xBC53, 0x11DF, { 0x8C, 0x49, 0x00, 0x1E, 0x4F, 0xC6, 0x86, 0xDA } };
/* Windows.Storage.Streams.IRandomAccessStream */
static const GUID IID_IRandomAccessStream_ =
    { 0x905A0FE1, 0xBC53, 0x11DF, { 0x8C, 0x49, 0x00, 0x1E, 0x4F, 0xC6, 0x86, 0xDA } };
/* Windows.Storage.Streams.IDataWriterFactory */
static const GUID IID_IDataWriterFactory_ =
    { 0x755E0E8F, 0xC4E8, 0x4A93, { 0xA2, 0xBB, 0x06, 0x6C, 0x98, 0x64, 0xE6, 0xEC } };
/* Windows.Storage.Streams.IDataWriter */
static const GUID IID_IDataWriter_ =
    { 0x64B89265, 0xD341, 0x4922, { 0xB3, 0x8A, 0xDD, 0x4A, 0xF8, 0x80, 0x80, 0x73 } };

/* IIDs that MUST be supplied by iids.h (generated at build time from the winmd) */
#include "iids.h"

#endif /* _DSCOURIER_H */
