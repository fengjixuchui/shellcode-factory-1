#pragma once
#include <windows.h>
#include <Winternl.h>
#define PAGE_EXECUTE_FLAGS (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         NumberOfLinks;
    BOOLEAN       DeletePending;
    BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;
typedef PVOID (NTAPI *t_RtlAddVectoredExceptionHandler)(IN ULONG FirstHandler, IN PVECTORED_EXCEPTION_HANDLER VectoredHandler);
typedef ULONG (NTAPI *t_RtlRemoveVectoredExceptionHandler)(IN PVOID VectoredHandlerHandle);

typedef int(__cdecl *t_vsnprintf_s)(char *DstBuf, size_t SizeInBytes, size_t MaxCount, const char *Format,
                                    va_list ArgList);
typedef int(NTAPI *t_sprintf_s)(char *DstBuf, size_t SizeInBytes, const char *Format, ...);



typedef NTSTATUS(WINAPI *t_LdrGetProcedureAddress)(IN PVOID DllHandle, IN PANSI_STRING ProcedureName OPTIONAL,
                                                  IN ULONG ProcedureNumber OPTIONAL, OUT FARPROC *ProcedureAddress);
typedef VOID(WINAPI *t_RtlFreeUnicodeString)(_Inout_ PUNICODE_STRING UnicodeString);
typedef VOID(WINAPI *t_RtlInitAnsiString)(_Out_ PANSI_STRING DestinationString, _In_opt_ PCSZ SourceString);
typedef NTSTATUS(WINAPI *t_RtlAnsiStringToUnicodeString)(_Inout_ PUNICODE_STRING DestinationString,
                                                        _In_ PCANSI_STRING      SourceString,
                                                        _In_ BOOLEAN            AllocateDestinationString);
typedef NTSTATUS(WINAPI *t_LdrLoadDll)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
typedef BOOL(APIENTRY *t_ProcDllMain)(LPVOID, DWORD, LPVOID);


typedef DWORD(WINAPI *t_ZwCreateSection)(PHANDLE            SectionHandle,
                                           ACCESS_MASK        DesiredAccess,
                                           POBJECT_ATTRIBUTES ObjectAttributes,
                                           PLARGE_INTEGER     MaximumSize,
                                           ULONG              SectionPageProtection,
                                           ULONG              AllocationAttributes,
                                           HANDLE             FileHandle);


typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2

} SECTION_INHERIT;

typedef DWORD(WINAPI *t_ZwMapViewOfSection)(HANDLE          SectionHandle,
                                              HANDLE          ProcessHandle,
                                              PVOID *         BaseAddress,
                                              ULONG_PTR       ZeroBits,
                                              SIZE_T          CommitSize,
                                              PLARGE_INTEGER  SectionOffset,
                                              PSIZE_T         ViewSize,
                                              SECTION_INHERIT InheritDisposition,
                                              ULONG           AllocationType,
                                              ULONG           Win32Protect);



typedef DWORD(WINAPI *t_ZwUnmapViewOfSection)(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress);

typedef NTSTATUS(WINAPI *t_ZwCreateFile)(_Out_ PHANDLE                        FileHandle,
                                           _In_ ACCESS_MASK                     DesiredAccess,
                                           _In_ POBJECT_ATTRIBUTES              ObjectAttributes,
                                           _Out_ PIO_STATUS_BLOCK               IoStatusBlock,
                                           _In_opt_ PLARGE_INTEGER              AllocationSize,
                                           _In_ ULONG                           FileAttributes,
                                           _In_ ULONG                           ShareAccess,
                                           _In_ ULONG                           CreateDisposition,
                                           _In_ ULONG                           CreateOptions,
                                           _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
                                           _In_ ULONG                           EaLength);

typedef VOID(WINAPI *t_RtlInitUnicodeString)(_Out_ PUNICODE_STRING              DestinationString,
                                               _In_opt_z_ __drv_aliasesMem PCWSTR SourceString);

typedef NTSTATUS(WINAPI *t_ZwQueryInformationFile)(_In_ HANDLE                      FileHandle,
                                                     _Out_ PIO_STATUS_BLOCK           IoStatusBlock,
                                                     _Out_writes_bytes_(Length) PVOID FileInformation,
                                                     _In_ ULONG                       Length,
                                                     _In_ ULONG                       FileInformationClass);

typedef NTSTATUS(WINAPI *t_ZwClose)(_In_ HANDLE Handle);



typedef NTSTATUS(NTAPI *_ZwGetContextThread)(IN HANDLE ThreadHandle, OUT PCONTEXT pContext);

typedef NTSTATUS(NTAPI *_ZwSetContextThread)(IN HANDLE ThreadHandle, IN PCONTEXT Context);

typedef NTSTATUS(NTAPI *_ZwSuspendThread)(IN HANDLE ThreadHandle, OUT PULONG PreviousSuspendCount OPTIONAL);

typedef NTSTATUS(NTAPI *_ZwResumeThread)(IN HANDLE ThreadHandle, OUT PULONG PreviousSuspendCount OPTIONAL);

typedef NTSTATUS(NTAPI *_NtSuspendThread)(IN HANDLE ThreadHandle, OUT PULONG PreviousSuspendCount OPTIONAL);

typedef NTSTATUS(NTAPI *_ZwCreateThreadEx)(OUT PHANDLE                            ThreadHandle,
                                           IN ACCESS_MASK                         DesiredAccess,
                                           IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
                                           IN HANDLE                              ProcessHandle,
                                           IN PTHREAD_START_ROUTINE               StartRoutine,
                                           IN PVOID                               StartContext,
                                           IN ULONG                               CreateThreadFlags,
                                           IN SIZE_T ZeroBits                     OPTIONAL,
                                           IN SIZE_T StackSize                    OPTIONAL,
                                           IN SIZE_T MaximumStackSize             OPTIONAL,
                                           IN PPROC_THREAD_ATTRIBUTE_LIST         AttributeList);


typedef NTSTATUS(NTAPI *t_ZwProtectVirtualMemory )(IN HANDLE ProcessHandle,
                                                IN PVOID *BaseAddress,
                                                IN SIZE_T *NumberOfBytesToProtect,
                                                IN ULONG   NewAccessProtection,
                                                OUT PULONG OldAccessProtection);


typedef  NTSTATUS (NTAPI *t_ZwReadVirtualMemory )(IN HANDLE               ProcessHandle,
                                                 IN PVOID                BaseAddress,
                                                 OUT PVOID               Buffer,
                                                 IN ULONG                BufferLength,
                                                 OUT PULONG ReturnLength OPTIONAL);

typedef  NTSTATUS (NTAPI *_ZwWriteVirtualMemory)(IN HANDLE               ProcessHandle,
                                                  IN PVOID                BaseAddress,
                                                  OUT PVOID               Buffer,
                                                  IN ULONG                BufferLength,
                                                  OUT PULONG ReturnLength OPTIONAL);


typedef BOOLEAN (NTAPI *t_RtlAddFunctionTable)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);


typedef PVOID(WINAPI *t_RtlImageDirectoryEntryToData)(_In_ PVOID   Base,
                                                    _In_ BOOLEAN MappedAsImage,
                                                    _In_ USHORT  DirectoryEntry,
                                                    _Out_ PULONG Size);

typedef PIMAGE_NT_HEADERS(WINAPI* t_RtlImageNtHeader)(PVOID Base);


typedef enum _MEMORY_INFORMATION_CLASS { MemoryBasicInformation } MEMORY_INFORMATION_CLASS;
typedef  NTSTATUS (WINAPI*t_ZwQueryVirtualMemory)(HANDLE                   ProcessHandle,
                                       PVOID                    BaseAddress,
                                       MEMORY_INFORMATION_CLASS MemoryInformationClass,
                                       PVOID                    MemoryInformation,
                                       SIZE_T                   MemoryInformationLength,
                                       PSIZE_T                  ReturnLength);