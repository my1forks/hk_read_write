/*
* 天擎客户端有感知进程创建的能力,但是他没有DeviceIoControl和FltSendMessage
* 
* 
* 
1: kd> k
# Child-SP          RetAddr               Call Site
00 fffff90e`86d67100 fffff802`514d1189     driver_analyse_tool!HandlerIrpRead+0xa6 [D:\source\hk_read\driver_analyse_tool\src\user.cpp @ 119] 
01 fffff90e`86d67150 fffff802`b0396219     nt!IofCallDriver+0x59
02 fffff90e`86d67190 fffff802`b0394a36     FLTMGR!FltpLegacyProcessingAfterPreCallbacksCompleted+0x289
03 fffff90e`86d67200 fffff802`514d1189     FLTMGR!FltpDispatch+0xb6
04 fffff90e`86d67260 fffff802`519bb2d1     nt!IofCallDriver+0x59
05 fffff90e`86d672a0 fffff802`51946d28     nt!IopSynchronousServiceTail+0x1b1
06 fffff90e`86d67350 fffff802`515d8285     nt!NtReadFile+0x688
07 fffff90e`86d67450 00000000`77641cbc     nt!KiSystemServiceCopyEnd+0x25
08 00000000`1dc9ebf8 00000000`7764199a     wow64cpu!CpupSyscallStub+0xc
09 00000000`1dc9ec00 00000000`77641199     wow64cpu!ReadWriteFileFault+0x31
0a 00000000`1dc9ecb0 00007ffd`ae98cf9a     wow64cpu!BTCpuSimulate+0x9
0b 00000000`1dc9ecf0 00007ffd`ae98ce60     wow64!RunCpuSimulation+0xa
0c 00000000`1dc9ed20 00007ffd`b017774b     wow64!Wow64LdrpInitialize+0x120
0d 00000000`1dc9efd0 00007ffd`b0177633     ntdll!_LdrpInitialize+0xff
0e 00000000`1dc9f070 00007ffd`b01775de     ntdll!LdrpInitialize+0x3b
0f 00000000`1dc9f0a0 00000000`00000000     ntdll!LdrInitializeThunk+0xe
* 
* 
* 
* 
*/

#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>

#include"utils.h"
#include"module.h"
#include"us_util.h"

UNICODE_STRING Ntfs = RTL_CONSTANT_STRING(L"\\??\\C:\\Windows\\System32\\drivers\\ntfs.sys");
UNICODE_STRING NtfsDriverName = RTL_CONSTANT_STRING(L"\\FileSystem\\Ntfs");
FILE_OBJECT* NtfsFileObject;
DEVICE_OBJECT* NtfsDeviceObject;            //这个其实是FltMgr的DeviceObject(或FltMgr的上层设备)
DRIVER_OBJECT* NtfsDriverObject;

PFAST_IO_READ OriNtfsIoFastRead;
PDRIVER_DISPATCH OriNtfsIrpMjRead;;
PFAST_IO_WRITE OriNtfsIoFastWrite;
PDRIVER_DISPATCH OriNtfsIrpMjWrite;

NTSTATUS HandlerIrpRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS HandlerIrpWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
BOOLEAN
HandlerFastIoRead(
    _In_ struct _FILE_OBJECT* FileObject,
    _In_ PLARGE_INTEGER FileOffset,
    _In_ ULONG Length,
    _In_ BOOLEAN Wait,
    _In_ ULONG LockKey,
    _Out_ PVOID Buffer,
    _Out_ PIO_STATUS_BLOCK IoStatus,
    _In_ struct _DEVICE_OBJECT* DeviceObject
);
BOOLEAN
HandlerFastIoWrite(
    _In_ struct _FILE_OBJECT* FileObject,
    _In_ PLARGE_INTEGER FileOffset,
    _In_ ULONG Length,
    _In_ BOOLEAN Wait,
    _In_ ULONG LockKey,
    _In_ PVOID Buffer,
    _Out_ PIO_STATUS_BLOCK IoStatus,
    _In_ struct _DEVICE_OBJECT* DeviceObject
);

void unload(PDRIVER_OBJECT drv) {
    UNREFERENCED_PARAMETER(drv);

    ObDereferenceObject(NtfsFileObject);
    
    NtfsDriverObject->MajorFunction[IRP_MJ_READ] = (PDRIVER_DISPATCH)OriNtfsIrpMjRead;
    NtfsDriverObject->FastIoDispatch->FastIoRead = (PFAST_IO_READ)OriNtfsIoFastRead;
    NtfsDriverObject->MajorFunction[IRP_MJ_WRITE] = (PDRIVER_DISPATCH)OriNtfsIrpMjWrite;
    NtfsDriverObject->FastIoDispatch->FastIoWrite = (PFAST_IO_READ)OriNtfsIoFastWrite;

    
    print("[+]driver unload...\n");
    return;
}


void user_main(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    UNREFERENCED_PARAMETER(drv);
    UNREFERENCED_PARAMETER(reg);
    NTSTATUS Status;
    Status = IoGetDeviceObjectPointer(&Ntfs, FILE_ALL_ACCESS, &NtfsFileObject, &NtfsDeviceObject);
    if (!NT_SUCCESS(Status)) {
        print("[-]IoGetDeviceObjectPointer failed with %x\n", Status);
    }

    DEVICE_OBJECT* DO = NtfsDeviceObject;
    
    //打印设备栈
    while (DO) {
        //print("[+]%wZ\n", DO->DriverObject->DriverName);

        if (RtlEqualUnicodeString(&NtfsDriverName, &DO->DriverObject->DriverName,true)) {
            NtfsDriverObject = DO->DriverObject;
            break;
        }

        DO = DO->DeviceObjectExtension->AttachedTo;
    }

    print("[+]ntfs driver name : %wZ\n", NtfsDriverObject->DriverName);
    print("[+]ntfs driver object : %p\n", NtfsDriverObject);

    //保存原指针
    OriNtfsIoFastRead = NtfsDriverObject->FastIoDispatch->FastIoRead;
    OriNtfsIrpMjRead = NtfsDriverObject->MajorFunction[IRP_MJ_READ];
    OriNtfsIoFastWrite = NtfsDriverObject->FastIoDispatch->FastIoWrite;
    OriNtfsIrpMjWrite = NtfsDriverObject->MajorFunction[IRP_MJ_WRITE];


    //hook
    NtfsDriverObject->MajorFunction[IRP_MJ_READ] = HandlerIrpRead;
    NtfsDriverObject->FastIoDispatch->FastIoRead = HandlerFastIoRead;
    NtfsDriverObject->MajorFunction[IRP_MJ_WRITE] = HandlerIrpWrite;
    NtfsDriverObject->FastIoDispatch->FastIoWrite = HandlerFastIoWrite;






    return;
}

//TQClient.exe
//\Users\user\AppData\Local\Temp\Rar$DRb6796.9207\cad0bd3e89c5f5068e476052ea238068c73584d0569ad13fa4ae10752f7d1245.exe
NTSTATUS HandlerIrpRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {

    unsigned char* IF = PsGetProcessImageFileName(IoGetCurrentProcess());

    PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
    FILE_OBJECT* FO = IrpStack->FileObject;
    if (stristr((const char*)IF, "TQClient")) {
        print("[Read]%wZ\n", FO->FileName);
    }
 
    return OriNtfsIrpMjRead(DeviceObject, Irp);
}

BOOLEAN
HandlerFastIoRead(
    _In_ struct _FILE_OBJECT* FileObject,
    _In_ PLARGE_INTEGER FileOffset,
    _In_ ULONG Length,
    _In_ BOOLEAN Wait,
    _In_ ULONG LockKey,
    _Out_ PVOID Buffer,
    _Out_ PIO_STATUS_BLOCK IoStatus,
    _In_ struct _DEVICE_OBJECT* DeviceObject
) {
    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(FileOffset);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Wait);
    UNREFERENCED_PARAMETER(LockKey);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(IoStatus);
    UNREFERENCED_PARAMETER(DeviceObject);
    return false;
}

NTSTATUS HandlerIrpWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    unsigned char* IF = PsGetProcessImageFileName(IoGetCurrentProcess());
    PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
    FILE_OBJECT* FO = IrpStack->FileObject;

    if (stristr((const char*)IF, "TQClient")) {
        print("[Wrtie]%wZ\n", FO->FileName);
    }

    return OriNtfsIrpMjWrite(DeviceObject, Irp);
}

BOOLEAN
HandlerFastIoWrite(
    _In_ struct _FILE_OBJECT* FileObject,
    _In_ PLARGE_INTEGER FileOffset,
    _In_ ULONG Length,
    _In_ BOOLEAN Wait,
    _In_ ULONG LockKey,
    _In_ PVOID Buffer,
    _Out_ PIO_STATUS_BLOCK IoStatus,
    _In_ struct _DEVICE_OBJECT* DeviceObject
) {
    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(FileOffset);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Wait);
    UNREFERENCED_PARAMETER(LockKey);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(IoStatus);
    UNREFERENCED_PARAMETER(DeviceObject);

    return false;
}
