/*++
	dependencies : no

--*/

#pragma once
#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>

class slist
{
public:
	void InitSlist() {  //construct
		Head = (PSLIST_HEADER)ExAllocatePoolWithTag(NonPagedPool, sizeof(SLIST_HEADER), 'tsil');
		if (!Head)
			KeBugCheck((ULONG)STATUS_INSUFFICIENT_RESOURCES);
		InitializeSListHead(Head); }
	void Push(PSLIST_ENTRY Item){
		NT_ASSERTMSG("call InitSlist first", Head);
		InterlockedPushEntrySList(Head, Item);
	}
	PSLIST_ENTRY Pop() {
		NT_ASSERTMSG("call InitSlist first", Head);
		return InterlockedPopEntrySList(Head);
	}
	USHORT Size() { 
		NT_ASSERTMSG("call InitSlist first", Head);
		return ExQueryDepthSList(Head); }
	PSLIST_HEADER GetRawHeadPtr() { return Head; }
private:
	PSLIST_HEADER Head = nullptr;

};