/*++
    dependencies : no
    
--*/

#pragma once

#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>

#define INTERNAL		//不要自己调用这种函数
#define HARDCODE_OFFSET	//系统相关的偏移(硬编码)

extern "C" {
    NTKERNELAPI 
        void* RtlFindExportedRoutineByName(void*, const char*);         //win10之后才有的导出函数

    NTKERNELAPI
        UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);

    NTSYSAPI
        PVOID RtlPcToFileHeader(
            PVOID PcValue,
            PVOID* BaseOfImage
        );
}


template<typename... types>
__inline void print(types... args)
{
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, args...);
}

__inline void dbgbreak() {
    if (*KdDebuggerNotPresent)
        print("[+]breakpoint trigger !!!\n");
    else
        DbgBreakPoint();
}

template<typename T>
T get_data(PVOID start) {
    return *(T*)start;
}


template <typename T>
using travelFuncType = T (*)(PLIST_ENTRY ListEntry);

template <typename T>
T travelsee_list(PLIST_ENTRY ListHead, travelFuncType<T> Function) {
    for (PLIST_ENTRY pListEntry = ListHead->Flink; pListEntry != ListHead; pListEntry = pListEntry->Flink)
    {
        T result = Function(pListEntry);

        if(result != 0)
            return result;
    }
    return (T)0;
}



inline PVOID GetDriverExportRoutine(void* DriverBase,const char* FunctionName) {
    return RtlFindExportedRoutineByName(DriverBase, FunctionName);
}

//windows nt5.1
inline char* stristr(const char* string1, const char* string2)
{
    char* pSave = (char*)string1;
    char* ps1 = (char*)string1;
    char* ps2 = (char*)string2;

    if (!*ps1 || !ps2 || !ps1)
        return NULL;

    if (!*ps2)
        return ps1;

    while (*ps1)
    {
        while (*ps2 && (toupper(*ps2) == toupper(*ps1)))
        {
            ps2++;
            ps1++;
        }
        if (!*ps2)
            return pSave;
        if (ps2 == string2)
        {
            ps1++;
            pSave = ps1;
        }
        else
            ps2 = (char*)string2;
    }

    return NULL;
}
