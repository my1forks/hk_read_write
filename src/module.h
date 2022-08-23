/*++
	dependencies : slist.h
				   utils.h
				   util_stru.hh

--*/

#pragma once
#pragma warning (disable : 4201)
#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>

#include "slist.h"
#include "utils.h"
#include "util_stru.hh"

#define INTERNAL		//不要自己调用这种函数
#define HARDCODE_OFFSET	//系统相关的偏移(硬编码)

extern "C" {
	extern PLIST_ENTRY PsLoadedModuleList;
	extern ERESOURCE PsLoadedModuleResource;
}

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	union {
		struct _LIST_ENTRY InLoadOrderLinks;	HARDCODE_OFFSET
		struct {
			make_offset(0x30);
			void* DllBase;
		};
		struct
		{
			make_offset(0x58);
			struct _UNICODE_STRING BaseDllName; HARDCODE_OFFSET
		};
	};
}KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;


template <typename T>
using travelFuncType = T(*)(PLIST_ENTRY ListEntry);

class kmodule {
public:

	//
	//通过遍历PsLoadedModuleList获得内核模块的基地址
	//
	template<typename T>
	static T get_module(travelFuncType<T> Function);








private:




};