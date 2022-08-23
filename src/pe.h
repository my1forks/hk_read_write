/*++
	dependencies : utils.h

--*/

#pragma once
#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>
#include<ntimage.h>

#include "utils.h"

extern "C" __declspec(dllimport)
PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(
	PVOID Base);

class pe64
{
public:
	//@isInMemory -> 表明当前是内存中的文件还是磁盘上的文件
	pe64(PVOID ImageBase, bool isInMemory = true);

	bool check_image();

	IMAGE_DOS_HEADER* get_dos_headers();
	void print_dos_headers();

	IMAGE_NT_HEADERS* get_nt_headers();
	void print_nt_headers();

	IMAGE_SECTION_HEADER* get_section(const char* section_name);
	void print_sections();

	using handler_type = void(*)(IMAGE_SECTION_HEADER*);
	void processing_sections(handler_type handler);

	IMAGE_DATA_DIRECTORY* get_data_dir(UINT32 id);

	IMAGE_IMPORT_DESCRIPTOR* get_import_descriptor();
	ULONG get_import_descriptor_size();
	IMAGE_EXPORT_DIRECTORY* get_export_descriptor();
	ULONG get_export_descriptor_size();

	PVOID RVAtoP(PVOID pBase, ULONG  rva);
	template<typename T = PVOID>
	T get_image_base() { return (T)_image_base; }

private:
	PVOID _image_base;
	bool _in_mem;
};
