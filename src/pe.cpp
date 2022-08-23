#include "pe.h"

pe64::pe64(PVOID ImageBase, bool isInMemory) {
	this->_image_base = ImageBase;
	this->_in_mem = isInMemory;
}

//windows/core/ntuser/client/extract.c
PVOID pe64::RVAtoP(PVOID pBase, ULONG  rva)
{
	IMAGE_DOS_HEADER* pmz;
	IMAGE_NT_HEADERS* ppe;
	IMAGE_SECTION_HEADER* pSection; // section table
	int                  i;
	ULONG                size;

	pmz = (IMAGE_DOS_HEADER*)pBase;
	ppe = (IMAGE_NT_HEADERS*)((char*)pBase + pmz->e_lfanew);

	/*
	 * Scan the section table looking for the RVA
	 */
	pSection = IMAGE_FIRST_SECTION(ppe);

	for (i = 0; i < ppe->FileHeader.NumberOfSections; i++) {

		size = pSection[i].Misc.VirtualSize ?
			pSection[i].Misc.VirtualSize : pSection[i].SizeOfRawData;

		if (rva >= pSection[i].VirtualAddress &&
			rva < pSection[i].VirtualAddress + size) {

			return (char*)pBase + pSection[i].PointerToRawData + (rva - pSection[i].VirtualAddress);
		}
	}

	return NULL;
}

bool pe64::check_image() {
	return MmIsAddressValid(this->_image_base);
}

IMAGE_NT_HEADERS* pe64::get_nt_headers()
{
	return RtlImageNtHeader(this->_image_base);
}

IMAGE_DOS_HEADER* pe64::get_dos_headers() {

	return (IMAGE_DOS_HEADER*)this->_image_base;
}

IMAGE_SECTION_HEADER* pe64::get_section(const char* section_name) {

	USHORT section_count = get_nt_headers()->FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(get_nt_headers());
	for (int i = 0; i < section_count; i++) {
		if (!section_name) {
			print("[+]Name : %s\n", section_header[i].Name);
			print("[+]VirtualSize : 0x%x\n", section_header[i].Misc.VirtualSize);
			print("[+]VirtualAddress : 0x%x\n", section_header[i].VirtualAddress);
			print("[+]PointerToRawData : 0x%x\n", section_header[i].PointerToRawData);
			print("[+]SizeOfRawData : 0x%x\n", section_header[i].SizeOfRawData);
			print("[+]Characteristics : 0x%x\n", section_header[i].Characteristics);
		}
		else {
			if (!strcmp(section_name, (const char*)section_header[i].Name)) {
				return &section_header[i];
			}
		}
	}
	return nullptr;
}

void pe64::print_dos_headers() {
	auto dos = get_dos_headers();
	print("[+]e_magic : 0x%x\n", dos->e_magic);
	print("[+]e_lfanew : %u\n", dos->e_lfanew);
	print("[+]dos header end...\n");
}

void pe64::print_nt_headers() {
	auto nt = get_nt_headers();
	print("[+]Signature : 0x%x\n", nt->Signature);
	print("[+]NumberOfSections : %d\n", nt->FileHeader.NumberOfSections);
	print("[+]SizeOfOptionalHeader : %d\n", nt->FileHeader.SizeOfOptionalHeader);
	print("[+]Magic : 0x%x\n", nt->OptionalHeader.Magic);
	print("[+]AddressOfEntryPoint : 0x%x\n", nt->OptionalHeader.AddressOfEntryPoint);
	print("[+]ImageBase : 0x%x\n", nt->OptionalHeader.ImageBase);
	print("[+]SectionAlignment : 0x%x\n", nt->OptionalHeader.SectionAlignment);
	print("[+]FileAlignment : 0x%x\n", nt->OptionalHeader.FileAlignment);
	print("[+]SizeOfImage : 0x%x\n", nt->OptionalHeader.SizeOfImage);
	print("[+]SizeOfHeaders : 0x%x\n", nt->OptionalHeader.SizeOfHeaders);
	print("[+]CheckSum : 0x%x\n", nt->OptionalHeader.CheckSum);
	print("[+]nt header end...\n");
}

void pe64::print_sections() {
	get_section(nullptr);
}

void pe64::processing_sections(handler_type handler) {
	USHORT section_count = get_nt_headers()->FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(get_nt_headers());
	for (int i = 0; i < section_count; i++) {
		handler(&section_header[i]);
	}
	return;
}

IMAGE_DATA_DIRECTORY* pe64::get_data_dir(UINT32 id) {
	return &get_nt_headers()->OptionalHeader.DataDirectory[id];
}


//导入表

IMAGE_IMPORT_DESCRIPTOR* pe64::get_import_descriptor()
{
	ULONG Rva = get_nt_headers()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (this->_in_mem) {
		return (IMAGE_IMPORT_DESCRIPTOR*)(get_image_base<char*>() + Rva);
	}
	else {
		return (IMAGE_IMPORT_DESCRIPTOR*)(get_image_base<char*>() + (ULONG64)RVAtoP(get_image_base(), Rva));
	}
}

ULONG pe64::get_import_descriptor_size() {
	return get_nt_headers()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
}


//导出表

IMAGE_EXPORT_DIRECTORY* pe64::get_export_descriptor() {
	ULONG Rva = get_nt_headers()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (this->_in_mem) {
		return (IMAGE_EXPORT_DIRECTORY*)(get_image_base<char*>() + Rva);
	}
	else {
		return (IMAGE_EXPORT_DIRECTORY*)(get_image_base<char*>() + (ULONG64)RVAtoP(get_image_base(), Rva));
	}

}

ULONG pe64::get_export_descriptor_size() {
	return get_nt_headers()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
}


//

