#include "us_util.h"

bool RtlFindSubUnicodeString(const WCHAR* sub, PCUNICODE_STRING src)
{
	if (!sub || !src || !src->Buffer)
		return false;

	WCHAR* tmp = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, src->Length + sizeof(L'\0'), 'bbs');
	WCHAR* sub_t = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, wcslen(sub) * 2 + sizeof(L'\0'), 'bbs');

	if (!tmp || !sub_t)
		return false;

	memcpy(tmp, src->Buffer, src->Length);
	tmp[src->Length / 2] = L'\0';


	memcpy(sub_t, sub, wcslen(sub) * 2);

	sub_t[wcslen(sub)] = L'\0';

	bool ret = (wcsstr(tmp, sub_t)) ? true : false;

	ExFreePoolWithTag(tmp, 'bbs');
	ExFreePoolWithTag(sub_t, 'bbs');


	return ret;
}

bool RtlFindSubUnicodeStringWithNoCase(const WCHAR* sub, const PCUNICODE_STRING src) {
	if (!sub || !src || !src->Buffer)
		return false;

	WCHAR* tmp = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, src->Length + sizeof(L'\0'), 'bbs');
	WCHAR* sub_t = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, wcslen(sub) * 2 + sizeof(L'\0'), 'bbs');

	if (!tmp || !sub_t)
		return false;

	memcpy(tmp, src->Buffer, src->Length);
	tmp[src->Length / 2] = L'\0';


	memcpy(sub_t, sub, wcslen(sub) * 2);

	sub_t[wcslen(sub)] = L'\0';

	RtlDowncaseUnicodeArray(tmp);
	RtlDowncaseUnicodeArray(sub_t);

	bool ret = (wcsstr(tmp, sub_t)) ? true : false;

	ExFreePoolWithTag(tmp, 'bbs');
	ExFreePoolWithTag(sub_t, 'bbs');

	return ret;
}