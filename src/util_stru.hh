/*++
	dependencies : no

--*/


#pragma once

#define STR_MERGE_IMPL(a, b) a##b
#define STR_MERGE(a, b) STR_MERGE_IMPL(a, b)
#define make_offset(offset) char STR_MERGE(pad,__COUNTER__)[offset]

//for IDA 
#define make_offset_n(offset,name) char STR_MERGE(pad,name)[offset]
