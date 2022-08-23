#include "module.h"

template<typename T>
T kmodule::get_module(travelFuncType<T> Function) {
	return travelsee_list(PsLoadedModuleList, Function);
}


template PVOID kmodule::get_module(travelFuncType<PVOID> Function);