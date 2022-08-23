#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>

template<typename returntype,typename... Args>
struct wrap_call {
	wrap_call() = delete;
	wrap_call(PVOID func_address) { this->_function_address_ = func_address; }
	
	returntype operator()(Args... args) {
		using type = returntype(*)(Args...);
		type T1 = (type)_function_address_;
		return T1(args...);
	}

	PVOID _function_address_;
};