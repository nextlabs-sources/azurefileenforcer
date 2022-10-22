// smb.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "ForceProxy.h"

#include <boost/asio.hpp>
#include <boost/make_shared.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread.hpp>
#include <boost/thread/tss.hpp>
#include <boost/filesystem.hpp>

#if _DEBUG
#include <iostream>
#endif

/*
// https://stackoverflow.com/questions/1505582/determining-32-vs-64-bit-in-c
#if _WIN32 || _WIN64 // Check windows
#if _WIN64
#pragma comment(lib,"..\\x64\\Debug\\frame.lib")
#else
#pragma comment(lib,"..\\Debug\\frame.lib")
#endif
#else
#error "Unsupported compiler"
#endif
*/


//ForceProxy g_Enforcer;

// boost::thread_specific_ptr<MyClass> or thread_local MyClass (C++11) do execute the destructor
//if (!instance.get()) {
//	// first time called by this thread
//	// construct test element to be used in all subsequent calls from this thread
//	instance.reset(new MyClass);
//}
// static boost::thread_specific_ptr<std::vector<char>> tls_CodecBuffers;
// thread_local boost::asio::streambuf tls_CodecBuffers;

// __ ImageBase is variable of type IMAGE_DOS_HEADER, and this is coming first in the PE (portable executable format). 
// It's a windows structure and is available only under Windows. 
// In my opinion is safe to use and will not be changed in the future. An alternative will be GetModuleHandle but needs dll name.
EXTERN_C IMAGE_DOS_HEADER __ImageBase;
extern void string_to_hex(std::stringstream & sstream, const char* input, size_t length);
