// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

// Headers for CppUnitTest
#include "CppUnitTest.h"

// TODO: reference additional headers your program requires here
#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>
#include "..\..\..\Frame\frame.h"
#include <windows.h>

// 1>c:\program files (x86)\windows kits\8.1\include\shared\sspi.h(64): fatal error C1189: #error:   You must define one of SECURITY_WIN32, SECURITY_KERNEL, or
#define SECURITY_WIN32

#define GUID_FORMAT "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX"
#define GUID_ARG(guid) guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]

/* e.g.
#define DIAG "diag"
std::wcout << _W(DIAG) << ", " << _W("_W(\"diag2\")") << ", " << __W("__W(\"diag3\")") <<std::endl;
*/
// innerally macro
#define __W(quote_string) L ## quote_string
// robust macro
#define _W(quoted_string_or_defined_string) __W(quoted_string_or_defined_string)



#ifdef _DEBUG
#define DBGPRINT(kwszDebugFormatString, ...) _DBGPRINT(__FUNCTIONW__, __LINE__, kwszDebugFormatString, __VA_ARGS__)

VOID _DBGPRINT(LPCWSTR kwszFunction, INT iLineNumber, LPCWSTR kwszDebugFormatString, ...);
#else
#define DBGPRINT( kwszDebugFormatString, ... ) ;;
#endif