// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

//#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <boost/asio.hpp>
#include <windows.h>



// TODO: reference additional headers your program requires here

/* e.g.
#define DIAG "diag"
std::wcout << _W(DIAG) << ", " << _W("_W(\"diag2\")") << ", " << __W("__W(\"diag3\")") <<std::endl;
*/
// innerally macro
#define __W(quote_string) L ## quote_string
// robust macro
#define _W(quoted_string_or_defined_string) __W(quoted_string_or_defined_string)


//https://en.wikipedia.org/wiki/Data_structure_alignment#Computing_padding
//Compute an `align`-bytes aligned address for `addr`, here `-align = ~((align) - 1))`
// padding = (align - (offset & (align - 1))) & (align - 1) = (-offset & (align - 1))

#define PADDING_UP(offset, align) ((-(intptr_t) (offset)) & ((align) - 1))
#define ALIGN_DOWN(addr, align) ((((intptr_t) (addr))) & ~((align) - 1))
#define ALIGN_UP(addr, align) ((((intptr_t) (addr)) + ((align) - 1)) & ~((align) - 1))


#define GUID_FORMAT "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX"
#define GUID_ARG(guid) guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]


#include <boost/log/trivial.hpp>
#include "frame.h"
#define SECURITY_WIN32