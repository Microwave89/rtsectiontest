#ifndef _GLOBAL_H_
#define _GLOBAL_H_
#define WIN32_NO_STATUS
//#define _NO_CRT_STDIO_INLINE

//#define BOOT_APP

#if defined(BOOT_APP)
#pragma comment(linker, "/SUBSYSTEM:NATIVE")
#else
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#endif

//#define BOOTSCR_OUTPUT

#include <windows.h>
#include <..\ndk\ntndk.h>
#include <intrin.h>
#include "auxfuncs.h"

#endif