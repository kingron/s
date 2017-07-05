//
// winsock2i.h - Include winsock2.h safely.
//
// Copyleft   02/24/2005   by freefalcon
//
//

// When WIN32_LEAN_AND_MEAN is not defined and _WIN32_WINNT is LESS THAN 0x400,
// if we include winsock2.h AFTER windows.h or winsock.h, we get some compiling
// errors as following:
//    winsock2.h(99) : error C2011: 'fd_set' : 'struct' type redefinition
//
// When WIN32_LEAN_AND_MEAN is not defined and _WIN32_WINNT is NOT LESS THAN 0x400,
// if we include winsock2.h BEFORE windows.h, we get some other compiling errors:
//    mswsock.h(69) : error C2065: 'SOCKET' : undeclared identifier
//
// So, this file is used to help us to include winsock2.h safely, it should be
// placed before any other header files.
//



#ifndef _WINSOCK2API_

// Prevent inclusion of winsock.h
#ifdef _WINSOCKAPI_
#error Header winsock.h is included unexpectedly.
#endif

// NOTE: If you use Windows Platform SDK, you should enable following definition:
#define USING_WIN_PSDK

#if !defined(WIN32_LEAN_AND_MEAN) && (_WIN32_WINNT >= 0x0400) && !defined(USING_WIN_PSDK)

#include <windows.h>
#else
#include <winsock2.h>
#endif

#endif//_WINSOCK2API_
