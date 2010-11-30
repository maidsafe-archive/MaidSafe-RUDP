//
// config.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2009, GuangZhu Wu  <guangzhuwu@gmail.com>
//
//This program is free software; you can redistribute it and/or modify it 
//under the terms of the GNU General Public License or any later version.
//
//This program is distributed in the hope that it will be useful, but 
//WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
//or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License 
//for more details.
//
//You should have received a copy of the GNU General Public License along 
//with this program; if not, contact <guangzhuwu@gmail.com>.
//
#ifndef P2ENGINE_CONFIG_HPP
#define P2ENGINE_CONFIG_HPP

//BOOST config
#define BOOST_SP_USE_QUICK_ALLOCATOR
//#define BOOST_SP_DISABLE_THREADS

#ifndef BOOST_ASIO_NO_TYPEID
# define BOOST_ASIO_NO_TYPEID
#endif
#ifndef BOOST_ASIO_ENABLE_CANCELIO
# define BOOST_ASIO_ENABLE_CANCELIO
#endif
#ifndef BOOST_ASIO_DISABLE_IOCP
# define BOOST_ASIO_DISABLE_IOCP
#endif
//#define BOOST_ASIO_HASH_MAP_BUCKETS 49157

// set up defines for target environments
#if (defined __APPLE__ && __MACH__) || defined __FreeBSD__ || defined __NetBSD__ \
	|| defined __OpenBSD__ || defined __bsdi__ || defined __DragonFly__ \
	|| defined __FreeBSD_kernel__
#	define P2ENGINE_BSD
#elif defined __linux__
#	define P2ENGINE_LINUX
#elif defined WIN32||defined _WIN32
#	define P2ENGINE_WINDOWS
#elif defined sun || defined __sun 
#	define P2ENGINE_SOLARIS
#else
#	warning unkown OS, assuming BSD
#	define P2ENGINE_BSD
#endif

//is in debug mode
#if defined(NDEBUG)&&defined(_DEBUG)
#	error  NDEBUG and _DEBUG are both defined, please check it.
#else 
#  if (!defined(NDEBUG)&&!defined(_DEBUG))
#		warning  NDEBUG and _DEBUG are both not defined, you must define one of them.
#		define NDEBUG
#  endif
#  if !defined(NDEBUG)||defined(_DEBUG)
#   define P2ENGINE_DEBUG
#  endif
#endif
#if defined(P2ENGINE_DEBUG)&&!defined(_DEBUG)
#define _DEBUG
#endif

//msvc
#if defined(_MSC_VER) && (_MSC_VER != 1500)&& !defined(_DEBUG)//there is a bug in vs90
#define _SECURE_SCL 0
#define _HAS_ITERATOR_DEBUGGING 0
#endif //

// should wpath or path be used?
#if defined UNICODE && !defined BOOST_FILESYSTEM_NARROW_ONLY \
	&& BOOST_VERSION >= 103400 && defined WIN32
#define P2ENGINE_USE_WPATH 1
#else
#define P2ENGINE_USE_WPATH 0
#endif

#if defined(__CYGWIN__)
#    define __USE_W32_SOCKETS
#endif

//#if defined(_MSC_VER)
//# define NOMINMAX
//#endif

#if defined(__CYGWIN__) || defined(_MSC_VER) || defined(__MINGW32__)
# if !defined(_WIN32_WINNT)
#  define _WIN32_WINNT 0x0501 
# endif
#endif

#if defined(P2ENGINE_HEADER_ONLY)
# define P2ENGINE_DECL inline
#else // defined(P2ENGINE_HEADER_ONLY)
//# if defined(BOOST_HAS_DECLSPEC)
#  if defined(BOOST_ALL_DYN_LINK) || defined(_DLL) || defined(_RTLDLL)|| defined(P2ENGINE_DYN_LINK)
#   if !defined(P2ENGINE_DYN_LINK)
#    define P2ENGINE_DYN_LINK
#   endif // !defined(P2ENGINE_DYN_LINK)
// Export if this is our own source, otherwise import.
#   if defined(P2ENGINE_EXPORT)
#    define P2ENGINE_DECL __declspec(dllexport)
#   else // defined(P2ENGINE_SOURCE)
#    define P2ENGINE_DECL __declspec(dllimport)
#   endif // defined(P2ENGINE_SOURCE)
#  endif // defined(BOOST_ALL_DYN_LINK) || defined(P2ENGINE_DYN_LINK)
//# endif // defined(BOOST_HAS_DECLSPEC)
#endif // defined(P2ENGINE_HEADER_ONLY)

#if !defined(P2ENGINE_DECL)
# define P2ENGINE_DECL
#endif // !defined(P2ENGINE_DECL)

// Enable library autolinking for MSVC.
#if !defined(BOOST_ALL_NO_LIB) && !defined(P2ENGINE_NO_LIB) \
	&& !defined(P2ENGINE_SOURCE) && !defined(P2ENGINE_HEADER_ONLY) \
	&& defined(_MSC_VER)

# if !defined(_MT)
#  error "You must use the multithreaded runtime (_MT)."
# endif//_MT

# if (defined(_DLL) || defined(_RTLDLL)) && defined(P2ENGINE_DYN_LINK)
#  define P2ENGINE_LIB_PREFIX
# elif defined(P2ENGINE_DYN_LINK)
#  error "Mixing a dll library with a static runtime is not supported."
# else
#  define P2ENGINE_LIB_PREFIX "lib"
# endif

# if defined(_DEBUG)
#  if defined(P2ENGINE_DYN_LINK)
#   define P2ENGINE_LIB_SUFFIX "-gd"
#  else
#   define P2ENGINE_LIB_SUFFIX "-sgd"
#  endif
# else
#  if defined(P2ENGINE_DYN_LINK)
#   define P2ENGINE_LIB_SUFFIX
#  else
#   define P2ENGINE_LIB_SUFFIX "-s"
#  endif
# endif

# pragma comment(lib, P2ENGINE_LIB_PREFIX "p2engine" P2ENGINE_LIB_SUFFIX ".lib")

#endif // !defined(BOOST_ALL_NO_LIB) && !defined(P2ENGINE_NO_LIB)
//  && !defined(P2ENGINE_SOURCE) && !defined(P2ENGINE_HEADER_ONLY)
//  && defined(_MSC_VER)

#define P2ENGINE_DEBUG_FOR_PACKET_FORMAT_DEF

#include "p2engine/push_warning_option.hpp"
#include <boost/config.hpp>
#include <boost/asio.hpp>
#include <boost/foreach.hpp>
#include <boost/noncopyable.hpp>
#include <cstddef>
#include <algorithm>
#include "p2engine/pop_warning_option.hpp"

#include "p2engine/macro.hpp"
#include "p2engine/typedef.hpp"

namespace boost{
	void inline assertion_failed(char const * expr, char const * func, char const * file, long line)
	{
		printf("(%s) assert failed, function:%s, file:%s, line:%d\n",expr,func,file,line);
#ifdef _WIN32
		//__asm{int 3};
#else
		//__asm__("int $3");
		//abort();
#endif
	}
}

/* The disadvantages of HEADER-ONLY include: 
1.brittleness ¨Cmost changes to the library will require recompilation of all 
  compilation units using that library
2.longer compilation times ¨Cthe compilation unit must see the implementation of 
  all components in the included files, rather than just their interfaces 
3.code-bloat (this may be disputed) ¨Cthe necessary use of inline statements in 
  non-class functions can lead to code bloat by over-inlining. 
Nonetheless, the header-only form is popular because it avoids the (often much 
more serious) problem of packaging.
So, using P2ENGINE_HEADER_ONLY to chose what you need.
*/
#endif//P2ENGINE_CONFIG_HPP