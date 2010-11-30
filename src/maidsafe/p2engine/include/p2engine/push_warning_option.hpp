//
// abi_prefix.hpp
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

// Disable some pesky MSVC warnings.
#if defined(_MSC_VER)
# pragma warning (push)
# pragma warning(disable : 4127)
# pragma warning(disable : 4244)
# pragma warning(disable : 4251)
# pragma warning(disable : 4309)
# pragma warning(disable : 4307)
# pragma warning(disable : 4333)
# pragma warning(disable : 4355)
# pragma warning(disable : 4503)
# pragma warning(disable : 4512)
# pragma warning(disable : 4800)
# pragma warning(disable : 4819)
# pragma warning(disable : 4996)

#ifndef _CRT_SECURE_NO_WARNINGS
#	define  _CRT_SECURE_NO_WARNINGS
#endif
#ifndef _SCL_SECURE_NO_WARNINGS
#	define  _SCL_SECURE_NO_WARNINGS
#endif

#endif // defined(_MSC_VER)

// Force external visibility of all types.
#if defined(__GNUC__)
# if (__GNUC__ == 4 && __GNUC_MINOR__ >= 1) || (__GNUC__ > 4)
#  pragma GCC visibility push (default)
# endif // (__GNUC__ == 4 && __GNUC_MINOR__ >= 1) || (__GNUC__ > 4)
#endif // defined(__GNUC__)

