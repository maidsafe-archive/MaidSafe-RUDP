//
// const_define.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~
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

#ifndef p2engine_rdp_const_define_h__
#define p2engine_rdp_const_define_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <string>

namespace p2engine{

	static const std::string INVALID_DOMAIN="INVALID_DOMAIN";
	static const std::string DEFAULT_DOMAIN="DEFAULT_DOMAIN";
	static const uint32_t    INVALID_FLOWID=0xffffff;
	static const uint16_t    INVALID_MSGTYPE=(uint16_t)0xffff;
	static const size_t MTU_SIZE=1450;

}

#endif//p2engine_rdp_h__