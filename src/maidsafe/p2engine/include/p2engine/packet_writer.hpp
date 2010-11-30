// packet_writer.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2009-2010  GuangZhu Wu <guangzhuwu@gmail.com>
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
//
// THANKS  Meng Zhang <albert.meng.zhang@gmail.com>
//
#ifndef P2ENGINE_PACKET_WRITER_HPP
#define P2ENGINE_PACKET_WRITER_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"

#include "p2engine/basic_object.hpp"
#include "p2engine/packet.hpp"

namespace p2engine {

	template<class PacketFormatDef>
	class packet_writer : public packet<PacketFormatDef>
	{
		typedef packet<PacketFormatDef> base_type;
		typedef basic_object this_type;
	public:
		typedef boost::shared_ptr<this_type> type;
		typedef boost::weak_ptr<this_type> weak_type;

	public:
		packet_writer() : base_type() {};
		packet_writer(const safe_buffer& buf, size_t len = (std::numeric_limits<size_t>::max)()) 
			: base_type(buf, len, true) {};
		packet_writer(const basic_packet &init_packet) : basic_packet(init_packet) {};
	};
}

#include "p2engine/pop_warning_option.hpp"

#endif // P2ENGINE_PACKET_WRITER_HPP

