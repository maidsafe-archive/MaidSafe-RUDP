// packet.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2009-2010  GuangZhu Wu
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

#ifndef P2ENGINE_PACKET_HPP
#define P2ENGINE_PACKET_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"

#include "p2engine/basic_object.hpp"
#include "p2engine/basic_packet.hpp"

namespace p2engine {

	template<class PacketFormatDef>
	class packet 
		: public basic_packet
	{
		typedef basic_object this_type;
		SHARED_ACCESS_DECLARE;
	protected:
		packet()
			: basic_packet(PacketFormatDef::packet_size()) 
			, packet_format_def_(buffer_, true)
		{
			assert(buffer_.memset(0));
		};
		packet(const safe_buffer& buf, size_t len = (std::numeric_limits<size_t>::max)(), bool init_reset = true) 
			: basic_packet(buf, (std::min)(PacketFormatDef::packet_size(), len))
			, packet_format_def_(buffer_, init_reset)
		{
			assert(!init_reset || buffer_.memset(0));
			assert(init_reset || 
				PacketFormatDef::format_signature() == packet_format_def_.get_signature());
		};
		packet(const basic_packet& init_packet) 
			: basic_packet(init_packet)
			, packet_format_def_(buffer_, false)
		{
			assert(packet_length_ <= PacketFormatDef::packet_size());
			assert(packet_length_ <= buffer_.length());
			assert(PacketFormatDef::format_signature() == packet_format_def_.get_signature());
		};

	public:
		typedef PacketFormatDef format_def;

		format_def &packet_format_def() {return packet_format_def_;};
		const format_def &packet_format_def()const {return packet_format_def_;};

		virtual size_t packet_length() const
		{
			return (user_specified_length_) ? packet_length_ : 
				(std::min)(packet_format_def_.truncated_size(), buffer_.length());
		}

		virtual void packet_length(size_t length)
		{
			basic_packet::packet_length(length);
			assert(length <= PacketFormatDef::packet_size());
			assert(length <= this->buffer_length());
		}
		//     packet& operator=(const packet& pkt)
		//     {
		//         this->buffer_ = pkt.buffer_;
		//         this->packet_length_ = pkt.packet_length_;
		//         this->user_specified_length_ = user_specified_length_;
		//this->packet_format_def_ = pkt.packet_format_def_;
		//return *this;
		//     }

	private:
		PacketFormatDef packet_format_def_;
	};

}

#include "p2engine/pop_warning_option.hpp"

#endif // P2ENGINE_PACKET_HPP

