// basic_packet.hpp
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
// Copyright (c) 2008 Meng Zhang
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef P2ENGINE_BASIC_PACKET_HPP
#define P2ENGINE_BASIC_PACKET_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"

#include "p2engine/basic_object.hpp"
#include "p2engine/safe_buffer.hpp"

namespace p2engine {

	class basic_packet 
		: public basic_object
	{
	public:
		basic_packet(size_t buffer_len) 
			: buffer_(buffer_len), packet_length_(buffer_len), user_specified_length_(false) 
		{};
		basic_packet(const safe_buffer& buf, size_t packet_len) 
			:buffer_(buf), packet_length_(packet_len), user_specified_length_(false) 
		{};
		basic_packet(const basic_packet& init_packet)
			: buffer_(init_packet.buffer_), packet_length_(init_packet.packet_length_), 
			user_specified_length_(init_packet.user_specified_length_) 
		{};
		virtual  ~basic_packet() {};

	public:
		void release_buffer()
		{
			buffer_.reset();
		}
		virtual size_t packet_length() const
		{
			return packet_length_;
		};

		virtual void packet_length(size_t length)
		{
			packet_length_ = length;
			user_specified_length_ = true;
		};

		safe_buffer buffer() const {return buffer_;};
		size_t buffer_length() const {return buffer_.length();};

		basic_packet& operator=(const basic_packet& pkt)
		{
			this->buffer_ = pkt.buffer_;//???deep copy buffer_?
			this->packet_length_ = pkt.packet_length_;
			this->user_specified_length_ = pkt.user_specified_length_;
			return *this;
		};

	protected:
		safe_buffer buffer_;
		size_t packet_length_;
		bool user_specified_length_;
	};

}//namespace p2engine 

#include "p2engine/push_warning_option.hpp"

#endif // P2ENGINE_BASIC_PACKET_HPP
