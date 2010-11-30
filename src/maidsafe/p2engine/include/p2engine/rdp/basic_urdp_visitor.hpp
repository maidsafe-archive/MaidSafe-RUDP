// basic_urdp_visitor.h
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2009-2010 GuangZhu Wu  <guangzhuwu@gmail.com>
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

#ifndef P2ENGINE_BASIC_RUDP_VISITOR_HPP
#define P2ENGINE_BASIC_RUDP_VISITOR_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <string>
#include "p2engine/pop_warning_option.hpp"

#include "p2engine/typedef.hpp"
#include "p2engine/packet.hpp"
#include "p2engine/rdp/const_define.hpp"

namespace p2engine{

	//////////////////////////////////////////////////////////////////////////
	//vistors,to extract information from special urdp_header_fomart.
	template <typename RudpPacketFormat>
	struct get_dst_peer_id_vistor 
	{
		uint32_t operator()(const RudpPacketFormat&)const;
	};

	template <typename RudpPacketFormat>
	struct get_src_peer_id_vistor 
	{
		uint32_t operator()(const RudpPacketFormat&)const;
	};

	template <typename RudpPacketFormat>
	struct get_session_vistor 
	{
		uint32_t operator()(const RudpPacketFormat&)const;
	};

	template <typename RudpPacketFormat>
	struct get_demain_name_vistor 
	{
		std::string operator()(const RudpPacketFormat&,const safe_buffer& buf)const;
	};

	template <typename RudpPacketFormat>
	struct make_refuse_vistor
	{
		safe_buffer operator()(const RudpPacketFormat& h)const;
	};

	template <typename RudpPacketFormat>
	struct is_conn_request_vistor
	{
		bool operator()(const RudpPacketFormat& h)const;
	};

	template <typename RudpPacketFormat>
	struct is_punch_ping_vistor
	{
		bool operator()(const RudpPacketFormat& h)const;
	};

	template <typename RudpPacketFormat>
	struct is_punch_pong_vistor
	{
		bool operator()(const RudpPacketFormat& h)const;
	};

	struct punch_pong
	{
		asio::ip::udp::endpoint remote_endpoint;
		safe_buffer pong;
	};

	template <typename RudpPacketFormat>
	struct make_punch_pong_vistor
	{
		punch_pong operator()(const RudpPacketFormat& h)const;
	};

	template <typename RudpPacketFormat>
	struct get_invalid_peer_id_vistor
	{
		uint32_t operator()(void)const{return INVALID_FLOWID;}
	};

	template <typename RudpPacketFormat>
	struct get_invalid_domain_vistor
	{
		std::string operator()(void)const{return INVALID_DOMAIN;}
	};

	template <typename RudpPacketFormat>
	struct get_default_domain_vistor
	{
		std::string operator()(void)const{return DEFAULT_DOMAIN;}
	};

}//name space p2engine

#endif//P2ENGINE_BASIC_RUDP_VISITOR_HPP