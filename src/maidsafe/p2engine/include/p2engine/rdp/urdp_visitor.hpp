//
// urdp_vistor.hpp
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

#ifndef urdp_vistor_h__
#define urdp_vistor_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <string>
#include <boost/optional.hpp>
#include "p2engine/pop_warning_option.hpp"

#include "p2engine/packet_format_def.hpp"
#include "p2engine/safe_buffer.hpp"
#include "p2engine/rdp/basic_urdp_visitor.hpp"

namespace p2engine { namespace urdp{

	enum urdp_dissconnect_reason
	{
		__DISCONN_INIT=0,
		DISCONN_LOCAL=(1<<0),
		DISCONN_REMOTE=(1<<1),
		DISCONN_ERROR=(1<<2)
	};
	enum urdp_packet_type
	{
		CTRL_NETWORK_UNREACHABLE,

		CTRL_PUNCH,

		CTRL_CONNECT,
		CTRL_CONNECT_ACK,
		CTRL_CONNECT_ACK_ACK,
		//CTRL_CONN_RESPONSE_ACK,
		CTRL_DATA,
		CTRL_UNRELIABLE_DATA,
		CTRL_SEMIRELIABLE_DATA,
		CTRL_ACK,

		CTRL_RST,
		CTRL_FIN,
		CTRL_FIN_ACK
	};

	//////////////////////////////////////////////////////////////////////
	//    urdp_packet_basic_format
	//    0                   1                   2                   3   
	//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  0 |    control    |                      peer_id                  |
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  4 |lostrateRecving|idForLostDetect|           session_id          |
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  8 |      bandwidth_recving        |             window            |
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//
	//////////////////////////////////////////////////////////////////////
	//urdp_packet_unreliable_format
	//    0                   1                   2                   3   
	//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  0 |    control    |                      peer_id                  |
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  4 |lostrateRecving|idForLostDetect|           session_id          |
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  8 |      bandwidth_recving        |             window            |
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// 12 |//---------- packet_id --------|//----------- type------------ |
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	//
	//////////////////////////////////////////////////////////////////////
	//urdp_packet_reliable_format
	//    0                   1                   2                   3   
	//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  0 |    control    |                      peer_id                  |
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  4 |lostrateRecving|idForLostDetect|           session_id          |
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  8 |      bandwidth_recving        |             window            |
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// 12 |         time_sending          |           time_echo           |
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// 16 |                              seqno                            |
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// 20 |                              ackno                            |
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// 24 |//---------- length -----------|//----------- type------------ |
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//

	static const double LOST_RATE_PRECISION=1.0/0xff;
	static const double BANDWIDTH_PRECISION=1000.0;

	P2ENGINE_PACKET_FORMAT_DEF_BEGIN(urdp_packet_basic_format,0, {})
		P2ENGINE_PACKET_BIT_FIELD_DEF_INIT (uint32_t,control,8,CTRL_NETWORK_UNREACHABLE)
		P2ENGINE_PACKET_BIT_FIELD_DEF_INIT (uint32_t,peer_id,24,0xffffff)
		P2ENGINE_PACKET_BIT_FIELD_DEF_INIT (uint32_t,lostrate_recving,8,0)
		P2ENGINE_PACKET_BIT_FIELD_DEF_INIT (uint32_t,id_for_lost_detect,8,0)
		P2ENGINE_PACKET_BIT_FIELD_DEF_INIT (uint32_t,session_id,16,0)
		P2ENGINE_PACKET_BIT_FIELD_DEF_INIT (uint32_t,bandwidth_recving,16,0)//BANDWIDTH_PRECISION为单位
		P2ENGINE_PACKET_BIT_FIELD_DEF_INIT (uint32_t,window,16,0)//BANDWIDTH_PRECISION为单位
		P2ENGINE_PACKET_FORMAT_DEF_END

		//---
		P2ENGINE_DERIVED_PACKET_FORMAT_DEF_BEGIN (urdp_packet_unreliable_format,urdp_packet_basic_format,{})
		P2ENGINE_DERIVED_PACKET_FORMAT_DEF_END

		//---
    P2ENGINE_DERIVED_PACKET_FORMAT_DEF_BEGIN (urdp_packet_reliable_format,urdp_packet_basic_format,{})
		P2ENGINE_PACKET_BIT_FIELD_DEF_INIT (uint32_t,time_sending,16,0)
		P2ENGINE_PACKET_BIT_FIELD_DEF_INIT (uint32_t,time_echo,16,0)
		P2ENGINE_PACKET_FIELD_DEF_INIT (uint32_t,seqno,0)
		P2ENGINE_PACKET_FIELD_DEF_INIT (uint32_t,ackno,0)
    P2ENGINE_DERIVED_PACKET_FORMAT_DEF_END

}//namespace urdp

template <>
struct is_conn_request_vistor<urdp::urdp_packet_basic_format> 
{
	typedef urdp::urdp_packet_basic_format header_format;
	bool operator()(const header_format& h)const
	{
		return h.get_control()==urdp::CTRL_CONNECT;
	}
};

template <>
struct make_refuse_vistor<urdp::urdp_packet_basic_format> 
{
	typedef urdp::urdp_packet_basic_format header_format;
	safe_buffer operator()(const header_format& h)
	{
		BOOST_ASSERT(is_conn_request_vistor<header_format>()(h));
		safe_buffer buf(header_format::packet_size());
		header_format header(buf);
		header.set_control(urdp::CTRL_NETWORK_UNREACHABLE);
		header.set_peer_id(h.get_peer_id());
		header.set_session_id(h.get_session_id());
		return buf;
	}
};

template <>
struct get_dst_peer_id_vistor<urdp::urdp_packet_basic_format> 
{
	typedef urdp::urdp_packet_basic_format header_format;

	uint32_t operator()(const header_format& h)const
	{
		if (is_conn_request_vistor<header_format>()(h))
			return get_invalid_peer_id_vistor<header_format>()();
		return h.get_peer_id();
	}
};

template <>
struct get_src_peer_id_vistor<urdp::urdp_packet_basic_format> 
{
	typedef urdp::urdp_packet_basic_format header_format;
	uint32_t operator()(const header_format& h)const
	{
		if (is_conn_request_vistor<header_format>()(h))
			return h.get_peer_id();
		return get_invalid_peer_id_vistor<header_format>()();
	}
};

template <>
struct get_session_vistor<urdp::urdp_packet_basic_format> 
{
	typedef urdp::urdp_packet_basic_format header_format;
	uint32_t operator()(const header_format& h)const
	{
		return h.get_session_id();
	}
};


template <>
struct get_demain_name_vistor<urdp::urdp_packet_basic_format> 
{
	typedef urdp::urdp_packet_basic_format header_format;
	std::string operator()(const header_format&h,const safe_buffer& buf)const
	{
		if (urdp::urdp_packet_reliable_format::packet_size()<buf.length())
		{
			if (is_conn_request_vistor<header_format>()(h))
			{
				safe_buffer domainBuf=buf.buffer_ref(urdp::urdp_packet_reliable_format::packet_size());
				return std::string(buffer_cast<const char*>(domainBuf),domainBuf.length());
			}
		}
		return get_invalid_domain_vistor<header_format>()();
	}
};

template <>
struct is_punch_ping_vistor<urdp::urdp_packet_basic_format> 
{
	typedef urdp::urdp_packet_basic_format header_format;
	bool operator()(const header_format& h)const
	{
		return h.get_control()==urdp::CTRL_PUNCH;
	}
};

}//namespace p2engine

#endif//urdp_vistor_h__