//
// urdp_flow.hpp
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

#ifndef P2ENGINE_BASIC_SIMPLE_RUDP_FLOW_H
#define P2ENGINE_BASIC_SIMPLE_RUDP_FLOW_H

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <boost/logic/tribool.hpp>
#include "p2engine/pop_warning_option.hpp"

#include "p2engine/wrappable_integer.hpp"
#include "p2engine/shared_access.hpp"
#include "p2engine/basic_object.hpp"
#include "p2engine/packet_reader.hpp"
#include "p2engine/packet_writer.hpp"
#include "p2engine/keeper.hpp"
#include "p2engine/timer.hpp"
#include "p2engine/speed_meter.hpp"
#include "p2engine/safe_asio_base.hpp"
#include "p2engine/rdp/rdp_fwd.hpp"
#include "p2engine/rdp/urdp_visitor.hpp"
#include "p2engine/rdp/basic_shared_udp_layer.hpp"
#include "p2engine/rdp/const_define.hpp"


namespace p2engine { namespace urdp{

	class urdp_flow
		: public basic_engine_object
		, public basic_flow_adaptor
		, public safe_asio_base
		, public fssignal::trackable
		, boost::noncopyable
	{
		typedef urdp_flow this_type;
		SHARED_ACCESS_DECLARE;

	public:
		typedef boost::uint16_t message_type;
		typedef basic_connection_adaptor connection_type;
		typedef urdp_packet_basic_format packet_format_type;
		typedef urdp_packet_unreliable_format unreliable_packet_format_type;
		typedef urdp_packet_reliable_format reliable_packet_format_type;
		typedef basic_acceptor_adaptor acceptor_type;

		typedef basic_shared_udp_layer shared_layer_type;
		typedef shared_layer_type::flow_token flow_token_type;

		typedef int64_t msec_type;
		typedef rough_timer timer_type;

		typedef boost::shared_ptr<shared_layer_type> shared_layer_sptr;
		typedef boost::shared_ptr<flow_token_type> flow_token_sptr;
		typedef boost::shared_ptr<acceptor_type> acceptor_sptr;
		typedef boost::shared_ptr<connection_type>  connection_sptr;
		typedef boost::shared_ptr<timer_type> timer_sptr;

		typedef  asio::ip::udp::resolver_iterator resolver_iterator;
		typedef  asio::ip::udp::resolver_query resolver_query;
		typedef  asio::ip::udp::resolver resolver_type;

		friend class basic_connection_adaptor;
		friend class basic_acceptor_adaptor;

		enum ShutdownMode{SD_NONE, SD_GRACEFUL, SD_FORCEFUL};
		enum TcpState {TCP_INIT,TCP_LISTEN, TCP_SYN_SENT, TCP_SYN_RECEIVED, 
			TCP_ESTABLISHED,TCP_CLOSING, TCP_CLOSED};

	public:
		static shared_ptr create_for_active_connect(connection_sptr sock,
			io_service& ios, const endpoint_type& local_edp, error_code& ec
			);

		static shared_ptr create_for_passive_connect(io_service& ios,
			acceptor_sptr acceptor,	shared_layer_sptr sharedLayer,
			const endpoint_type& remote_edp, error_code& ec
			);

	protected:
		urdp_flow(io_service&);
		virtual ~urdp_flow();
		void __init();
		void called_by_sharedlayer_on_recvd(safe_buffer& buf, const endpoint_type& from);

	public:
		virtual bool is_connected()const;
		virtual void set_socket(connection_sptr sock){m_socket=sock.get();}
		virtual int flow_id()const;
		virtual void close(bool graceful=true){__close(graceful);}

		TcpState state() const { return m_state; }
		void async_connect(const endpoint_type& remoteEnp,
			const std::string&domainName, error_code& ec,
			const time_duration& time_out=boost::date_time::pos_infin
			);
		void async_send(const safe_buffer& buf, message_type msgType
			,boost::logic::tribool reliable);

		void keep_async_receiving();
		void block_async_receiving();
		void __do_async_receive(boost::int64_t mark);

		bool is_open()const;

		void ping_interval(const time_duration& t);
		time_duration ping_interval()const;
		void ping(error_code& ec);

		endpoint_type local_endpoint(error_code& ec)const;
		endpoint_type remote_endpoint(error_code& ec)const;

		error_code  get_error();

		time_duration rtt() const
		{
			return milliseconds(m_rx_srtt);
		}
		double alive_probability()const;
		double local_to_remote_speed()const
		{
			return out_speed_meter_.bytes_per_second();
		}
		double remote_to_local_speed()const
		{
			return in_speed_meter_.bytes_per_second();
		}
		double local_to_remote_lost_rate() const;
		double remote_to_local_lost_rate() const
		{
			return __calc_remote_to_local_lost_rate();
		}

		//用于链接NAT后节点
		//A链接NAT后节点B时，A首先要在connect前调用本接口生成一个punch包，
		//然后将这个punch包发给stunserver，stunserver会将这个包relay给目标节点B；
		//B收到这个punch包后，应该原封不动的将这个包发往A，每隔几十毫秒发一次，连发多次。
		virtual safe_buffer make_punch_packet(error_code& ec,const endpoint& externalEdp);
		virtual void on_received_punch_request(const safe_buffer& buf);
	
private:
		enum SendFlags { sfNone, sfDelayedAck, sfImmediateAck };
		enum {RECV_BUF_SIZE = 0xffff,SND_BUF_SIZE =(RECV_BUF_SIZE*3)/2};

		template<typename IntType>
		static bool mod_less(IntType n1, IntType n2)
		{
			static wrappable_less<IntType> comp;
			return comp(n1,n2);
		}
		template<typename IntType>
		static bool mod_less_equal(IntType n1, IntType n2)
		{
			static wrappable_less_equal<IntType> comp;
			return comp(n1,n2);
		}
		template<typename IntType>
		static long mod_minus(IntType n1, IntType n2)
		{
			static wrappable_minus<IntType> comp;
			return (long)comp(n1,n2);
		}

		struct SSegment {
			uint32_t seq;
			uint8_t xmit;
			uint8_t ctrlType;
			safe_buffer buf;
			SSegment(uint32_t s,uint8_t c) 
				: seq(s),xmit(0), ctrlType(c) 
			{ }
		};

		struct RSegment {
			uint32_t seq;
			safe_buffer buf;
			bool operator<(RSegment const& rhs)const
			{
				return mod_less(seq,rhs.seq);
			}
		};

		struct SUnraliableSegment {
			uint16_t pktID;
			uint16_t msgType;
			safe_buffer buf;
			int remainXmit;
			uint32_t timeout;
			uint8_t control;
		};

		typedef std::list<SSegment> SSegmentList;
		typedef std::set<RSegment> RSegmentList;
		typedef std::list<safe_buffer > RUnraliablePacketList;
		typedef std::list<SUnraliableSegment> SUnraliableSegmentList;

		int  __recv(safe_buffer &buf,error_code& ec);
		int  __send(safe_buffer buf,uint16_t msgType,
			boost::logic::tribool reliable,error_code& ec);
		void __close(bool graceful);

		uint32_t __queue(const char * data, size_t len, uint8_t ctrlType,
			size_t reserveLen=0);

		int __packet_reliable_and_sendout(uint32_t seq,uint8_t control,
			const char * data, uint32_t len);
		int __packet_unreliable_and_sendout(SUnraliableSegment& seg); 
		bool __transmit(const SSegmentList::iterator& seg, uint32_t now);

		bool __process(safe_buffer& buf,const endpoint_type& from);

		void __attempt_send(SendFlags sflags = sfNone);

		void __to_closed_state();

		bool __clock_check(uint32_t now, long& nTimeout);
		void __on_clock();


		void __adjust_mtu();
		void __incress_rto();
		void __updata_rtt(long msec);

		void __schedul_timer(bool calledInOnClock=false);

		//判断是否收到了完整的packet，-1：错误发生，0：would block；>0：可读
		int __can_let_transport_read();

		void __allert_connected(const error_code&);
		void __allert_disconnected();
		void __allert_received(safe_buffer buf);
		void __allert_readable();
		void __allert_writeable();
		void __allert_accepted();

		void __do_nothing(){}

		double __calc_remote_to_local_lost_rate(wrappable_integer<int8_t>* id=NULL) const;
	protected:
		//有关unreliable
		RUnraliablePacketList m_unreliable_rlist;
		SUnraliableSegmentList m_unreliable_slist;
		uint16_t m_unreliable_pktid;
		timed_keeper<uint16_t> m_unreliable_rkeeper;

	protected:
		//host& m_host;
		ShutdownMode m_shutdown;
		int m_error;

		uint32_t m_establish_time;

		// TCB data
		uint16_t m_session_id;
		bool m_detect_readable, m_detect_writable;
		uint32_t m_lasttraffic;

		// Incoming data

		RSegmentList m_rlist;
		//char m_rbuf[kRcvBufSize];
		uint32_t m_rcv_nxt, m_rcv_wnd, m_rlen, m_lastrecv;

		// Outgoing data
		SSegmentList m_slist,m_retrans_slist;
		//char m_sbuf[kSndBufSize];
		uint32_t m_snd_nxt, m_snd_wnd, m_slen, m_lastsend, m_snd_una;
		// Maximum segment size, estimated protocol level, largest segment sent
		uint32_t m_mss/*, m_msslevel, m_largest, m_mtu_advise*/;
		// Retransmit timer
		uint32_t m_rto_base;

		// Timestamp tracking
		uint16_t m_ts_recent;
		uint16_t m_ts_recent_now;
		uint32_t m_ts_lastack;

		// Round-trip calculation
		uint32_t m_rx_rttvar, m_rx_srtt, m_rx_rto;

		// Congestion avoidance, Fast retransmit/recovery, Delayed ACKs
		uint32_t m_ssthresh, m_cwnd;
		uint8_t  m_dup_acks;
		uint32_t m_recover;
		uint32_t m_t_ack;

		uint32_t m_remote_peer_id;
		uint32_t m_ping_interval;

	protected:
		shared_ptr m_self_holder;
		endpoint_type m_remote_endpoint;
		std::string m_domain;
		TcpState m_state;
		bool m_is_active;

		timer_sptr m_timer;
		bool      m_timer_posted;

		connection_type*    m_socket;
		flow_token_sptr m_token;
		boost::weak_ptr<acceptor_type> m_acceptor;

		int m_dissconnect_reason;

		boost::optional<uint32_t> m_close_base_time;

	protected:
		bool	b_keep_recving_;

	protected:
		mutable double remote_to_local_lost_rate_;
		mutable double local_to_remote_lost_rate_;
		mutable std::map<wrappable_integer<int8_t>,uint32_t> 
			recvd_seqno_mark_for_lost_rate_;
		int8_t id_for_lost_rate_;
		rough_speed_meter in_speed_meter_;
		rough_speed_meter out_speed_meter_;
	};

}//namespace urdp
}//namespace p2engine

#endif//basic_urdp_flow_h__