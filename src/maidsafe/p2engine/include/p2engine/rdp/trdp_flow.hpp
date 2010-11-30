//
// tcp_rdp_flow.hpp
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

#ifndef P2ENGINE_TCP_RDP_FLOW_H__
#define P2ENGINE_TCP_RDP_FLOW_H__

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <list>
#include <string>
#include <boost/noncopyable.hpp>
#include "p2engine/pop_warning_option.hpp"

#include "p2engine/typedef.hpp"
#include "p2engine/fssignal.hpp"
#include "p2engine/shared_access.hpp"
#include "p2engine/io.hpp"
#include "p2engine/safe_buffer.hpp"
#include "p2engine/safe_buffer_io.hpp"
#include "p2engine/safe_socket_base.hpp"
#include "p2engine/coroutine.hpp"
#include "p2engine/basic_engine_object.hpp"
#include "p2engine/timer.hpp"
#include "p2engine/wrappable_integer.hpp"
#include "p2engine/trafic_statistics.hpp"
#include "p2engine/rdp/const_define.hpp"
#include "p2engine/rdp/rdp_fwd.hpp"

namespace p2engine{ namespace trdp{

	class basic_shared_tcp_layer;

	class trdp_flow
		: public basic_engine_object
		, public basic_flow_adaptor
		, public fssignal::trackable
		, public safe_asio_base
		, boost::noncopyable
	{
		typedef trdp_flow this_type;
		SHARED_ACCESS_DECLARE;

	public:
		typedef basic_connection_adaptor connection_type;
		typedef basic_acceptor_adaptor acceptor_type;
		typedef basic_shared_tcp_layer shared_layer_type;

		typedef int64_t msec_type;
		typedef rough_timer timer_type;

		typedef boost::shared_ptr<shared_layer_type> shared_layer_sptr;
		typedef boost::shared_ptr<acceptor_type> acceptor_sptr;
		typedef boost::shared_ptr<connection_type>  connection_sptr;
		typedef boost::shared_ptr<timer_type> timer_sptr;

		typedef  asio::ip::tcp::resolver_iterator resolver_iterator;
		typedef  asio::ip::tcp::resolver_query resolver_query;
		typedef  asio::ip::tcp::resolver resolver_type;

		typedef tcp_socket::lowest_layer_type lowest_layer_type;

		friend class basic_connection_adaptor;
		friend class basic_acceptor_adaptor;
		friend class basic_shared_tcp_layer;

	protected:
		//some consts
		//BOOST_STATIC_CONSTANT(char,TCP_RDP_MAGIC='%');
		BOOST_STATIC_CONSTANT(char,CONN_PKT=(char)'a');
		BOOST_STATIC_CONSTANT(char,ACCEPT_PKT=(char)'b');
		BOOST_STATIC_CONSTANT(char,PING_PKT=(char)'c');
		BOOST_STATIC_CONSTANT(char,PONG_PKT=(char)'d');
		BOOST_STATIC_CONSTANT(char,DATA_PKT=(char)'e');

		enum{INIT, OPENED, CONNECTING, CONNECTED, CLOSED} 
		state_;

		enum{RECVING, RECVED} 
		recv_state_;

		enum sendmode{RELIABLE_SEND,UNRELIABLE_SEND,SEMIRELIABLE_SEND};

		struct send_emlment 
			:object_allocator
		{
			safe_buffer buf;
			uint16_t    msgType;
			msec_type   outTime;
			bool alertWritable;//only realiable packet
		};

	protected:
		trdp_flow(io_service& ios, bool realTimeUtility, bool passiveMode=false);
		virtual  ~trdp_flow();
		void __init();

	public:
		static shared_ptr create_for_passive_connect(
			io_service& ios,
			bool realTimeUtility=true
			)
		{
			return shared_ptr(new this_type(ios,realTimeUtility,true),
				shared_access_destroy<this_type>());
		}
		static shared_ptr create_for_active_connect(connection_sptr conn,
			io_service& ios, const endpoint_type& local_edp, error_code& ec,
			bool realTimeUtility=true
			)
		{
			shared_ptr flow(new this_type(ios,realTimeUtility,false),
				shared_access_destroy<this_type>());
			flow->open(local_edp,ec);
			flow->connection_=conn.get();
			return flow;
		}
		//shared_tcp_layer should access asio::ip::tcp::socket& to async_accept
		lowest_layer_type& lowest_layer() {return socket_impl_.lowest_layer();}

		//called by shared_tcp_layer when accepted a socket. so, the socket 
		//can receive domain that the remote endpoint requested.
		void waiting_domain(shared_layer_sptr shared_layer);
		void __waiting_domain_coro(const error_code& ec, size_t len, int64_t stamp,
			coroutine coro=coroutine());
		void accept(const error_code& ec);

	public:
		virtual bool is_connected()const
		{
			return CONNECTED==state_;
		}

		virtual void set_socket(connection_sptr sock)
		{
			connection_=sock.get();
		}

		virtual int flow_id()const
		{
			return flowid_;//a random value
		}

		//called
		virtual void close(bool graceful=true);

		error_code open(const endpoint_type& local_edp, error_code& ec)
		{
			local_edp_=local_edp;
			return __open(ec);
		}

		error_code open(error_code& ec)
		{
			return open(endpoint_type(),ec);
		}

		void connect(const std::string& remote_host, int port, 
			const std::string& domainName);

		void  connect(const endpoint_type& remote_edp, const std::string& domainName);

		void keep_async_receiving();

		void block_receiving()
		{
			is_recv_blocked_=true;
		}

		void async_send_unreliable(const safe_buffer& buffer,uint16_t msgType,
			const time_duration& maxRandomDelay=boost::posix_time::neg_infin
			)
		{
			(void)(maxRandomDelay);//not support yet
			//if send_buffer of TCP is full, we drop unrealiable packet
			if (qued_sending_size_>8*1024)
				return;
			__send(buffer,(char)DATA_PKT,false,&msgType);
		}

		void async_send_semireliable(const safe_buffer& buffer, uint16_t msgType,
			bool fastDupTrans=true)
		{
			//treat as reliable
			(void)(fastDupTrans);//not support yet
			__send(buffer,(char)DATA_PKT,false,&msgType);
		}

		void async_send_reliable(const safe_buffer& buffer,uint16_t msgType)
		{
			__send(buffer,(char)DATA_PKT,true,&msgType);
		}

		bool is_open() const 
		{
			return socket_impl_.is_open();
		}

		void ping() {error_code ec; ping(ec);}
		error_code ping(error_code& ec);

		void ping_interval(const time_duration& t);
		time_duration  ping_interval()const
		{
			return ping_interval_;
		}

		endpoint_type local_endpoint(error_code& ec)const
		{
			return socket_impl_.local_endpoint(ec);
		}

		endpoint_type remote_endpoint(error_code& ec)const
		{
			return socket_impl_.remote_endpoint(ec);
		}

		safe_buffer make_punch_packet(error_code& ec)
		{
			ec=asio::error::operation_not_supported;
			return safe_buffer();
		}

		void on_received_punch_request(safe_buffer& buf, const endpoint_type& remote_edp)
		{//not support yet
			(void)(buf);
			(void)(remote_edp);
		}

		bool is_passive()const 
		{
			return is_passive_;
		}

		int session_id()const
		{
			error_code ec;
			return (int)socket_impl_.local_endpoint(ec).address().to_v4().to_ulong();
		}

		const std::string& domain()const{
			return domain_;
		}

		 time_duration rtt() const
		 {
			 return milliseconds(srtt_);
		 }
		 double alive_probability()const
		 {
			 if (state_==CONNECTED)
				 return 1.0;
			 return 0.0;
		 }
		 double local_to_remote_speed()const
		 {
			 return out_speed_meter_.bytes_per_second();
		 }
		 double remote_to_local_speed()const
		 {
			 return in_speed_meter_.bytes_per_second();
		 }
		 double local_to_remote_lost_rate()  const
		 {
			 return __local_to_remote_lost_rate();
		 }
		 double remote_to_local_lost_rate() const
		 {
			 return __remote_to_local_lost_rate();
		 }

	private:
		void do_keep_receiving(error_code ec, size_t len, int64_t stamp,
			coroutine coro=coroutine());

		void __async_resolve_connect_coro(error_code err, resolver_iterator itr, 
			int64_t stamp, coroutine coro=coroutine(), resolver_query* qy=NULL);

		void __domain_request_coro(error_code ec, size_t len, int64_t stamp,
			coroutine coro=coroutine());

		bool __process_data(int64_t stamp);

		error_code __open(error_code& ec);
		void __close(bool greacful);

		void __send(const safe_buffer& buffer,char type,bool alertWritable
			,uint16_t* msgType=NULL,bool fromQue=false);

		void __handle_sent_packet(const error_code& ec, size_t bytes_trans,
			bool allertWritable, int64_t stamp);

		void __to_close_state(const error_code& ec,int64_t stamp);

		void __update_rtt(int64_t echoTime);

		void __do_ping(){ping();}
		void __do_close(){close(true);}

		void __post_action_exec(boost::function<void()> action, int64_t stamp)
		{
			if (is_canceled_op(stamp))
				return;
			action();
		}

		void __allert_connected(error_code ec, int64_t stamp);

		double __local_to_remote_lost_rate(int8_t* id=NULL)  const;
		double __remote_to_local_lost_rate(int8_t* id=NULL) const;
	private:
		boost::weak_ptr<shared_layer_type> shared_layer_;
		connection_type* connection_;

		endpoint_type remote_edp_;
		endpoint_type local_edp_;
		std::string domain_;
		std::string remote_host_;
		//tcp_socket socket_impl_;
		boost::asio::ip::tcp::socket socket_impl_;

		bool is_passive_;
		bool is_recv_blocked_;
		bool is_realtime_utility_;
		bool is_sending_bussy_;

		char recv_header_buf_[4];
		safe_buffer recv_buf_;

		resolver_type resolver_;
		resolver_iterator endpoint_iterator_;

		timer_sptr conn_timer_;
		timer_sptr ping_timer_;//used to detect rtt

		time_duration ping_interval_;
		int srtt_;
		int rttvar_;
		int rto_;

		std::queue<send_emlment> send_bufs_;
		bool sending_;
		int qued_sending_size_;

		int flowid_;

	protected:
		mutable double remote_to_local_lost_rate_;
		mutable double local_to_remote_lost_rate_;
		mutable std::map<wrappable_integer<int8_t>,msec_type> 
			recvd_seqno_mark_for_lost_rate_,send_seqno_mark_for_lost_rate_;
		int8_t id_for_lost_rate_;
		rough_speed_meter in_speed_meter_;
		rough_speed_meter out_speed_meter_;
	};

}
}

#endif//tcp_rdp_flow_h__