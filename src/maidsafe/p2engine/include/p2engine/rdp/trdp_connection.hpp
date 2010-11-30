//
// trdp_connection.hpp
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

#ifndef P2ENGINE_TCP_RDP_SOCKET_H__
#define P2ENGINE_TCP_RDP_SOCKET_H__

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
#include "p2engine/coroutine.hpp"
#include "p2engine/rdp/rdp_fwd.hpp"
#include "p2engine/rdp/trdp_flow.hpp"
#include "p2engine/rdp/const_define.hpp"

namespace p2engine{ namespace trdp{

	template<typename BaseConnectionType>
	class basic_trdp_connection
		: public basic_connection_adaptor
		, public BaseConnectionType
	{
		typedef basic_trdp_connection<BaseConnectionType> this_type;
		SHARED_ACCESS_DECLARE;
		BOOST_STATIC_ASSERT((boost::is_same<BaseConnectionType,basic_connection>::value)
			||(boost::is_base_and_derived<basic_connection,BaseConnectionType>::value));
	protected:
		typedef trdp_flow flow_type;
		template<typename Connection, typename ConnectionBase>
		friend class basic_trdp_acceptor;

	public:
		typedef typename BaseConnectionType::connection_t connection_t;
		typedef this_type type;
		typedef basic_shared_tcp_layer shared_layer_type;
		typedef BaseConnectionType connection_base_type;

		typedef boost::shared_ptr<shared_layer_type> shared_layer_sptr;
	protected:
		basic_trdp_connection(io_service& ios, bool realTimeUtility, bool passiveMode=false)
			:BaseConnectionType(ios,realTimeUtility,passiveMode)
		{
		}

		virtual  ~basic_trdp_connection() {close();}

	public:
		static shared_ptr create(io_service& ios,bool realTimeUtility, 
			bool passive=false)
		{
			return shared_ptr(new this_type(ios,realTimeUtility,passive),
				shared_access_destroy<this_type>());
		}

	public:
		virtual error_code open(const endpoint& local_edp, error_code& ec,
			const proxy_settings& ps=proxy_settings()
			)
		{
			if (!flow_)
			{
				flow_=trdp_flow::create_for_active_connect(SHARED_OBJ_FROM_THIS,
					this->get_io_service(),local_edp,ec,b_real_time_usage_);
				return ec;
			}
			else
				return boost::asio::error::already_open;
		}

		virtual void async_connect(const std::string& remote_host, int port, 
			const std::string& domainName,
			const time_duration& time_out=boost::date_time::pos_infin
			)
		{
			if (!flow_)
			{
				error_code ec;
				open(endpoint(),ec);
			}
			flow_->connect(remote_host,port,domainName);
		}
		virtual void  async_connect(const endpoint& peer_endpoint,
			const std::string& domainName,
			const time_duration& time_out=boost::date_time::pos_infin
			)
		{
			if (!flow_)
			{
				error_code ec;
				open(endpoint(),ec);
			}
			flow_->connect(peer_endpoint,domainName);
		}

		//reliable send
		virtual void async_send_reliable(const safe_buffer& buf, message_type msgType)
		{
			if (flow_)
				flow_->async_send_reliable(buf,msgType);
		}
		//unreliable send
		virtual void async_send_unreliable(const safe_buffer& buf, message_type msgType)
		{
			if (flow_)
				flow_->async_send_unreliable(buf,msgType);
		}
		//partial reliable send. message will be send for twice within about 100ms.
		//reliable is not confirmed.
		virtual void async_send_semireliable(const safe_buffer& buf, message_type msgType)
		{
			if (flow_)
				flow_->async_send_semireliable(buf,msgType);
		}

		virtual void keep_async_receiving()
		{
			if (flow_)
				flow_->keep_async_receiving();
		}
		virtual void block_async_receiving()
		{
			if (flow_)
				flow_->block_receiving();
		}

		virtual void close(bool greaceful=true)
		{
			if (flow_)
			{
				flow_->close(greaceful);
				flow_.reset();
			}
		}

		virtual bool is_open() const
		{
			if (flow_)
				return flow_->is_open();
			return false;
		}

		virtual void ping_interval(const time_duration& t)
		{
			if (flow_)
				flow_->ping_interval(t);
		}
		virtual time_duration ping_interval()const
		{
			if (flow_)
				return flow_->ping_interval();
			return boost::date_time::pos_infin;
		}
		virtual void ping(error_code& ec)
		{
			if (flow_)
				flow_->ping(ec);
			else
				ec=boost::asio::error::not_connected;
		}

		virtual endpoint local_endpoint(error_code& ec)const
		{
			if (flow_)
				return flow_->local_endpoint(ec);
			ec=boost::asio::error::not_socket;
			return endpoint();
		}
		virtual endpoint remote_endpoint(error_code& ec)const
		{
			if (flow_)
				return flow_->remote_endpoint(ec);
			ec=boost::asio::error::not_connected;
			return endpoint();
		}

		virtual connection_t connection_category()const
		{
			return basic_connection::TCP;
		}

		virtual const std::string& domain()const
		{
			if (flow_)
				return flow_->domain();
			return INVALID_DOMAIN;
		}
		virtual time_duration rtt() const
		{
			if (flow_)
				return flow_->rtt();
			return seconds(0x7fffffff);
		}
		virtual double alive_probability()const
		{
			if (flow_)
				return flow_->alive_probability();
			return 0.0;
		}
		virtual double local_to_remote_speed()const
		{
			if (flow_)
				return flow_->local_to_remote_speed();
			return 0.0;
		}
		virtual double remote_to_local_speed()const
		{
			if (flow_)
				return flow_->remote_to_local_speed();
			return 0.0;
		}
		virtual double local_to_remote_lost_rate()  const
		{
			if (flow_)
				return flow_->local_to_remote_lost_rate();
			return 1.0;
		}
		virtual double remote_to_local_lost_rate() const
		{
			if (flow_)
				return flow_->remote_to_local_lost_rate();
			return 1.0;
		}

		virtual safe_buffer make_punch_packet(error_code& ec,const endpoint& externalEdp)
		{
			ec=boost::asio::error::service_not_found;
			(void)(externalEdp);
			return safe_buffer();
		}
		virtual void on_received_punch_request(safe_buffer& buf)
		{
			BOOST_ASSERT(0);
			return;
		}

		virtual int session_id()const
		{
			if (flow_)
				return flow_->session_id();
			return INVALID_FLOWID;
		}

	protected:
		virtual void set_flow(flow_sptr flow)
		{
			BOOST_ASSERT(!flow_);
			BOOST_ASSERT(is_passive_);
			BOOST_ASSERT(boost::shared_dynamic_cast<flow_type>(flow));
			flow_=boost::shared_static_cast<flow_type>(flow);
		}

	protected:
		virtual void on_connected(const error_code&ec)
		{
			this->connected_signal()(ec);
		}
		virtual void on_disconnected(const error_code&ec)
		{
			this->disconnected_signal()(ec);
		}
		virtual void on_received(safe_buffer buf)
		{
			safe_buffer_io io(&buf);
			message_type msgType;
			io>>msgType;
			this->received_signal(msgType)(buf);
		}
		virtual void on_writeable()
		{
			this->writable_signal()();
		}

	protected:
		boost::weak_ptr<shared_layer_type> shared_layer_;
		boost::shared_ptr<trdp_flow> flow_;
		bool b_real_time_usage_;
	};

}
}
#endif//tcp_rdp_socket_h__