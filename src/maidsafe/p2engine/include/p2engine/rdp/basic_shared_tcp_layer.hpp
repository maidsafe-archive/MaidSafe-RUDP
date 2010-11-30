//
// basic_shared_tcp_layer.hpp
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

#ifndef BASIC_RDP_SHARED_TCP_LAYER_H__
#define BASIC_RDP_SHARED_TCP_LAYER_H__

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <queue>
#include <vector>
#include <list>
#include <boost/noncopyable.hpp>
#include <boost/unordered_map.hpp>
#include <boost/random.hpp>
#include "p2engine/pop_warning_option.hpp"

#include "p2engine/basic_engine_object.hpp"
#include "p2engine/socket_utility.hpp"
#include "p2engine/safe_buffer.hpp"
#include "p2engine/logging.hpp"
#include "p2engine/local_id_allocator.hpp"
#include "p2engine/keeper.hpp"
#include "p2engine/speed_meter.hpp"
#include "p2engine/fssignal.hpp"
#include "p2engine/rdp/rdp_fwd.hpp"

namespace p2engine { namespace trdp{

	class trdp_flow;

	class basic_shared_tcp_layer 
		: public basic_engine_object
		, public fssignal::trackable
		, boost::noncopyable
	{
		typedef basic_shared_tcp_layer this_type;
		SHARED_ACCESS_DECLARE;
	public:
		typedef endpoint endpoint_type;
		typedef trdp_flow flow_type;
		typedef basic_connection_adaptor connection_type;
		typedef basic_acceptor_adaptor acceptor_type;
		typedef basic_shared_tcp_layer shared_layer_type;

		typedef boost::shared_ptr<flow_type> flow_sptr;
		typedef boost::shared_ptr<connection_type> connection_sptr;
		typedef boost::shared_ptr<acceptor_type> acceptor_sptr;
		typedef boost::shared_ptr<shared_layer_type>shared_layer_sptr;

	protected:
		typedef boost::unordered_map<std::string, acceptor_type*> acceptor_container;
		typedef std::map<endpoint_type, this_type*>   this_type_container;

	public:
		struct acceptor_token:public basic_object
		{
			typedef acceptor_token this_type;
			typedef boost::shared_ptr<this_type> shared_ptr;

			shared_layer_sptr shared_layer;
			const std::string domain;
			acceptor_type* acceptor;

			acceptor_token(const std::string& domainName,
				shared_layer_sptr sharedLayer,acceptor_type&acc)
				:domain(domainName),shared_layer(sharedLayer),acceptor(&acc)
			{
				set_obj_desc("basic_shared_tcp_layer::acceptor_token");
			}
			~acceptor_token()
			{
				shared_layer->unregister_acceptor(*acceptor);
			}
		};
		friend struct acceptor_token;

	protected:
		typedef asio::ip::tcp::acceptor tcp_acceptor_type;
		enum{INIT,STARTED,STOPED};

	protected:
		static shared_ptr create(io_service& ios, 
			const endpoint_type& local_edp,
			error_code& ec,
			bool realTimeUsage);

		static bool is_shared_endpoint_type(const endpoint_type& endpoint_type)
		{
			boost::mutex::scoped_lock lock(s_this_type_pool_mutex_);
			return s_this_type_pool_.find(endpoint_type)!=s_this_type_pool_.end(); 
		}

	public:
		static boost::shared_ptr<acceptor_token> create_acceptor_token(
			io_service& ios,
			const endpoint_type& local_edp,
			acceptor_type& acceptor,
			const std::string domainName,
			error_code& ec,
			bool realTimeUsage=true
			)
		{
			shared_ptr obj=create(ios,local_edp,ec,realTimeUsage);
			if (ec) 
				return acceptor_token::shared_ptr();
			obj->register_acceptor(acceptor,domainName,ec);
			return boost::shared_ptr<acceptor_token>(
				new acceptor_token(domainName,obj,acceptor));
		}

		virtual ~basic_shared_tcp_layer();

		bool is_open()const
		{
			return tcp_acceptor_.is_open();
		}

		endpoint_type local_endpoint( error_code&ec)const
		{
			return tcp_acceptor_.local_endpoint(ec);
		}

		acceptor_type* find_acceptor(const std::string& domainName);

		bool is_real_time_usage()const
		{
			return b_real_time_usage_;
		}

	protected:
		basic_shared_tcp_layer(io_service& ios, 
			const endpoint_type& local_edp,
			error_code& ec,
			bool realTimeUsage);

		void start();

		void cancel()
		{
			OBJ_PROTECTOR(protector);
			cancel_without_protector();
		}

		void cancel_without_protector()
		{
			error_code ec;
			tcp_acceptor_.cancel(ec);
			state_=STOPED;
		}

		void handle_accept(const error_code& ec, flow_sptr flow);

		void async_accept();

	protected:
		error_code register_acceptor(acceptor_type& acc,
			const std::string& domainName,error_code& ec)
		{
			std::pair<acceptor_container::iterator,bool> insertRst
				=acceptors_.insert(std::make_pair(domainName,&acc));
			if (!insertRst.second)
			{
				ec=asio::error::already_open; 
				return ec;
			}
			ec.clear();
			return ec;
		}

		void  unregister_acceptor(const acceptor_type& acptor);

	public:
		static double out_bytes_per_second()
		{
			return s_out_speed_meter_.bytes_per_second();
		}
		static double in_bytes_per_second()
		{
			return s_in_speed_meter_.bytes_per_second();
		}

	protected:
		tcp_acceptor_type tcp_acceptor_;
		endpoint_type local_endpoint_type_;
		acceptor_container	  acceptors_;
		int                   state_;
		timed_keeper<flow_sptr> flow_keeper_;
		bool b_real_time_usage_;

		static this_type_container s_this_type_pool_;
		static boost::mutex s_this_type_pool_mutex_;
		static rough_speed_meter s_out_speed_meter_;//(millisec(3000));
		static rough_speed_meter s_in_speed_meter_;//(millisec(3000));
	};

}//namespace trdp
}// namespace p2engine

#endif//