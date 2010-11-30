//
// basic_shared_udp_layer.hpp
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

#ifndef BASIC_RUDP_UDP_LAYER_H__
#define BASIC_RUDP_UDP_LAYER_H__

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
#include "p2engine/pop_warning_option.hpp"

#include "p2engine/basic_engine_object.hpp"
#include "p2engine/socket_utility.hpp"
#include "p2engine/safe_buffer.hpp"
#include "p2engine/logging.hpp"
#include "p2engine/local_id_allocator.hpp"
#include "p2engine/keeper.hpp"
#include "p2engine/speed_meter.hpp"
#include "p2engine/trafic_statistics.hpp"
#include "p2engine/rdp/const_define.hpp"

namespace p2engine { namespace urdp{

	class basic_shared_udp_layer 
		: public basic_engine_object
	{
		typedef basic_shared_udp_layer this_type;
		SHARED_ACCESS_DECLARE;

		BOOST_STATIC_CONSTANT(size_t, mtu_size=MTU_SIZE+128);

	public:
		BOOST_STATIC_CONSTANT(size_t, SMSS=MTU_SIZE);
		typedef asio::ip::udp::endpoint endpoint_type;
		typedef asio::ip::udp::socket	 udp_socket_type;

		typedef shared_ptr	  shared_layer_sptr;

		typedef boost::function<void(safe_buffer&,const endpoint&)> 
			recvd_data_handler_type;
		typedef boost::function<int(const endpoint&)> 
			recvd_request_handler_type;

		struct flow_element 
		{
			recvd_data_handler_type handler;
			void* flow;
			flow_element():flow(NULL){}
		};
		struct acceptor_element 
		{
			recvd_request_handler_type handler;
			void* acceptor;
			acceptor_element():acceptor(NULL){}
		};

		typedef boost::unordered_map<std::string,acceptor_element> acceptor_container;
		typedef std::vector<flow_element>			flow_container;
		typedef boost::unordered_map<int,std::list<safe_buffer> >  linger_send_container;
		typedef std::map<endpoint_type, this_type*>			this_type_container;

		typedef basic_local_id_allocator<int> local_id_allocator;

	public:
		enum{INIT,STARTED,STOPED};

		struct flow_token:public basic_object
		{
			typedef flow_token this_type;
			typedef boost::shared_ptr<this_type> shared_ptr;

			shared_layer_sptr shared_layer;
			const int  flow_id;
			void* flow;

			flow_token(int flowID,shared_layer_sptr udpLayer,
				void* flow)
				:flow_id(flowID),shared_layer(udpLayer),flow(flow)
			{
				set_obj_desc("basic_shared_udp_layer::flow_token");
			}
			~flow_token()
			{
				shared_layer->unregister_flow(flow_id,flow);
			}
		};

		struct acceptor_token:public basic_object
		{
			typedef acceptor_token this_type;
			typedef boost::shared_ptr<this_type> shared_ptr;

			shared_layer_sptr shared_layer;
			const std::string domain;
			void* acceptor;

			acceptor_token(const std::string& domainName,
				shared_layer_sptr udpLayer,void*acc)
				:domain(domainName),shared_layer(udpLayer),acceptor(acc)
			{
				set_obj_desc("basic_shared_udp_layer::acceptor_token");
			}
			~acceptor_token()
			{
				shared_layer->unregister_acceptor(acceptor);
			}
		};

	public:
		//called by urdp to connect a remote endpoint
		static  flow_token::shared_ptr create_flow_token(
			io_service& ios,
			const endpoint_type& local_edp,
			void* flow,
			recvd_data_handler_type handler,
			error_code& ec
			);

		//called by flow,when listened a passive connect request
		static  flow_token::shared_ptr create_flow_token(
			shared_layer_sptr udplayer,
			void* flow,//the flow that has been created when received SYN
			recvd_data_handler_type handler,
			error_code& ec
			);

		//called by acceptor to listen at a local endpoint
		static  acceptor_token::shared_ptr create_acceptor_token(
			io_service& ios,
			const endpoint_type& local_edp,
			void* acceptor,
			recvd_request_handler_type handler,
			const std::string domainName,
			error_code& ec
			);

	protected:
		static shared_ptr create(io_service& ios, 
			const endpoint_type& local_edp, error_code& ec
			);

		static bool is_shared_endpoint(const endpoint_type& endpoint);

	public:
		virtual ~basic_shared_udp_layer();

		udp_socket_type& socket()
		{
			return socket_;
		}

		bool is_open()const
		{
			return socket_.is_open();
		}

		shared_ptr shared_ptr_from_this() {return SHARED_OBJ_FROM_THIS;}

		endpoint_type local_endpoint( error_code&ec)const
		{
			return socket_.local_endpoint(ec);
		}

		int flow_count()const
		{
			return flows_cnt_;
		}

	protected:
		basic_shared_udp_layer(io_service& ios, const endpoint_type& local_edp,
			error_code& ec);

		void start()
		{
			if (state_!=INIT)
				return;
			state_=STARTED;
			this->async_receive();
		}

		void cancel()
		{
			OBJ_PROTECTOR(protector);
			close_without_protector();
		}

		void close_without_protector()
		{
			error_code ec;
			socket_.close(ec);
			state_=STOPED;
		}

		void handle_receive(const error_code& ec, size_t bytes_transferred);
		void async_receive();

	protected:
		error_code register_acceptor(const void* acc,
			const std::string& domainName,
			recvd_request_handler_type callBack,
			error_code& ec
			);

		void register_flow(const void* flow, 
			recvd_data_handler_type callBack,
			int& id, error_code& ec);

		void unregister_flow(object_id_type flow_id,void* flow);
		void  unregister_acceptor(const void*acptor);

	public:
		static double out_bytes_per_second()
		{
			return s_local_to_remote_speed_meter().bytes_per_second();
		}
		static double in_bytes_per_second()
		{
			return s_remote_to_local_speed_meter().bytes_per_second();
		}

		size_t send_to_imeliately(void const* p, size_t len,
			const endpoint_type& ep, error_code& ec);

		template <typename ConstBuffers>
		size_t send_to_imeliately(const ConstBuffers& bufs,
			const endpoint_type& ep,error_code& ec);

	protected:
		void __release_flow_id(int id);

		void do_handle_received(const safe_buffer& buffer);
		void do_handle_received_urdp_msg(safe_buffer& buffer);

	protected:
		//用来存储链接请求的ID，避免因对方还没有收到SYNACK期间，再次发送SYN；
		//从而造成本端认为是一个新的链接请求而又为其分配了一个pseudoport。
		struct request_uuid{
			endpoint_type	remoteEndpoint;
			uint32_t remotePeerID;
			uint32_t session;
			uint32_t flow_id;
			bool operator <(const request_uuid& rhs)const
			{
				if (session<rhs.session)
					return true;
				else if (session>rhs.session)
					return false;
				if (remotePeerID<rhs.remotePeerID)
					return true;
				else if (remotePeerID>rhs.remotePeerID)
					return false;
				return remoteEndpoint<rhs.remoteEndpoint;
			}
		};

		udp_socket_type socket_;
		endpoint_type local_endpoint_;
		safe_buffer recv_buffer_;
		endpoint_type sender_endpoint_;
		timed_keeper<request_uuid>   request_uuid_keeper_;
		local_id_allocator id_allocator_;
		std::list<int> released_id_catch_;
		timed_keeper<int> released_id_keeper_;
		acceptor_container	  acceptors_;
		flow_container        flows_;
		int                   flows_cnt_;
		linger_send_container lingerSends_;
		boost::recursive_mutex flow_mutex_;
		boost::mutex acceptor_mutex_;
		//rough_timer_shared_ptr lingerSendTimer_;
		int                   state_;
		
		static this_type_container s_shared_this_type_pool_;
		static boost::mutex s_shared_this_type_pool_mutex_;
	};


	template <typename ConstBuffers>
	inline size_t basic_shared_udp_layer::send_to_imeliately(
		const ConstBuffers& bufs,const endpoint_type& ep,
		error_code& ec)
	{
		//if(!is_open())
		//{
		//	ec=asio::error::not_socket;
		//	return 0;
		//}
		//ec.clear();
		//error_code e;//do not care about other send errors
		size_t len=0;
		typename  ConstBuffers::const_iterator itr=bufs.begin();
		for (;itr!=bufs.end();++itr)
			len+=p2engine::buffer_size(*itr);
		s_local_to_remote_speed_meter()+=len;
		socket_.send_to(bufs, ep,0,ec);
		return len;
	}

	template <>
	inline size_t basic_shared_udp_layer::send_to_imeliately(
		const safe_buffer& safebuffer,const endpoint_type& ep,
		error_code& ec)
	{
		//if(!is_open())
		//{
		//	ec=asio::error::not_socket;
		//	return 0;
		//}
		//ec.clear();
		//error_code e;//do not care about other send errors
		size_t len=buffer_size(safebuffer);
		s_local_to_remote_speed_meter()+=len;
		//socket_.send_to(safebuffer.to_asio_const_buffers_1(), ep,0,e);
		socket_.send_to(asio::buffer(p2engine::buffer_cast<const char*>(safebuffer),safebuffer.length()),
			ep,0,ec);
		return len;
	}

}
}// namespace p2engine

#endif//BASIC_RUDP_UDP_LAYER_H__