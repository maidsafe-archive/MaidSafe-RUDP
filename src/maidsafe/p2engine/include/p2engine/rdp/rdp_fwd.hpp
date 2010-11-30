//
// tcp_rdp_fwd.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~
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

#ifndef rdp_fwd_h__
#define rdp_fwd_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/basic_dispatcher.hpp"
#include "p2engine/connection.hpp"
//#include "p2engine/rdp/urdp_visitor.hpp"

namespace p2engine{

	class basic_flow_adaptor;
	class basic_connection_adaptor;
	class basic_acceptor_adaptor;

	class basic_flow_adaptor
	{
		typedef basic_flow_adaptor this_type;
		SHARED_ACCESS_DECLARE;
	public:
		typedef variant_endpoint endpoint_type;
		typedef basic_flow_adaptor flow_type;
		typedef basic_connection_adaptor connection_type;
		typedef basic_acceptor_adaptor acceptor_type;

		typedef boost::shared_ptr<flow_type> flow_sptr;
		typedef boost::shared_ptr<connection_type> connection_sptr;
		typedef boost::shared_ptr<acceptor_type> acceptor_sptr;

		//friend  flow_type; 
		friend  class basic_connection_adaptor; 
		friend  class basic_acceptor_adaptor; 

	protected:
		basic_flow_adaptor(){}
		virtual ~basic_flow_adaptor(){}

	public:
		//this will be called by acceptor when a passive flow is established
		virtual bool is_connected()const=0;
		virtual void set_socket(connection_sptr sock)=0;
		virtual int flow_id()const=0;
		virtual endpoint_type remote_endpoint(error_code& ec)const=0;
		//called
		virtual void close(bool graceful)=0;
	};

	class basic_connection_adaptor
	{
		typedef basic_connection_adaptor this_type;
		SHARED_ACCESS_DECLARE;

	public:
		typedef basic_flow_adaptor flow_type;
		typedef basic_connection_adaptor type;
		typedef basic_acceptor_adaptor acceptor_type;

		typedef boost::shared_ptr<flow_type> flow_sptr;
		typedef boost::shared_ptr<type> connection_sptr;
		typedef boost::shared_ptr<acceptor_type> acceptor_sptr;

		friend class basic_flow_adaptor; 
		//friend  connection_type; 
		friend class basic_acceptor_adaptor; 

	protected:
		basic_connection_adaptor(){}
		virtual ~basic_connection_adaptor(){}

	public:
		//these will be called by flow
		virtual void on_connected(const error_code&)=0;
		virtual void on_disconnected(const error_code&)=0;
		virtual void on_writeable()=0;
		virtual void on_received(safe_buffer)=0;
		virtual void set_flow(flow_sptr sock)=0;
	};

	class basic_acceptor_adaptor
	{
		typedef basic_acceptor_adaptor this_type;
		SHARED_ACCESS_DECLARE;
	public:
		typedef basic_flow_adaptor flow_type;
		typedef basic_connection_adaptor connection_type;
		typedef basic_acceptor_adaptor acceptor_type;

		typedef boost::shared_ptr<flow_type> flow_sptr;
		typedef boost::shared_ptr<connection_type> connection_sptr;
		typedef boost::shared_ptr<acceptor_type> acceptor_sptr;

		friend class basic_flow_adaptor; 
		friend class basic_connection_adaptor; 
		//friend  acceptor_type; 

	protected:
		basic_acceptor_adaptor(){}
		virtual ~basic_acceptor_adaptor(){}

	public:
		//this will be called by flow when a passive flow is established
		virtual void accept_flow(flow_sptr flow)=0;
		virtual const std::string& get_domain()const=0;
	};
}

#endif // basic_urdp_fwd_h__
