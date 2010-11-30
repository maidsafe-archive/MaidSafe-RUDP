//
// trdp_acceptor.hpp
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

#ifndef tcp_rdp_acceptor_h__
#define tcp_rdp_acceptor_h__

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
#include "p2engine/shared_access.hpp"
#include "p2engine/fssignal.hpp"
#include "p2engine/timer.hpp"
#include "p2engine/safe_buffer.hpp"
#include "p2engine/wrappable_integer.hpp"

#include "p2engine/rdp/rdp_fwd.hpp"
#include "p2engine/rdp/basic_shared_tcp_layer.hpp"
#include "p2engine/rdp/const_define.hpp"

namespace p2engine{ namespace trdp{

	template<typename ConnectionType, typename ConnectionBaseType>
	class basic_trdp_acceptor 
		: public basic_acceptor_adaptor
		, public basic_acceptor<ConnectionBaseType>
	{
		typedef basic_trdp_acceptor<ConnectionType,ConnectionBaseType> this_type;
		SHARED_ACCESS_DECLARE;

	public:
		typedef this_type acceptor_type;
		typedef ConnectionType connection_type;
		typedef ConnectionBaseType connection_base_type;
		typedef basic_shared_tcp_layer shared_layer_type;
		typedef typename shared_layer_type::acceptor_token token_type;

		typedef boost::shared_ptr<shared_layer_type> shared_layer_sptr;
		typedef boost::shared_ptr<token_type>  token_sptr;
		typedef boost::shared_ptr<connection_type>  connection_sptr;

		enum state{CLOSED,LISTENING};

	public:
		//if this is used in a utility that low delay is important(
		//such as p2p live streaming or VOIP), please set "realtimeUtility"
		//be true, otherwise, please set "realtimeUtility" be false.
		static shared_ptr create(io_service& ios, bool realTimeUtility)
		{
			return shared_ptr(new this_type(ios,realTimeUtility),
				shared_access_destroy<this_type>()
				);
		}

	protected:
		basic_trdp_acceptor(io_service& ios, bool realTimeUtility)
			: basic_acceptor<ConnectionBaseType>(ios,realTimeUtility)
			, state_(CLOSED)
			, domain_(INVALID_DOMAIN)
			, b_keep_accepting_(true)
		{
			this->set_obj_desc("trdp_acceptor");
		}

		virtual ~basic_trdp_acceptor()
		{
			error_code ec;
			close(ec);
		}

	public:
		//listen on a local_edp to accept connections of domainName
		//listen(localEdp,"bittorrent/p2p",ec)
		virtual error_code listen(const endpoint& local_edp, 
			const std::string& domainName, error_code& ec)
		{
			if (state_==LISTENING)
				ec=asio::error::already_started;
			else
			{
				ec.clear();
				BOOST_ASSERT(!token_);
				token_=shared_layer_type::create_acceptor_token(
					this->get_io_service(),local_edp,*this,
					domainName,ec,this->b_real_time_usage_);
				if (ec)
				{
					token_.reset();
					domain_=INVALID_DOMAIN;
				}
				else
				{
					domain_=domainName;
					state_=LISTENING;
				}
			}
			return ec;
		}

		virtual error_code listen(const endpoint& local_edp, error_code& ec)
		{
			listen(local_edp,DEFAULT_DOMAIN,ec);
			return ec;
		}

		virtual void keep_async_accepting()
		{
			b_keep_accepting_=true;
			BOOST_ASSERT(!accepted_signal().empty());
			do_async_accept();
		}

		virtual void block_async_accepting()
		{
			b_keep_accepting_=false;
		}

		virtual error_code close(error_code& ec)
		{
			if (state_==LISTENING)
			{
				ec.clear();
				if (token_)
				{
					token_.reset();
					domain_=INVALID_DOMAIN;
				}
				state_=CLOSED;
			}
			else
			{
				BOOST_ASSERT(!token_);
				BOOST_ASSERT(domain_==INVALID_DOMAIN);
				ec=asio::error::not_socket;
			}
			return ec;
		}

		virtual endpoint local_endpoint(error_code& ec) const
		{
			if (token_)
				return token_->shared_layer->local_endpoint(ec);
			else 
			{
				ec=asio::error::not_socket;
				return endpoint();
			}
		}

		const std::string& get_domain() const
		{
			return this->domain();
		}
	protected:
		virtual void accept_flow(flow_sptr flow)
		{
			if (pending_sockets_.size()<8)
				pending_sockets_.push(flow);
			else
				flow->close(false);
			do_async_accept();
		}

	protected:
		void do_async_accept()
		{
			if (!b_keep_accepting_||this->accepted_signal().empty())
				return;

			if (!token_)
			{
				this->get_io_service().post(
					boost::bind(&this_type::__on_accepted,SHARED_OBJ_FROM_THIS,
					asio::error::bad_descriptor)
					);
			}
			else if(!pending_sockets_.empty())
			{
				this->get_io_service().post(
					boost::bind(&this_type::__on_accepted,SHARED_OBJ_FROM_THIS,
					error_code())
					);
			}
		}

		void __on_accepted(const error_code&ec)
		{
			if (!b_keep_accepting_)
				return;

			if (ec)
			{
				this->accepted_signal()(connection_sptr(),ec);
			}
			else
			{
				connection_sptr sock=pop_first_pending_socket();
				for(;sock;sock=pop_first_pending_socket())
				{
					if (sock->is_open())
					{
						sock->keep_async_receiving();
						this->accepted_signal()(sock,ec);
					}
				}
			}
			do_async_accept();
		}

	protected:
		connection_sptr pop_first_pending_socket()
		{
			if (pending_sockets_.empty())
				return connection_sptr();
			flow_sptr flow=pending_sockets_.front();
			pending_sockets_.pop();
			connection_sptr sock=connection_type::create(this->get_io_service(),
				this->is_real_time_usage(),true);
			sock->set_flow(flow);
			flow->set_socket(sock);
			return sock;
		}

	//private:
		token_sptr token_;
		std::queue<flow_sptr>pending_sockets_;

		std::string domain_; 
		state state_;

		bool b_keep_accepting_;
	};

}
}//p2engine

#endif//tcp_rdp_acceptor_h__