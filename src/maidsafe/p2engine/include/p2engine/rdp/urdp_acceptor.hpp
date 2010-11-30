//
// urdp_acceptor.hpp
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

#ifndef p2engine_urdp_acceptor_h__
#define p2engine_urdp_acceptor_h__

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
#include "p2engine/acceptor.hpp"
#include "p2engine/connection.hpp"
#include "p2engine/rdp/rdp_fwd.hpp"
#include "p2engine/rdp/urdp_connection.hpp"

namespace p2engine { namespace urdp{

	template<typename ConnectionType,typename ConnectionBaseType>
	class basic_urdp_acceptor 
		: public basic_acceptor_adaptor
		, public basic_acceptor<ConnectionBaseType>
	{
		typedef basic_urdp_acceptor<ConnectionType,ConnectionBaseType> this_type;
		SHARED_ACCESS_DECLARE;
		BOOST_STATIC_ASSERT((boost::is_same<ConnectionType,ConnectionBaseType>::type::value)
			||(boost::is_base_and_derived<ConnectionBaseType,ConnectionType>::type::value)
			);
	public:
		typedef this_type acceptor_type;
		typedef ConnectionType connection_type;
		typedef ConnectionBaseType connection_base_type;
		typedef typename connection_type::flow_type flow_type;
		typedef typename connection_type::shared_layer_type shared_layer_type;
		typedef typename shared_layer_type::acceptor_token token_type;
		typedef rough_timer timer_type;

		typedef boost::shared_ptr<shared_layer_type> shared_layer_sptr;
		typedef boost::shared_ptr<token_type>  token_sptr;
		typedef boost::shared_ptr<acceptor_type> acceptor_sptr;
		typedef boost::shared_ptr<flow_type> flow_sptr;
		typedef boost::shared_ptr<connection_type>  connection_sptr;
		typedef boost::shared_ptr<timer_type> timer_sptr;

		typedef int64_t msec_type;

	protected:
		enum state{CLOSED,LISTENING};

	public:
		static shared_ptr create(io_service& ios,bool realTimeUsage)
		{
			return shared_ptr(new this_type(ios,realTimeUsage),
				shared_access_destroy<this_type>()
				);
		}

	protected:
		basic_urdp_acceptor(io_service& svc,bool realTimeUsage)
			: basic_acceptor<ConnectionBaseType>(svc,realTimeUsage)
			, state_(CLOSED)
			, b_keep_accepting_(false)
		{
			this->set_obj_desc("urdp_acceptor");
			this->domain_=DEFAULT_DOMAIN;
		}

		virtual ~basic_urdp_acceptor()
		{
			error_code ec;
			close(ec);
		}

	public:
		//listen on a local_edp to accept connections of domainName
		//listen(localEdp,"bittorrent/p2p",ec)
		virtual error_code listen(const endpoint& local_edp, 
			const std::string& domainName, 
			error_code& ec)
		{
			if (state_==LISTENING)
			{
				BOOST_ASSERT(token_);
				ec=asio::error::already_started;
			}
			else
			{
				ec.clear();
				BOOST_ASSERT(!token_);
				token_=shared_layer_type::create_acceptor_token(
					this->get_io_service(),local_edp,this,
					boost::bind(&this_type::on_passive_request,this,_1),
					domainName,ec
					);

				if (ec)
				{
					token_.reset();
					this->domain_=INVALID_DOMAIN;
				}
				else
				{
					this->domain_=domainName;
					state_=LISTENING;
				}
			}
			return ec;
		}

		virtual error_code listen(const endpoint& local_edp, 
			error_code& ec)
		{
			listen(local_edp,DEFAULT_DOMAIN,ec);
			return ec;
		}

		virtual void keep_async_accepting()
		{
			b_keep_accepting_=true;
			BOOST_ASSERT(!this->accepted_signal().empty());
			do_async_accept();
		}

		virtual void block_async_accepting()
		{
			b_keep_accepting_=false;
		}

		virtual error_code close()
		{
			error_code ec;
			return close(ec);
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

	public:
		error_code close(error_code& ec)
		{
			if (state_==LISTENING)
			{
				ec.clear();
				if (token_)
				{
					token_.reset();
					this->domain_=INVALID_DOMAIN;
				}
				state_=CLOSED;
			}
			else
			{
				BOOST_ASSERT(!token_);
				BOOST_ASSERT(this->domain_==INVALID_DOMAIN);
				ec=asio::error::not_socket;
			}
			//accept_op_queue_.cancel_operations(this);
			return ec;
		}

		shared_layer_sptr get_shared_layer()
		{
			if (token_)
				return token_->shared_layer;
			return shared_layer_sptr();
		}

		const std::string& get_domain()const
		{
			return this->domain();
		}

	protected:
		void do_async_accept()
		{
			if (this->accepted_signal().empty())
				return;

			if (!b_keep_accepting_)
				return;

			if (!token_)
			{
				this->get_io_service().post(
					boost::bind(&this_type::__on_accepted,SHARED_OBJ_FROM_THIS,
					asio::error::bad_descriptor)
					);
			}
			else if(!pending_flows_.empty())
			{
				this->get_io_service().post(
					boost::bind(&this_type::__on_accepted,SHARED_OBJ_FROM_THIS,
					error_code())
					);
			}
		}

		void __on_accepted(const error_code& ec)
		{
			if (!b_keep_accepting_)
				return;
			if (ec)
			{
				this->accepted_signal()(connection_sptr(),ec);
			}
			else
			{
				flow_sptr flow=pop_first_pending_flow();
				for(;flow&&b_keep_accepting_&&!this->accepted_signal().empty()
					;flow=pop_first_pending_flow())
				{
					if (flow->is_connected())
					{
						error_code ec;
						connection_sptr sock(connection_type::create(this->get_io_service(),this->is_real_time_usage(),true));
						sock->set_flow(flow);
						flow->set_socket(sock);
						this->accepted_signal()(sock,ec);
					}
				}
			}
			do_async_accept();
		}

	private:
		int on_passive_request(const endpoint& from)
		{
			//std::cout<<"------------------------------"<<pending_flows_.size()<<std::endl;
			//OBJ_PROTECTOR(this_object);//do we really need to protect this?
			error_code ec;
			flow_sptr flow=flow_type::create_for_passive_connect(
				this->get_io_service(),SHARED_OBJ_FROM_THIS,get_shared_layer(),from,ec
				);//the new flow will register itself to shared_layer,don't worry about it.
			if (!flow)
				return INVALID_FLOWID;
			return flow->flow_id();
		}

		virtual void accept_flow(boost::shared_ptr<basic_flow_adaptor> flow)
		{
			//OBJ_PROTECTOR(this_object);//do we really need to protect this?
			if (pending_flows_.size()<128)
			{
				BOOST_ASSERT(boost::shared_dynamic_cast<flow_type>(flow));
				pending_flows_.push(boost::shared_static_cast<flow_type>(flow));
			}
			else
				flow->close(false);
			__on_accepted(error_code());
		}

	protected:
		flow_sptr pop_first_pending_flow()
		{
			if (pending_flows_.empty())
				return flow_sptr();
			flow_sptr flow=pending_flows_.front();
			pending_flows_.pop();
			return flow;
		}

	private:
		token_sptr token_;
		std::queue<flow_sptr> pending_flows_;

		state state_;
		bool b_keep_accepting_;
	};

} // namespace urdp
} // namespace p2engine

#endif//basic_urdp_acceptor_h__
