//
// http_acceptor.hpp
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
#ifndef P2ENGINE_HTTP_ACCEPTOR_HPP
#define P2ENGINE_HTTP_ACCEPTOR_HPP

#include "p2engine/http/http_acceptor_base.hpp"
#include "p2engine/safe_asio_base.hpp"
#include "p2engine/timer.hpp"
#include "p2engine/coroutine.hpp"

namespace p2engine { namespace http {

	template<typename ConnectionType, typename ConnectionBaseType>
	class basic_http_acceptor 
		:public http_acceptor_base<ConnectionBaseType>
		,public safe_asio_base
	{
		typedef basic_http_acceptor<ConnectionType,ConnectionBaseType> this_type;
		SHARED_ACCESS_DECLARE;

	public:
		typedef this_type acceptor_type;
		typedef ConnectionType connection_type;
		typedef ConnectionBaseType connection_base_type;

	public:
		static shared_ptr create(io_service& ios)
		{
			return shared_ptr(new this_type(ios),
				shared_access_destroy<this_type>()
				);
		}

	protected:
		basic_http_acceptor(io_service&ios)
			:http_acceptor_base<ConnectionBaseType>(ios)
			,acceptor_(ios)
			,is_accepting_(false)
			,block_async_accepting_(true)
		{}
		virtual ~basic_http_acceptor()
		{
			set_cancel();
		};

	public:
		virtual error_code listen(const endpoint& local_edp,error_code& ec)
		{
			this->next_op_stamp();
			acceptor_.open(boost::asio::ip::tcp::endpoint(local_edp).protocol(),ec);
			acceptor_.bind(local_edp,ec);
			acceptor_.listen(asio::socket_base::max_connections, ec);
			if(!ec)
				keep_async_accepting();
			return ec;
		}
		virtual void keep_async_accepting()
		{
			if (accepted_)
			{
				boost::shared_ptr<connection_type> conn=accepted_;
				error_code ec=accepted_ec_;
				accepted_.reset();
				accepted_ec_.clear();
				this->get_io_service().post(
					boost::bind(&this_type::__accept_handler,SHARED_OBJ_FROM_THIS,
					accepted_ec_,accepted_,this->op_stamp())
					);
			}
			else if (block_async_accepting_&&!is_accepting_)
			{
				is_accepting_=true;
				block_async_accepting_=false;
				boost::shared_ptr<connection_type> conn=connection_type::create(this->get_io_service(),true);
				acceptor_.async_accept(conn->lowest_layer(),
					boost::bind(&this_type::__accept_handler,SHARED_OBJ_FROM_THIS,_1,conn,this->op_stamp())
					);
			}
		}
		virtual void block_async_accepting()
		{
			block_async_accepting_=true;
		}

		virtual error_code close(){error_code ec; return close(ec);}
		virtual error_code close(error_code& ec)
		{
			ec.clear();
			set_cancel();
			acceptor_.cancel(ec);
			acceptor_.close(ec);
			return ec;
		}

		virtual endpoint local_endpoint(error_code& ec) const
		{
			return acceptor_.local_endpoint(ec);
		}

		virtual bool is_open()const
		{
			return acceptor_.is_open();
		}

	protected:
		void __accept_handler(error_code ec,boost::shared_ptr<connection_type> conn,uint64_t stamp)
		{
			if (this->is_canceled_op(stamp))
				return;
			is_accepting_=false;
			if (block_async_accepting_)
			{
				accepted_=conn;
				accepted_ec_=ec;
				return;
			}
			conn->keep_async_receiving();
			dispatch_accepted(conn,ec);
			if (acceptor_.is_open()&&!block_async_accepting_)
			{
				is_accepting_=true;
				boost::shared_ptr<connection_type> conn=connection_type::create(this->get_io_service(),true);
				acceptor_.async_accept(conn->lowest_layer(),
					boost::bind(&this_type::__accept_handler,SHARED_OBJ_FROM_THIS,_1,conn,stamp));
			}
		}

	protected:
		boost::asio::ip::tcp::acceptor acceptor_;
		bool block_async_accepting_;
		bool is_accepting_;

		boost::shared_ptr<connection_type> accepted_;
		error_code accepted_ec_;
	};


} // namespace http
} // namespace p2engine

#endif // P2ENGINE_HTTP_CONNECTION_HPP
