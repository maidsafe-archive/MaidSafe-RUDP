//
// http_connection.hpp
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
#ifndef P2ENGINE_HTTP_CONNECTION_HPP
#define P2ENGINE_HTTP_CONNECTION_HPP

#include "p2engine/http/http_connection_base.hpp"
#include "p2engine/safe_asio_base.hpp"
#include "p2engine/timer.hpp"
#include "p2engine/coroutine.hpp"

namespace p2engine { namespace http {

	class basic_http_connection_impl
		: public safe_asio_base
		, public fssignal::trackable
	{
		typedef basic_http_connection_impl  this_type;

		typedef variant_endpoint endpoint_type;
		typedef variant_endpoint endpoint;
		typedef  asio::ip::tcp::resolver_iterator resolver_iterator;
		typedef  asio::ip::tcp::resolver_query resolver_query;
		typedef  asio::ip::tcp::resolver resolver_type;
		typedef rough_timer timer_type;
		typedef boost::shared_ptr<timer_type> timer_sptr;
		typedef boost::asio::ip::tcp::socket::lowest_layer_type lowest_layer_type;

	public:
		basic_http_connection_impl(http_connection_base&conn,bool passive);

		error_code open(const endpoint_type& local_edp, error_code& ec,
			const proxy_settings& ps=proxy_settings()
			);

		void async_connect(const std::string& remote_host, int port, 
			const time_duration& time_out=boost::date_time::pos_infin
			);

		void async_connect(const endpoint& remote_edp,
			const time_duration& time_out=boost::date_time::pos_infin
			);

		//reliable send
		void async_send(const safe_buffer& buf);

		void keep_async_receiving();

		void block_async_receiving()
		{
			is_recv_blocked_=true;
		}

		void close(bool greaceful=true);

		bool is_open() const
		{
			return socket_impl_.is_open();
		}

		endpoint local_endpoint(error_code& ec)const
		{
			return socket_impl_.local_endpoint(ec);
		}
		endpoint remote_endpoint(error_code& ec)const
		{
			return socket_impl_.remote_endpoint(ec);
		}

		lowest_layer_type& lowest_layer() 
		{
			return socket_impl_.lowest_layer();
		}

	protected:
		void do_keep_receiving(uint64_t stamp);

		void __init();

		error_code __open(error_code& ec);

		void __to_close_state(const error_code& ec, uint64_t stamp);

		void __async_resolve_connect_coro(boost::shared_ptr<http_connection_base>conn,
			error_code err, resolver_iterator itr, 
			uint64_t stamp, coroutine coro=coroutine(), resolver_query* qy=NULL
			);

		void __async_send_handler(boost::shared_ptr<http_connection_base>conn,
			error_code ec, size_t len,uint64_t stamp);

		void __async_recv_handler(boost::shared_ptr<http_connection_base>conn, 
			error_code ec, size_t len,uint64_t stamp);

		void __allert_connected(boost::shared_ptr<http_connection_base>conn,
			error_code ec, uint64_t stamp);

	protected:
		boost::asio::ip::tcp::socket socket_impl_;
		http_connection_base& connection_;
		enum{INIT, OPENED, CONNECTING, CONNECTED, CLOSED} state_;
		enum{RECVING,RECVED} recv_state_;
		bool is_header_recvd_;
		timer_sptr conn_timer_;
		std::string remote_host_;
		resolver_type resolver_;
		endpoint_type remote_edp_;
		endpoint_type local_edp_;
		bool sending_;
		bool closing_;
		bool is_passive_;
		bool is_recv_blocked_;
		std::queue<safe_buffer> send_bufs_;
		boost::asio::streambuf recv_buf_;
	};


	template<typename BaseConnectionType>
	class basic_http_connection
		: public BaseConnectionType
		, public safe_asio_base
	{
		typedef basic_http_connection<BaseConnectionType> this_type;
		SHARED_ACCESS_DECLARE;
		BOOST_STATIC_ASSERT((boost::is_same<BaseConnectionType,http_connection_base>::value)
			||(boost::is_base_and_derived<http_connection_base,BaseConnectionType>::value));
	protected:
		basic_http_connection(io_service& ios,bool isPassive)
			:BaseConnectionType(ios,isPassive),impl_(*this,isPassive)
		{}

		virtual ~basic_http_connection(){};

	public:
		typedef boost::asio::ip::tcp::socket::lowest_layer_type lowest_layer_type;

		static shared_ptr create(io_service& ios,bool passive=false)
		{
			return shared_ptr(new this_type(ios,passive),
				shared_access_destroy<this_type>());
		}

	public:
		virtual error_code open(const endpoint& local_edp, error_code& ec,
			const proxy_settings& ps=proxy_settings()
			)
		{
			return impl_.open(local_edp,ec,ps);
		}

		virtual void async_connect(const std::string& remote_host, int port, 
			const time_duration& time_out=boost::date_time::pos_infin
			)
		{
			impl_.async_connect(remote_host,port,time_out);
		}
		virtual void  async_connect(const endpoint& peer_endpoint,
			const time_duration& time_out=boost::date_time::pos_infin
			)
		{
			impl_.async_connect(peer_endpoint,time_out);
		}

		virtual void async_send(const safe_buffer& buf)
		{
			impl_.async_send(buf);
		}

		virtual void keep_async_receiving()
		{
			impl_.keep_async_receiving();
		}
		virtual void block_async_receiving()
		{
			impl_.block_async_receiving();
		}

		virtual void close(bool greaceful=true)
		{
			impl_.close();
		}
		virtual bool is_open() const
		{
			return impl_.is_open();
		}

		virtual endpoint local_endpoint(error_code& ec)const
		{
			return impl_.local_endpoint(ec);
		}
		virtual endpoint remote_endpoint(error_code& ec)const
		{
			return impl_.remote_endpoint(ec);
		}

		lowest_layer_type& lowest_layer() 
		{
			return impl_.lowest_layer();
		}

	protected:
		basic_http_connection_impl impl_;
	};

} // namespace http
} // namespace p2engine

#endif // P2ENGINE_HTTP_CONNECTION_HPP
