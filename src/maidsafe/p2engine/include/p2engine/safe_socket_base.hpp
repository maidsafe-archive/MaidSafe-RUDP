#ifndef SAFE_SOCKET_BASE_HPP
#define SAFE_SOCKET_BASE_HPP

#include "p2engine/safe_asio_base.hpp"
#include "p2engine/basic_engine_object.hpp"
#include "p2engine/contrib.hpp"

namespace p2engine {

	template <typename Socket>
	class safe_socket_base
		:public safe_asio_base
		,public basic_engine_object
	{
		typedef safe_socket_base<Socket> this_type;

	public:
		/// The protocol type.
		typedef typename Socket::protocol_type protocol_type;

		/// The endpoint type.
		typedef typename Socket::endpoint_type endpoint_type;

		/// A basic_safe_socket is always the lowest layer.
		typedef typename Socket::lowest_layer_type lowest_layer_type;

	private:
		void instantiate_socket()
		{
			set_cancel();
			next_op_stamp();
			socket_=boost::shared_ptr<Socket>(new Socket(get_io_service()));
			instantiate_connection(get_io_service(), proxy_settings_, *socket_);
		}

	public:
		safe_socket_base(io_service& ios)
			:basic_engine_object(ios)
			,resolver_(ios)
		{
		}

		~safe_socket_base()
		{		
			if(socket_&&socket_->is_open())
			{
				error_code ec;
				socket_->close(ec);
			}
		}

		void set_proxy(const proxy_settings& ps)
		{
			if (proxy_settings_.type!=ps.type
				||proxy_settings_.hostname!=ps.hostname
				||proxy_settings_.port!=ps.port
				||proxy_settings_.username!=ps.username
				||proxy_settings_.password!=ps.password
				)
			{
				proxy_settings_=ps;
				error_code ec;
				close(ec);
				instantiate_socket();//close old£¬and creat a new one
			}
		}

		lowest_layer_type& lowest_layer()
		{
			if (!socket_)
				instantiate_socket();
			return socket_->lowest_layer();
		}

		bool is_open() const
		{
			if (!socket_)
				return false;
			return socket_->is_open();
		}

		void open(protocol_type const& p, error_code& ec)
		{
			if (!socket_)
				instantiate_socket();
			socket_->open(p,ec);
		}

		void close(error_code& ec)
		{
			set_cancel();
			if(socket_)
			{
				error_code ec;
				socket_->close(ec);
				socket_.reset();
			}
		}

		endpoint_type local_endpoint(error_code& ec) const
		{
			if (socket_)
				return socket_->local_endpoint(ec);
			ec=boost::asio::error::not_socket;
			return endpoint_type();
		}

		endpoint_type remote_endpoint(error_code& ec) const
		{
			if (socket_)
				return socket_->remote_endpoint(ec);
			ec=boost::asio::error::not_socket;
			return endpoint_type();
		}

		void bind(endpoint_type const& endpoint, error_code& ec)
		{
			if (!socket_)
				instantiate_socket();
			return socket_->bind(endpoint,ec);
		}

		std::size_t available(error_code& ec) const
		{
			if (!socket_)
			{
				ec=boost::asio::error::not_connected;
				return 0;
			}
			return socket_->available(ec);
		}

		template <class Mutable_Buffers>
		std::size_t read_some(Mutable_Buffers const& buffers, error_code& ec)
		{ 
			if (!socket_)
			{
				ec=boost::asio::error::not_connected;
				return 0;
			}
			return socket_->read_some(buffers,ec);
		}

		template <class Mutable_Buffers, class Handler>
		void async_read_some(Mutable_Buffers const& buffers, Handler const& handler)
		{
			if (!socket_)
			{
				get_io_service().post(
					boost::bind(&this_type::dispatch_handler,this,
					boost::asio::error::not_connected,0,handler,op_stamp())
					);
				return;
			}
			socket_->async_read_some(buffers,
				boost::bind(&this_type::dispatch_handler,this,
				_1,_2,handler,op_stamp()));
		}

		template <class Const_Buffers, class Handler>
		void async_write_some(Const_Buffers const& buffers, Handler const& handler)
		{
			if (!socket_)
			{
				get_io_service().post(
					boost::bind(&this_type::dispatch_handler,this,
					boost::asio::error::not_connected,0,handler,op_stamp())
					);
				return;
			}
			socket_->async_write_some(buffers,
				boost::bind(&this_type::dispatch_handler,this,
				_1,_2,handler,op_stamp()));
		}

		template <class Handler>
		void async_connect(endpoint_type const& endpoint, Handler const& handler)
		{
			if (!socket_)
				instantiate_socket();
			set_cancel();
			next_op_stamp();
			if (!socket_)
			{
				get_io_service().post(
					boost::bind(&this_type::dispatch_handler,this,
					boost::asio::error::not_socket,handler,op_stamp())
					);
				return;
			}
			socket_->async_connect(endpoint,
				boost::bind(&this_type::dispatch_handler,this,
				_1,handler,op_stamp()));
		}

		template <class Handler>
		void async_connect(std::string const& remoteHost,int port,
			Handler const& handler)
		{
			if (!socket_)
				instantiate_socket();
			set_cancel();
			next_op_stamp();
			if (!socket_)
			{
				get_io_service().post(
					boost::bind(&this_type::dispatch_handler,this,
					boost::asio::error::not_socket,handler,op_stamp())
					);
				return;
			}

			socket_->async_connect(remoteHost,
				boost::bind(&this_type::dispatch_handler,this,
				_1,handler,op_stamp()));
		}

		template <class IO_Control_Command>
		void io_control(IO_Control_Command& ioc, error_code& ec)
		{ 
			if (socket_)
				socket_->io_control(ioc, ec); 
			else
				ec=boost::asio::error::not_socket;
		}

		template <class SettableSocketOption>
		error_code set_option(SettableSocketOption const& opt, error_code& ec)
		{
			if (socket_)
				socket_->set_option(opt, ec);
			else
				ec=boost::asio::error::not_socket;
		}

	protected:
		void dispatch_handler(const error_code& ec, size_t len,
			const handler_2_type& handler, boost::int64_t stamp )
		{
			if (op_cancel_<stamp)
				handler(ec,len);
		}
		void dispatch_handler(const error_code& ec,
			const handler_1_type& handler, boost::int64_t stamp )
		{
			if (op_cancel_<stamp)
				handler(ec);
		}

	private:
		proxy_settings proxy_settings_;
		boost::shared_ptr<Socket> socket_;

		boost::asio::ip::tcp::resolver resolver_;
	};
}
#endif//SAFE_SOCKET_BASE_HPP
