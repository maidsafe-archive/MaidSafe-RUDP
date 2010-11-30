#include "p2engine/http/http_connection.hpp"

namespace p2engine { namespace http {

	basic_http_connection_impl::basic_http_connection_impl(http_connection_base&conn,
		bool passive)
		:connection_(conn),socket_impl_(conn.get_io_service())
		,resolver_(conn.get_io_service()), is_passive_(passive)
	{
		__init();
	}

	error_code basic_http_connection_impl::open(const endpoint_type& local_edp, error_code& ec,
		const proxy_settings& ps
		)
	{
		local_edp_=local_edp;
		return __open(ec);
	}

	void basic_http_connection_impl::async_connect(const std::string& remote_host, int port, 
		const time_duration& time_out
		)
	{
		BOOST_ASSERT(!is_passive_);
		error_code err;
		address_v4 addr=address_v4::from_string(remote_host.c_str(),err);
		if (!err)//if the format of xxx.xxx.xxx.xxx
		{
			remote_edp_=boost::asio::ip::tcp::endpoint(addr,port);
			async_connect(remote_edp_);
		}
		else
		{
			remote_host_=remote_host;
			remote_edp_.port(port);
			async_connect(endpoint_type());
		}
	}

	void basic_http_connection_impl::async_connect(const endpoint& remote_edp,
		const time_duration& time_out
		)
	{
		error_code ec;
		if (state_==INIT||state_==CLOSED)
			open(endpoint_type(),ec);
		else if (state_!=OPENED)
			ec=asio::error::in_progress;

		next_op_stamp();

		if (ec)
		{
			connection_.get_io_service().post(
				boost::bind(&this_type::__allert_connected,this,
				connection_.shared_obj_from_this<http_connection_base>(),ec,op_stamp())
				);
			return;
		}

		state_=CONNECTING;

		if (remote_edp.port())//we know the remote_endpoint
		{
			remote_edp_=remote_edp;
			__async_resolve_connect_coro(connection_.shared_obj_from_this<http_connection_base>(),
				error_code(),resolver_iterator(),op_stamp());
		}
		else//we know the remote_host name
		{
			resolver_query qy(remote_host_,"");
			__async_resolve_connect_coro(connection_.shared_obj_from_this<http_connection_base>(),
				error_code(),resolver_iterator(),op_stamp(),coroutine(),&qy);
		}
	}

	//reliable send
	void basic_http_connection_impl::async_send(const safe_buffer& buf)
	{
		if (state_!=CONNECTED)
			return;

		if (sending_)
		{
			send_bufs_.push(buf);
		}
		else
		{
			sending_=true;
			boost::asio::async_write(socket_impl_,
				buf.to_asio_const_buffers_1(),
				boost::asio::transfer_all(),
				boost::bind(&this_type::__async_send_handler,this,
				connection_.shared_obj_from_this<http_connection_base>(),_1,_2,op_stamp_)
				);
		}
	}

	void basic_http_connection_impl::keep_async_receiving()
	{
		if (is_recv_blocked_&&recv_state_!=RECVING)
		{
			is_recv_blocked_=false;
			if (is_header_recvd_&&recv_buf_.size()>0)
			{
				connection_.get_io_service().post(			
					boost::bind(&this_type::__async_recv_handler,this,
					connection_.shared_obj_from_this<http_connection_base>(),
					error_code(),recv_buf_.size(),op_stamp())
					);
			}
			else
				do_keep_receiving(op_stamp_);
		}
	}

	void basic_http_connection_impl::do_keep_receiving(uint64_t stamp)
	{
		if(is_canceled_op(stamp)||state_==CLOSED)//all canceled operation will not be invoked
			return;

		recv_state_=RECVING;
		boost::asio::async_read(socket_impl_,
			recv_buf_,
			boost::asio::transfer_at_least(1),
			boost::bind(&this_type::__async_recv_handler,this,
			connection_.shared_obj_from_this<http_connection_base>(),
			_1,_2,stamp)
			);
	}

	void basic_http_connection_impl::close(bool greaceful)
	{
		if (CLOSED==state_)
			return;
		set_cancel();
		if (greaceful)
		{
			if (send_bufs_.empty())
			{
				error_code ec;
				socket_impl_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
				socket_impl_.close(ec);
				state_=CLOSED;
			}
			else
			{
				closing_=true;
			}
		}
		else
		{
			error_code ec;
			socket_impl_.close(ec);
			state_=CLOSED;
		}
	}

	void basic_http_connection_impl::__init()
	{
		op_cancel_=op_stamp_;
		next_op_stamp();
		sending_=false;
		closing_=false;
		is_header_recvd_=false;
		is_recv_blocked_=true;
		recv_state_=RECVED;
		state_=INIT;
		recv_buf_.consume(recv_buf_.size());
		while(!send_bufs_.empty())
			send_bufs_.pop();
		if (conn_timer_)
			conn_timer_->cancel();
		conn_timer_=timer_type::create(connection_.get_io_service());
		if (is_passive_) 
			state_=CONNECTED;
	}

	error_code basic_http_connection_impl::__open(error_code& ec)
	{
		__init();
		if (state_!=INIT)
		{
			ec=asio::error::already_open;
			return ec;
		}
		BOOST_ASSERT(!is_passive_);
		is_passive_=false;
		socket_impl_.open(boost::asio::ip::tcp::endpoint(local_edp_).protocol(), ec);
		if (!ec)
		{
			if (local_edp_.port()!=0)
				socket_impl_.bind(boost::asio::ip::tcp::endpoint(local_edp_),ec);
		}
		if (ec)
		{
			error_code err;
			socket_impl_.close(err);
			return ec;
		}
		if (!ec)
		{
			error_code e;
			//using a larg buffer
			asio::socket_base::receive_buffer_size receive_buffer_size_option(1024*1024);
			asio::socket_base::send_buffer_size send_buffer_size_option(1024*1024);
			//asio::socket_base::send_low_watermark send_low_watermark_option(512);
			socket_impl_.set_option(receive_buffer_size_option, e);
			socket_impl_.set_option(send_buffer_size_option, e);
			//socket_impl_.set_option(send_low_watermark_option);
			state_=OPENED;
		}
		return ec;
	}

	void basic_http_connection_impl::__to_close_state(const error_code& ec, uint64_t stamp)
	{
		if(is_canceled_op(stamp)||state_==CLOSED)//all canceled operation will not be invoked
			return;
		if(!closing_)//主动关闭时，不dispatch_disconnected也不dispatch_connected
		{
			if (is_passive_)
			{
				if (state_==CONNECTED)
					connection_.dispatch_disconnected(ec);
			}
			else
			{
				if (state_<CONNECTED)
					connection_.dispatch_connected(ec);
				else
					connection_.dispatch_disconnected(ec);
			}
		}

		close();
	}


	void basic_http_connection_impl::__async_resolve_connect_coro(
		boost::shared_ptr<http_connection_base>conn,
		error_code err, resolver_iterator itr, 
		uint64_t stamp, coroutine coro, 
		resolver_query* qy
		)
	{
		BOOST_ASSERT(conn.get()==&connection_);

		if(is_canceled_op(stamp)||state_==CLOSED)//all canceled operation will not be invoked
			return;

		CORO_REENTER(coro)
		{
			state_=CONNECTING;

			// Start the conn timer
			{
				error_code timeoutErr=asio::error::timed_out;
				conn_timer_->time_signal().clear();
				conn_timer_->time_signal().bind(&this_type::__to_close_state,
					this,timeoutErr,stamp);
				conn_timer_->async_wait(seconds(10));
			}
			//if qy is not null, we yield async resolve
			if (qy)
			{
				CORO_YIELD(resolver_.async_resolve(*qy,
					boost::bind(&this_type::__async_resolve_connect_coro,
					this,conn,_1,_2,stamp,coro,qy)) 
					);

				if (err||itr==resolver_iterator())
				{
					__to_close_state(err,stamp);
					return;
				}
				remote_edp_.address(endpoint_type(*itr++).address());
			}

			//yield async connect
			CORO_YIELD(socket_impl_.async_connect(remote_edp_,
				boost::bind(&this_type::__async_resolve_connect_coro,
				this,conn,_1,itr,stamp,coro,(resolver_query*)NULL)
				));

			while(err && itr != resolver_iterator())
			{
				//close socket that failed to connect, and open a new one
				socket_impl_.close(err);
				__open(err);
				if (err)
				{
					__to_close_state(err,stamp);
					return;
				}

				// retart the conn timer
				{
					error_code timeoutErr=asio::error::timed_out;
					conn_timer_->time_signal().clear();
					conn_timer_->time_signal().bind(&this_type::__to_close_state,
						this,timeoutErr,stamp);
					conn_timer_->async_wait(seconds(6));
				}

				remote_edp_.address(endpoint_type(*itr++).address());
				//yeld async connect
				CORO_YIELD(socket_impl_.async_connect(remote_edp_,
					boost::bind(&this_type::__async_resolve_connect_coro,
					this,conn,_1,itr,stamp,coro,(resolver_query*)NULL))
					);
			}
			if (err)
			{
				__to_close_state(err,stamp);
				return;
			}

			//now lowlayer connected
			conn_timer_->cancel();
			conn_timer_->time_signal().clear();

			if (!err)
				keep_async_receiving();
			state_=CONNECTED;
			connection_.dispatch_connected(err);
		}
	}

	void basic_http_connection_impl::__async_send_handler(
		boost::shared_ptr<http_connection_base>conn,
		error_code ec, std::size_t len,uint64_t stamp)
	{
		BOOST_ASSERT(conn.get()==&connection_);

		if(is_canceled_op(stamp)||state_==CLOSED)//all canceled operation will not be invoked
			return;
		sending_=false;
		if (!ec)
		{
			if(!send_bufs_.empty())
			{
				boost::asio::async_write(socket_impl_,
					send_bufs_.front().to_asio_const_buffers_1(),
					boost::asio::transfer_all(),
					boost::bind(&this_type::__async_send_handler,this,
					conn,_1,_2,stamp)
					);
				send_bufs_.pop();
				sending_=true;
			}
			else if(closing_)
			{
				__to_close_state(ec,stamp);
			}
			else
			{
				connection_.dispatch_sendout();
			}
		}
		else
		{
			__to_close_state(ec,stamp);
		}
	}

	void basic_http_connection_impl::__async_recv_handler(
		boost::shared_ptr<http_connection_base>conn, 
		error_code ec, std::size_t len,uint64_t stamp)
	{
		BOOST_ASSERT(conn.get()==&connection_);

		if(is_canceled_op(stamp)||state_==CLOSED)//all canceled operation will not be invoked
			return;

		if (ec)
		{
			__to_close_state(boost::asio::error::message_size,stamp);
			return;
		}
		
		recv_state_=RECVED;
		if (is_recv_blocked_)
			return;
		if (!is_header_recvd_)
		{
			http::request  req;
			http::response res;
			http::header* h=NULL;
			if(is_passive_)
				h=&req;
			else
				h=&res;
			h->clear();
			boost::asio::streambuf::const_buffers_type bf=recv_buf_.data();
			const char* s=asio::buffer_cast<const char*>(bf);
			int parseRst=h->read(s,recv_buf_.size());
			if(parseRst>0)
			{
				is_header_recvd_=true;
				safe_buffer buf;
				const char* readPtr=h->read_ptr();
				if (std::size_t(readPtr-s)<recv_buf_.size())
				{
					safe_buffer_io bio(&buf);
					bio.write(readPtr,recv_buf_.size()-(readPtr-s));
				}
				recv_buf_.consume(recv_buf_.size());
				if(is_passive_)
					connection_.dispatch_request(req);
				else
					connection_.dispatch_response(res);
				if(buf.length()>0&&!(is_canceled_op(stamp)||state_==CLOSED))
				{
					if (is_recv_blocked_)
					{
						memcpy(asio::buffer_cast<char*>(recv_buf_.prepare(buf.length())),
							p2engine::buffer_cast<char*>(buf),buf.size());
						recv_buf_.commit(buf.length());
						return;
					}
					else
						connection_.dispatch_packet(buf);
				}
			}
			else if(parseRst==0)
			{
				recv_state_=RECVING;
			}
			else
			{
				recv_buf_.consume(recv_buf_.size());
				__to_close_state(boost::asio::error::message_size,stamp);
				return;
			}

		}
		else
		{
			safe_buffer buf;
			safe_buffer_io bio(&buf);
			const char* s=asio::buffer_cast<const char*>(recv_buf_.data());
			bio.write(s,recv_buf_.size());
			recv_buf_.consume(recv_buf_.size());
			connection_.dispatch_packet(buf);
		}
		recv_state_=RECVING;
		boost::asio::async_read(socket_impl_,
			recv_buf_,
			boost::asio::transfer_at_least(1),
			boost::bind(&this_type::__async_recv_handler,this,conn,_1,_2,stamp)
			);
	}


	void basic_http_connection_impl::__allert_connected(boost::shared_ptr<http_connection_base>conn,
		error_code ec, uint64_t stamp)
	{
		if(is_canceled_op(stamp)||state_==CLOSED)//all canceled operation will not be invoked
			return;
		conn->dispatch_connected(ec);
	}



}
}