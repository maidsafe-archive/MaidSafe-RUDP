// basic_urdp_visitor.h
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2009-2010 GuangZhu Wu  <guangzhuwu@gmail.com>
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

#ifndef P2ENGINE_ASYNC_CONNECT_HPP
#define P2ENGINE_ASYNC_CONNECT_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <string>
#include "p2engine/pop_warning_option.hpp"

#include <boost/asio/ip/tcp.hpp>
#include <sstream>

#include "p2engine/coroutine.hpp"

namespace p2engine {
	namespace detail {
		template <typename Socket, typename Handler>
		class connect_coro : coroutine
		{
		public:
			connect_coro(Handler handler,Socket& socket,
				boost::asio::ip::tcp::resolver& resolver)
				: handler_(handler),
				socket_(socket),
				resolver_(resolver),
				first_try_(true)
			{
			}

			void operator()(boost::system::error_code ec,
				boost::asio::ip::tcp::resolver::iterator iter)
			{
				iter_ = iter;
				(*this)(ec);
			}

			void operator()( boost::system::error_code ec,
				const boost::asio::ip::tcp::resolver::query* query = 0
				)
			{
				if (ec && iter_ == boost::asio::ip::tcp::resolver::iterator())
				{
					handler_(ec);
					return;
				}
				CORO_REENTER(this)
				{
					//如果socket没有打开，打开socket（默认为IPv4）
					if (!socket_.is_open())
					{
						socket_.open(boost::asio::ip::tcp::v4(), ec);
						if (ec)
							CORO_YIELD (socket_.get_io_service().post(
							boost::asio::detail::bind_handler(*this, ec)));
					}

					//进行域名解析
					CORO_YIELD(resolver_.async_resolve(*query, *this));

					//逐个尝试解析后的结果
					ec = boost::asio::error::host_not_found;
					while (ec && iter_ != boost::asio::ip::tcp::resolver::iterator())
					{
						// 检查操作是否被终止了（因为这是非阻塞的异步操作）
						if (!socket_.is_open())
						{
							ec = boost::asio::error::operation_aborted;
							handler_(ec);
							return;
						}
						if (!first_try_)
							socket_.close(ec);//从尝试第二个地址开始，就要首先关闭原链接了
						else
							first_try_=false;
						endpoint_ = *iter_++;
						CORO_YIELD (socket_.async_connect(endpoint_, *this));
					}

					// 检查操作是否被终止了（因为这是非阻塞的异步操作）
					if (!socket_.is_open())
					{
						ec = boost::asio::error::operation_aborted;
						handler_(ec);
						return;
					}

					// Disable the Nagle algorithm on all sockets.
					socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec);
					handler_(ec);
				}
			}

			friend void* asio_handler_allocate(size_t size,
				connect_coro<Socket,Handler>* this_handler)
			{
				using boost::asio::asio_handler_allocate;
				return asio_handler_allocate(size, &this_handler->handler_);
			}

			friend void asio_handler_deallocate(void* pointer, size_t size,
				connect_coro<Socket,Handler>* this_handler)
			{
				using boost::asio::asio_handler_deallocate;
				asio_handler_deallocate(pointer, size, &this_handler->handler_);
			}

			template <typename Function>
			friend void asio_handler_invoke(const Function& function,
				connect_coro<Socket,Handler>* this_handler)
			{
				using boost::asio::asio_handler_invoke;
				asio_handler_invoke(function, &this_handler->handler_);
			}

		private:
			Handler handler_;
			Socket& socket_;
			boost::asio::ip::tcp::resolver& resolver_;
			boost::asio::ip::tcp::resolver::iterator iter_;
			boost::asio::ip::tcp::endpoint endpoint_;
			bool first_try_;
		};
	} // namespace detail

	template <typename Socket, typename Handler>
	void async_connect(Socket& socket, boost::asio::ip::tcp::resolver& resolver, 
		const std::string hostName, int port, Handler handler)
	{
		boost::asio::ip::tcp::resolver::query query(hostName,
			boost::lexical_cast<std::string>(port));
		detail::connect_coro<Socket,Handler>(handler, socket, resolver)(
			boost::system::error_code(), &query);
	}

} // namespace libtorrent

#endif // P2ENGINE_DETAIL_CONNECT_HPP
