
/*Copyright (c) 2010 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "StdAfx.h"
#include "tcp_connection2.h"
#include "tcp_connection_manager2.h"
#include <boost\bind.hpp>
#include <boost\asio.hpp>

namespace asio=boost::asio;

namespace transport {

tcp_connection2::tcp_connection2(asio::io_service& io_service_, tcp_connection_manager2& connection_manager_)
	  :socket_(io_service_),
	  tcp_connection_manager_(connection_manager_)
{}

void tcp_connection2::receive(const boost::system::error_code& e,std::size_t bytes_transferred)
{
    if(!e)
    {
//      parse(buffer.data(), request);
//      handle_request(request, reply);
		asio::async_write(socket_, boost::asio::buffer(reply_),
        boost::bind(&tcp_connection2::sent, shared_from_this(), asio::placeholders::error));
    }
	else  
	{
		tcp_connection_manager_.remove_connection(shared_from_this());
	}
}

void tcp_connection2::sent(const boost::system::error_code& e)
{
	if (!e)
    {
	  boost::system::error_code ignored_ec;
	  socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ignored_ec);
    }
	else  
	{
		tcp_connection_manager_.remove_connection(shared_from_this());
	}
}

boost::asio::ip::tcp::socket& tcp_connection2::socket()
{
	return socket_;
}

void tcp_connection2::start()
{
	socket_.async_read_some(asio::buffer(buffer_),
    boost::bind(&tcp_connection2::receive, shared_from_this(),
	boost::asio::placeholders::error,
    asio::placeholders::bytes_transferred));
}


tcp_connection2::~tcp_connection2()
{
	socket_.close();
}

}  // namespace transport
