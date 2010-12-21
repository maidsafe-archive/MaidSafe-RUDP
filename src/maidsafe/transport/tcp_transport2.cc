/* Copyright (c) 2010 maidsafe.net limited
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
#include "tcptransport2.h"


namespace transport {

tcp_transport2::tcp_transport2(io_service& io_service__, const Endpoint& endpoint)
:Transport2(io_service__), 
	acceptor_(io_service__), 
	connection_(new tcp_connection2(io_service__, tcp_connection_manager_))
{}

void tcp_transport2::accept_connection(const boost::system::error_code& e)
{
  if (!e)
  {
	tcp_connection_manager_.add_connection(connection_);
	connection_.reset(new tcp_connection2(io_service_, tcp_connection_manager_));
    	acceptor_.async_accept(connection_->socket(), 
      	boost::bind(&tcp_transport2::accept_connection, this, boost::asio::placeholders::error));
  }
}

tcp_transport2::~tcp_transport2() 
{
    acceptor_.close();	
}

void tcp_transport2::start() 
{
	boost::asio::ip::tcp::endpoint tcp_endpoint_;
//	transform_to_tcp(endpoint, tcp_endpoint_);
	acceptor_.open(tcp_endpoint_.protocol());
	acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
	acceptor_.bind(tcp_endpoint_);
	acceptor_.listen();
	acceptor_.async_accept(connection_->socket(), 
	boost::bind(&tcp_transport2::accept_connection, this, boost::asio::placeholders::error));
}

void tcp_transport2::stop()
{
	tcp_connection_manager_.remove_all();
}

}  // namespace transport
