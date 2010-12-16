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

#include <maidsafe/transport/tcptransport.h>
#include <maidsafe/transport/tcpconnection.h>
#include <maidsafe/transport/udtconnection.h>  // for timeout constants
#include <maidsafe/protobuf/transport_message.pb.h>
#include <maidsafe/base/log.h>

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#include <google/protobuf/descriptor.h>

#include <algorithm>
#include <vector>

namespace asio = boost::asio;
namespace bs = boost::system;
namespace ip = asio::ip;
namespace pt = boost::posix_time;

namespace transport {

	tcpConnection2::tcpConnection2(asio::io_service& io_service_):soclet_(io_service_)
	{
	  socket_.async_read_some(asio::buffer(buffer_),
		  boost::bind(&tcpConnection2::handle_read, shared_from_this(),
			asio::placeholders::error,
			asio::placeholders::bytes_transferred));
	}

	tcpConnection2::handle_read(const asio::error_code& e,std::size_t bytes_transferred)
	{
		if(!e)
		{
			parse(buffer.data(), request);
			handle_request(request, reply);
			asio::async_write(socket_, reply_.to_buffers(),
				boost::bind(&connection::handle_write, shared_from_this(), asio::placeholders::error));
		}
	}

	tcpConnection2::handle_write(const asio::error_code& e)
	{
		if (!e)
		{
			socket_.shutdown();
		}
	}

	tcpConnection2::~tcpConnection2()
	{
		socket_.close();
	}

}  // namespace transport
