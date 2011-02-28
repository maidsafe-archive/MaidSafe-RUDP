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

#include <functional>

#include "google/protobuf/descriptor.h"

#include "maidsafe-dht/transport/tcp_transport.h"
#include "maidsafe-dht/common/log.h"

namespace asio = boost::asio;
namespace bs = boost::system;
namespace ip = asio::ip;
namespace arg = std::placeholders;

namespace maidsafe {

namespace transport {

TcpTransport::TcpTransport(
    std::shared_ptr<boost::asio::io_service> asio_service)
        : Transport(asio_service),
          acceptor_(),
          connections_(),
          mutex_() {}

TcpTransport::~TcpTransport() {
  while (!connections_.empty())
    (*connections_.begin())->Close();
//  for (auto it = connections_.begin(); it != connections_.end(); ++it)
//    (*it)->Close();
  StopListening();
}

TransportCondition TcpTransport::StartListening(const Endpoint &endpoint) {
  if (listening_port_ != 0)
    return kAlreadyStarted;

  if (endpoint.port == 0)
    return kInvalidPort;

  ip::tcp::endpoint ep(endpoint.ip, endpoint.port);
  acceptor_.reset(new ip::tcp::acceptor(*asio_service_));

  bs::error_code ec;
  acceptor_->open(ep.protocol(), ec);

  if (ec)
    return kInvalidAddress;

  acceptor_->bind(ep, ec);

  if (ec)
    return kBindError;

  acceptor_->listen(asio::socket_base::max_connections, ec);

  if (ec)
    return kListenError;

  ConnectionPtr new_connection(
      std::make_shared<TcpConnection>(this, boost::asio::ip::tcp::endpoint()));
  listening_port_ = acceptor_->local_endpoint().port();

  // The connection object is kept alive in the acceptor handler until
  // HandleAccept() is called.
  acceptor_->async_accept(new_connection->Socket(),
                          std::bind(&TcpTransport::HandleAccept, this,
                                    new_connection, arg::_1));
  return kSuccess;
}

void TcpTransport::StopListening() {
  boost::system::error_code ec;
  if (acceptor_)
    acceptor_->close(ec);
  listening_port_ = 0;
}

void TcpTransport::HandleAccept(ConnectionPtr connection,
                                const bs::error_code &ec) {
  if (listening_port_ == 0)
    return;

  if (!ec) {
    boost::mutex::scoped_lock lock(mutex_);
    connections_.insert(connection);
    connection->StartReceiving();
  }

  ConnectionPtr new_connection(
      std::make_shared<TcpConnection>(this, boost::asio::ip::tcp::endpoint()));

  // The connection object is kept alive in the acceptor handler until
  // HandleAccept() is called.
  acceptor_->async_accept(new_connection->Socket(),
                          std::bind(&TcpTransport::HandleAccept, this,
                                    new_connection, arg::_1));
}

void TcpTransport::Send(const std::string &data,
                        const Endpoint &endpoint,
                        const Timeout &timeout) {
  ip::tcp::endpoint tcp_endpoint(endpoint.ip, endpoint.port);
  ConnectionPtr connection(std::make_shared<TcpConnection>(this, tcp_endpoint));

  {
    boost::mutex::scoped_lock lock(mutex_);
    connections_.insert(connection);
  }

  connection->Send(data, timeout, false);
}

void TcpTransport::RemoveConnection(ConnectionPtr connection) {
  boost::mutex::scoped_lock lock(mutex_);
  connections_.erase(connection);
}

}  // namespace transport

}  // namespace maidsafe
