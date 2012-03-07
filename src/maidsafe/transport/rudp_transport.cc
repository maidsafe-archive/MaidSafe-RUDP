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

// Author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#include "maidsafe/transport/rudp_transport.h"

#include <cassert>
#include <functional>

#include "maidsafe/transport/rudp_acceptor.h"
#include "maidsafe/transport/rudp_connection.h"
#include "maidsafe/transport/rudp_multiplexer.h"
#include "maidsafe/transport/rudp_socket.h"
#include "maidsafe/transport/log.h"
#include "maidsafe/transport/contact.h"
#include "maidsafe/transport/nat_detection.h"
#include "maidsafe/transport/rudp_message_handler.h"

namespace asio = boost::asio;
namespace bs = boost::system;
namespace ip = asio::ip;
namespace args = std::placeholders;

namespace maidsafe {

namespace transport {

RudpTransport::RudpTransport(asio::io_service &asio_service)   // NOLINT
  : Transport(asio_service),
    strand_(asio_service),
    multiplexer_(new RudpMultiplexer(asio_service)),
    acceptor_(),
    connections_() {}

RudpTransport::~RudpTransport() {
  for (auto it = connections_.begin(); it != connections_.end(); ++it)
    (*it)->Close();
}

TransportCondition RudpTransport::StartListening(const Endpoint &endpoint) {
  if (listening_port_ != 0)
    return kAlreadyStarted;

  ip::udp::endpoint ep(endpoint.ip, endpoint.port);
  TransportCondition condition = multiplexer_->Open(ep);
  if (condition != kSuccess)
    return condition;

  acceptor_.reset(new RudpAcceptor(*multiplexer_));
  listening_port_ = endpoint.port;
  transport_details_.endpoint.port = listening_port_;
  transport_details_.endpoint.ip = endpoint.ip;

  StartAccept();
  StartDispatch();

  return kSuccess;
}

TransportCondition RudpTransport::Bootstrap(
    const std::vector<Contact> &/*candidates*/) {
  return kSuccess;
}

void RudpTransport::StopListening() {
  if (acceptor_)
    strand_.dispatch(std::bind(&RudpTransport::CloseAcceptor, acceptor_));
  if (multiplexer_)
    strand_.dispatch(std::bind(&RudpTransport::CloseMultiplexer, multiplexer_));
  listening_port_ = 0;
  acceptor_.reset();
  multiplexer_.reset(new RudpMultiplexer(asio_service_));
}

void RudpTransport::CloseAcceptor(AcceptorPtr acceptor) {
  acceptor->Close();
}

void RudpTransport::CloseMultiplexer(MultiplexerPtr multiplexer) {
  multiplexer->Close();
}

void RudpTransport::StartDispatch() {
  auto handler = strand_.wrap(std::bind(&RudpTransport::HandleDispatch,
                                        shared_from_this(),
                                        multiplexer_, args::_1));
  multiplexer_->AsyncDispatch(handler);
}

void RudpTransport::HandleDispatch(MultiplexerPtr multiplexer,
                                   const bs::error_code &/*ec*/) {
  if (!multiplexer->IsOpen())
    return;

  StartDispatch();
}

void RudpTransport::StartAccept() {
  ip::udp::endpoint endpoint;  // Endpoint is assigned when socket is accepted.
  ConnectionPtr connection(std::make_shared<RudpConnection>(shared_from_this(),
                                                           strand_,
                                                           multiplexer_,
                                                           endpoint));

  acceptor_->AsyncAccept(connection->Socket(),
                         strand_.wrap(std::bind(&RudpTransport::HandleAccept,
                                                shared_from_this(), acceptor_,
                                                connection, args::_1)));
}

void RudpTransport::HandleAccept(AcceptorPtr acceptor,
                                 ConnectionPtr connection,
                                 const bs::error_code &ec) {
  if (!acceptor->IsOpen())
    return;

  if (!ec) {
    // It is safe to call DoInsertConnection directly because HandleAccept() is
    // already being called inside the strand.
    DoInsertConnection(connection);
    connection->StartReceiving();
  }

  StartAccept();
}

void RudpTransport::Send(const std::string &data,
                         const Contact &remote_contact,
                         const Timeout &timeout) {
  if (remote_contact.rendezvous_endpoint().ip != IP()) {
    RudpMessageHandlerPtr message_handler;
    std::string message(message_handler->CreateForwardRendezvousRequest(
        remote_contact.endpoint()));
    Send(message, remote_contact.rendezvous_endpoint(), timeout);
    Connect(remote_contact.endpoint(), timeout,
        std::bind(&RudpTransport::ConnectCallback, this, args::_1, data,
                  remote_contact.endpoint(), timeout));
  } else {
    Send(data, remote_contact.endpoint(), timeout);
  }
}

void RudpTransport::ConnectCallback(const int &result,
                                    const std::string &data,
                                    const Endpoint &endpoint,
                                    const Timeout &timeout) {
  if (result == kSuccess) {
    Send(data, endpoint, timeout);
  }
  // TODO(Mahmoud): if otherwise!
}

void RudpTransport::Send(const std::string &data,
                         const Endpoint &endpoint,
                         const Timeout &timeout) {
  strand_.dispatch(std::bind(&RudpTransport::DoSend,
                             shared_from_this(),
                             data, endpoint, timeout));
}

void RudpTransport::DoSend(const std::string &data,
                           const Endpoint &endpoint,
                           const Timeout &timeout) {
  ip::udp::endpoint ep(endpoint.ip, endpoint.port);
  bool multiplexer_opened_now(false);

  if (!multiplexer_->IsOpen()) {
    TransportCondition condition = multiplexer_->Open(ep.protocol());
    if (kSuccess != condition) {
      (*on_error_)(condition, endpoint);
      return;
    }
    multiplexer_opened_now = true;
    // StartDispatch();
  }

  ConnectionPtr connection(std::make_shared<RudpConnection>(shared_from_this(),
                                                           strand_,
                                                           multiplexer_, ep));

  DoInsertConnection(connection);
  connection->StartSending(data, timeout);
// Moving StartDispatch() after StartSending(), as on Windows - client-socket's
// attempt to call async_receive_from() will result in EINVAL error until it is
// either bound to any port or a sendto() operation is performed by the socket.
// Also, this makes it in sync with tcp transport's implementation.

  if (multiplexer_opened_now)
    StartDispatch();
}

void RudpTransport::Connect(const Endpoint &endpoint, const Timeout &timeout,
                            ConnectFunctor callback) {
  strand_.dispatch(std::bind(&RudpTransport::DoConnect,
                             shared_from_this(), endpoint, timeout, callback));
}
void RudpTransport::DoConnect(const Endpoint &endpoint,
                            const Timeout &timeout, ConnectFunctor callback) {
  ip::udp::endpoint ep(endpoint.ip, endpoint.port);
  bool multiplexer_opened_now(false);

  if (!multiplexer_->IsOpen()) {
    TransportCondition condition = multiplexer_->Open(ep.protocol());
    if (kSuccess != condition) {
      (*on_error_)(condition, endpoint);
      return;
    }
    multiplexer_opened_now = true;
    // StartDispatch();
  }

  ConnectionPtr connection(std::make_shared<RudpConnection>(shared_from_this(),
                                                            strand_,
                                                            multiplexer_, ep));
  DoInsertConnection(connection);
  connection->Connect(timeout, callback);

  if (multiplexer_opened_now)
    StartDispatch();
}

void RudpTransport::InsertConnection(ConnectionPtr connection) {
  strand_.dispatch(std::bind(&RudpTransport::DoInsertConnection,
                             shared_from_this(), connection));
}

void RudpTransport::DoInsertConnection(ConnectionPtr connection) {
  connections_.insert(connection);
}

void RudpTransport::RemoveConnection(ConnectionPtr connection) {
  strand_.dispatch(std::bind(&RudpTransport::DoRemoveConnection,
                             shared_from_this(), connection));
}

void RudpTransport::DoRemoveConnection(ConnectionPtr connection) {
  connections_.erase(connection);
}

}  // namespace transport

}  // namespace maidsafe
