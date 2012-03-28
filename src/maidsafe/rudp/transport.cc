/*******************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of MaidSafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the licence   *
 *  file licence.txt found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of MaidSafe.net. *
 ******************************************************************************/
// Original author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

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

void RudpTransport::Connect(const Endpoint &endpoint,
                            const Timeout &timeout,
                            ConnectFunctor callback) {
  strand_.dispatch(std::bind(&RudpTransport::DoConnect,
                             shared_from_this(), endpoint, timeout, callback));
}

void RudpTransport::DoConnect(const Endpoint &endpoint,
                              const Timeout &timeout,
                              ConnectFunctor callback) {
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
