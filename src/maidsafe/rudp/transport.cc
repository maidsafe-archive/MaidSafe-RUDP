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

#include "maidsafe/rudp/transport.h"

#include <cassert>
#include <functional>

#include "maidsafe/rudp/core/acceptor.h"
#include "maidsafe/rudp/connection.h"
#include "maidsafe/rudp/core/multiplexer.h"
#include "maidsafe/rudp/core/socket.h"
#include "maidsafe/rudp/log.h"
#include "maidsafe/rudp/contact.h"
#include "maidsafe/rudp/nat_detection.h"
#include "maidsafe/rudp/core/message_handler.h"

namespace asio = boost::asio;
namespace bs = boost::system;
namespace ip = asio::ip;
namespace args = std::placeholders;

namespace maidsafe {

namespace rudp {

Transport::Transport(asio::io_service &asio_service)   // NOLINT
    : Transport(asio_service),
      strand_(asio_service),
      multiplexer_(new Multiplexer(asio_service)),
      acceptor_(),
      connections_() {}

Transport::~Transport() {
  for (auto it = connections_.begin(); it != connections_.end(); ++it)
    (*it)->Close();
}

ReturnCode Transport::StartListening(const Endpoint &endpoint) {
  if (listening_port_ != 0)
    return kAlreadyStarted;

  ip::udp::endpoint ep(endpoint.ip, endpoint.port);
  ReturnCode condition = multiplexer_->Open(ep);
  if (condition != kSuccess)
    return condition;

  acceptor_.reset(new Acceptor(*multiplexer_));
  listening_port_ = endpoint.port;
  transport_details_.endpoint.port = listening_port_;
  transport_details_.endpoint.ip = endpoint.ip;

  StartAccept();
  StartDispatch();

  return kSuccess;
}

ReturnCode Transport::Bootstrap(
    const std::vector<Contact> &/*candidates*/) {
  return kSuccess;
}

void Transport::StopListening() {
  if (acceptor_)
    strand_.dispatch(std::bind(&Transport::CloseAcceptor, acceptor_));
  if (multiplexer_)
    strand_.dispatch(std::bind(&Transport::CloseMultiplexer, multiplexer_));
  listening_port_ = 0;
  acceptor_.reset();
  multiplexer_.reset(new Multiplexer(asio_service_));
}

void Transport::CloseAcceptor(AcceptorPtr acceptor) {
  acceptor->Close();
}

void Transport::CloseMultiplexer(MultiplexerPtr multiplexer) {
  multiplexer->Close();
}

void Transport::StartDispatch() {
  auto handler = strand_.wrap(std::bind(&Transport::HandleDispatch,
                                        shared_from_this(),
                                        multiplexer_, args::_1));
  multiplexer_->AsyncDispatch(handler);
}

void Transport::HandleDispatch(MultiplexerPtr multiplexer,
                               const bs::error_code &/*ec*/) {
  if (!multiplexer->IsOpen())
    return;

  StartDispatch();
}

void Transport::StartAccept() {
  ip::udp::endpoint endpoint;  // Endpoint is assigned when socket is accepted.
  ConnectionPtr connection(std::make_shared<Connection>(shared_from_this(),
                                                        strand_,
                                                        multiplexer_,
                                                        endpoint));

  acceptor_->AsyncAccept(connection->Socket(),
                         strand_.wrap(std::bind(&Transport::HandleAccept,
                                                shared_from_this(), acceptor_,
                                                connection, args::_1)));
}

void Transport::HandleAccept(AcceptorPtr acceptor,
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

void Transport::Send(const std::string &data,
                     const Endpoint &endpoint,
                     const Timeout &timeout) {
  strand_.dispatch(std::bind(&Transport::DoSend, shared_from_this(), data,
                             endpoint, timeout));
}

void Transport::DoSend(const std::string &data,
                       const Endpoint &endpoint,
                       const Timeout &timeout) {
  ip::udp::endpoint ep(endpoint.ip, endpoint.port);
  bool multiplexer_opened_now(false);

  if (!multiplexer_->IsOpen()) {
    ReturnCode condition = multiplexer_->Open(ep.protocol());
    if (kSuccess != condition) {
      (*on_error_)(condition, endpoint);
      return;
    }
    multiplexer_opened_now = true;
    // StartDispatch();
  }

  ConnectionPtr connection(std::make_shared<Connection>(shared_from_this(),
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

void Transport::InsertConnection(ConnectionPtr connection) {
  strand_.dispatch(std::bind(&Transport::DoInsertConnection,
                             shared_from_this(), connection));
}

void Transport::DoInsertConnection(ConnectionPtr connection) {
  connections_.insert(connection);
}

void Transport::RemoveConnection(ConnectionPtr connection) {
  strand_.dispatch(std::bind(&Transport::DoRemoveConnection,
                             shared_from_this(), connection));
}

void Transport::DoRemoveConnection(ConnectionPtr connection) {
  connections_.erase(connection);
}

}  // namespace rudp

}  // namespace maidsafe
