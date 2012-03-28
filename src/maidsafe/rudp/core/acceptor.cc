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

#include <cassert>

#include "maidsafe/transport/log.h"
#include "maidsafe/transport/rudp_acceptor.h"
#include "maidsafe/transport/rudp_socket.h"
#include "maidsafe/transport/rudp_handshake_packet.h"
#include "maidsafe/transport/rudp_multiplexer.h"

namespace asio = boost::asio;
namespace ip = boost::asio::ip;
namespace bs = boost::system;
namespace bptime = boost::posix_time;
namespace args = std::placeholders;

namespace maidsafe {

namespace transport {

RudpAcceptor::RudpAcceptor(RudpMultiplexer &multiplexer)  // NOLINT (Fraser)
  : multiplexer_(multiplexer),
    waiting_accept_(multiplexer.socket_.get_io_service()),
    waiting_accept_socket_(0),
    pending_requests_() {
  waiting_accept_.expires_at(boost::posix_time::pos_infin);
  multiplexer_.dispatcher_.SetAcceptor(this);
}

RudpAcceptor::~RudpAcceptor() {
  if (IsOpen())
    multiplexer_.dispatcher_.SetAcceptor(0);
}

bool RudpAcceptor::IsOpen() const {
  return multiplexer_.dispatcher_.GetAcceptor() == this;
}

void RudpAcceptor::Close() {
  pending_requests_.clear();
  waiting_accept_.cancel();
  if (IsOpen())
    multiplexer_.dispatcher_.SetAcceptor(0);
}

void RudpAcceptor::StartAccept(RudpSocket &socket) {  // NOLINT (Fraser)
  assert(waiting_accept_socket_ == 0);  // Only one accept operation at a time.

  if (!pending_requests_.empty()) {
    socket.peer_.SetEndpoint(pending_requests_.front().remote_endpoint);
    socket.peer_.SetId(pending_requests_.front().remote_id);
    pending_requests_.pop_front();
    waiting_accept_.cancel();
  } else {
    waiting_accept_socket_ = &socket;
  }
}

void RudpAcceptor::HandleReceiveFrom(const asio::const_buffer &data,
                                     const asio::ip::udp::endpoint &endpoint) {
  RudpHandshakePacket packet;
  if (packet.Decode(data)) {
    if (RudpSocket* socket = waiting_accept_socket_) {
      // A socket is ready and waiting to accept the new connection.
      socket->peer_.SetEndpoint(endpoint);
      socket->peer_.SetId(packet.SocketId());
      waiting_accept_socket_ = 0;
      waiting_accept_.cancel();
    } else {
      // There's no socket waiting, queue it for later.
      PendingRequest pending_request;
      pending_request.remote_id = packet.SocketId();
      pending_request.remote_endpoint = endpoint;
      pending_requests_.push_back(pending_request);
    }
  } else {
    DLOG(ERROR) << "Acceptor ignoring invalid packet from " << endpoint;
  }
}

}  // namespace transport

}  // namespace maidsafe

