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

#include "maidsafe/transport/rudp_multiplexer.h"
#include "maidsafe/transport/rudp_packet.h"
#include "maidsafe/transport/log.h"

namespace asio = boost::asio;
namespace ip = boost::asio::ip;
namespace bs = boost::system;

namespace maidsafe {

namespace transport {

RudpMultiplexer::RudpMultiplexer(asio::io_service &asio_service) //NOLINT
  : socket_(asio_service),
    receive_buffer_(RudpParameters::max_size),
    sender_endpoint_(),
    dispatcher_() {}

RudpMultiplexer::~RudpMultiplexer() {
}

TransportCondition RudpMultiplexer::Open(const ip::udp &protocol) {
  if (socket_.is_open())
    return kAlreadyStarted;

  bs::error_code ec;
  socket_.open(protocol, ec);

  if (ec)
    return kInvalidAddress;

  ip::udp::socket::non_blocking_io nbio(true);
  socket_.io_control(nbio, ec);

  if (ec)
    return kSetOptionFailure;

  return kSuccess;
}

TransportCondition RudpMultiplexer::Open(const ip::udp::endpoint &endpoint) {
  if (socket_.is_open())
    return kAlreadyStarted;

  if (endpoint.port() == 0)
    return kInvalidPort;

  bs::error_code ec;
  socket_.open(endpoint.protocol(), ec);

  if (ec)
    return kInvalidAddress;

  ip::udp::socket::non_blocking_io nbio(true);
  socket_.io_control(nbio, ec);

  if (ec)
    return kSetOptionFailure;

  socket_.bind(endpoint, ec);

  if (ec)
    return kBindError;

  return kSuccess;
}

bool RudpMultiplexer::IsOpen() const {
  return socket_.is_open();
}

void RudpMultiplexer::Close() {
  bs::error_code ec;
  socket_.close(ec);
}

}  // namespace transport

}  // namespace maidsafe

