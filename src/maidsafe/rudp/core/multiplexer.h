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

#ifndef MAIDSAFE_TRANSPORT_RUDP_MULTIPLEXER_H_
#define MAIDSAFE_TRANSPORT_RUDP_MULTIPLEXER_H_

#include <array>  // NOLINT
#include <vector>

#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/udp.hpp"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/rudp_dispatch_op.h"
#include "maidsafe/transport/rudp_dispatcher.h"
#include "maidsafe/transport/rudp_packet.h"
#include "maidsafe/transport/rudp_parameters.h"

namespace maidsafe {

namespace transport {

class RudpMultiplexer {
 public:
  explicit RudpMultiplexer(boost::asio::io_service &asio_service);  // NOLINT (Fraser)
  ~RudpMultiplexer();

  // Open the multiplexer as a client for the specified protocol.
  TransportCondition Open(const boost::asio::ip::udp &protocol);

  // Open the multiplexer as a server on the specified endpoint.
  TransportCondition Open(const boost::asio::ip::udp::endpoint &endpoint);

  // Whether the multiplexer is open.
  bool IsOpen() const;

  // Close the multiplexer.
  void Close();

  // Asynchronously receive a single packet and dispatch it.
  template <typename DispatchHandler>
  void AsyncDispatch(DispatchHandler handler) {
    RudpDispatchOp<DispatchHandler> op(handler, &socket_,
                                       boost::asio::buffer(receive_buffer_),
                                       &sender_endpoint_, &dispatcher_);
    socket_.async_receive_from(boost::asio::buffer(receive_buffer_),
                               sender_endpoint_, 0, op);
  }

  // Called by the acceptor or socket objects to send a packet. Returns true if
  // the data was sent successfully, false otherwise.
  template <typename Packet>
  TransportCondition SendTo(const Packet &packet,
                            const boost::asio::ip::udp::endpoint &endpoint) {
    std::array<unsigned char, RudpParameters::kUDPPayload> data;
    auto buffer = boost::asio::buffer(&data[0], RudpParameters::max_size);
    if (size_t length = packet.Encode(buffer)) {
      boost::system::error_code ec;
      socket_.send_to(boost::asio::buffer(buffer, length), endpoint, 0, ec);
      return ec ? kSendFailure : kSuccess;
    }
    return kSendFailure;
  }

 private:
  friend class RudpAcceptor;
  friend class RudpSocket;

  // Disallow copying and assignment.
  RudpMultiplexer(const RudpMultiplexer&);
  RudpMultiplexer &operator=(const RudpMultiplexer&);

  // The UDP socket used for all RUDP protocol communication.
  boost::asio::ip::udp::socket socket_;

  // Data members used to receive information about incoming packets.
  std::vector<unsigned char> receive_buffer_;
  boost::asio::ip::udp::endpoint sender_endpoint_;

  // Dispatcher keeps track of the active sockets and the acceptor.
  RudpDispatcher dispatcher_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_MULTIPLEXER_H_
