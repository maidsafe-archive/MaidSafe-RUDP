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

#ifndef MAIDSAFE_RUDP_CORE_MULTIPLEXER_H_
#define MAIDSAFE_RUDP_CORE_MULTIPLEXER_H_

#include <array>  // NOLINT
#include <vector>

#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/udp.hpp"

#include "maidsafe/common/log.h"

#include "maidsafe/rudp/operations/dispatch_op.h"
#include "maidsafe/rudp/core/dispatcher.h"
#include "maidsafe/rudp/packets/packet.h"
#include "maidsafe/rudp/parameters.h"
#include "maidsafe/rudp/return_codes.h"

namespace maidsafe {

namespace rudp {

namespace detail {

class ConnectionManager;
class Socket;

class Multiplexer {
 public:
  explicit Multiplexer(boost::asio::io_service& asio_service);  // NOLINT (Fraser)

  // Open the multiplexer.  If endpoint is valid, the new socket will be bound to it.
  ReturnCode Open(const boost::asio::ip::udp::endpoint& endpoint);

  // Whether the multiplexer is open.
  bool IsOpen() const;

  // Close the multiplexer.
  void Close();

  // Asynchronously receive a single packet and dispatch it.
  template <typename DispatchHandler>
  void AsyncDispatch(DispatchHandler handler) {
    DispatchOp<DispatchHandler> op(handler, &socket_,
                                   boost::asio::buffer(receive_buffer_),
                                   &sender_endpoint_, &dispatcher_);
    socket_.async_receive_from(boost::asio::buffer(receive_buffer_),
                               sender_endpoint_, 0, op);
  }

  // Called by the socket objects to send a packet. Returns kSuccess if the data was sent
  // successfully, kSendFailure otherwise.
  template <typename Packet>
  ReturnCode SendTo(const Packet& packet,
                    const boost::asio::ip::udp::endpoint& endpoint) {
    std::array<unsigned char, Parameters::kUDPPayload> data;
    auto buffer = boost::asio::buffer(&data[0], Parameters::max_size);
    if (size_t length = packet.Encode(buffer)) {
      boost::system::error_code ec;
      socket_.send_to(boost::asio::buffer(buffer, length), endpoint, 0, ec);
      if (ec) {
        LOG(kWarning) << "Error sending from " << external_endpoint_ << " to << " << endpoint
                      << " - " << ec.message();
        return kSendFailure;
      } else {
        return kSuccess;
      }
    }
    return kSendFailure;
  }

  boost::asio::ip::udp::endpoint local_endpoint() const;
  boost::asio::ip::udp::endpoint external_endpoint() const;

  friend class ConnectionManager;
  friend class Socket;

 private:
  // Disallow copying and assignment.
  Multiplexer(const Multiplexer&);
  Multiplexer& operator=(const Multiplexer&);

  // The UDP socket used for all RUDP protocol communication.
  boost::asio::ip::udp::socket socket_;

  // Data members used to receive information about incoming packets.
  std::vector<unsigned char> receive_buffer_;
  boost::asio::ip::udp::endpoint sender_endpoint_;

  // Dispatcher keeps track of the active sockets.
  Dispatcher dispatcher_;

  // This node's external endpoint - passed to session and set during handshaking.
  boost::asio::ip::udp::endpoint external_endpoint_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CORE_MULTIPLEXER_H_
