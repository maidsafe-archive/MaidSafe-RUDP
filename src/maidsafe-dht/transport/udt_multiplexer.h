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

#ifndef MAIDSAFE_DHT_TRANSPORT_UDT_MULTIPLEXER_H_
#define MAIDSAFE_DHT_TRANSPORT_UDT_MULTIPLEXER_H_

#ifdef __MSVC__
#pragma warning(disable:4996)
#endif
#include <memory>
#ifdef __MSVC__
#pragma warning(default:4996)
#endif

#include <vector>
#include <queue>
#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/udp.hpp"
#include "maidsafe-dht/transport/transport.h"

namespace maidsafe {

namespace transport {

class UdtSocket;

class UdtMultiplexer : public std::enable_shared_from_this<UdtMultiplexer> {
 public:
  UdtMultiplexer(boost::asio::io_service &asio_service);
  ~UdtMultiplexer();

  // Open the multiplexer as a server on the specified endpoint.
  TransportCondition Open(const Endpoint &endpoint);

  // Stop listening for incoming connections and terminate all connections.
  void Close();

  // Create a new client-side connection.
  std::shared_ptr<UdtSocket> NewClient(const Endpoint &endpoint);

  // Initiate an asynchronous operation to accept a new server-side connection.
  template <typename AcceptHandler>
  void AsyncAccept(AcceptHandler handler) {
    waiting_op_.async_wait(AcceptOp<AcceptHandler>(handler, &accept_queue_));
    StartAccept();
  }

 private:
  typedef std::shared_ptr<UdtSocket> SocketPtr;
  typedef std::queue<SocketPtr> SocketQueue;

  // Disallow copying and assignment.
  UdtMultiplexer(const UdtMultiplexer&);
  UdtMultiplexer &operator=(const UdtMultiplexer&);

  void StartAccept();
  void StartReceive();
  void HandleReceive(const boost::system::error_code &ec,
                     size_t bytes_transferred);

  // The UDP socket used for all UDT protocol communication.
  boost::asio::ip::udp::socket socket_;

  // A timer is used to "store" the pending asynchronous accept operations.
  boost::asio::deadline_timer waiting_op_;

  // The queue of incoming connections waiting to be accepted.
  SocketQueue accept_queue_;

  // Data members used to receive information about incoming packets.
  static const size_t kMaxPacketSize = 1500;
  std::vector<unsigned char> receive_buffer_;
  boost::asio::ip::udp::endpoint sender_endpoint_;

  // Helper class to adapt an accept handler into a waiting operation.
  template <typename AcceptHandler>
  class AcceptOp {
   public:
    AcceptOp(AcceptHandler handler, SocketQueue *accept_queue)
      : handler_(handler),
        accept_queue_(accept_queue) {
    }

    void operator()(boost::system::error_code) {
      SocketPtr socket;
      if (!accept_queue_->empty()) {
        socket = accept_queue_->front();
        accept_queue_->pop();
      }
      boost::system::error_code ec;
      if (!socket)
        ec = boost::asio::error::operation_aborted;
      handler_(ec, socket);
    }

   private:
    AcceptHandler handler_;
    SocketQueue *accept_queue_;
  };
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_TRANSPORT_UDT_MULTIPLEXER_H_
