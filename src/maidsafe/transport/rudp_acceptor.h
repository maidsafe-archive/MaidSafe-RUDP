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

#ifndef MAIDSAFE_TRANSPORT_RUDP_ACCEPTOR_H_
#define MAIDSAFE_TRANSPORT_RUDP_ACCEPTOR_H_

#ifdef __MSVC__
#pragma warning(disable:4996)
#endif
#include <memory>
#ifdef __MSVC__
#pragma warning(default:4996)
#endif

#include <deque>
#include "boost/asio/buffer.hpp"
#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/udp.hpp"
#include "maidsafe/transport/transport.h"

#include "maidsafe/transport/rudp_accept_op.h"

namespace maidsafe {

namespace transport {

class RudpDispatcher;
class RudpMultiplexer;
class RudpSocket;

class RudpAcceptor {
 public:
  explicit RudpAcceptor(RudpMultiplexer &multiplexer);  // NOLINT (Fraser)
  ~RudpAcceptor();

  // Returns whether the acceptor is open.
  bool IsOpen() const;

  // Close the acceptor and cancel pending asynchronous operations.
  void Close();

  // Initiate an asynchronous operation to accept a new server-side connection.
  template <typename AcceptHandler>
  void AsyncAccept(RudpSocket &socket, AcceptHandler handler) {  // NOLINT (Fraser)
    RudpAcceptOp<AcceptHandler> op(handler, socket);
    waiting_accept_.async_wait(op);
    StartAccept(socket);
  }

 private:
  // Disallow copying and assignment.
  RudpAcceptor(const RudpAcceptor&);
  RudpAcceptor &operator=(const RudpAcceptor&);

  void StartAccept(RudpSocket &socket);  // NOLINT (Fraser)

  // Called by the RudpDispatcher when a new packet arrives for the acceptor.
  friend class RudpDispatcher;
  void HandleReceiveFrom(const boost::asio::const_buffer &data,
                         const boost::asio::ip::udp::endpoint &endpoint);

  // The multiplexer used to send and receive UDP packets.
  RudpMultiplexer &multiplexer_;

  // This class allows only one outstanding asynchronous accept operation at a
  // time. The following data members store the pending accept, and the socket
  // object that is waiting to be accepted.
  boost::asio::deadline_timer waiting_accept_;
  RudpSocket *waiting_accept_socket_;

  // A connection request that is yet to be processed by the acceptor.
  struct PendingRequest {
    PendingRequest()
        : remote_id(0),
          remote_endpoint() {}
    boost::uint32_t remote_id;
    boost::asio::ip::udp::endpoint remote_endpoint;
  };

  // A queue of the connections that are pending accept processing.
  typedef std::deque<PendingRequest> PendingRequestQueue;
  PendingRequestQueue pending_requests_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_ACCEPTOR_H_
