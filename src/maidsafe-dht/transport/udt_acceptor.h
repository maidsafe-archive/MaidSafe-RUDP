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

#ifndef MAIDSAFE_DHT_TRANSPORT_UDT_ACCEPTOR_H_
#define MAIDSAFE_DHT_TRANSPORT_UDT_ACCEPTOR_H_

#ifdef __MSVC__
#pragma warning(disable:4996)
#endif
#include <memory>
#ifdef __MSVC__
#pragma warning(default:4996)
#endif

#include <queue>
#include "boost/asio/buffer.hpp"
#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/udp.hpp"
#include "maidsafe-dht/transport/transport.h"
#include "maidsafe-dht/transport/udt_accept_op.h"

namespace maidsafe {

namespace transport {

class UdtSocket;

class UdtAcceptor : public std::enable_shared_from_this<UdtAcceptor> {
 public:
  ~UdtAcceptor();

  // Initiate an asynchronous operation to accept a new server-side connection.
  template <typename AcceptHandler>
  void AsyncAccept(AcceptHandler handler) {
    UdtAcceptOp<AcceptHandler> op(handler, &accept_queue_);
    waiting_accept_.async_wait(op);
    StartAccept();
  }

 private:
  friend class UdtMultiplexer;

  typedef std::shared_ptr<UdtSocket> SocketPtr;
  typedef std::queue<SocketPtr> SocketQueue;

  // Only the multiplexer can create acceptor instances.
  UdtAcceptor(const std::shared_ptr<UdtMultiplexer> &udt_multiplexer,
              boost::asio::io_service &asio_service);

  // Disallow copying and assignment.
  UdtAcceptor(const UdtAcceptor&);
  UdtAcceptor &operator=(const UdtAcceptor&);

  void StartAccept();

  // Called by the UdtMultiplexer when a new packet arrives for the acceptor.
  void HandleReceiveFrom(const boost::asio::const_buffer &data,
                         const boost::asio::ip::udp::endpoint &endpoint);

  // The multiplexer used to send and receive UDP packets.
  std::shared_ptr<UdtMultiplexer> multiplexer_;

  // A timer is used to "store" the pending asynchronous accept operations.
  boost::asio::deadline_timer waiting_accept_;

  // The queue of incoming connections waiting to be accepted.
  SocketQueue accept_queue_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_TRANSPORT_UDT_ACCEPTOR_H_
