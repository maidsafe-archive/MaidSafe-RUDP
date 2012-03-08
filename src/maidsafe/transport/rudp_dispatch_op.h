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

#ifndef MAIDSAFE_TRANSPORT_RUDP_DISPATCH_OP_H_
#define MAIDSAFE_TRANSPORT_RUDP_DISPATCH_OP_H_

#include "boost/asio/buffer.hpp"
#include "boost/asio/handler_alloc_hook.hpp"
#include "boost/asio/handler_invoke_hook.hpp"
#include "boost/system/error_code.hpp"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/rudp_dispatcher.h"

namespace maidsafe {

namespace transport {

// Helper class to perform an asynchronous dispatch operation.
template <typename DispatchHandler>
class RudpDispatchOp {
 public:
  RudpDispatchOp(DispatchHandler handler,
                 boost::asio::ip::udp::socket *socket,
                 const boost::asio::mutable_buffer &buffer,
                 boost::asio::ip::udp::endpoint *sender_endpoint,
                 RudpDispatcher *dispatcher)
    : handler_(handler),
      socket_(socket),
      buffer_(buffer),
      sender_endpoint_(sender_endpoint),
      dispatcher_(dispatcher) {
  }

  RudpDispatchOp(const RudpDispatchOp &L)
    : handler_(L.handler_),
      socket_(L.socket_),
      buffer_(L.buffer_),
      sender_endpoint_(L.sender_endpoint_),
      dispatcher_(L.dispatcher_) {
  }

  RudpDispatchOp & operator=(const RudpDispatchOp &L) {
    // check for "self assignment" and do nothing in that case
    if (this != &L) {
      delete socket_;
      delete sender_endpoint_;
      delete dispatcher_;
      handler_ = L.handler_;
      socket_ = L.socket_;
      buffer_ = L.buffer_;
      sender_endpoint_ = L.sender_endpoint_;
      dispatcher_ = L.dispatcher_;
    }
    return *this;
  }

  void operator()(const boost::system::error_code &ec,
                  size_t bytes_transferred) {
    boost::system::error_code local_ec = ec;

    while (!local_ec) {
      dispatcher_->HandleReceiveFrom(boost::asio::buffer(buffer_,
                                                         bytes_transferred),
                                     *sender_endpoint_);

      bytes_transferred = socket_->receive_from(boost::asio::buffer(buffer_),
                                                *sender_endpoint_, 0, local_ec);
    }

    handler_(ec);
  }

  friend void *asio_handler_allocate(size_t n, RudpDispatchOp *op) {
    using boost::asio::asio_handler_allocate;
    return asio_handler_allocate(n, &op->handler_);
  }

  friend void asio_handler_deallocate(void *p, size_t n, RudpDispatchOp *op) {
    using boost::asio::asio_handler_deallocate;
    asio_handler_deallocate(p, n, &op->handler_);
  }

  template <typename Function>
  friend void asio_handler_invoke(const Function &f, RudpDispatchOp *op) {
    using boost::asio::asio_handler_invoke;
    asio_handler_invoke(f, &op->handler_);
  }

 private:
  // Disallow copying and assignment.
//  RudpDispatchOp(const RudpDispatchOp&);
//  RudpDispatchOp &operator=(const RudpDispatchOp&);

  DispatchHandler handler_;
  boost::asio::ip::udp::socket *socket_;
  boost::asio::mutable_buffer buffer_;
  boost::asio::ip::udp::endpoint *sender_endpoint_;
  RudpDispatcher *dispatcher_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_DISPATCH_OP_H_
