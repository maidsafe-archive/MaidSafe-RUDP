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

#ifndef MAIDSAFE_TRANSPORT_RUDP_TICK_OP_H_
#define MAIDSAFE_TRANSPORT_RUDP_TICK_OP_H_

#include "boost/asio/error.hpp"
#include "boost/asio/handler_alloc_hook.hpp"
#include "boost/asio/handler_invoke_hook.hpp"
#include "boost/system/error_code.hpp"
#include "maidsafe/transport/rudp_receiver.h"
#include "maidsafe/transport/rudp_sender.h"
#include "maidsafe/transport/rudp_session.h"
#include "maidsafe/transport/rudp_tick_timer.h"

namespace maidsafe {

namespace transport {

// Helper class to perform an asynchronous tick operation.
template <typename TickHandler, typename Socket>
class RudpTickOp {
 public:
  RudpTickOp(TickHandler handler, Socket *socket, RudpTickTimer *tick_timer)
    : handler_(handler),
      socket_(socket),
      tick_timer_(tick_timer) {
  }

  RudpTickOp(const RudpTickOp &L)
    : handler_(L.handler_),
      socket_(L.socket_),
      tick_timer_(L.tick_timer_) {
  }

  RudpTickOp & operator=(const RudpTickOp &L) {
    // check for "self assignment" and do nothing in that case
    if (this != &L) {
      delete socket_;
      handler_ = L.handler_;
      socket_ = L.socket_;
      tick_timer_ = L.tick_timer_;
    }
    return *this;
  }

  void operator()(boost::system::error_code) {
    boost::system::error_code ec;
    if (socket_->IsOpen()) {
      if (tick_timer_->Expired()) {
        tick_timer_->Reset();
        DispatchTick(socket_);
      }
    } else {
      ec = boost::asio::error::operation_aborted;
    }
    handler_(ec);
  }

  friend void *asio_handler_allocate(size_t n, RudpTickOp *op) {
    using boost::asio::asio_handler_allocate;
    return asio_handler_allocate(n, &op->handler_);
  }

  friend void asio_handler_deallocate(void *p, size_t n, RudpTickOp *op) {
    using boost::asio::asio_handler_deallocate;
    asio_handler_deallocate(p, n, &op->handler_);
  }

  template <typename Function>
  friend void asio_handler_invoke(const Function &f, RudpTickOp *op) {
    using boost::asio::asio_handler_invoke;
    asio_handler_invoke(f, &op->handler_);
  }

 private:
  TickHandler handler_;
  Socket *socket_;
  RudpTickTimer *tick_timer_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_TICK_OP_H_
