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
