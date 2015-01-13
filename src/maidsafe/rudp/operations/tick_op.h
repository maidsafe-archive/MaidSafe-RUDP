/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

// Original author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#ifndef MAIDSAFE_RUDP_OPERATIONS_TICK_OP_H_
#define MAIDSAFE_RUDP_OPERATIONS_TICK_OP_H_

#include "boost/asio/error.hpp"
#include "boost/asio/handler_alloc_hook.hpp"
#include "boost/asio/handler_invoke_hook.hpp"
#include "boost/system/error_code.hpp"
#include "maidsafe/rudp/core/receiver.h"
#include "maidsafe/rudp/core/sender.h"
#include "maidsafe/rudp/core/session.h"
#include "maidsafe/rudp/core/tick_timer.h"

namespace maidsafe {

namespace rudp {

namespace detail {

// Helper class to perform an asynchronous tick operation.
template <typename TickHandler, typename Socket>
class TickOp {
 public:
  TickOp(TickHandler handler, Socket& socket, TickTimer& tick_timer)
      : handler_(std::move(handler)), socket_(socket), tick_timer_(tick_timer) {}

  TickOp(const TickOp& other)
      : handler_(other.handler_), socket_(other.socket_), tick_timer_(other.tick_timer_) {}

  void operator()(boost::system::error_code) {
    std::error_code ec;
    if (socket_.IsOpen()) {
      if (tick_timer_.Expired()) {
        tick_timer_.Reset();
        DispatchTick(socket_);
      }
    } else {
      ec = RudpErrors::operation_aborted;
    }
    handler_(ec);
  }

  friend void* asio_handler_allocate(size_t n, TickOp* op) {
    using boost::asio::asio_handler_allocate;
    return asio_handler_allocate(n, &op->handler_);
  }

  friend void asio_handler_deallocate(void* p, size_t n, TickOp* op) {
    using boost::asio::asio_handler_deallocate;
    asio_handler_deallocate(p, n, &op->handler_);
  }

  template <typename Function>
  friend void asio_handler_invoke(Function f, TickOp* op) {
    using boost::asio::asio_handler_invoke;
    asio_handler_invoke(f, &op->handler_);
  }

 private:
  // Disallow assignment.
  TickOp& operator=(const TickOp&);

  TickHandler handler_;
  Socket& socket_;
  TickTimer& tick_timer_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_OPERATIONS_TICK_OP_H_
