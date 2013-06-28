/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

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
      : handler_(handler),
        socket_(socket),
        tick_timer_(tick_timer) {}

  TickOp(const TickOp& other)
      : handler_(other.handler_),
        socket_(other.socket_),
        tick_timer_(other.tick_timer_) {}

  void operator()(boost::system::error_code) {
    boost::system::error_code ec;
    if (socket_.IsOpen()) {
      if (tick_timer_.Expired()) {
        tick_timer_.Reset();
        DispatchTick(socket_);
      }
    } else {
      ec = boost::asio::error::operation_aborted;
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
  friend void asio_handler_invoke(const Function& f, TickOp* op) {
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
