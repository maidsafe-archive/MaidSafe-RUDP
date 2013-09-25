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

#ifndef MAIDSAFE_RUDP_OPERATIONS_DISPATCH_OP_H_
#define MAIDSAFE_RUDP_OPERATIONS_DISPATCH_OP_H_

#include <mutex>
#include "boost/asio/buffer.hpp"
#include "boost/asio/handler_alloc_hook.hpp"
#include "boost/asio/handler_invoke_hook.hpp"
#include "boost/system/error_code.hpp"
#include "maidsafe/rudp/core/dispatcher.h"

namespace maidsafe {

namespace rudp {

namespace detail {

// Helper class to perform an asynchronous dispatch operation.
template <typename DispatchHandler>
class DispatchOp {
 public:
  DispatchOp(DispatchHandler handler, boost::asio::ip::udp::socket& socket,
             boost::asio::mutable_buffer buffer, boost::asio::ip::udp::endpoint& sender_endpoint,
             Dispatcher& dispatcher)
      : handler_(std::move(handler)),
        socket_(socket),
        buffer_(std::move(buffer)),
        mutex_(std::make_shared<std::mutex>()),
        sender_endpoint_(sender_endpoint),
        dispatcher_(dispatcher) {}

  DispatchOp(const DispatchOp& other)
      : handler_(other.handler_),
        socket_(other.socket_),
        buffer_(other.buffer_),
        mutex_(other.mutex_),
        sender_endpoint_(other.sender_endpoint_),
        dispatcher_(other.dispatcher_) {}

  void operator()(const boost::system::error_code& ec, size_t bytes_transferred) {
    boost::system::error_code local_ec = ec;
    while (!local_ec) {
      std::lock_guard<std::mutex> lock(*mutex_);
      dispatcher_.HandleReceiveFrom(boost::asio::buffer(buffer_, bytes_transferred),
                                    sender_endpoint_);
      bytes_transferred =
          socket_.receive_from(boost::asio::buffer(buffer_), sender_endpoint_, 0, local_ec);
    }

    handler_(ec);
  }

  friend void* asio_handler_allocate(size_t n, DispatchOp* op) {
    using boost::asio::asio_handler_allocate;
    return asio_handler_allocate(n, &op->handler_);
  }

  friend void asio_handler_deallocate(void* p, size_t n, DispatchOp* op) {
    using boost::asio::asio_handler_deallocate;
    asio_handler_deallocate(p, n, &op->handler_);
  }

  template <typename Function>
  friend void asio_handler_invoke(const Function& f, DispatchOp* op) {
    using boost::asio::asio_handler_invoke;
    asio_handler_invoke(f, &op->handler_);
  }

 private:
  // Disallow assignment.
  DispatchOp& operator=(const DispatchOp&);

  DispatchHandler handler_;
  boost::asio::ip::udp::socket& socket_;
  boost::asio::mutable_buffer buffer_;
  std::shared_ptr<std::mutex> mutex_;
  boost::asio::ip::udp::endpoint& sender_endpoint_;
  Dispatcher& dispatcher_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_OPERATIONS_DISPATCH_OP_H_
