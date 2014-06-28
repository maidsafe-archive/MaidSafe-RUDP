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

#include "maidsafe/rudp/core/multiplexer.h"

#include <cassert>

#include "maidsafe/rudp/managed_connections.h"
#include "maidsafe/rudp/packets/packet.h"
#include "maidsafe/rudp/utils.h"

namespace asio = boost::asio;
namespace ip = boost::asio::ip;
namespace bs = boost::system;

namespace maidsafe {

namespace rudp {

namespace detail {

Multiplexer::Multiplexer(asio::io_service& asio_service)
    : socket_(asio_service),
      receive_buffer_(Parameters::max_size),
      sender_endpoint_(),
      dispatcher_(),
      external_endpoint_(),
      best_guess_external_endpoint_(),
      mutex_() {}

ReturnCode Multiplexer::Open(const ip::udp::endpoint& endpoint) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (socket_.is_open()) {
    LOG(kWarning) << "Multiplexer already open.";
    return kAlreadyStarted;
  }

  assert(!endpoint.address().is_unspecified());

  bs::error_code ec;
  socket_.open(endpoint.protocol(), ec);

  if (ec) {
    LOG(kError) << "Multiplexer socket opening error while attempting on " << endpoint
                << "  Error: " << ec.message();
    return kInvalidAddress;
  }

  ip::udp::socket::non_blocking_io nbio(true);
  socket_.io_control(nbio, ec);

  if (ec) {
    LOG(kError) << "Multiplexer setting option error while attempting on " << endpoint
                << "  Error: " << ec.message();
    return kSetOptionFailure;
  }

  if (endpoint.port() == 0U) {
    // Try to bind to Resilience port first. If this fails, just fall back to port 0 (i.e. any port)
    socket_.bind(ip::udp::endpoint(endpoint.address(), ManagedConnections::kResiliencePort()), ec);
    if (!ec)
      return kSuccess;
  }

  socket_.bind(endpoint, ec);
  if (ec) {
    LOG(kError) << "Multiplexer socket binding error while attempting on " << endpoint
                << "  Error: " << ec.value();
    return kBindError;
  }

  return kSuccess;
}

bool Multiplexer::IsOpen() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return socket_.is_open();
}

void Multiplexer::Close() {
  bs::error_code ec;
  std::lock_guard<std::mutex> lock(mutex_);
  socket_.close(ec);
  if (ec)
    LOG(kWarning) << "Multiplexer closing error: " << ec.message();
  assert(!socket_.is_open());
  external_endpoint_ = ip::udp::endpoint();
  best_guess_external_endpoint_ = ip::udp::endpoint();
}

ip::udp::endpoint Multiplexer::local_endpoint() const {
  boost::system::error_code ec;
  std::lock_guard<std::mutex> lock(mutex_);
  ip::udp::endpoint local_endpoint(socket_.local_endpoint(ec));
  if (ec) {
    if (socket_.is_open())
      LOG(kError) << ec.message();
    return ip::udp::endpoint();
  }
  return local_endpoint;
}

ip::udp::endpoint Multiplexer::external_endpoint() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return IsValid(external_endpoint_) ? external_endpoint_ : best_guess_external_endpoint_;
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
