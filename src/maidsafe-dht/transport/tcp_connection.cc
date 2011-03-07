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

#include "maidsafe-dht/transport/tcp_connection.h"

#include <algorithm>
#include <array>  // NOLINT
#include <functional>

#include "boost/asio/read.hpp"
#include "boost/asio/write.hpp"

#include "maidsafe-dht/transport/tcp_transport.h"
#include "maidsafe/common/log.h"

namespace asio = boost::asio;
namespace bs = boost::system;
namespace ip = asio::ip;
namespace bptime = boost::posix_time;
namespace arg = std::placeholders;

namespace maidsafe {

namespace transport {

TcpConnection::TcpConnection(TcpTransport *tcp_transport,
                             ip::tcp::endpoint const &remote)
  : transport_(tcp_transport),
    socket_(*transport_->asio_service_),
    timer_(*transport_->asio_service_),
    remote_endpoint_(remote),
    size_buffer_(sizeof(DataSize)),
    data_buffer_(),
    timeout_for_response_(kDefaultInitialTimeout) {
  static_assert((sizeof(DataSize)) == 4, "DataSize must be 4 bytes.");
}

TcpConnection::~TcpConnection() {}

void TcpConnection::Close() {
  socket_.close();
  timer_.cancel();
  transport_->RemoveConnection(shared_from_this());
}

ip::tcp::socket &TcpConnection::Socket() {
  return socket_;
}

void TcpConnection::StartTimeout(const Timeout &timeout) {
  timer_.expires_from_now(timeout);
  timer_.async_wait(std::bind(&TcpConnection::HandleTimeout,
                                shared_from_this(), arg::_1));
}

void TcpConnection::StartReceiving() {
  // Start by receiving the message size.
  // socket_.async_receive(...);
  asio::async_read(socket_, asio::buffer(size_buffer_, size_buffer_.size()),
                   std::bind(&TcpConnection::HandleSize, shared_from_this(),
                             arg::_1));
  StartTimeout(timeout_for_response_);
}

void TcpConnection::HandleTimeout(const bs::error_code &ec) {
  if (ec)
    return;
  socket_.close();
}

void TcpConnection::HandleSize(const bs::error_code &ec) {
  // If the socket is closed, it means the timeout has been triggered.
  if (!socket_.is_open()) {
    (*transport_->on_error_)(kReceiveTimeout);
    return Close();
  }

  if (ec) {
    (*transport_->on_error_)(kReceiveFailure);
    return Close();
  }

  DataSize size = (((((size_buffer_.at(0) << 8) | size_buffer_.at(1)) << 8) |
                    size_buffer_.at(2)) << 8) | size_buffer_.at(3);
  data_buffer_.resize(size);

  asio::async_read(socket_, asio::buffer(data_buffer_, size),
                   std::bind(&TcpConnection::HandleRead, shared_from_this(),
                             arg::_1));
}

void TcpConnection::HandleRead(const bs::error_code &ec) {
  // If the socket is closed, it means the timeout has been triggered.
  if (!socket_.is_open()) {
    (*transport_->on_error_)(kReceiveTimeout);
    return Close();
  }

  if (ec) {
    (*transport_->on_error_)(kReceiveFailure);
    return Close();
  }

  timer_.cancel();

  DispatchMessage();
}

void TcpConnection::DispatchMessage() {
  // Signal message received and send response if applicable
  std::string response;
  Timeout response_timeout(kImmediateTimeout);
  Info info;
  // TODO(Fraser#5#): 2011-01-18 - Add info details.
  (*transport_->on_message_received_)(
      std::string(data_buffer_.begin(), data_buffer_.end()), info, &response,
      &response_timeout);
  if (response.empty())
    return;

  Send(response, response_timeout, true);
}

void TcpConnection::Send(const std::string &data,
                         const Timeout &timeout,
                         bool is_response) {
  // Serialize message to internal buffer
  DataSize msg_size = data.size();
  if (static_cast<size_t>(msg_size) >
          static_cast<size_t>(kMaxTransportMessageSize)) {
    DLOG(ERROR) << "Data size " << msg_size << " bytes (exceeds limit of "
                << kMaxTransportMessageSize << ")" << std::endl;
    (*transport_->on_error_)(kMessageSizeTooLarge);
    return;
  }

  for (int i = 0; i != 4; ++i)
    size_buffer_.at(i) = static_cast<char>(msg_size >> (8 * (3 - i)));
  data_buffer_.assign(data.begin(), data.end());

  // TODO(Fraser#5#): 2011-01-18 - Check timeout logic
  timeout_for_response_ = timeout;
  if (is_response) {
    assert(socket_.is_open());
//    timeout_for_response_ = kImmediateTimeout;
    Timeout tm_out(bptime::milliseconds(std::max(
        static_cast<boost::int64_t>(msg_size * kTimeoutFactor),
        kMinTimeout.total_milliseconds())));
    StartTimeout(tm_out);
    std::array<boost::asio::const_buffer, 2> asio_buffer;
    asio_buffer[0] = boost::asio::buffer(size_buffer_);
    asio_buffer[1] = boost::asio::buffer(data_buffer_);
    asio::async_write(socket_, asio_buffer,
                      std::bind(&TcpConnection::HandleWrite, shared_from_this(),
                                arg::_1));
  } else {
    assert(!socket_.is_open());
    StartTimeout(kDefaultInitialTimeout);
    socket_.async_connect(remote_endpoint_,
                          std::bind(&TcpConnection::HandleConnect,
                                    shared_from_this(), arg::_1));
  }
}

void TcpConnection::HandleConnect(const bs::error_code &ec) {
  // If the socket is closed, it means the timeout has been triggered.
  if (!socket_.is_open()) {
    (*transport_->on_error_)(kSendTimeout);
    return Close();
  }

  if (ec) {
    (*transport_->on_error_)(kSendFailure);
    return Close();
  }

  Timeout tm_out(bptime::milliseconds(std::max(
      static_cast<boost::int64_t>(data_buffer_.size() * kTimeoutFactor),
      kMinTimeout.total_milliseconds())));
  StartTimeout(tm_out);

  std::array<boost::asio::const_buffer, 2> asio_buffer;
  asio_buffer[0] = boost::asio::buffer(size_buffer_);
  asio_buffer[1] = boost::asio::buffer(data_buffer_);
  asio::async_write(socket_, asio_buffer,
                    std::bind(&TcpConnection::HandleWrite, shared_from_this(),
                              arg::_1));
}

void TcpConnection::HandleWrite(const bs::error_code &ec) {
  // If the socket is closed, it means the timeout has been triggered.
  if (!socket_.is_open()) {
    (*transport_->on_error_)(kSendTimeout);
    return Close();
  }

  if (ec) {
    (*transport_->on_error_)(kSendFailure);
    return Close();
  }

  // Start receiving response
  if (timeout_for_response_ != kImmediateTimeout) {
    StartReceiving();
  } else {
    Close();
  }
}

}  // namespace transport

}  // namespace maidsafe

