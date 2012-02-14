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

#include "maidsafe/transport/tcp_connection.h"

#include <algorithm>
#include <array>  // NOLINT
#include <functional>

#include "boost/asio/read.hpp"
#include "boost/asio/write.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"

#include "maidsafe/transport/tcp_transport.h"
#include "maidsafe/transport/log.h"

namespace asio = boost::asio;
namespace bs = boost::system;
namespace ip = asio::ip;
namespace bptime = boost::posix_time;
namespace args = std::placeholders;

namespace maidsafe {

namespace transport {

TcpConnection::TcpConnection(const std::shared_ptr<TcpTransport> &tcp_transport,
                             ip::tcp::endpoint const &remote)
  : transport_(tcp_transport),
    strand_(tcp_transport->asio_service_),
    socket_(tcp_transport->asio_service_),
    timer_(tcp_transport->asio_service_),
    response_deadline_(),
    remote_endpoint_(remote),
    size_buffer_(sizeof(DataSize)),
    data_buffer_(),
    data_size_(0),
    data_received_(0),
    timeout_for_response_(kDefaultInitialTimeout) {
  static_assert((sizeof(DataSize)) == 4, "DataSize must be 4 bytes.");
}

TcpConnection::~TcpConnection() {}

ip::tcp::socket &TcpConnection::Socket() {
  return socket_;
}

void TcpConnection::Close() {
  strand_.dispatch(std::bind(&TcpConnection::DoClose, shared_from_this()));
}

void TcpConnection::DoClose() {
  bs::error_code ignored_ec;
  socket_.close(ignored_ec);
  timer_.cancel();
  if (std::shared_ptr<TcpTransport> transport = transport_.lock())
    transport->RemoveConnection(shared_from_this());
}

void TcpConnection::StartReceiving() {
  strand_.dispatch(std::bind(&TcpConnection::DoStartReceiving,
                             shared_from_this()));
}

void TcpConnection::DoStartReceiving() {
  StartReadSize();
  bs::error_code ignored_ec;
  CheckTimeout(ignored_ec);
}

void TcpConnection::StartSending(const std::string &data,
                                 const Timeout &timeout) {
  EncodeData(data);
  timeout_for_response_ = timeout;
  strand_.dispatch(std::bind(&TcpConnection::DoStartSending,
                             shared_from_this()));
}

void TcpConnection::DoStartSending() {
  StartConnect();
}

void TcpConnection::CheckTimeout(const bs::error_code &ec) {
  if (ec && ec != boost::asio::error::operation_aborted) {
    DLOG(ERROR) << "TcpConnection check timeout error: " << ec.message();
    bs::error_code ignored_ec;
    socket_.close(ignored_ec);
    return;
  }

  // If the socket is closed, it means the connection has been shut down.
  if (!socket_.is_open())
    return;

  if (timer_.expires_at() <= asio::deadline_timer::traits_type::now()) {
    // Time has run out. Close the socket to cancel outstanding operations.
    bs::error_code ignored_ec;
    socket_.close(ignored_ec);
  } else {
    // Timeout not yet reached. Go back to sleep.
    timer_.async_wait(strand_.wrap(std::bind(&TcpConnection::CheckTimeout,
                                             shared_from_this(), args::_1)));
  }
}

void TcpConnection::StartReadSize() {
  assert(socket_.is_open());

  asio::async_read(socket_, asio::buffer(size_buffer_),
                   strand_.wrap(std::bind(&TcpConnection::HandleReadSize,
                                          shared_from_this(), args::_1)));

  boost::posix_time::ptime now = asio::deadline_timer::traits_type::now();
  response_deadline_ = now + timeout_for_response_;
  timer_.expires_at(std::min(response_deadline_, now + kStallTimeout));
}

void TcpConnection::HandleReadSize(const bs::error_code &ec) {
  bs::error_code ignored_ec;
  CheckTimeout(ignored_ec);

  // If the socket is closed, it means the timeout has been triggered.
  if (!socket_.is_open()) {
    return CloseOnError(kReceiveTimeout);
  }

  if (ec) {
    return CloseOnError(kReceiveFailure);
  }

  DataSize size = (((((size_buffer_.at(0) << 8) | size_buffer_.at(1)) << 8) |
                    size_buffer_.at(2)) << 8) | size_buffer_.at(3);

  data_size_ = size;
  data_received_ = 0;

  StartReadData();
}

void TcpConnection::StartReadData() {
  assert(socket_.is_open());

  size_t buffer_size = data_received_;
  buffer_size += std::min(static_cast<size_t>(kMaxTransportChunkSize),
                          data_size_ - data_received_);
  data_buffer_.resize(buffer_size);

  asio::mutable_buffer data_buffer = asio::buffer(data_buffer_) +
                                     data_received_;
  asio::async_read(socket_, asio::buffer(data_buffer),
                   strand_.wrap(std::bind(&TcpConnection::HandleReadData,
                                          shared_from_this(),
                                          args::_1, args::_2)));

  boost::posix_time::ptime now = asio::deadline_timer::traits_type::now();
  timer_.expires_at(std::min(response_deadline_, now + kStallTimeout));
//  timer_.expires_from_now(kDefaultInitialTimeout);
}

void TcpConnection::HandleReadData(const bs::error_code &ec, size_t length) {
  bs::error_code ignored_ec;
  CheckTimeout(ignored_ec);

  // If the socket is closed, it means the timeout has been triggered.
  if (!socket_.is_open()) {
    return CloseOnError(kReceiveTimeout);
  }

  if (ec) {
    return CloseOnError(kReceiveFailure);
  }

  data_received_ += length;

  if (data_received_ == data_size_) {
    // No timeout applies while dispatching the message.
    timer_.expires_at(boost::posix_time::pos_infin);

    // Dispatch the message outside the strand.
    strand_.get_io_service().post(std::bind(&TcpConnection::DispatchMessage,
                                            shared_from_this()));
  } else {
    // Need more data to complete the message.
    StartReadData();
  }
}

void TcpConnection::DispatchMessage() {
  if (std::shared_ptr<TcpTransport> transport = transport_.lock()) {
    // Signal message received and send response if applicable
    std::string response;
    Timeout response_timeout(kImmediateTimeout);
    Info info;
    // TODO(Fraser#5#): 2011-01-18 - Add info details.
    (*transport->on_message_received_)(std::string(data_buffer_.begin(),
                                                   data_buffer_.end()),
                                       info,
                                       &response,
                                       &response_timeout);
    DataSize msg_size(static_cast<DataSize>(response.size()));
    if (response.empty() || msg_size > transport->kMaxTransportMessageSize()) {
      DLOG(INFO) << "Data size " << msg_size << " bytes ("
                 << transport->kMaxTransportMessageSize() << ")";
      Close();
      return;
    }

    EncodeData(response);
    timeout_for_response_ = response_timeout;
    strand_.dispatch(std::bind(&TcpConnection::StartWrite,
                               shared_from_this()));
  }
}

void TcpConnection::EncodeData(const std::string &data) {
  // Serialize message to internal buffer
  DataSize msg_size = static_cast<DataSize>(data.size());
  for (int i = 0; i != 4; ++i)
    size_buffer_.at(i) = static_cast<char>(msg_size >> (8 * (3 - i)));
  data_buffer_.assign(data.begin(), data.end());
}

void TcpConnection::StartConnect() {
  assert(!socket_.is_open());

  socket_.async_connect(remote_endpoint_,
                        strand_.wrap(std::bind(&TcpConnection::HandleConnect,
                                               shared_from_this(), args::_1)));

  timer_.expires_from_now(kDefaultInitialTimeout);
}

void TcpConnection::HandleConnect(const bs::error_code &ec) {
  // If the socket is closed, it means the timeout has been triggered.
  if (!socket_.is_open()) {
    return CloseOnError(kSendTimeout);
  }

  if (ec) {
    return CloseOnError(kSendFailure);
  }

  StartWrite();
}

void TcpConnection::StartWrite() {
  assert(socket_.is_open());

//  timeout_for_response_ = kImmediateTimeout;
  Timeout tm_out(bptime::milliseconds(std::max(
      static_cast<int64_t>(data_buffer_.size() * kTimeoutFactor),
      kMinTimeout.total_milliseconds())));

  std::array<boost::asio::const_buffer, 2> asio_buffer;
  asio_buffer[0] = boost::asio::buffer(size_buffer_);
  asio_buffer[1] = boost::asio::buffer(data_buffer_);
  asio::async_write(socket_, asio_buffer,
                    strand_.wrap(std::bind(&TcpConnection::HandleWrite,
                                           shared_from_this(), args::_1)));

  timer_.expires_from_now(tm_out);
  bs::error_code error_code;
  CheckTimeout(error_code);
}

void TcpConnection::HandleWrite(const bs::error_code &ec) {
  // If the socket is closed, it means the timeout has been triggered.
  if (!socket_.is_open()) {
    return CloseOnError(kSendTimeout);
  }

  if (ec) {
    return CloseOnError(kSendFailure);
  }

  // Start receiving response
  if (timeout_for_response_ != kImmediateTimeout) {
    StartReadSize();
  } else {
    DoClose();
  }
}

void TcpConnection::CloseOnError(const TransportCondition &error) {
  if (std::shared_ptr<TcpTransport> transport = transport_.lock()) {
    Endpoint ep;
    (*transport->on_error_)(error, ep);
  }
  DoClose();
}

}  // namespace transport

}  // namespace maidsafe

