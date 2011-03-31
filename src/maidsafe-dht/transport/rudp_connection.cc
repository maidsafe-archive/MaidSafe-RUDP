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

#include "maidsafe-dht/transport/rudp_connection.h"

#include <algorithm>
#include <array>  // NOLINT
#include <functional>

#include "boost/asio/read.hpp"
#include "boost/asio/write.hpp"

#include "maidsafe-dht/transport/rudp_multiplexer.h"
#include "maidsafe-dht/transport/rudp_transport.h"
#include "maidsafe/common/log.h"

namespace asio = boost::asio;
namespace bs = boost::system;
namespace ip = asio::ip;
namespace bptime = boost::posix_time;
namespace arg = std::placeholders;

namespace maidsafe {

namespace transport {

RudpConnection::RudpConnection(const std::shared_ptr<RudpTransport> &transport,
                               const asio::io_service::strand &strand,
                               const std::shared_ptr<RudpMultiplexer> &multiplexer,
                               const ip::udp::endpoint &remote)
  : transport_(transport),
    strand_(strand),
    multiplexer_(multiplexer),
    socket_(*multiplexer_),
    timer_(strand_.get_io_service()),
    response_deadline_(),
    remote_endpoint_(remote),
    buffer_(),
    data_size_(0),
    data_received_(0),
    timeout_for_response_(kDefaultInitialTimeout) {
  static_assert((sizeof(DataSize)) == 4, "DataSize must be 4 bytes.");
}

RudpConnection::~RudpConnection() {}

RudpSocket &RudpConnection::Socket() {
  return socket_;
}

void RudpConnection::Close() {
  strand_.dispatch(std::bind(&RudpConnection::DoClose, shared_from_this()));
}

void RudpConnection::DoClose() {
  socket_.Close();
  timer_.cancel();
  if (std::shared_ptr<RudpTransport> transport = transport_.lock())
    transport->RemoveConnection(shared_from_this());
}

void RudpConnection::StartReceiving() {
  strand_.dispatch(std::bind(&RudpConnection::DoStartReceiving,
                             shared_from_this()));
}

void RudpConnection::DoStartReceiving() {
  StartTick();
  StartServerConnect();
  CheckTimeout();
}

void RudpConnection::StartSending(const std::string &data,
                                  const Timeout &timeout) {
  EncodeData(data);
  timeout_for_response_ = timeout;
  strand_.dispatch(std::bind(&RudpConnection::DoStartSending,
                             shared_from_this()));
}

void RudpConnection::DoStartSending() {
  StartTick();
  StartClientConnect();
  CheckTimeout();
}

void RudpConnection::CheckTimeout() {
  // If the socket is closed, it means the connection has been shut down.
  if (!socket_.IsOpen())
    return;

  if (timer_.expires_at() <= asio::deadline_timer::traits_type::now()) {
    // Time has run out. Close the socket to cancel outstanding operations.
    socket_.Close();
  } else {
    // Timeout not yet reached. Go back to sleep.
    timer_.async_wait(strand_.wrap(std::bind(&RudpConnection::CheckTimeout,
                                             shared_from_this())));
  }
}

void RudpConnection::StartTick() {
  auto handler = strand_.wrap(std::bind(&RudpConnection::HandleTick,
                                        shared_from_this()));
  socket_.AsyncTick(handler);
}

void RudpConnection::HandleTick() {
  // If the socket is closed, it means the timeout has been triggered.
  if (socket_.IsOpen()) {
    StartTick();
  }
}

void RudpConnection::StartServerConnect() {
  auto handler = strand_.wrap(std::bind(&RudpConnection::HandleServerConnect,
                                        shared_from_this(), arg::_1));
  socket_.AsyncConnect(handler);

  timer_.expires_from_now(kDefaultInitialTimeout);
}

void RudpConnection::HandleServerConnect(const bs::error_code &ec) {
  // If the socket is closed, it means the timeout has been triggered.
  if (!socket_.IsOpen()) {
    return CloseOnError(kReceiveTimeout);
  }

  if (ec) {
    return CloseOnError(kReceiveFailure);
  }

  StartReadSize();
}

void RudpConnection::StartClientConnect() {
  auto handler = strand_.wrap(std::bind(&RudpConnection::HandleClientConnect,
                                        shared_from_this(), arg::_1));
  socket_.AsyncConnect(remote_endpoint_, handler);

  timer_.expires_from_now(kDefaultInitialTimeout);
}

void RudpConnection::HandleClientConnect(const bs::error_code &ec) {
  // If the socket is closed, it means the timeout has been triggered.
  if (!socket_.IsOpen()) {
    return CloseOnError(kSendTimeout);
  }

  if (ec) {
    return CloseOnError(kSendFailure);
  }

  StartWrite();
}

void RudpConnection::StartReadSize() {
  assert(socket_.IsOpen());

  buffer_.resize(sizeof(DataSize));
  socket_.AsyncRead(asio::buffer(buffer_), sizeof(DataSize),
                    strand_.wrap(std::bind(&RudpConnection::HandleReadSize,
                                           shared_from_this(), arg::_1)));

  boost::posix_time::ptime now = asio::deadline_timer::traits_type::now();
  response_deadline_ = now + timeout_for_response_;
  timer_.expires_at(std::min(response_deadline_, now + kStallTimeout));
}

void RudpConnection::HandleReadSize(const bs::error_code &ec) {
  // If the socket is closed, it means the timeout has been triggered.
  if (!socket_.IsOpen()) {
    return CloseOnError(kReceiveTimeout);
  }

  if (ec) {
    return CloseOnError(kReceiveFailure);
  }

  DataSize size = (((((buffer_.at(0) << 8) | buffer_.at(1)) << 8) |
                    buffer_.at(2)) << 8) | buffer_.at(3);

  data_size_ = size;
  data_received_ = 0;

  StartReadData();
}

void RudpConnection::StartReadData() {
  assert(socket_.IsOpen());

  size_t buffer_size = data_received_;
  buffer_size += std::min(static_cast<size_t>(kMaxTransportChunkSize),
                          data_size_ - data_received_);
  buffer_.resize(buffer_size);

  asio::mutable_buffer data_buffer = asio::buffer(buffer_) + data_received_;
  socket_.AsyncRead(asio::buffer(data_buffer), 1,
                    strand_.wrap(std::bind(&RudpConnection::HandleReadData,
                                           shared_from_this(),
                                           arg::_1, arg::_2)));

  boost::posix_time::ptime now = asio::deadline_timer::traits_type::now();
  timer_.expires_at(std::min(response_deadline_, now + kStallTimeout));
}

void RudpConnection::HandleReadData(const bs::error_code &ec, size_t length) {
  // If the socket is closed, it means the timeout has been triggered.
  if (!socket_.IsOpen()) {
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
    strand_.get_io_service().post(std::bind(&RudpConnection::DispatchMessage,
                                            shared_from_this()));
  } else {
    // Need more data to complete the message.
    StartReadData();
  }
}

void RudpConnection::DispatchMessage() {
  if (std::shared_ptr<RudpTransport> transport = transport_.lock()) {
    // Signal message received and send response if applicable
    std::string response;
    Timeout response_timeout(kImmediateTimeout);
    Info info;
    // TODO(Fraser#5#): 2011-01-18 - Add info details.
    (*transport->on_message_received_)(std::string(buffer_.begin(),
                                                   buffer_.end()),
                                       info, &response,
                                       &response_timeout);
    if (response.empty()) {
      strand_.dispatch(std::bind(&RudpConnection::StartFlush,
                                 shared_from_this()));
      return;
    }

    EncodeData(response);
    timeout_for_response_ = response_timeout;
    strand_.dispatch(std::bind(&RudpConnection::StartWrite,
                               shared_from_this()));
  }
}

void RudpConnection::EncodeData(const std::string &data) {
  // Serialize message to internal buffer
  DataSize msg_size = data.size();
  if (static_cast<size_t>(msg_size) >
          static_cast<size_t>(RudpTransport::kMaxTransportMessageSize())) {
    DLOG(ERROR) << "Data size " << msg_size << " bytes (exceeds limit of "
                << RudpTransport::kMaxTransportMessageSize() << ")" << std::endl;
    if (std::shared_ptr<RudpTransport> transport = transport_.lock()) {
      Endpoint ep(remote_endpoint_.address(), remote_endpoint_.port());
      (*transport->on_error_)(kMessageSizeTooLarge, ep);
    }
    return;
  }

  buffer_.clear();
  for (int i = 0; i != 4; ++i)
    buffer_.push_back(static_cast<char>(msg_size >> (8 * (3 - i))));
  buffer_.insert(buffer_.end(), data.begin(), data.end());
}

void RudpConnection::StartWrite() {
  assert(socket_.IsOpen());

//  timeout_for_response_ = kImmediateTimeout;
  Timeout tm_out(bptime::milliseconds(std::max(
      static_cast<boost::int64_t>(buffer_.size() * kTimeoutFactor),
      kMinTimeout.total_milliseconds())));

  socket_.AsyncWrite(asio::buffer(buffer_),
                     strand_.wrap(std::bind(&RudpConnection::HandleWrite,
                                            shared_from_this(), arg::_1)));

  timer_.expires_from_now(tm_out);
}

void RudpConnection::HandleWrite(const bs::error_code &ec) {
  // If the socket is closed, it means the timeout has been triggered.
  if (!socket_.IsOpen()) {
    return CloseOnError(kSendTimeout);
  }

  if (ec) {
    return CloseOnError(kSendFailure);
  }

  // Start receiving response
  if (timeout_for_response_ != kImmediateTimeout) {
    StartReadSize();
  } else {
    StartFlush();
  }
}

void RudpConnection::StartFlush() {
  assert(socket_.IsOpen());

  socket_.AsyncFlush(strand_.wrap(std::bind(&RudpConnection::HandleFlush,
                                            shared_from_this(), arg::_1)));

  timer_.expires_from_now(kStallTimeout); // TODO kDefaultFinalTimeout?
}

void RudpConnection::HandleFlush(const bs::error_code &ec) {
  // If the socket is closed, it means the timeout has been triggered.
  if (!socket_.IsOpen()) {
    return CloseOnError(kSendTimeout);
  }

  if (ec) {
    return CloseOnError(kSendFailure);
  }

  DoClose();
}

void RudpConnection::CloseOnError(const TransportCondition &error) {
  if (std::shared_ptr<RudpTransport> transport = transport_.lock()) {
    Endpoint ep(remote_endpoint_.address(), remote_endpoint_.port());
    (*transport->on_error_)(error, ep);
  }
  DoClose();
}

}  // namespace transport

}  // namespace maidsafe

