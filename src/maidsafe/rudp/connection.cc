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

#include "maidsafe/rudp/connection.h"

#include <algorithm>
#include <array>  // NOLINT
#include <functional>

#include "boost/asio/read.hpp"
#include "boost/asio/write.hpp"

#include "maidsafe/rudp/log.h"
#include "maidsafe/rudp/transport.h"
#include "maidsafe/rudp/managed_connections.h"
#include "maidsafe/rudp/core/multiplexer.h"

namespace asio = boost::asio;
namespace bs = boost::system;
namespace ip = asio::ip;
namespace bptime = boost::posix_time;
namespace args = std::placeholders;

namespace maidsafe {

namespace rudp {

Connection::Connection(const std::shared_ptr<Transport> &transport,
                       const asio::io_service::strand &strand,
                       const std::shared_ptr<detail::Multiplexer> &multiplexer,
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
      timeout_for_response_(Parameters::default_receive_timeout),
      timeout_state_(kNoTimeout) {
  static_assert((sizeof(DataSize)) == 4, "DataSize must be 4 bytes.");
}

Connection::~Connection() {}

detail::Socket &Connection::Socket() {
  return socket_;
}

void Connection::Close() {
  strand_.dispatch(std::bind(&Connection::DoClose, shared_from_this()));
}

void Connection::DoClose() {
  if (std::shared_ptr<Transport> transport = transport_.lock()) {
    // We're still connected to the transport. We need to detach and then
    // start flushing the socket to attempt a graceful closure.
    transport->RemoveConnection(shared_from_this());
    transport_.reset();
    socket_.AsyncFlush(strand_.wrap(std::bind(&Connection::DoClose,
                                              shared_from_this())));
    timer_.expires_from_now(Parameters::speed_calculate_inverval);
  } else {
    // We've already had a go at graceful closure. Just tear down the socket.
    socket_.Close();
    timer_.cancel();
  }
}

void Connection::StartReceiving() {
  strand_.dispatch(std::bind(&Connection::DoStartReceiving,
                             shared_from_this()));
}

void Connection::DoStartReceiving() {
  StartTick();
  StartServerConnect();
  bs::error_code ignored_ec;
  CheckTimeout(ignored_ec);
}

void Connection::StartSending(const std::string &data, const Timeout &timeout) {
  EncodeData(data);
  timeout_for_response_ = timeout;
  strand_.dispatch(std::bind(&Connection::DoStartSending, shared_from_this()));
}

void Connection::DoStartSending() {
  StartTick();
  StartClientConnect();
  bs::error_code ignored_ec;
  CheckTimeout(ignored_ec);
}

void Connection::CheckTimeout(const bs::error_code &ec) {
  if (ec && ec != boost::asio::error::operation_aborted) {
    DLOG(ERROR) << "Connection check timeout error: " << ec.message();
    socket_.Close();
    return;
  }

  // If the socket is closed, it means the connection has been shut down.
  if (!socket_.IsOpen()) {
    if (timeout_state_ == kSending)
      CloseOnError(kSendStalled);
    return;
  }

  if (timer_.expires_at() <= asio::deadline_timer::traits_type::now()) {
    // Time has run out.
    if (timeout_state_ == kSending)
      CloseOnError(kSendTimeout);
    else
      CloseOnError(kReceiveTimeout);
  }

  // Keep processing timeouts until the socket is completely closed.
  timer_.async_wait(strand_.wrap(std::bind(&Connection::CheckTimeout,
                                           shared_from_this(), args::_1)));
}

bool Connection::Stopped() const {
  return (!transport_.lock() || !socket_.IsOpen());
}

void Connection::StartTick() {
  auto handler = strand_.wrap(std::bind(&Connection::HandleTick,
                                        shared_from_this()));
  socket_.AsyncTick(handler);
}

// During sending : average one tick every 1.22ms (range from 1.1 to 1.4)
// 1.22ms = 1ms (congestion_control.SendDelay()) + system variant process time
// During receiving : averagle one tick every 140ms
// 140ms=100ms(congestion_control.ReceiveDelay()) + system variant process time
void Connection::HandleTick() {
  if (!socket_.IsOpen())
    return;
  if (timeout_state_ == kSending) {
    uint32_t sent_length = socket_.SentLength();
    if (sent_length > 0)
      timer_.expires_from_now(Parameters::speed_calculate_inverval);
    // If transmission speed is too slow, the socket shall be forced closed
    if (socket_.IsSlowTransmission(sent_length)) {
      CloseOnError(kSendTimeout);
    }
  }
  // We need to keep ticking during a graceful shutdown.
  if (socket_.IsOpen()) {
    StartTick();
  }
}

void Connection::StartServerConnect() {
  auto handler = strand_.wrap(std::bind(&Connection::HandleServerConnect,
                                        shared_from_this(), args::_1));
  socket_.AsyncConnect(handler);

  timer_.expires_from_now(Parameters::client_connect_timeout);
  timeout_state_ = kSending;
}

void Connection::HandleServerConnect(const bs::error_code &ec) {
  if (Stopped()) {
    return;
  }

  if (ec) {
    return CloseOnError(kReceiveFailure);
  }

  remote_endpoint_ = socket_.RemoteEndpoint();
  StartReadSize();
}

void Connection::StartClientConnect() {
  auto handler = strand_.wrap(std::bind(&Connection::HandleClientConnect,
                                        shared_from_this(), args::_1));
  socket_.AsyncConnect(remote_endpoint_, handler);

  timer_.expires_from_now(Parameters::client_connect_timeout);
  timeout_state_ = kSending;
}

void Connection::HandleClientConnect(const bs::error_code &ec) {
  if (Stopped()) {
    return;
  }

  if (ec) {
    return CloseOnError(kSendFailure);
  }

  StartWrite();
}

void Connection::StartReadSize() {
  assert(!Stopped());

  buffer_.resize(sizeof(DataSize));
  socket_.AsyncRead(asio::buffer(buffer_), sizeof(DataSize),
                    strand_.wrap(std::bind(&Connection::HandleReadSize,
                                           shared_from_this(), args::_1)));

  boost::posix_time::ptime now = asio::deadline_timer::traits_type::now();
  response_deadline_ = now + Parameters::default_receive_timeout;
  timer_.expires_at(std::max(response_deadline_,
                             now + Parameters::speed_calculate_inverval));
  timeout_state_ = kReceiving;
}

void Connection::HandleReadSize(const bs::error_code &ec) {
  if (ec)
    return CloseOnError(kReceiveFailure);

  if (Stopped())
    return CloseOnError(kReceiveTimeout);

  DataSize size = (((((buffer_.at(0) << 8) | buffer_.at(1)) << 8) |
                    buffer_.at(2)) << 8) | buffer_.at(3);

  data_size_ = size;
  data_received_ = 0;

  timer_.expires_from_now(Parameters::speed_calculate_inverval);
  StartReadData();
}

void Connection::StartReadData() {
  if (Stopped())
    return CloseOnError(kNoConnection);

  size_t buffer_size = data_received_;
  buffer_size += std::min(static_cast<size_t> (socket_.BestReadBufferSize()),
                          data_size_ - data_received_);
  buffer_.resize(buffer_size);
  asio::mutable_buffer data_buffer = asio::buffer(buffer_) + data_received_;
  socket_.AsyncRead(asio::buffer(data_buffer), 1,
                    strand_.wrap(std::bind(&Connection::HandleReadData,
                                           shared_from_this(),
                                           args::_1, args::_2)));
}

void Connection::HandleReadData(const bs::error_code &ec, size_t length) {
  if (Stopped())
    return CloseOnError(kReceiveTimeout);

  if (ec)
    return CloseOnError(kReceiveFailure);

  data_received_ += length;

  if (data_received_ == data_size_) {
    // No timeout applies while dispatching the message.
    timer_.expires_at(boost::posix_time::pos_infin);

    // Dispatch the message outside the strand.
    strand_.get_io_service().post(std::bind(&Connection::DispatchMessage,
                                            shared_from_this()));
  } else {
    // Need more data to complete the message.
    if (length > 0)
      timer_.expires_from_now(Parameters::speed_calculate_inverval);
    // If transmission speed is too slow, the socket shall be forced closed
    if (socket_.IsSlowTransmission(length)) {
      CloseOnError(kReceiveTimeout);
    }
    StartReadData();
  }
}

void Connection::DispatchMessage() {
  if (std::shared_ptr<Transport> transport = transport_.lock()) {
    // Signal message received and send response if applicable
    std::string response;
    Timeout response_timeout(bptime::seconds(0));

//    Info info;
//    info.endpoint.ip = socket_.RemoteEndpoint().address();
//    info.endpoint.port = socket_.RemoteEndpoint().port();

//    // Changes for managed connection
//    if (managed_) {
//      //  Keep Alive case
//       if (data_size_ == 9) {
//         std::string data(buffer_.begin(), buffer_.end());
//         if (data == "KeepAlive") {
//           DLOG(INFO) << "DispatchMessage -- received >>KeepAlive<<";
//           // if a keep alive message received, do nothing.
//           return;
//         }
//      }
//      // managed connection - need to keep connection alive.
//      timeout_for_response_ = bptime::seconds(bptime::pos_infin);
//      timeout_state_ = kNoTimeout;
//      if (response_functor_) {
//        response_functor_(kSuccess, std::string(buffer_.begin(),
//                                                buffer_.end()));
//        response_functor_ = ResponseFunctor();
//      }
//      return;
//    } else if (response_functor_) {
//      response_functor_(kSuccess, std::string(buffer_.begin(), buffer_.end()));
//      response_functor_ = ResponseFunctor();
//      Close();
//      return;
//    } else {


//      (*transport->on_message_received_)(std::string(buffer_.begin(),
//                                                     buffer_.end()),
//                                         info, &response,
//                                         &response_timeout);
      if (response.empty()) {
        Close();
        return;
      }
      EncodeData(response);
      timeout_for_response_ = response_timeout;
      strand_.dispatch(std::bind(&Connection::StartWrite, shared_from_this()));
//    }
  }
}

void Connection::EncodeData(const std::string &data) {
  // Serialize message to internal buffer
  DataSize msg_size = static_cast<DataSize>(data.size());
  if (static_cast<size_t>(msg_size) >
          static_cast<size_t>(ManagedConnections::kMaxMessageSize())) {
    DLOG(ERROR) << "Data size " << msg_size << " bytes (exceeds limit of "
                << ManagedConnections::kMaxMessageSize() << ")"
                << std::endl;
    CloseOnError(kMessageSizeTooLarge);
    return;
  }

  buffer_.clear();
  for (int i = 0; i != 4; ++i)
    buffer_.push_back(static_cast<char>(msg_size >> (8 * (3 - i))));
  buffer_.insert(buffer_.end(), data.begin(), data.end());
}

void Connection::StartWrite() {
  if (Stopped())
    return CloseOnError(kNoConnection);
  socket_.AsyncWrite(asio::buffer(buffer_),
                     strand_.wrap(std::bind(&Connection::HandleWrite,
                                            shared_from_this(), args::_1)));
  timer_.expires_from_now(Parameters::speed_calculate_inverval);
  timeout_state_ = kSending;
}

void Connection::HandleWrite(const bs::error_code &ec) {
  if (Stopped())
    return CloseOnError(kNoConnection);

  if (ec)
    return CloseOnError(kSendFailure);

  // Once data sent out, stop the timer for the sending procedure
  timer_.expires_at(boost::posix_time::pos_infin);
  timeout_state_ = kNoTimeout;
//  // For managed connection, write op doesn't continue to read response.
//  if (managed_ && write_complete_functor_) {
//    write_complete_functor_(kSuccess);
//    return;
//  }
  // Start receiving response
//  if (timeout_for_response_ != bptime::seconds(0)) {
    StartReadSize();
//  } else {
//    DoClose();
//  }
}

void Connection::CloseOnError(const ReturnCode &/*error*/) {
//  if (std::shared_ptr<Transport> transport = transport_.lock()) {
//    Endpoint ep(remote_endpoint_.address(), remote_endpoint_.port());
//    if (managed_) {
//      if (write_complete_functor_) {
//        write_complete_functor_(error);
//        write_complete_functor_ = WriteCompleteFunctor();
//      } else if (response_functor_) {
//        response_functor_(error, "");
//        response_functor_ = ResponseFunctor();
//      }
//      DoClose();  // Need not to call transport->on_error_ signal for mngd conn.
//    } else {
//      if (response_functor_) {
//        response_functor_(error, "");
//        response_functor_ = ResponseFunctor();
//      } else {

    
//        (*transport->on_error_)(error, ep);
//      }
      DoClose();
//    }
//  }
}

Endpoint Connection::StartRvConnecting() {
  EncodeData("RV");
                                      timeout_for_response_ = bptime::milliseconds(100000);
  StartTick();

  auto handler = strand_.wrap(std::bind(&Connection::HandleClientConnect,
                                        shared_from_this(), args::_1));
  socket_.AsyncConnect(remote_endpoint_, handler);

  timer_.expires_from_now(Parameters::client_connect_timeout);
  timeout_state_ = kSending;



  socket_.AsyncWrite(asio::buffer(buffer_),
                     strand_.wrap(std::bind(&Connection::HandleWrite,
                                            shared_from_this(), args::_1)));
  timer_.expires_from_now(Parameters::speed_calculate_inverval);
  timeout_state_ = kSending;


  bs::error_code ignored_ec;
  CheckTimeout(ignored_ec);


  return Endpoint();
}

}  // namespace rudp

}  // namespace maidsafe
