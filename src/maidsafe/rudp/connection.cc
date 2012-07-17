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

#include <array>
#include <thread>
#include <algorithm>
#include <functional>

#include "boost/asio/read.hpp"
#include "boost/asio/write.hpp"

#include "maidsafe/common/log.h"

#include "maidsafe/rudp/transport.h"
#include "maidsafe/rudp/managed_connections.h"
#include "maidsafe/rudp/core/multiplexer.h"
#include "maidsafe/rudp/core/session.h"

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
      probe_interval_timer_(strand_.get_io_service()),
      lifespan_timer_(strand_.get_io_service()),
      remote_endpoint_(remote),
      send_buffer_(),
      receive_buffer_(),
      data_size_(0),
      data_received_(0),
      failed_probe_count_(0),
      timeout_state_(kConnecting),
      sending_(false) {
  static_assert((sizeof(detail::DataSize)) == 4, "DataSize must be 4 bytes.");
}

detail::Socket &Connection::Socket() {
  return socket_;
}

void Connection::Close() {
  strand_.dispatch(std::bind(&Connection::DoClose, shared_from_this()));
}

void Connection::DoClose() {
  probe_interval_timer_.cancel();
  lifespan_timer_.cancel();
  if (std::shared_ptr<Transport> transport = transport_.lock()) {
    // We're still connected to the transport. We need to detach and then start flushing the socket
    // to attempt a graceful closure.
    socket_.NotifyClose();
    socket_.AsyncFlush(strand_.wrap(std::bind(&Connection::DoClose, shared_from_this())));
    transport->RemoveConnection(shared_from_this());
    transport_.reset();
    sending_ = false;
    timer_.expires_from_now(Parameters::disconnection_timeout);
    timeout_state_ = kClosing;
  } else {
    // We've already had a go at graceful closure. Just tear down the socket.
    socket_.Close();
    timer_.cancel();
  }
}

void Connection::StartConnecting(std::shared_ptr<asymm::PublicKey> this_public_key,
                                 const std::string &validation_data,
                                 const boost::posix_time::time_duration &lifespan) {
  strand_.dispatch(std::bind(&Connection::DoStartConnecting, shared_from_this(),
                             this_public_key, validation_data, lifespan, PingFunctor()));
}

void Connection::Ping(std::shared_ptr<asymm::PublicKey> this_public_key,
                      const PingFunctor &ping_functor) {
  strand_.dispatch(std::bind(&Connection::DoStartConnecting, shared_from_this(),
                             this_public_key, "", bptime::time_duration(), ping_functor));
}

void Connection::DoStartConnecting(std::shared_ptr<asymm::PublicKey> this_public_key,
                                   const std::string &validation_data,
                                   const boost::posix_time::time_duration &lifespan,
                                   const PingFunctor &ping_functor) {
  StartTick();
  StartConnect(this_public_key, validation_data, lifespan, ping_functor);
  bs::error_code ignored_ec;
  CheckTimeout(ignored_ec);
}

bool Connection::IsTemporary() const {
  return lifespan_timer_.expires_from_now() < bptime::pos_infin;
}

void Connection::MakePermanent() {
  lifespan_timer_.expires_at(bptime::pos_infin);
  socket_.MakePermanent();
}

void Connection::StartSending(const std::string &data,
                              const MessageSentFunctor &message_sent_functor) {
  if (sending_) {
    strand_.post(std::bind(&Connection::StartSending, shared_from_this(), data,
                           message_sent_functor));
  } else {
    std::string encrypted_data;
    int result(asymm::Encrypt(data, *socket_.PeerPublicKey(), &encrypted_data));
    if (result != kSuccess) {
      LOG(kError) << "Failed to encrypt message.  Result: " << result;
      return InvokeSentFunctor(message_sent_functor, result);
    }
    strand_.dispatch(std::bind(&Connection::DoStartSending, shared_from_this(), encrypted_data,
                               message_sent_functor));
  }
}

void Connection::DoStartSending(const std::string &data,
                                const MessageSentFunctor &message_sent_functor) {
  sending_ = true;
  MessageSentFunctor wrapped_functor([&, message_sent_functor](int result) {
    InvokeSentFunctor(message_sent_functor, result);
//    MessageSentFunctor sent_functor(message_sent_functor);
//    if (sent_functor)
//      sent_functor(result);
    sending_ = false;
  });

  if (Stopped() || !EncodeData(data)) {
    InvokeSentFunctor(message_sent_functor, kSendFailure);
    sending_ = false;
    return;
  }

  strand_.dispatch(std::bind(&Connection::StartWrite, shared_from_this(), wrapped_functor));
}

void Connection::CheckTimeout(const bs::error_code &ec) {
  if (ec && ec != boost::asio::error::operation_aborted) {
    LOG(kError) << "Connection check timeout error: " << ec.message();
    socket_.Close();
    return;
  }

  // If the socket is closed, it means the connection has been shut down.
  if (!socket_.IsOpen())
    return DoClose();

  if (timer_.expires_from_now().is_negative()) {
    // Time has run out.
    LOG(kError) << "Closing connection to " << socket_.RemoteEndpoint() << " - timed out.";
    return DoClose();
  }

  // Keep processing timeouts until the socket is completely closed.
  timer_.async_wait(strand_.wrap(std::bind(&Connection::CheckTimeout,
                                           shared_from_this(), args::_1)));
}

bool Connection::Stopped() const {
  return (!transport_.lock() || !socket_.IsOpen());
}

void Connection::StartTick() {
  auto handler = strand_.wrap(std::bind(&Connection::HandleTick, shared_from_this()));
  socket_.AsyncTick(handler);
}

void Connection::HandleTick() {
  if (!socket_.IsOpen())
    return DoClose();
//  if (sending_) {
//    uint32_t sent_length = socket_.SentLength();
//    if (sent_length > 0)
//      timer_.expires_from_now(Parameters::speed_calculate_inverval);

    // If transmission speed is too slow, the socket shall be forced closed
//    if (socket_.IsSlowTransmission(sent_length)) {
//      LOG(kWarning) << "Connection to " << socket_.RemoteEndpoint()
//                    << " has slow transmission - closing now.";
//      return DoClose();
//    }
//  }

  // We need to keep ticking during a graceful shutdown.
  if (timeout_state_ == kClosing && timer_.expires_from_now().is_negative())
    return DoClose();

  StartTick();
}

void Connection::StartConnect(std::shared_ptr<asymm::PublicKey> this_public_key,
                              const std::string &validation_data,
                              const boost::posix_time::time_duration &lifespan,
                              const PingFunctor &ping_functor) {
  auto handler = strand_.wrap(std::bind(&Connection::HandleConnect, shared_from_this(),
                                        args::_1, validation_data, ping_functor));
  detail::Session::Mode open_mode(detail::Session::kNormal);
  lifespan_timer_.expires_from_now(lifespan);
  if (validation_data.empty()) {
    assert(lifespan != bptime::pos_infin);
    if (lifespan > bptime::time_duration()) {
      open_mode = detail::Session::kBootstrapAndKeep;
      lifespan_timer_.async_wait(strand_.wrap(std::bind(&Connection::CheckLifespanTimeout,
                                                        shared_from_this(), args::_1)));
    } else {
      open_mode = detail::Session::kBootstrapAndDrop;
    }
  }
  socket_.AsyncConnect(this_public_key, remote_endpoint_, handler, open_mode);
  timer_.expires_from_now(ping_functor ? Parameters::ping_timeout : Parameters::connect_timeout);
  timeout_state_ = kConnecting;
}

void Connection::CheckLifespanTimeout(const bs::error_code &ec) {
  if (ec && ec != boost::asio::error::operation_aborted) {
    LOG(kError) << "Connection lifespan check timeout error: " << ec.message();
    return DoClose();
  }
  if (!socket_.IsOpen())
    return DoClose();

  if (lifespan_timer_.expires_from_now() != bptime::pos_infin) {
    LOG(kInfo) << "Closing connection to " << socket_.RemoteEndpoint() << "  Lifespan remaining: "
               << lifespan_timer_.expires_from_now();
    return DoClose();
  }
}

void Connection::HandleConnect(const bs::error_code &ec,
                               const std::string &validation_data,
                               const PingFunctor &ping_functor) {
  if (ec) {
#ifndef NDEBUG
    if (!Stopped())
      LOG(kError) << "Failed to connect to " << socket_.RemoteEndpoint() << " - " << ec.message();
#endif
    if (ping_functor)
      ping_functor(kPingFailed);
    return DoClose();
  }

  if (Stopped()) {
    if (ping_functor)
      ping_functor(kSuccess);
    else
      LOG(kWarning) << "Connection to " << socket_.RemoteEndpoint() << " already stopped.";
    return DoClose();
  }

  if (std::shared_ptr<Transport> transport = transport_.lock()) {
    transport->InsertConnection(shared_from_this());
  } else {
    LOG(kError) << "Transport already destroyed.";
    return DoClose();
  }

  timer_.expires_at(boost::posix_time::pos_infin);
  timeout_state_ = kConnected;

  StartProbing();
  StartReadSize();
  if (!validation_data.empty())
    StartSending(validation_data, MessageSentFunctor());
}

void Connection::StartReadSize() {
  if (Stopped()) {
    LOG(kWarning) << "Connection to " << socket_.RemoteEndpoint() << " already stopped.";
    return DoClose();
  }
  receive_buffer_.clear();
  receive_buffer_.resize(sizeof(detail::DataSize));
  socket_.AsyncRead(asio::buffer(receive_buffer_), sizeof(detail::DataSize),
                    strand_.wrap(std::bind(&Connection::HandleReadSize,
                                           shared_from_this(), args::_1)));
}

void Connection::HandleReadSize(const bs::error_code &ec) {
  if (ec) {
#ifndef NDEBUG
    if (!Stopped()) {
      LOG(kWarning) << "Failed to read size from " << socket_.RemoteEndpoint() << " - "
                    << ec.message();
    }
#endif
    return DoClose();
  }

  if (Stopped()) {
    LOG(kWarning) << "Failed to read size from " << socket_.RemoteEndpoint()
                  << " - connection stopped.";
    return DoClose();
  }

  detail::DataSize size = (((((receive_buffer_.at(0) << 8) | receive_buffer_.at(1)) << 8) |
                           receive_buffer_.at(2)) << 8) | receive_buffer_.at(3);

  data_size_ = size;
  data_received_ = 0;

  StartReadData();
}

void Connection::StartReadData() {
  if (Stopped()) {
    LOG(kWarning) << "Connection to " << socket_.RemoteEndpoint() << " already stopped.";
    return DoClose();
  }
  size_t buffer_size = data_received_;
  buffer_size += std::min(static_cast<size_t> (socket_.BestReadBufferSize()),
                          data_size_ - data_received_);
  receive_buffer_.resize(buffer_size);
  asio::mutable_buffer data_buffer = asio::buffer(receive_buffer_) + data_received_;
  socket_.AsyncRead(asio::buffer(data_buffer), 1,
                    strand_.wrap(std::bind(&Connection::HandleReadData, shared_from_this(),
                                           args::_1, args::_2)));
}

void Connection::HandleReadData(const bs::error_code &ec, size_t length) {
  if (ec) {
#ifndef NDEBUG
    if (!Stopped()) {
      LOG(kError) << "Failed to read data from " << socket_.RemoteEndpoint()
                  << " - " << ec.message();
    }
#endif
    return DoClose();
  }

  if (Stopped()) {
    LOG(kError) << "Failed to read data from " << socket_.RemoteEndpoint()
                << " - connection stopped.";
    return DoClose();
  }

  data_received_ += length;
  if (data_received_ == data_size_) {
    // Dispatch the message outside the strand.
    strand_.get_io_service().post(std::bind(&Connection::DispatchMessage, shared_from_this()));
  } else {
    // Need more data to complete the message.
//    if (length > 0)
//      timer_.expires_from_now(Parameters::speed_calculate_inverval);
//    // If transmission speed is too slow, the socket shall be forced closed
//    if (socket_.IsSlowTransmission(length)) {
//      LOG(kWarning) << "Connection to " << socket_.RemoteEndpoint()
//                    << " has slow transmission - closing now.";
//      return DoClose();
//    }
    StartReadData();
  }
}

void Connection::DispatchMessage() {
  if (std::shared_ptr<Transport> transport = transport_.lock()) {
    transport->SignalMessageReceived(std::string(receive_buffer_.begin(), receive_buffer_.end()));
    StartReadSize();
  }
}

bool Connection::EncodeData(const std::string &data) {
  // Serialize message to internal buffer
  detail::DataSize msg_size = static_cast<detail::DataSize>(data.size());
  if (static_cast<size_t>(msg_size) >
          static_cast<size_t>(ManagedConnections::kMaxMessageSize())) {
    LOG(kError) << "Data size " << msg_size << " bytes (exceeds limit of "
                << ManagedConnections::kMaxMessageSize() << ")";
    return false;
  }

  send_buffer_.clear();
  for (int i = 0; i != 4; ++i)
    send_buffer_.push_back(static_cast<char>(msg_size >> (8 * (3 - i))));
  send_buffer_.insert(send_buffer_.end(), data.begin(), data.end());
  return true;
}

void Connection::StartWrite(const MessageSentFunctor &message_sent_functor) {
  if (Stopped()) {
    LOG(kError) << "Failed to write to " << socket_.RemoteEndpoint() << " - connection stopped.";
    InvokeSentFunctor(message_sent_functor, kSendFailure);
    return DoClose();
  }

  socket_.AsyncWrite(asio::buffer(send_buffer_),
                     std::bind(&Connection::HandleWrite, shared_from_this(),
                               args::_1, message_sent_functor));
}

void Connection::HandleWrite(const bs::error_code &ec,
                             const MessageSentFunctor &message_sent_functor) {
  if (ec) {
#ifndef NDEBUG
    if (!Stopped()) {
      LOG(kError) << "Failed to write to " << socket_.RemoteEndpoint()
                  << " - " << ec.message();
    }
#endif
    InvokeSentFunctor(message_sent_functor, kSendFailure);
    return DoClose();
  }

  if (Stopped()) {
    LOG(kError) << "Failed to write to " << socket_.RemoteEndpoint()
                << " - connection stopped.";
    InvokeSentFunctor(message_sent_functor, kSendFailure);
    return DoClose();
  }

  InvokeSentFunctor(message_sent_functor, kSuccess);
}

void Connection::StartProbing() {
  probe_interval_timer_.expires_from_now(Parameters::keepalive_interval);
  probe_interval_timer_.async_wait(strand_.wrap(std::bind(&Connection::DoProbe,
                                                shared_from_this(), args::_1)));
}

void Connection::DoProbe(const bs::error_code &ec) {
  if ((asio::error::operation_aborted != ec) && !Stopped()) {
    socket_.AsyncProbe(strand_.wrap(std::bind(&Connection::HandleProbe,
                                              shared_from_this(), args::_1)));
  }
}

void Connection::HandleProbe(const bs::error_code &ec) {
  if (!ec) {
    failed_probe_count_ = 0;
    return StartProbing();
  }

  if (((asio::error::try_again == ec) || (asio::error::timed_out == ec) ||
       (asio::error::operation_aborted == ec)) &&
       (failed_probe_count_ < Parameters::maximum_keepalive_failures)) {
    ++failed_probe_count_;
    bs::error_code ignored_ec;
    DoProbe(ignored_ec);
  } else {
    LOG(kWarning) << "Failed to probe " << socket_.RemoteEndpoint() << " - " << ec.message();
    return DoClose();
  }
}

void Connection::InvokeSentFunctor(const MessageSentFunctor &message_sent_functor,
                                   int result) const {
  if (message_sent_functor) {
    if (std::shared_ptr<Transport> transport = transport_.lock())
      message_sent_functor(result);
  }
}

}  // namespace rudp

}  // namespace maidsafe
