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
      probe_retry_attempts_(0),
      timeout_for_response_(Parameters::default_receive_timeout),
      timeout_state_(kNoTimeout) {
  static_assert((sizeof(detail::DataSize)) == 4, "DataSize must be 4 bytes.");
                                                                            static std::atomic<int> count(0);
                                                                            conn_id_ = "Connection " + boost::lexical_cast<std::string>(count++);
                                                                            LOG(kVerbose) << conn_id_ << " constructor";
}

Connection::~Connection() {
                                                                      LOG(kVerbose) << conn_id_ << " destructor";
}

detail::Socket &Connection::Socket() {
  return socket_;
}

void Connection::Close() {
  strand_.dispatch(std::bind(&Connection::DoClose, shared_from_this()));
}

void Connection::DoClose() {
                                                                        LOG(kVerbose) << conn_id_ << " DoClose";
  probe_interval_timer_.cancel();
  lifespan_timer_.cancel();
  if (std::shared_ptr<Transport> transport = transport_.lock()) {
                                                                        LOG(kVerbose) << conn_id_ << " DoClose got transport lock";
    // We're still connected to the transport. We need to detach and then
    // start flushing the socket to attempt a graceful closure.
    socket_.NotifyClose();
    socket_.AsyncFlush(strand_.wrap(std::bind(&Connection::DoClose, shared_from_this())));
    timer_.expires_from_now(Parameters::speed_calculate_inverval);
    transport->RemoveConnection(shared_from_this());
    transport_.reset();
  } else {
                                                                        LOG(kVerbose) << conn_id_ << " DoClose didn't get transport lock";
    // We've already had a go at graceful closure. Just tear down the socket.
    socket_.Close();
    timer_.cancel();
  }
}

void Connection::StartConnecting(const std::string &validation_data,
                                 const boost::posix_time::time_duration &lifespan) {
  strand_.dispatch(std::bind(&Connection::DoStartConnecting, shared_from_this(),
                             validation_data, lifespan));
}

void Connection::DoStartConnecting(const std::string &validation_data,
                                   const boost::posix_time::time_duration &lifespan) {
  StartTick();
  StartConnect(validation_data, lifespan);
  bs::error_code ignored_ec;
  CheckTimeout(ignored_ec);
}

bool Connection::IsTemporary() const {
  return lifespan_timer_.expires_from_now() < bptime::pos_infin;
}

void Connection::MakePermanent() {
  lifespan_timer_.expires_at(bptime::pos_infin);
}

void Connection::StartSending(const std::string &data,
                              const MessageSentFunctor &message_sent_functor) {
  EncodeData(data);
  timeout_for_response_ = Parameters::default_send_timeout;
  strand_.dispatch(std::bind(&Connection::StartWrite, shared_from_this(), message_sent_functor));
}

void Connection::CheckTimeout(const bs::error_code &ec) {
  if (ec && ec != boost::asio::error::operation_aborted) {
    LOG(kError) << "Connection check timeout error: " << ec.message();
    socket_.Close();
    return;
  }

  // If the socket is closed, it means the connection has been shut down.
  if (!socket_.IsOpen()) {
    if (timeout_state_ == kSending) {
      LOG(kWarning) << "Connection to " << socket_.RemoteEndpoint() << " already closed.";
    }
    return DoClose();
  }

  if (timer_.expires_at() <= asio::deadline_timer::traits_type::now()) {
    // Time has run out.
    LOG(kError) << "Closing connection to " << socket_.RemoteEndpoint() << " - timed out "
                << (timeout_state_ == kSending ? "send" : "connect") << "ing.";
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
                                                                            LOG(kVerbose) << conn_id_ << " Ticking";
  auto handler = strand_.wrap(std::bind(&Connection::HandleTick, shared_from_this()));
  socket_.AsyncTick(handler);
}

void Connection::HandleTick() {
  if (!socket_.IsOpen())
    return DoClose();
  if (timeout_state_ == kSending) {
    uint32_t sent_length = socket_.SentLength();
    if (sent_length > 0)
      timer_.expires_from_now(Parameters::speed_calculate_inverval);

    // If transmission speed is too slow, the socket shall be forced closed
//                                                                                        if (socket_.IsSlowTransmission(sent_length)) {
//                                                                                          LOG(kWarning) << "Connection to " << socket_.RemoteEndpoint()
//                                                                                                        << " has slow transmission - closing now.";
//                                                                                          return DoClose();
//                                                                                        }
  }
  // We need to keep ticking during a graceful shutdown.
                                                            LOG(kInfo) << conn_id_ << " Timer expires at " << timer_.expires_at();
  if (socket_.IsOpen()) {
    StartTick();
  }
}

void Connection::StartConnect(const std::string &validation_data,
                              const boost::posix_time::time_duration &lifespan) {
  auto handler = strand_.wrap(std::bind(&Connection::HandleConnect, shared_from_this(),
                                        args::_1, validation_data));
  if (std::shared_ptr<Transport> transport = transport_.lock()) LOG(kVerbose) << conn_id_ << " StartConnect connecting "
                                                          << transport->local_endpoint() << " to " << remote_endpoint_ << "   " << validation_data;
  detail::Session::Mode open_mode(detail::Session::kNormal);
  lifespan_timer_.expires_from_now(lifespan);
  if (validation_data.empty()) {
    assert(lifespan != bptime::pos_infin);
    open_mode = ((lifespan > bptime::time_duration()) ? detail::Session::kBootstrapAndKeep :
                                                        detail::Session::kBootstrapAndDrop);
    lifespan_timer_.async_wait(strand_.wrap(std::bind(&Connection::CheckLifespanTimeout,
                                             shared_from_this(), args::_1)));
  }
  socket_.AsyncConnect(remote_endpoint_, handler, open_mode);
  timer_.expires_from_now(Parameters::connect_timeout);
  timeout_state_ = kConnecting;
}

void Connection::CheckLifespanTimeout(const bs::error_code &ec) {
  if (ec && ec != boost::asio::error::operation_aborted) {
    LOG(kError) << "Connection lifespan check timeout error: " << ec.message();
    return DoClose();
  }
  if (!socket_.IsOpen())
    return DoClose();

  if (timer_.expires_at() <= asio::deadline_timer::traits_type::now()) {
    LOG(kError) << "Closing connection to " << socket_.RemoteEndpoint() << " - Lifespan expired.";
    return DoClose();
  }
}

void Connection::HandleConnect(const bs::error_code &ec, const std::string &validation_data) {
  if (ec) {
#ifndef NDEBUG
    if (!Stopped())
      LOG(kError) << "Failed to connect to " << socket_.RemoteEndpoint() << " - " << ec.message();
#endif
    return DoClose();
  }

  if (Stopped()) {
    LOG(kWarning) << "Connection to " << socket_.RemoteEndpoint() << " already stopped.";
    return DoClose();
  }

                           LOG(kVerbose) << conn_id_ << " HandleConnect connected to " << socket_.RemoteEndpoint();
  if (std::shared_ptr<Transport> transport = transport_.lock())
    transport->InsertConnection(shared_from_this());

//  StartProbing();
  if (!validation_data.empty()) {
    EncodeData(validation_data);
                              LOG(kVerbose) << conn_id_ << " Sending validation data now !!!!!!!!!!     " << validation_data << " to " << socket_.RemoteEndpoint();
    StartWrite(MessageSentFunctor());
  } else {
    StartReadSize();
  }
}

void Connection::StartReadSize() {
  assert(!Stopped());
  //if (Stopped()) {
  //  LOG(kError) << "Failed to start read size from " << socket_.RemoteEndpoint()
  //              << " - connection stopped.";
  //  return;
  //}

                                                                              //  receive_buffer_.clear();
  receive_buffer_.resize(sizeof(detail::DataSize));
  socket_.AsyncRead(asio::buffer(receive_buffer_), sizeof(detail::DataSize),
                    strand_.wrap(std::bind(&Connection::HandleReadSize,
                                           shared_from_this(), args::_1)));

  timer_.expires_at(boost::posix_time::pos_infin);
//  boost::posix_time::ptime now = asio::deadline_timer::traits_type::now();
//  response_deadline_ = now + Parameters::default_receive_timeout;
//  timer_.expires_at(std::max(response_deadline_,
//                             now + Parameters::speed_calculate_inverval));
  timeout_state_ = kNoTimeout;
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

  timer_.expires_from_now(Parameters::speed_calculate_inverval);
  StartReadData();
}

void Connection::StartReadData() {
  assert(!Stopped());
  //if (Stopped()) {
  //  LOG(kError) << "Failed to read data from " << socket_.RemoteEndpoint()
  //              << " - connection stopped.";
  //  return DoClose();
  //}

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
      LOG(kWarning) << "Connection to " << socket_.RemoteEndpoint()
                    << " has slow transmission - closing now.";
      return DoClose();
    }
    StartReadData();
  }
}

void Connection::DispatchMessage() {
  if (std::shared_ptr<Transport> transport = transport_.lock()) {
    transport->SignalMessageReceived(std::string(receive_buffer_.begin(),
                                                 receive_buffer_.end()));
    StartReadSize();
//    StartProbing();
  }
}

void Connection::EncodeData(const std::string &data) {
  // Serialize message to internal buffer
  detail::DataSize msg_size = static_cast<detail::DataSize>(data.size());
  if (static_cast<size_t>(msg_size) >
          static_cast<size_t>(ManagedConnections::kMaxMessageSize())) {
    LOG(kError) << "Data size " << msg_size << " bytes (exceeds limit of "
                << ManagedConnections::kMaxMessageSize() << ")";
    return DoClose();
  }

  send_buffer_.clear();
  for (int i = 0; i != 4; ++i)
    send_buffer_.push_back(static_cast<char>(msg_size >> (8 * (3 - i))));
  send_buffer_.insert(send_buffer_.end(), data.begin(), data.end());
}

void Connection::StartWrite(const MessageSentFunctor &message_sent_functor) {
  if (Stopped()) {
    LOG(kError) << "Failed to write to " << socket_.RemoteEndpoint()
                << " - connection stopped.";
    if (message_sent_functor)
      message_sent_functor(false);
    return DoClose();
  }

  socket_.AsyncWrite(asio::buffer(send_buffer_),
                     std::bind(&Connection::HandleWrite, shared_from_this(),
                               args::_1, message_sent_functor));
  timer_.expires_from_now(Parameters::speed_calculate_inverval);
  if (kConnecting != timeout_state_)
    timeout_state_ = kSending;
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
    if (message_sent_functor)
      message_sent_functor(false);
    return DoClose();
  }

  if (Stopped()) {
    LOG(kError) << "Failed to write to " << socket_.RemoteEndpoint()
                << " - connection stopped.";
    if (message_sent_functor)
      message_sent_functor(false);
    return DoClose();
  }

  // If this is completion of sending validation data, we need to start the read cycle.
  if (kConnecting == timeout_state_)
    StartReadSize();

  // Once data sent out, stop the timer for the sending procedure
  timer_.expires_at(boost::posix_time::pos_infin);
  timeout_state_ = kNoTimeout;

  if (message_sent_functor)
    message_sent_functor(true);
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
    probe_retry_attempts_ = 0;
//    StartProbing();
    return;
  }

  if (((asio::error::try_again == ec) || (asio::error::timed_out == ec) ||
       (asio::error::operation_aborted == ec)) && (probe_retry_attempts_< 3)) {
    ++probe_retry_attempts_;
    bs::error_code ignored_ec;
    DoProbe(ignored_ec);
  } else {
    LOG(kError) << "Failed to probe " << socket_.RemoteEndpoint()
                << " - " << ec.message();
    return DoClose();
  }
}

}  // namespace rudp

}  // namespace maidsafe
