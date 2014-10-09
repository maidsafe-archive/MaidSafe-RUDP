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

#include "maidsafe/rudp/connection.h"

#include <array>
#include <algorithm>
#include <functional>
#include <queue>
#include <thread>

#include "boost/asio/read.hpp"
#include "boost/asio/write.hpp"

#include "maidsafe/common/log.h"

#include "maidsafe/rudp/managed_connections.h"
#include "maidsafe/rudp/transport.h"
#include "maidsafe/rudp/utils.h"
#include "maidsafe/rudp/core/multiplexer.h"
#include "maidsafe/rudp/core/session.h"
#include "maidsafe/rudp/core/socket.h"

namespace asio = boost::asio;
namespace bs = boost::system;
namespace ip = asio::ip;
namespace bptime = boost::posix_time;
namespace args = std::placeholders;

namespace maidsafe {

namespace rudp {

namespace detail {

namespace {

#if USE_LOGGING
std::ostream& operator<<(std::ostream& ostream, const Multiplexer& multiplexer) {
  ostream << multiplexer.external_endpoint() << " / " << multiplexer.local_endpoint();
  return ostream;
}
#endif

typedef std::function<void(int /*result*/)> PingFunctor;

}  // unnamed namespace

Connection::Connection(const std::shared_ptr<Transport>& transport,
                       const asio::io_service::strand& strand,
                       std::shared_ptr<Multiplexer> multiplexer)
    : transport_(transport),
      strand_(strand),
      multiplexer_(std::move(multiplexer)),
      socket_(*multiplexer_, transport->nat_type_),
      cookie_syn_(0),
      timer_(strand_.get_io_service()),
      probe_interval_timer_(strand_.get_io_service()),
      lifespan_timer_(strand_.get_io_service()),
      peer_node_id_(),
      peer_endpoint_(),
      send_buffer_(),
      receive_buffer_(),
      data_size_(0),
      data_received_(0),
      failed_probe_count_(0),
      state_(State::kPending),
      state_mutex_(),
      timeout_state_(TimeoutState::kConnecting),
      sending_(false),
      failure_functor_(),
      send_queue_(),
      handle_tick_lock_() {
  static_assert((sizeof(DataSize)) == 4, "DataSize must be 4 bytes.");
  timer_.expires_from_now(bptime::pos_infin);
}

Socket& Connection::Socket() { return socket_; }

void Connection::Close() {
  strand_.dispatch(std::bind(&Connection::DoClose, shared_from_this(), false));
}

void Connection::DoClose(bool timed_out) {
  LOG(kVerbose) << "RUDP Connection::DoClose";
  probe_interval_timer_.cancel();
  lifespan_timer_.cancel();
  if (std::shared_ptr<Transport> transport = transport_.lock()) {
    LOG(kVerbose) << "rudp connection disconnecting transport";
    // We're still connected to the transport. We need to detach and then start flushing the socket
    // to attempt a graceful closure.
    socket_.NotifyClose();
    socket_.AsyncFlush(strand_.wrap(std::bind(&Connection::DoClose, shared_from_this(), false)));
    transport->RemoveConnection(shared_from_this(), timed_out);
    // TODO(PeterJ): Better error codes if !timed_out.
    FireOnConnectFunctor(timed_out ? asio::error::timed_out : asio::error::not_connected);
    transport_.reset();
    sending_ = false;
    std::queue<SendRequest>().swap(send_queue_);
    timer_.expires_from_now(Parameters::disconnection_timeout);
    timeout_state_ = TimeoutState::kClosing;
  } else {
    // We've already had a go at graceful closure. Just tear down the socket.
    LOG(kVerbose) << "rudp connection cleanup resource";
    socket_.Close();
    timer_.cancel();
  }
  LOG(kInfo) << "RUDP Connection::DoClose connection closed";
}

void Connection::StartConnecting(const NodeId& peer_node_id, const ip::udp::endpoint& peer_endpoint,
                                 const std::string& validation_data,
                                 const boost::posix_time::time_duration& connect_attempt_timeout,
                                 const boost::posix_time::time_duration& lifespan,
                                 const OnConnect& on_connect,
                                 const std::function<void()>& failure_functor) {
  LOG(kVerbose) << "Scheduling Connection::DoStartConnecting from Connection::StartConnecting";
  strand_.dispatch(std::bind(&Connection::DoStartConnecting, shared_from_this(), peer_node_id,
                             peer_endpoint, validation_data, connect_attempt_timeout, lifespan,
                             PingFunctor(), on_connect, failure_functor));
}

void Connection::Ping(const NodeId& peer_node_id, const ip::udp::endpoint& peer_endpoint,
                      const PingFunctor& ping_functor) {
  LOG(kVerbose) << "Scheduling Connection::DoStartConnecting from Connection::Ping";
  strand_.dispatch(std::bind(&Connection::DoStartConnecting, shared_from_this(), peer_node_id,
                             peer_endpoint, "", Parameters::ping_timeout, bptime::time_duration(),
                             ping_functor, OnConnect(), std::function<void()>()));
}

void Connection::DoStartConnecting(const NodeId& peer_node_id,
                                   const ip::udp::endpoint& peer_endpoint,
                                   const std::string& validation_data,
                                   const boost::posix_time::time_duration& connect_attempt_timeout,
                                   const boost::posix_time::time_duration& lifespan,
                                   const PingFunctor& ping_functor,
                                   const OnConnect& on_connect,
                                   const std::function<void()>& failure_functor) {
  peer_node_id_    = peer_node_id;
  peer_endpoint_   = peer_endpoint;
  on_connect_      = on_connect;
  failure_functor_ = failure_functor;

  StartTick();
  LOG(kVerbose) << "Connection::DoStartConnecting";
  StartConnect(validation_data, connect_attempt_timeout, lifespan, ping_functor);
  bs::error_code ignored_ec;
  CheckTimeout(ignored_ec);
}

Connection::State Connection::state() const {
  std::lock_guard<std::mutex> lock(state_mutex_);
  return state_;
}

void Connection::MakePermanent(bool validated) {
  strand_.dispatch(std::bind(&Connection::DoMakePermanent, shared_from_this(), validated));
}

void Connection::DoMakePermanent(bool validated) {
  lifespan_timer_.expires_at(bptime::pos_infin);
  socket_.MakeNormal();
  std::lock_guard<std::mutex> lock(state_mutex_);
  state_ = (validated ? State::kPermanent : State::kUnvalidated);
}

void Connection::MarkAsDuplicateAndClose() {
  {
    std::lock_guard<std::mutex> lock(state_mutex_);
    state_ = State::kDuplicate;
  }
  strand_.dispatch(std::bind(&Connection::DoClose, shared_from_this(), false));
}

std::function<void()> Connection::GetAndClearFailureFunctor() {
  if (std::shared_ptr<Transport> transport = transport_.lock()) {
    std::function<void()> failure_functor;
    failure_functor.swap(failure_functor_);
    return failure_functor;
  } else {
    return std::function<void()>();
  }
}

ip::udp::endpoint Connection::RemoteNatDetectionEndpoint() const {
  return socket_.RemoteNatDetectionEndpoint();
}

void Connection::StartSending(const std::string& data,
                              const MessageSentFunctor& message_sent_functor) {
  if (data.size() > static_cast<size_t>(ManagedConnections::kMaxMessageSize())) {
    LOG(kError) << "Data size " << data.size() << " bytes (exceeds limit of "
                << ManagedConnections::kMaxMessageSize() << ")";
    InvokeSentFunctor(message_sent_functor, kMessageTooLarge);
  }
  try {
    // 2014-8-26 ned: TODO FIXME: This code is encrypting the message into
    // a string which enters a queue. Encode() later on COPIES that string
    // into send_buffer_ plus 3 bytes which it then hands off to be sent.
    // This needs to go away and save another memory copy.
    strand_.post(
        std::bind(&Connection::DoQueueSendRequest, shared_from_this(),
                  SendRequest(
#ifdef TESTING
                      !Parameters::rudp_encrypt ? data :
#endif
                          asymm::Encrypt(asymm::PlainText(data), *socket_.PeerPublicKey()).string(),
                      message_sent_functor)));
  }
  catch (const std::exception& e) {
    LOG(kError) << "Failed to encrypt message: " << e.what();
    return InvokeSentFunctor(message_sent_functor, kFailedToEncryptMessage);
  }
}

void Connection::DoQueueSendRequest(SendRequest const& request) {
  if (sending_) {
    send_queue_.push(request);
  } else {
    DoStartSending(request);
  }
}

void Connection::FinishSendAndQueueNext() {
  if (send_queue_.empty()) {
    sending_ = false;
  } else {
    strand_.post(std::bind(&Connection::DoStartSending, shared_from_this(), send_queue_.front()));
    send_queue_.pop();
  }
}

void Connection::DoStartSending(SendRequest const& request) {
  sending_ = true;
  const std::function<void(int)>& message_sent_functor = request.message_sent_functor_;  // NOLINT
  MessageSentFunctor wrapped_functor([this, message_sent_functor](int result) {
    InvokeSentFunctor(message_sent_functor, result);
  });

  if (Stopped()) {
    InvokeSentFunctor(message_sent_functor, kSendFailure);
    FinishSendAndQueueNext();
  } else {
    EncodeData(request.encrypted_data_);
    strand_.dispatch(std::bind(&Connection::StartWrite, shared_from_this(), wrapped_functor));
  }
}

void Connection::CheckTimeout(const bs::error_code& ec) {
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
    LOG(kWarning) << "Failed to " << (timeout_state_ == TimeoutState::kClosing ? "dis" : "")
                  << "connect from " << *multiplexer_ << " to " << socket_.PeerEndpoint()
                  << " - timed out.";
    return DoClose(true);
  }

  // Keep processing timeouts until the socket is completely closed.
  timer_.async_wait(
      strand_.wrap(std::bind(&Connection::CheckTimeout, shared_from_this(), args::_1)));
}

// May return true if connection still being gracefully closed down
bool Connection::Stopped() const { return (!transport_.lock() || !socket_.IsOpen()); }

// Only returns true if connection is completely closed down and ticks stopped
bool Connection::TicksStopped() const { return (!transport_.lock() && !socket_.IsOpen()); }

void Connection::StartTick() {
  auto handler = strand_.wrap(std::bind(&Connection::HandleTick, shared_from_this()));
  socket_.AsyncTick(handler);
}

void Connection::HandleTick() {
  // 2014-04-15 ned: We had a double free induced by two ticks calling
  //                 DoClose simultaneously which should never happen as
  //                 HandleTick is called by strand_, so we assert under
  //                 debug and let the mutex serialise in release.
  bool have_lock = handle_tick_lock_.try_lock();
  assert(have_lock);  // If this fails it's because another HandleTick is running (bad)
  if (!have_lock) handle_tick_lock_.lock();  // For release builds
  std::unique_lock<decltype(handle_tick_lock_)> lock(handle_tick_lock_, std::adopt_lock);

  if (!socket_.IsOpen())
    return DoClose();

  //  if (sending_) {
  //    uint32_t sent_length = socket_.SentLength();
  //    if (sent_length > 0)
  //      timer_.expires_from_now(Parameters::speed_calculate_interval);

  // If transmission speed is too slow, the socket shall be forced closed
  //    if (socket_.IsSlowTransmission(sent_length)) {
  //      LOG(kWarning) << "Connection to " << socket_.PeerEndpoint()
  //                    << " has slow transmission - closing now.";
  //      return DoClose();
  //    }
  //  }

  if (timeout_state_ == TimeoutState::kConnecting && !multiplexer_->IsOpen())
    return DoClose();

  // We need to keep ticking during a graceful shutdown.
  if (timeout_state_ == TimeoutState::kClosing && timer_.expires_from_now().is_negative())
    return DoClose();

  StartTick();
}

void Connection::StartConnect(const std::string& validation_data,
                              const boost::posix_time::time_duration& connect_attempt_timeout,
                              const boost::posix_time::time_duration& lifespan,
                              const PingFunctor& ping_functor) {
  auto handler = strand_.wrap(std::bind(&Connection::HandleConnect, shared_from_this(), args::_1,
                                        validation_data, ping_functor));
  Session::Mode open_mode(Session::kNormal);
  lifespan_timer_.expires_from_now(lifespan);
  if (validation_data.empty()) {
    assert(lifespan != bptime::pos_infin);
    if (lifespan > bptime::time_duration()) {
      open_mode = Session::kBootstrapAndKeep;
      state_ = State::kBootstrapping;
      lifespan_timer_.async_wait(
          strand_.wrap(std::bind(&Connection::CheckLifespanTimeout, shared_from_this(), args::_1)));
    } else {
      open_mode = Session::kBootstrapAndDrop;
      state_ = State::kTemporary;
    }
  } else {
    state_ = State::kUnvalidated;
  }
  if (std::shared_ptr<Transport> transport = transport_.lock()) {
    LOG(kVerbose) << "Connection::StartConnect";
    cookie_syn_ = socket_.AsyncConnect(transport->node_id(), transport->public_key(),
                         peer_endpoint_, peer_node_id_, handler, open_mode, cookie_syn_,
                         transport->on_nat_detection_requested_slot_);
    timer_.expires_from_now(connect_attempt_timeout);
    timeout_state_ = TimeoutState::kConnecting;
  }
}

void Connection::CheckLifespanTimeout(const bs::error_code& ec) {
  if (ec && ec != boost::asio::error::operation_aborted) {
    LOG(kError) << "Connection lifespan check timeout error: " << ec.message();
    return DoClose();
  }
  if (!socket_.IsOpen())
    return DoClose();

  if (lifespan_timer_.expires_from_now() != bptime::pos_infin) {
    if (lifespan_timer_.expires_at() <= boost::asio::deadline_timer::traits_type::now()) {
      LOG(kInfo) << "Closing connection from " << *multiplexer_ << " to " << socket_.PeerEndpoint()
                 << "  Lifespan remaining: " << lifespan_timer_.expires_from_now();
      return DoClose();
    } else {
      LOG(kInfo) << "Spuriously checking lifespan timeout of connection from " << *multiplexer_
                 << " to " << socket_.PeerEndpoint()
                 << "  Lifespan remaining: " << lifespan_timer_.expires_from_now();
      lifespan_timer_.async_wait(
          strand_.wrap(std::bind(&Connection::CheckLifespanTimeout, shared_from_this(), args::_1)));
    }
  }
}

void Connection::HandleConnect(const bs::error_code& ec, const std::string& validation_data,
                               PingFunctor ping_functor) {
  if (timeout_state_ == TimeoutState::kConnected) {
    LOG(kWarning) << "Duplicate Connect received, ignoring";
    return;
  }

  if (ec) {
#ifndef NDEBUG
    if (!Stopped())
      LOG(kError) << "Failed to connect from " << *multiplexer_ << " to " << socket_.PeerEndpoint()
                  << " - " << ec.message();
#endif
    if (ping_functor)
      ping_functor(kPingFailed);
    return DoClose();
  }

  if (Stopped()) {
    if (ping_functor) {
      ping_functor(kSuccess);
#ifndef NDEBUG
    } else if (state_ != State::kTemporary) {
      LOG(kWarning) << "Connection from " << *multiplexer_ << " to " << socket_.PeerEndpoint()
                    << " already stopped.";
#endif
    }
    return DoClose();
  }

  if (std::shared_ptr<Transport> transport = transport_.lock()) {
    peer_node_id_ = socket_.PeerNodeId();
    auto self = shared_from_this();

    transport->strand_.dispatch([transport, self]() {
        self->FireOnConnectFunctor(Error());
      });
  } else {
    LOG(kError) << "Pointer to Transport already destroyed.";
    return DoClose();
  }

  timer_.expires_at(boost::posix_time::pos_infin);
  timeout_state_ = TimeoutState::kConnected;

  StartProbing();
  StartReadSize();
  if (!validation_data.empty()) {
    StartSending(validation_data, [this](int result) {
      if (result != kSuccess) {
        LOG(kWarning) << "Failed to send validation data from " << *multiplexer_ << " to "
                      << socket_.PeerEndpoint() << "  Result: " << result;
      }
    });
  }
}

void Connection::StartReadSize() {
  if (Stopped()) {
    LOG(kWarning) << "Connection from " << *multiplexer_ << " to " << socket_.PeerEndpoint()
                  << " already stopped.";
    return DoClose();
  }
  receive_buffer_.clear();
  receive_buffer_.resize(sizeof(DataSize));
  socket_.AsyncRead(
      asio::buffer(receive_buffer_), sizeof(DataSize),
      strand_.wrap(std::bind(&Connection::HandleReadSize, shared_from_this(), args::_1)));
}

void Connection::HandleReadSize(const bs::error_code& ec) {
  if (ec) {
#ifndef NDEBUG
    if (!Stopped()) {
      LOG(kWarning) << "Failed to read size.  Connection from " << *multiplexer_ << " to "
                    << socket_.PeerEndpoint() << " error - " << ec.message();
    }
#endif
    return DoClose();
  }

  if (Stopped()) {
    LOG(kWarning) << "Failed to read size.  Connection from " << *multiplexer_ << " to "
                  << socket_.PeerEndpoint() << " already stopped.";
    return DoClose();
  }

  data_size_ =
      (((((receive_buffer_.at(0) << 8) | receive_buffer_.at(1)) << 8) | receive_buffer_.at(2))
       << 8) |
      receive_buffer_.at(3);
  // LOG(kInfo) << "Connection::HandleReadSize to " << *multiplexer_ << " sees "
  //            << data_size_ << " bytes.";
  // Allow some leeway for encryption overhead
  if (data_size_ > ManagedConnections::kMaxMessageSize() + 1024) {
    LOG(kError) << "Won't receive a message of size " << data_size_ << " which is > "
                << ManagedConnections::kMaxMessageSize() + 1024 << ", closing.";
    return DoClose();
  }

  data_received_ = 0;

  StartReadData();
}

void Connection::StartReadData() {
  if (Stopped()) {
    LOG(kWarning) << "Connection from " << *multiplexer_ << " to " << socket_.PeerEndpoint()
                  << " already stopped.";
    return DoClose();
  }
  DataSize buffer_size = data_received_;
  buffer_size += std::min(socket_.BestReadBufferSize(), data_size_ - data_received_);
  receive_buffer_.resize(buffer_size);
  asio::mutable_buffer data_buffer = asio::buffer(receive_buffer_) + data_received_;
  socket_.AsyncRead(
      asio::buffer(data_buffer), 1,
      strand_.wrap(std::bind(&Connection::HandleReadData, shared_from_this(), args::_1, args::_2)));
}

void Connection::HandleReadData(const bs::error_code& ec, size_t length) {
  if (ec) {
#ifndef NDEBUG
    if (!Stopped()) {
      LOG(kError) << "Failed to read data.  Connection from " << *multiplexer_ << " to "
                  << socket_.PeerEndpoint() << " error - " << ec.message();
    }
#endif
    return DoClose();
  }

  if (Stopped()) {
    LOG(kError) << "Failed to read data.  Connection from " << *multiplexer_ << " to "
                << socket_.PeerEndpoint() << " already stopped.";
    return DoClose();
  }

  assert(static_cast<DataSize>(length) >= 0);
  data_received_ += static_cast<DataSize>(length);
  if (data_received_ == data_size_) {
    if (std::shared_ptr<Transport> transport = transport_.lock()) {
      transport->SignalMessageReceived(std::string(receive_buffer_.begin(), receive_buffer_.end()));
      StartReadSize();
    }
  } else {
    // Need more data to complete the message.
    //    if (length > 0)
    //      timer_.expires_from_now(Parameters::speed_calculate_inverval);
    //    // If transmission speed is too slow, the socket shall be forced closed
    //    if (socket_.IsSlowTransmission(length)) {
    //      LOG(kWarning) << "Connection to " << socket_.PeerEndpoint()
    //                    << " has slow transmission - closing now.";
    //      return DoClose();
    //    }
    StartReadData();
  }
}

void Connection::EncodeData(const std::string& data) {
  // Serialize message to internal buffer
  DataSize msg_size = static_cast<DataSize>(data.size());
  send_buffer_.clear();
  for (int i = 0; i != 4; ++i)
    send_buffer_.push_back(static_cast<char>(msg_size >> (8 * (3 - i))));
  send_buffer_.insert(send_buffer_.end(), data.begin(), data.end());
}

void Connection::StartWrite(const MessageSentFunctor& message_sent_functor) {
  if (Stopped()) {
    LOG(kError) << "Failed to write from " << *multiplexer_ << " to " << socket_.PeerEndpoint()
                << " - connection stopped.";
    InvokeSentFunctor(message_sent_functor, kSendFailure);
    FinishSendAndQueueNext();
    return DoClose();
  }
  socket_.AsyncWrite(
      asio::buffer(send_buffer_), message_sent_functor,
      strand_.wrap(std::bind(&Connection::HandleWrite, shared_from_this(), message_sent_functor)));
}

void Connection::HandleWrite(MessageSentFunctor message_sent_functor) {
  // Message has now been fully sent, so safe to start sending next.  message_sent_functor will be
  // invoked by Socket::HandleAck once peer has acknowledged receipt.
  FinishSendAndQueueNext();
  if (Stopped()) {
    LOG(kError) << "Failed to write from " << *multiplexer_ << " to " << socket_.PeerEndpoint()
                << " - connection stopped.";
    InvokeSentFunctor(message_sent_functor, kSendFailure);
    return DoClose();
  }

  //  LOG(kInfo) << boost::posix_time::microsec_clock::universal_time()
  //             << "  Message sent functor would have been called with kSuccess here.";
  //  InvokeSentFunctor(message_sent_functor, kSuccess);
}

void Connection::StartProbing() {
  failed_probe_count_ = 0;
  probe_interval_timer_.expires_from_now(Parameters::keepalive_interval);
  probe_interval_timer_.async_wait(
      strand_.wrap(std::bind(&Connection::DoProbe, shared_from_this(), args::_1)));
}

void Connection::DoProbe(const bs::error_code& ec) {
  if ((asio::error::operation_aborted != ec) && !Stopped()) {
    socket_.AsyncProbe(
        strand_.wrap(std::bind(&Connection::HandleProbe, shared_from_this(), args::_1)));
  }
}

void Connection::HandleProbe(const bs::error_code& ec) {
  if (!ec)
    return StartProbing();

  if (((asio::error::try_again == ec) || (asio::error::timed_out == ec) ||
       (asio::error::operation_aborted == ec)) &&
      (failed_probe_count_ < Parameters::maximum_keepalive_failures)) {
    ++failed_probe_count_;
    LOG(kWarning) << "Probe error from " << *multiplexer_ << " to " << socket_.PeerEndpoint()
                  << "   error - " << ec.message()
                  << "   probe_count: " << int(failed_probe_count_);
    bs::error_code ignored_ec;
    DoProbe(ignored_ec);
  } else {
    LOG(kWarning) << "Failed to probe from " << *multiplexer_ << " to " << socket_.PeerEndpoint()
                  << "   error - " << ec.message();
    return DoClose();
  }
}

void Connection::InvokeSentFunctor(const MessageSentFunctor& message_sent_functor,
                                   int result) const {
  if (message_sent_functor) {
    if (std::shared_ptr<Transport> transport = transport_.lock())
      message_sent_functor(result);
  }
}

bptime::time_duration Connection::ExpiresFromNow() const {
  return lifespan_timer_.expires_from_now();
}

std::string Connection::PeerDebugId() const {
  return std::string("[") + DebugId(socket_.PeerNodeId()).substr(0, 7) + " - " +
         boost::lexical_cast<std::string>(socket_.PeerEndpoint()) + "]";
}

void Connection::FireOnConnectFunctor(const Error& error) {
  if (on_connect_) {
    auto h(std::move(on_connect_));
    on_connect_ = nullptr;
    h(error, shared_from_this());
  }
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
