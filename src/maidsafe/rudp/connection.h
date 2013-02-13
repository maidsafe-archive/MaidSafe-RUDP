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

#ifndef MAIDSAFE_RUDP_CONNECTION_H_
#define MAIDSAFE_RUDP_CONNECTION_H_

#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <vector>

#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/asio/strand.hpp"

#include "maidsafe/rudp/core/socket.h"
#include "maidsafe/rudp/transport.h"

namespace maidsafe {

namespace rudp {

namespace detail {

typedef int32_t DataSize;

class Multiplexer;


#ifdef __GNUC__
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Weffc++"
#endif
class Connection : public std::enable_shared_from_this<Connection> {
#ifdef __GNUC__
#  pragma GCC diagnostic pop
#endif

 public:
  enum class State {
    // GetAvailableEndpoint has been called, but connection has not yet been made.
    kPending,
    // Not used for sending messages; ping, peer external IP or NAT detection, etc.
    kTemporary,
    // Incoming or outgoing short-lived (unvalidated) connection - classed as a "normal" connection.
    kBootstrapping,
    // Permanent connection which has not been validated - classed as a "normal" connection.
    kUnvalidated,
    // Validated permanent connection - classed as a "normal" connection.
    kPermanent,
    // A duplicate "normal" connection already exists on a different Transport.  Will be closed
    // without triggering callback as soon as state set to this.
    kDuplicate,
    // A duplicate "normal" connection already exists on the same Transport.  Will be closed without
    // triggering callback or removal from ConnectionManager as soon as state set to this.
    kExactDuplicate
  };

  Connection(const std::shared_ptr<Transport> &transport,
             const boost::asio::io_service::strand& strand,
             const std::shared_ptr<Multiplexer> &multiplexer);

  detail::Socket& Socket();

  void Close();
  // If lifespan is 0, only handshaking will be done.  Otherwise, the connection will be closed
  // after lifespan has passed.
  void StartConnecting(const NodeId& peer_node_id,
                       const boost::asio::ip::udp::endpoint& peer_endpoint,
                       const std::string& validation_data,
                       const boost::posix_time::time_duration& connect_attempt_timeout,
                       const boost::posix_time::time_duration& lifespan,
                       const std::function<void()>& failure_functor);
  void Ping(const NodeId& peer_node_id,
            const boost::asio::ip::udp::endpoint& peer_endpoint,
            const std::function<void(int)> &ping_functor);  // NOLINT (Fraser)
  void StartSending(const std::string& data, const std::function<void(int)> &message_sent_functor);  // NOLINT (Fraser)
  State state() const;
  // Sets the state_ to kPermanent or kUnvalidated and sets the lifespan_timer_ to expire at
  // pos_infin.
  void MakePermanent(bool validated);
  // state must be either kDuplicate or kExactDuplicate.
  void MarkAsDuplicateAndClose(State state);
  std::function<void()> GetAndClearFailureFunctor();

  // Get the remote endpoint offered for NAT detection.
  boost::asio::ip::udp::endpoint RemoteNatDetectionEndpoint() const;
  // Helpers for debugging
  boost::posix_time::time_duration ExpiresFromNow() const;
  std::string PeerDebugId() const;

 private:
  Connection(const Connection&);
  Connection& operator=(const Connection&);

  struct SendRequest {
    std::string encrypted_data_;
    std::function<void(int)> message_sent_functor_;  // NOLINT (Dan)

    SendRequest(std::string const&encrypted_data,
                std::function<void(int)> const& message_sent_functor)  // NOLINT (Dan)
        : encrypted_data_(encrypted_data),
          message_sent_functor_(message_sent_functor) {}
  };

  void DoClose(bool timed_out = false);
  void DoStartConnecting(const NodeId& peer_node_id,
                         const boost::asio::ip::udp::endpoint& peer_endpoint,
                         const std::string& validation_data,
                         const boost::posix_time::time_duration& connect_attempt_timeout,
                         const boost::posix_time::time_duration& lifespan,
                         const std::function<void(int)>& ping_functor,  // NOLINT (Fraser)
                         const std::function<void()>& failure_functor);
  void DoStartSending(SendRequest const& request);  // NOLINT (Fraser)
  void DoQueueSendRequest(SendRequest const& request);
  void FinishSendAndQueueNext();

  void CheckTimeout(const boost::system::error_code& ec);
  void CheckLifespanTimeout(const boost::system::error_code& ec);
  bool Stopped() const;

  void StartTick();
  void HandleTick();

  void StartConnect(const std::string& validation_data,
                    const boost::posix_time::time_duration& connect_attempt_timeout,
                    const boost::posix_time::time_duration& lifespan,
                    const std::function<void(int)> &ping_functor);  // NOLINT (Fraser)
  void HandleConnect(const boost::system::error_code& ec,
                     const std::string& validation_data,
                     std::function<void(int)> ping_functor);  // NOLINT (Fraser)

  void StartReadSize();
  void HandleReadSize(const boost::system::error_code& ec);

  void StartReadData();
  void HandleReadData(const boost::system::error_code& ec, size_t length);

  void StartWrite(const std::function<void(int)> &message_sent_functor);  // NOLINT (Fraser)
  void HandleWrite(std::function<void(int)> message_sent_functor);  // NOLINT (Fraser)

  void StartProbing();
  void DoProbe(const boost::system::error_code& ec);
  void HandleProbe(const boost::system::error_code& ec);

  void DoMakePermanent(bool validated);

  void EncodeData(const std::string& data);

  void InvokeSentFunctor(const std::function<void(int)> &message_sent_functor, int result) const;  // NOLINT (Fraser)

  std::weak_ptr<Transport> transport_;
  boost::asio::io_service::strand strand_;
  std::shared_ptr<Multiplexer> multiplexer_;
  detail::Socket socket_;
  boost::asio::deadline_timer timer_, probe_interval_timer_, lifespan_timer_;
  NodeId peer_node_id_;
  boost::asio::ip::udp::endpoint peer_endpoint_;
  std::vector<unsigned char> send_buffer_, receive_buffer_;
  DataSize data_size_, data_received_;
  uint8_t failed_probe_count_;
  State state_;
  mutable std::mutex state_mutex_;
  enum class TimeoutState { kConnecting, kConnected, kClosing } timeout_state_;
  bool sending_;
  std::function<void()> failure_functor_;
  std::queue<SendRequest> send_queue_;
};


template <typename Elem, typename Traits>
std::basic_ostream<Elem, Traits>& operator<<(std::basic_ostream<Elem, Traits>& ostream,
                                             const Connection::State &state) {
  std::string state_str;
  switch (state) {
    case Connection::State::kPending:
      state_str = "Pending";
      break;
    case Connection::State::kTemporary:
      state_str = "Temporary";
      break;
    case Connection::State::kBootstrapping:
      state_str = "Bootstrapping";
      break;
    case Connection::State::kUnvalidated:
      state_str = "Unvalidated";
      break;
    case Connection::State::kPermanent:
      state_str = "Permanent";
      break;
    default:
      state_str = "Invalid";
      break;
  }

  for (std::string::iterator itr(state_str.begin()); itr != state_str.end(); ++itr)
    ostream << ostream.widen(*itr);
  return ostream;
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CONNECTION_H_
