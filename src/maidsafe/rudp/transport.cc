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

#include "maidsafe/rudp/transport.h"

#include <algorithm>
#include <cassert>

#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"
#include "maidsafe/common/log.h"

#include "maidsafe/rudp/connection.h"
#include "maidsafe/rudp/connection_manager.h"
#include "maidsafe/rudp/core/multiplexer.h"
#include "maidsafe/rudp/core/socket.h"
#include "maidsafe/rudp/managed_connections.h"
#include "maidsafe/rudp/parameters.h"
#include "maidsafe/rudp/utils.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace args = std::placeholders;

namespace maidsafe {

namespace rudp {

namespace detail {

namespace { typedef boost::asio::ip::udp::endpoint Endpoint; }


Transport::Transport(AsioService& asio_service, NatType& nat_type)  // NOLINT (Fraser)
    : asio_service_(asio_service),
      nat_type_(nat_type),
      strand_(asio_service.service()),
      multiplexer_(new Multiplexer(asio_service.service())),
      connection_manager_(),
      on_message_(),
      on_connection_added_(),
      on_connection_lost_(),
      on_nat_detection_requested_slot_(),
      is_resilience_transport_(false) {}

Transport::~Transport() {
  Close();
}

void Transport::Bootstrap(
    const std::vector<Endpoint> &bootstrap_endpoints,
    const std::string& this_node_id,
    std::shared_ptr<asymm::PublicKey> this_public_key,
    Endpoint local_endpoint,
    bool bootstrap_off_existing_connection,
    const OnMessage::slot_type& on_message_slot,
    const OnConnectionAdded::slot_type& on_connection_added_slot,
    const OnConnectionLost::slot_type& on_connection_lost_slot,
    const Session::OnNatDetectionRequested::slot_function_type& on_nat_detection_requested_slot,
    std::string& chosen_id,
    boost::signals2::connection& on_message_connection,
    boost::signals2::connection& on_connection_added_connection,
    boost::signals2::connection& on_connection_lost_connection) {
  BOOST_ASSERT(on_nat_detection_requested_slot);
  BOOST_ASSERT(!multiplexer_->IsOpen());

  chosen_id.clear();
  // We want these 3 slots to be invoked before any others connected, so that if we wait elsewhere
  // for the other connected slot(s) to be executed, we can be assured that these main slots have
  // already been executed at that point in time.
  on_message_connection = on_message_.connect(on_message_slot, boost::signals2::at_front);
  on_connection_added_connection =
      on_connection_added_.connect(on_connection_added_slot, boost::signals2::at_front);
  on_connection_lost_connection =
      on_connection_lost_.connect(on_connection_lost_slot, boost::signals2::at_front);

  on_nat_detection_requested_slot_ = on_nat_detection_requested_slot;

  connection_manager_.reset(new ConnectionManager(shared_from_this(), strand_, multiplexer_,
                                                  this_node_id, this_public_key));
  ReturnCode result = multiplexer_->Open(local_endpoint);
  if (result != kSuccess) {
    if (!(local_endpoint.port() == ManagedConnections::kResiliencePort() && result == kBindError)) {
      LOG(kError) << "Failed to open multiplexer.  Result: " << result;
    }
    return;
  }

  StartDispatch();

  bool try_connect(true);
  bptime::time_duration lifespan;
  if (bootstrap_off_existing_connection)
    try_connect = (nat_type_ != NatType::kSymmetric);
  else
    lifespan = Parameters::bootstrap_connection_lifespan;

  if (local_endpoint.port() == ManagedConnections::kResiliencePort()) {
    is_resilience_transport_ = true;
    try_connect = false;
  }

  if (try_connect) {
    for (auto itr(bootstrap_endpoints.begin()); itr != bootstrap_endpoints.end(); ++itr) {
      if (!ConnectToBootstrapEndpoint(*itr, lifespan))
        continue;
      LOG(kVerbose) << "Started new transport on " << multiplexer_->local_endpoint()
                    << " connected to " << *itr;
      *chosen_endpoint = *itr;
      break;
    }
  } else {
    *chosen_endpoint = kNonRoutable;
  }

  if (is_resilience_transport_) {
    if (multiplexer_->external_endpoint().port() != ManagedConnections::kResiliencePort() &&
        multiplexer_->local_endpoint().port() != ManagedConnections::kResiliencePort()) {
      LOG(kWarning) << "Failed to start resilience transport - got port "
                    << multiplexer_->external_endpoint().port() << " instead of "
                    << ManagedConnections::kResiliencePort();
      *chosen_endpoint = Endpoint();
    } else {
      LOG(kInfo) << "Started resilience transport on " << multiplexer_->external_endpoint() << " / "
                 << multiplexer_->local_endpoint();
    }
  }
}

bool Transport::ConnectToBootstrapEndpoint(const Endpoint& bootstrap_endpoint,
                                           const bptime::time_duration& lifespan) {
  if (!IsValid(bootstrap_endpoint)) {
    LOG(kError) << bootstrap_endpoint << " is an invalid endpoint.";
    return false;
  }

  // Temporarily connect to the signals until the connect attempt has succeeded or failed.
  boost::mutex local_mutex;
  boost::condition_variable local_cond_var;
  bool slot_called(false);
  bool timed_out_connecting(false);
  auto slot_connection_added(on_connection_added_.connect(
      [&](const Endpoint& /*peer_endpoint*/, detail::TransportPtr /*transport*/) {
    assert(!slot_called);
    boost::mutex::scoped_lock local_lock(local_mutex);
    slot_called = true;
    local_cond_var.notify_one();
  }, boost::signals2::at_back));
  auto slot_connection_lost(on_connection_lost_.connect(
      [&](const Endpoint& /*peer_endpoint*/,
          detail::TransportPtr /*transport*/,
          bool /*connections_empty*/,
          bool /*temporary_connection*/,
          bool timed_out) {
    boost::mutex::scoped_lock local_lock(local_mutex);
    if (!slot_called) {
      slot_called = true;
      timed_out_connecting = timed_out;
      local_cond_var.notify_one();
    }
  }, boost::signals2::at_back));

  boost::mutex::scoped_lock lock(local_mutex);
  connection_manager_->Connect(bootstrap_endpoint, "", Parameters::bootstrap_connect_timeout,
                               lifespan);

  bool success(local_cond_var.timed_wait(lock,
                                         Parameters::bootstrap_connect_timeout + bptime::seconds(1),
                                         [&] { return slot_called; }));  // NOLINT (Fraser)
  slot_connection_added.disconnect();
  slot_connection_lost.disconnect();
  if (!success) {
    LOG(kError) << "Timed out waiting for connection. External endpoint: "
                << multiplexer_->external_endpoint() << "  Local endpoint: "
                << multiplexer_->local_endpoint();
    return false;
  }

  if (timed_out_connecting) {
    LOG(kInfo) << "Failed to make bootstrap connection to " << bootstrap_endpoint;
    return false;
  }

  Endpoint nat_detection_endpoint(
      connection_manager_->RemoteNatDetectionEndpoint(bootstrap_endpoint));
  if (IsValid(nat_detection_endpoint)) {
    int result(kPendingResult);
    connection_manager_->Ping(nat_detection_endpoint,
                              [&](int result_in) {
                                boost::mutex::scoped_lock local_lock(local_mutex);
                                result = result_in;
                                local_cond_var.notify_one();
                              });

    success = local_cond_var.timed_wait(lock,
                                        Parameters::ping_timeout + bptime::seconds(1),
                                        [&] { return result != kPendingResult; });  // NOLINT (Fraser)
    if (!success || result != kSuccess) {
      LOG(kWarning) << "Timed out waiting for NAT detection ping - setting NAT type to symmetric";
      nat_type_ = NatType::kSymmetric;
    }
  }

  return true;
}

void Transport::Close() {
  if (connection_manager_)
    connection_manager_->Close();
  if (multiplexer_)
    multiplexer_->Close();
}

void Transport::Connect(const Endpoint& peer_endpoint, const std::string& validation_data) {
  strand_.dispatch(std::bind(&Transport::DoConnect, shared_from_this(), peer_endpoint,
                             validation_data));
}

void Transport::DoConnect(const Endpoint& peer_endpoint, const std::string& validation_data) {
  if (multiplexer_->IsOpen())
    connection_manager_->Connect(peer_endpoint, validation_data,
                                 Parameters::rendezvous_connect_timeout, bptime::pos_infin);
}

int Transport::CloseConnection(const Endpoint& peer_endpoint) {
  return connection_manager_->CloseConnection(peer_endpoint);
}

bool Transport::Send(const Endpoint& peer_endpoint,
                     const std::string& message,
                     const MessageSentFunctor& message_sent_functor) {
  return connection_manager_->Send(peer_endpoint, message, message_sent_functor);
}

void Transport::Ping(const Endpoint& peer_endpoint, const PingFunctor& ping_functor) {
  connection_manager_->Ping(peer_endpoint, ping_functor);
}

Endpoint Transport::external_endpoint() const {
  return multiplexer_->external_endpoint();
}

Endpoint Transport::local_endpoint() const {
  return multiplexer_->local_endpoint();
}

Endpoint Transport::ThisEndpointAsSeenByPeer(const Endpoint& peer_endpoint) {
  return connection_manager_->ThisEndpoint(peer_endpoint);
}

void Transport::SetBestGuessExternalEndpoint(const Endpoint& external_endpoint) {
  connection_manager_->SetBestGuessExternalEndpoint(external_endpoint);
}

bool Transport::IsTemporaryConnection(const Endpoint& peer_endpoint) {
  return connection_manager_->IsTemporaryConnection(peer_endpoint);
}

Endpoint Transport::MakeConnectionPermanent(const Endpoint& peer_endpoint) {
  return connection_manager_->MakeConnectionPermanent(peer_endpoint);
}

size_t Transport::ConnectionsCount() const {
  return connection_manager_->size();
}

void Transport::StartDispatch() {
  auto handler = strand_.wrap(std::bind(&Transport::HandleDispatch, shared_from_this(), args::_1));
  multiplexer_->AsyncDispatch(handler);
}

void Transport::HandleDispatch(const boost::system::error_code &/*ec*/) {
  if (!multiplexer_->IsOpen())
    return;

  StartDispatch();
}

void Transport::SignalMessageReceived(const std::string& message) {
  strand_.dispatch(std::bind(&Transport::DoSignalMessageReceived,
                             shared_from_this(), message));
// TODO(Prakash) Test the performance with below option.
// Dispatch the message outside the strand.
// strand_.get_io_service().post(std::bind(&Transport::DoSignalMessageReceived,
//                                         shared_from_this(), message));
}

void Transport::DoSignalMessageReceived(const std::string& message) {
  on_message_(message);
}

void Transport::InsertConnection(ConnectionPtr connection) {
  strand_.dispatch(std::bind(&Transport::DoInsertConnection, shared_from_this(), connection));
}

void Transport::DoInsertConnection(ConnectionPtr connection) {
  connection_manager_->InsertConnection(connection);
  on_connection_added_(connection->Socket().RemoteEndpoint(), shared_from_this());
}

void Transport::RemoveConnection(ConnectionPtr connection, bool timed_out) {
  strand_.dispatch(
      std::bind(&Transport::DoRemoveConnection, shared_from_this(), connection, timed_out));
}

void Transport::DoRemoveConnection(ConnectionPtr connection, bool timed_out) {
  bool connections_empty(false), temporary_connection(false);
  connection_manager_->RemoveConnection(connection, connections_empty, temporary_connection);
  on_connection_lost_(connection->Socket().RemoteEndpoint(), shared_from_this(),
                      connections_empty, temporary_connection, timed_out);
}

std::string Transport::DebugString() {
  std::string s = std::string("\t") + external_endpoint().address().to_string() + ":";
  s += boost::lexical_cast<std::string>(external_endpoint().port()) + " / ";
  s += local_endpoint().address().to_string() + ":";
  s += boost::lexical_cast<std::string>(local_endpoint().port());
  switch (nat_type_) {
    case NatType::kSymmetric: s += "   Symmetric NAT\n"; break;
    case NatType::kOther:     s += "   Other NAT\n";     break;
    case NatType::kUnknown:   s += "   Unknown NAT\n";   break;
  }
  s += connection_manager_->DebugString();
  return s;
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
