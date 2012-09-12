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
      on_message_connection_(),
      on_connection_added_connection_(),
      on_connection_lost_connection_(),
      is_resilience_transport_(false) {
                                                                                            my_tprt_ = tprt++;
                                                                                                LOG(kWarning) << "Ctor Transport " << my_tprt_;
}

Transport::~Transport() {
  Close();
                                                                                                LOG(kWarning) << "\tDtor Transport " << my_tprt_;
}

void Transport::Bootstrap(
    const std::vector<std::pair<NodeId, Endpoint>> &bootstrap_peers,
    const NodeId& this_node_id,
    std::shared_ptr<asymm::PublicKey> this_public_key,
    Endpoint local_endpoint,
    bool bootstrap_off_existing_connection,
    const OnMessage::slot_type& on_message_slot,
    const OnConnectionAdded::slot_type& on_connection_added_slot,
    const OnConnectionLost::slot_type& on_connection_lost_slot,
    const Session::OnNatDetectionRequested::slot_function_type& on_nat_detection_requested_slot,
    NodeId& chosen_id) {
  BOOST_ASSERT(on_nat_detection_requested_slot);
  BOOST_ASSERT(!multiplexer_->IsOpen());

  chosen_id = NodeId();
  // We want these 3 slots to be invoked before any others connected, so that if we wait elsewhere
  // for the other connected slot(s) to be executed, we can be assured that these main slots have
  // already been executed at that point in time.
  on_message_connection_ = on_message_.connect(on_message_slot, boost::signals2::at_front);
  on_connection_added_connection_ =
      on_connection_added_.connect(on_connection_added_slot, boost::signals2::at_front);
  on_connection_lost_connection_ =
      on_connection_lost_.connect(on_connection_lost_slot, boost::signals2::at_front);

  on_nat_detection_requested_slot_ = on_nat_detection_requested_slot;

  connection_manager_.reset(new ConnectionManager(shared_from_this(), strand_, multiplexer_,
                                                  this_node_id, this_public_key));
  ReturnCode result = multiplexer_->Open(local_endpoint);
  if (result != kSuccess) {
    if (!(local_endpoint.port() == ManagedConnections::kResiliencePort() && result == kBindError))
      LOG(kError) << "Failed to open multiplexer.  Result: " << result;
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
    for (auto peer : bootstrap_peers) {
      chosen_id = ConnectToBootstrapEndpoint(peer.first, peer.second, lifespan);
      if (chosen_id == NodeId())
        continue;
      LOG(kVerbose) << "Started new transport on " << multiplexer_->local_endpoint()
                    << " connected to " << DebugId(peer.first).substr(0, 7) << " - " << peer.second;
      break;
    }
  } else {
    chosen_id = NodeId();
  }

  //if (is_resilience_transport_) {
  //  if (multiplexer_->external_endpoint().port() != ManagedConnections::kResiliencePort() &&
  //      multiplexer_->local_endpoint().port() != ManagedConnections::kResiliencePort()) {
  //    LOG(kWarning) << "Failed to start resilience transport - got port "
  //                  << multiplexer_->external_endpoint().port() << " instead of "
  //                  << ManagedConnections::kResiliencePort();
  //    *chosen_endpoint = Endpoint();
  //  } else {
  //    LOG(kInfo) << "Started resilience transport on " << multiplexer_->external_endpoint() << " / "
  //               << multiplexer_->local_endpoint();
  //  }
  //}
}

NodeId Transport::ConnectToBootstrapEndpoint(const NodeId& bootstrap_node_id,
                                             const Endpoint& bootstrap_endpoint,
                                             const bptime::time_duration& lifespan) {
  if (!IsValid(bootstrap_endpoint)) {
    LOG(kError) << bootstrap_endpoint << " is an invalid endpoint.";
    return NodeId();
  }

  // Temporarily connect to the signals until the connect attempt has succeeded or failed.
  boost::mutex local_mutex;
  boost::condition_variable local_cond_var;
  bool slot_called(false);
  bool timed_out_connecting(false);
  NodeId peer_id;
  auto slot_connection_added(on_connection_added_.connect(
      [&](const NodeId& connected_peer_id,
          TransportPtr /*transport*/,
          bool /*temporary_connection*/,
          bool& /*is_duplicate_normal_connection*/) {
    assert(!slot_called);
    boost::mutex::scoped_lock local_lock(local_mutex);
    slot_called = true;
    peer_id = connected_peer_id;
    local_cond_var.notify_one();
  }, boost::signals2::at_back));
  auto slot_connection_lost(on_connection_lost_.connect(
      [&](const NodeId& connected_peer_id,
          TransportPtr /*transport*/,
          bool /*temporary_connection*/,
          bool timed_out) {
    boost::mutex::scoped_lock local_lock(local_mutex);
    if (!slot_called) {
      slot_called = true;
      peer_id = connected_peer_id;
      timed_out_connecting = timed_out;
      local_cond_var.notify_one();
    }
  }, boost::signals2::at_back));

  boost::mutex::scoped_lock lock(local_mutex);
  connection_manager_->Connect(bootstrap_node_id, bootstrap_endpoint, "",
                               Parameters::bootstrap_connect_timeout, lifespan);

  bool success(local_cond_var.timed_wait(lock,
                                         Parameters::bootstrap_connect_timeout + bptime::seconds(1),
                                         [&] { return slot_called; }));  // NOLINT (Fraser)
  slot_connection_added.disconnect();
  slot_connection_lost.disconnect();
  if (!success) {
    LOG(kError) << "Timed out waiting for connection. External endpoint: "
                << multiplexer_->external_endpoint() << "  Local endpoint: "
                << multiplexer_->local_endpoint();
    return NodeId();
  }

  if (timed_out_connecting) {
    LOG(kInfo) << "Failed to make bootstrap connection to " << bootstrap_endpoint;
    return NodeId();
  }

  Endpoint nat_detection_endpoint(
      connection_manager_->RemoteNatDetectionEndpoint(peer_id));
  if (IsValid(nat_detection_endpoint)) {
    int result(kPendingResult);
    connection_manager_->Ping(peer_id,
                              nat_detection_endpoint,
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

  return peer_id;
}

void Transport::Close() {
  on_message_connection_.disconnect();
  on_connection_added_connection_.disconnect();
  on_connection_lost_connection_.disconnect();
  if (connection_manager_)
    connection_manager_->Close();
  if (multiplexer_)
    multiplexer_->Close();
}

void Transport::Connect(const NodeId& peer_id,
                        const EndpointPair& peer_endpoint_pair,
                        const std::string& validation_data) {
  strand_.dispatch(std::bind(&Transport::DoConnect, shared_from_this(), peer_id, peer_endpoint_pair,
                             validation_data));
}

void Transport::DoConnect(const NodeId& peer_id,
                          const EndpointPair& peer_endpoint_pair,
                          const std::string& validation_data) {
  if (!multiplexer_->IsOpen())
    return;

  // TODO(Fraser#5#): 2012-09-11 - This code block is largely copied from ConnectToBootstrapEndpoint
  //                             - move to separate function.
  if (IsValid(peer_endpoint_pair.external)) {
    // Temporarily connect to the signals until the connect attempt has succeeded or failed.
    boost::mutex local_mutex;
    boost::condition_variable local_cond_var;
    bool slot_called(false);
    bool timed_out_connecting(false);
    auto slot_connection_added(on_connection_added_.connect(
        [&](const NodeId& connected_peer_id,
            TransportPtr /*transport*/,
            bool /*temporary_connection*/,
            bool& /*is_duplicate_normal_connection*/) {
      boost::mutex::scoped_lock local_lock(local_mutex);
      if (peer_id == connected_peer_id) {
        slot_called = true;
        local_cond_var.notify_one();
      }
    }, boost::signals2::at_back));
    auto slot_connection_lost(on_connection_lost_.connect(
        [&](const NodeId& connected_peer_id,
            TransportPtr /*transport*/,
            bool /*temporary_connection*/,
            bool timed_out) {
      boost::mutex::scoped_lock local_lock(local_mutex);
      if (peer_id == connected_peer_id) {
        slot_called = true;
        timed_out_connecting = timed_out;
        local_cond_var.notify_one();
      }
    }, boost::signals2::at_back));

    boost::mutex::scoped_lock lock(local_mutex);
    connection_manager_->Connect(peer_id, peer_endpoint_pair.external, validation_data,
                                 Parameters::rendezvous_connect_timeout, bptime::pos_infin);

    bool success(local_cond_var.timed_wait(lock,
                                           Parameters::bootstrap_connect_timeout + bptime::seconds(1),
                                           [&] { return slot_called; }));  // NOLINT (Fraser)
    slot_connection_added.disconnect();
    slot_connection_lost.disconnect();

    if (success && !timed_out_connecting)
      return;
  }

  connection_manager_->Connect(peer_id, peer_endpoint_pair.local, validation_data,
                               Parameters::rendezvous_connect_timeout, bptime::pos_infin);
}

bool Transport::CloseConnection(const NodeId& peer_id) {
  return connection_manager_->CloseConnection(peer_id);
}

bool Transport::Send(const NodeId& peer_id,
                     const std::string& message,
                     const MessageSentFunctor& message_sent_functor) {
  return connection_manager_->Send(peer_id, message, message_sent_functor);
}

void Transport::Ping(const NodeId& peer_id,
                     const Endpoint& peer_endpoint,
                     const PingFunctor& ping_functor) {
  connection_manager_->Ping(peer_id, peer_endpoint, ping_functor);
}

bool Transport::AddPending(const NodeId& peer_id,
                           const boost::asio::ip::udp::endpoint& peer_endpoint) {
  return connection_manager_->AddPending(peer_id, peer_endpoint);
}

bool Transport::RemovePending(const NodeId& peer_id) {
  return connection_manager_->RemovePending(peer_id);
}

bool Transport::HasNormalConnectionTo(const NodeId& peer_id) const {
  return connection_manager_->HasNormalConnectionTo(peer_id);
}

std::shared_ptr<Connection> Transport::GetConnection(const NodeId& peer_id) {
  return connection_manager_->GetConnection(peer_id);
}

Endpoint Transport::external_endpoint() const {
  return multiplexer_->external_endpoint();
}

Endpoint Transport::local_endpoint() const {
  return multiplexer_->local_endpoint();
}

Endpoint Transport::ThisEndpointAsSeenByPeer(const NodeId& peer_id) {
  return connection_manager_->ThisEndpoint(peer_id);
}

void Transport::SetBestGuessExternalEndpoint(const Endpoint& external_endpoint) {
  connection_manager_->SetBestGuessExternalEndpoint(external_endpoint);
}

//bool Transport::IsTemporaryConnection(const Endpoint& peer_endpoint) {
//  return connection_manager_->IsTemporaryConnection(peer_endpoint);
//}

bool Transport::MakeConnectionPermanent(const NodeId& peer_id, Endpoint& peer_endpoint) {
  return connection_manager_->MakeConnectionPermanent(peer_id, peer_endpoint);
}

size_t Transport::NormalConnectionsCount() const {
  return connection_manager_->NormalConnectionsCount();
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

NodeId Transport::node_id() const {
  return connection_manager_->node_id();
}

std::shared_ptr<asymm::PublicKey> Transport::public_key() const {
  return connection_manager_->public_key();
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

void Transport::AddConnection(ConnectionPtr connection) {
  strand_.dispatch(std::bind(&Transport::DoAddConnection, shared_from_this(), connection));
}

void Transport::DoAddConnection(ConnectionPtr connection) {
  bool is_duplicate_normal_connection(false);
  on_connection_added_(connection->Socket().PeerNodeId(),
                       shared_from_this(),
                       connection->state() == Connection::State::kTemporary,
                       is_duplicate_normal_connection);

  if (is_duplicate_normal_connection) {
    LOG(kError) << "Connection is a duplicate.  Failed to add " << connection->state()
                << " connection from " << ThisDebugId() << " to " << connection->PeerDebugId();
    connection->Close();
  }

  if (!connection_manager_->AddConnection(connection)) {
    LOG(kError) << "Failed to add " << connection->state() << " connection from "
                << ThisDebugId() << " to " << connection->PeerDebugId();
    connection->Close();
  }
  LOG(kSuccess) << "Successfully made " << connection->state() << " connection from "
                << ThisDebugId() << " to " << connection->PeerDebugId();
}

void Transport::RemoveConnection(ConnectionPtr connection, bool timed_out) {
  strand_.dispatch(
      std::bind(&Transport::DoRemoveConnection, shared_from_this(), connection, timed_out));
}

void Transport::DoRemoveConnection(ConnectionPtr connection, bool timed_out) {
  connection_manager_->RemoveConnection(connection);
  on_connection_lost_(connection->Socket().PeerNodeId(),
                      shared_from_this(),
                      connection->state() == Connection::State::kTemporary,
                      timed_out);
  LOG(kVerbose) << "Removed " << connection->state() << " connection from "
                << ThisDebugId() << " to " << connection->PeerDebugId();
}

std::string Transport::ThisDebugId() const {
  return std::string("[") + DebugId(node_id()).substr(0, 7) + " - " +
         boost::lexical_cast<std::string>(external_endpoint()) + " / " +
         boost::lexical_cast<std::string>(local_endpoint()) + "]";
}

std::string Transport::DebugString() const {
  std::string s = std::string("\t") + ThisDebugId();
  switch (nat_type_) {
    case NatType::kSymmetric: s += "  Symmetric NAT\n"; break;
    case NatType::kOther:     s += "  Other NAT\n";     break;
    case NatType::kUnknown:   s += "  Unknown NAT\n";   break;
  }
  s += connection_manager_->DebugString();
  return s;
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
