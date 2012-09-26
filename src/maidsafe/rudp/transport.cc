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
      managed_connections_debug_printout_() {}

Transport::~Transport() {
  Close();
}

bool Transport::Bootstrap(
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
  ReturnCode result = multiplexer_->Open(local_endpoint);
  if (result != kSuccess) {
    LOG(kError) << "Failed to open multiplexer.  Result: " << result;
    return false;
  }

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

  StartDispatch();

  bool try_connect(true);
  bptime::time_duration lifespan;
  if (bootstrap_off_existing_connection)
    try_connect = (nat_type_ != NatType::kSymmetric);
  else
    lifespan = Parameters::bootstrap_connection_lifespan;

  if (!try_connect) {
    LOG(kVerbose) << "Started new transport on " << multiplexer_->local_endpoint();
    return true;
  }

  for (auto peer : bootstrap_peers) {
    chosen_id = ConnectToBootstrapEndpoint(peer.first, peer.second, lifespan);
    if (chosen_id != NodeId()) {
      LOG(kVerbose) << "Started new transport on " << multiplexer_->local_endpoint()
                    << " connected to " << DebugId(peer.first).substr(0, 7) << " - " << peer.second;
      return true;
    }
  }

  return false;
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
  if (multiplexer_) {
    strand_.post(std::bind(&Multiplexer::Close, multiplexer_));
    while (IsValid(multiplexer_->external_endpoint()))
      boost::this_thread::yield();
  }
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

    bool success(local_cond_var.timed_wait(
        lock,
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

bool Transport::MakeConnectionPermanent(const NodeId& peer_id,
                                        bool validated,
                                        Endpoint& peer_endpoint) {
  return connection_manager_->MakeConnectionPermanent(peer_id, validated, peer_endpoint);
}

size_t Transport::NormalConnectionsCount() const {
  return connection_manager_->NormalConnectionsCount();
}

bool Transport::IsIdle() const {
  return connection_manager_->NormalConnectionsCount() == 0U;
}

bool Transport::IsAvailable() const {
  return detail::IsValid(multiplexer_->external_endpoint()) ||
         detail::IsValid(multiplexer_->local_endpoint());
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
  // Dispatch the message outside the strand.
  strand_.get_io_service().post(std::bind(&Transport::DoSignalMessageReceived,
                                          shared_from_this(),
                                          message));
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

  // For temporary connections, we only need to fire the signal then finish.
  if (connection->state() != Connection::State::kTemporary) {
    if (is_duplicate_normal_connection) {
      LOG(kError) << "Connection is a duplicate.  Failed to add " << connection->state()
                  << " connection from " << ThisDebugId() << " to " << connection->PeerDebugId();
      connection->MarkAsDuplicateAndClose();
    }

    if (!connection_manager_->AddConnection(connection)) {
      LOG(kError) << "Failed to add " << connection->state() << " connection from "
                  << ThisDebugId() << " to " << connection->PeerDebugId();
      connection->Close();
    }
  }
  LOG(kSuccess) << "Successfully made " << connection->state() << " connection from "
                << ThisDebugId() << " to " << connection->PeerDebugId();
#ifndef NDEBUG
  std::string s("\n++++++++++++++++++++++++\nAdded ");
  s += boost::lexical_cast<std::string>(connection->state()) + " connection from ";
  s += ThisDebugId() + " to " + connection->PeerDebugId() + '\n';
  if (managed_connections_debug_printout_)
    s += managed_connections_debug_printout_();
  LOG(kVerbose) << s;
#endif
}

void Transport::RemoveConnection(ConnectionPtr connection, bool timed_out) {
  strand_.dispatch(
      std::bind(&Transport::DoRemoveConnection, shared_from_this(), connection, timed_out));
}

void Transport::DoRemoveConnection(ConnectionPtr connection, bool timed_out) {
  // The call to connection_manager_->RemoveConnection must come before the invocation of the
  // on_connection_lost_ slot so that the transport can be assessed for IsIdle properly during the
  // execution of the slot.
  if (connection->state() != Connection::State::kTemporary)
    connection_manager_->RemoveConnection(connection);
  if (connection->state() != Connection::State::kDuplicate) {
    on_connection_lost_(connection->Socket().PeerNodeId(),
                        shared_from_this(),
                        connection->state() == Connection::State::kTemporary,
                        timed_out);
#ifndef NDEBUG
    std::string s("\n************************\nRemoved ");
    s += boost::lexical_cast<std::string>(connection->state()) + " connection from ";
    s += ThisDebugId() + " to " + connection->PeerDebugId() + '\n';
    if (managed_connections_debug_printout_ && on_connection_lost_connection_.connected())
      s += managed_connections_debug_printout_();
    LOG(kVerbose) << s;
#endif
  }
}

std::string Transport::ThisDebugId() const {
  return std::string("[") + DebugId(node_id()).substr(0, 7) + " - " +
         boost::lexical_cast<std::string>(external_endpoint()) + " / " +
         boost::lexical_cast<std::string>(local_endpoint()) + "]";
}

std::string Transport::DebugString() const {
  std::string s = std::string("\t") + ThisDebugId() + "  ";
  s += boost::lexical_cast<std::string>(nat_type_) + '\n';
  s += connection_manager_->DebugString();
  return s;
}

void Transport::SetManagedConnectionsDebugPrintout(std::function<std::string()> functor) {
  managed_connections_debug_printout_ = functor;
}


}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
