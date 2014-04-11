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
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

namespace detail {

std::chrono::nanoseconds BoostToChrono(bptime::time_duration const& from) {
  return std::chrono::nanoseconds(from.total_nanoseconds());
}

namespace {

typedef boost::asio::ip::udp::endpoint Endpoint;

template <typename FunctorType>
class LocalFunctorReplacement {
 public:
  LocalFunctorReplacement(std::mutex& mutex, FunctorType& functor_to_replace,
                          FunctorType& save_slot, FunctorType replacement)
      : mutex_(mutex), functor_to_replace_(functor_to_replace), save_slot_(save_slot) {
    std::lock_guard<std::mutex> guard(mutex_);
    save_slot_ = std::move(functor_to_replace_);
    functor_to_replace_ = std::move(replacement);
  }
  ~LocalFunctorReplacement() {
    std::lock_guard<std::mutex> guard(mutex_);
    functor_to_replace_ = std::move(save_slot_);
  }

 private:
  std::mutex& mutex_;
  FunctorType& functor_to_replace_;
  FunctorType& save_slot_;

  explicit LocalFunctorReplacement(LocalFunctorReplacement const&);
  LocalFunctorReplacement& operator=(LocalFunctorReplacement const&);
};

}  // namespace

Transport::Transport(AsioService& asio_service, NatType& nat_type)
    : asio_service_(asio_service),
      nat_type_(nat_type),
      strand_(asio_service.service()),
      multiplexer_(new Multiplexer(asio_service.service())),
      connection_manager_(),
      callback_mutex_(),
      on_message_(),
      on_connection_added_(),
      on_connection_lost_(),
      on_nat_detection_requested_slot_(),
      managed_connections_debug_printout_() {}

Transport::~Transport() { Close(); }

bool Transport::Bootstrap(
    const std::vector<std::pair<NodeId, Endpoint>>& bootstrap_peers, const NodeId& this_node_id,
    std::shared_ptr<asymm::PublicKey> this_public_key, Endpoint local_endpoint,
    bool bootstrap_off_existing_connection, OnMessage on_message_slot,
    OnConnectionAdded on_connection_added_slot, OnConnectionLost on_connection_lost_slot,
    const Session::OnNatDetectionRequested::slot_function_type& on_nat_detection_requested_slot,
    NodeId& chosen_id) {
  assert(on_nat_detection_requested_slot);
  assert(!multiplexer_->IsOpen());

  chosen_id = NodeId();
  ReturnCode result = multiplexer_->Open(local_endpoint);
  if (result != kSuccess) {
    LOG(kError) << "Failed to open multiplexer.  Result: " << result;
    return false;
  }

  // We want these 3 slots to be invoked before any others connected, so that if we wait elsewhere
  // for the other connected slot(s) to be executed, we can be assured that these main slots have
  // already been executed at that point in time.
  {
    std::lock_guard<std::mutex> guard(callback_mutex_);
    on_message_ = std::move(on_message_slot);
    on_connection_added_ = std::move(on_connection_added_slot);
    on_connection_lost_ = std::move(on_connection_lost_slot);
  }

  on_nat_detection_requested_slot_ = on_nat_detection_requested_slot;

  connection_manager_.reset(new ConnectionManager(shared_from_this(), strand_, multiplexer_,
                                                  this_node_id, this_public_key));

  StartDispatch();

  return TryBootstrapping(bootstrap_peers, bootstrap_off_existing_connection, chosen_id);
}

bool Transport::TryBootstrapping(const std::vector<std::pair<NodeId, Endpoint>>& bootstrap_peers,
                                 bool bootstrap_off_existing_connection, NodeId& chosen_id) {
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
  std::mutex local_mutex;
  std::promise<std::tuple<NodeId, bool>> result_out;
  auto result_in = result_out.get_future();
  std::atomic<bool> slot_called(false);
  std::unique_lock<std::mutex> lock(local_mutex, std::defer_lock);

  /* ned 2014-04-11: I'm not happy with the code below because I don't know why
                     removing the unnecessary mutex causes segfaults. Clearly
                     the mutex forces context back onto the strand so it can clean up,
                     but I've traced the code backwards through the strand and I can see
                     nowhere which ought to trip just because one is concurrently
                     swapping out on_connection_added_ and on_connection_lost_.
                     I don't like mysteries, and this is one of those.
  */
  {
    OnConnectionAdded saved_on_connection_added;
    OnConnectionLost saved_on_connection_lost;

    LocalFunctorReplacement<OnConnectionAdded> on_conn_added_guard(
        callback_mutex_, on_connection_added_, saved_on_connection_added,
        [&](const NodeId & connected_peer_id, TransportPtr transport, bool temporary_connection,
            std::atomic<bool> & is_duplicate_normal_connection) {
          saved_on_connection_added(connected_peer_id, transport, temporary_connection,
                                    is_duplicate_normal_connection);
          assert(!slot_called);
          std::lock_guard<std::mutex> local_lock(local_mutex);
          slot_called = true;
          result_out.set_value(std::make_tuple(NodeId(connected_peer_id), false));
        });
    LocalFunctorReplacement<OnConnectionLost> on_conn_lost_guard(
        callback_mutex_, on_connection_lost_, saved_on_connection_lost,
        [&](const NodeId & connected_peer_id, TransportPtr transport, bool temporary_connection,
            bool timed_out) {
          saved_on_connection_lost(connected_peer_id, transport, temporary_connection, timed_out);
          std::lock_guard<std::mutex> local_lock(local_mutex);
          if (!slot_called) {
            slot_called = true;
            result_out.set_value(std::make_tuple(NodeId(connected_peer_id), timed_out));
          }
        });

    connection_manager_->Connect(bootstrap_node_id, bootstrap_endpoint, "",
                                 Parameters::bootstrap_connect_timeout, lifespan);

    if (std::future_status::timeout == result_in.wait_for(
        BoostToChrono(Parameters::bootstrap_connect_timeout + bptime::seconds(1)))
        || !slot_called) {
      LOG(kError) << "Timed out waiting for connection. External endpoint: "
                  << multiplexer_->external_endpoint()
                  << "  Local endpoint: " << multiplexer_->local_endpoint();
      return NodeId();
    }
    lock.lock();
  }
  auto result = result_in.get();
  NodeId peer_id = std::get<0>(result);
  bool timed_out_connecting = std::get<1>(result);

  if (timed_out_connecting) {
    LOG(kInfo) << "Failed to make bootstrap connection to " << bootstrap_endpoint;
    return NodeId();
  }

  DetectNatType(peer_id);
  return peer_id;
}

void Transport::DetectNatType(NodeId const& peer_id) {
  Endpoint nat_detection_endpoint(connection_manager_->RemoteNatDetectionEndpoint(peer_id));
  if (IsValid(nat_detection_endpoint)) {
    std::promise<int> result_out;
    auto result_in = result_out.get_future();
    connection_manager_->Ping(peer_id, nat_detection_endpoint, [&](int result_in) {
      result_out.set_value(result_in);
    });

    if (std::future_status::timeout == result_in.wait_for(
        BoostToChrono(Parameters::ping_timeout + bptime::seconds(1)))
        || result_in.get() != kSuccess) {
      LOG(kWarning) << "Timed out waiting for NAT detection ping - setting NAT type to symmetric";
      nat_type_ = NatType::kSymmetric;
    }
  }
}

void Transport::Close() {
  {
    std::lock_guard<std::mutex> guard(callback_mutex_);
    on_message_ = nullptr;
    on_connection_added_ = nullptr;
    on_connection_lost_ = nullptr;
  }
  if (connection_manager_)
    connection_manager_->Close();
  if (multiplexer_) {
    strand_.post(std::bind(&Multiplexer::Close, multiplexer_));
    while (IsValid(multiplexer_->external_endpoint()))
      boost::this_thread::yield();
  }
}

void Transport::Connect(const NodeId& peer_id, const EndpointPair& peer_endpoint_pair,
                        const std::string& validation_data) {
  strand_.dispatch(std::bind(&Transport::DoConnect, shared_from_this(), peer_id, peer_endpoint_pair,
                             validation_data));
}

void Transport::DoConnect(const NodeId& peer_id, const EndpointPair& peer_endpoint_pair,
                          const std::string& validation_data) {
  if (!multiplexer_->IsOpen())
    return;

  if (IsValid(peer_endpoint_pair.external)) {
    std::function<void()> failure_functor;
    if (peer_endpoint_pair.local != peer_endpoint_pair.external) {
      failure_functor = [=] {
        if (!multiplexer_->IsOpen())
          return;
        connection_manager_->Connect(peer_id, peer_endpoint_pair.local, validation_data,
                                     Parameters::rendezvous_connect_timeout, bptime::pos_infin);
      };
    }
    connection_manager_->Connect(peer_id, peer_endpoint_pair.external, validation_data,
                                 Parameters::rendezvous_connect_timeout, bptime::pos_infin,
                                 failure_functor);
  } else {
    connection_manager_->Connect(peer_id, peer_endpoint_pair.local, validation_data,
                                 Parameters::rendezvous_connect_timeout, bptime::pos_infin);
  }
}

bool Transport::CloseConnection(const NodeId& peer_id) {
  return connection_manager_->CloseConnection(peer_id);
}

bool Transport::Send(const NodeId& peer_id, const std::string& message,
                     const MessageSentFunctor& message_sent_functor) {
  return connection_manager_->Send(peer_id, message, message_sent_functor);
}

void Transport::Ping(const NodeId& peer_id, const Endpoint& peer_endpoint,
                     const std::function<void(int /*result*/)>& ping_functor) {
  connection_manager_->Ping(peer_id, peer_endpoint, ping_functor);
}

std::shared_ptr<Connection> Transport::GetConnection(const NodeId& peer_id) {
  return connection_manager_->GetConnection(peer_id);
}

Endpoint Transport::external_endpoint() const { return multiplexer_->external_endpoint(); }

Endpoint Transport::local_endpoint() const { return multiplexer_->local_endpoint(); }

Endpoint Transport::ThisEndpointAsSeenByPeer(const NodeId& peer_id) {
  return connection_manager_->ThisEndpoint(peer_id);
}

void Transport::SetBestGuessExternalEndpoint(const Endpoint& external_endpoint) {
  connection_manager_->SetBestGuessExternalEndpoint(external_endpoint);
}

bool Transport::MakeConnectionPermanent(const NodeId& peer_id, bool validated,
                                        Endpoint& peer_endpoint) {
  return connection_manager_->MakeConnectionPermanent(peer_id, validated, peer_endpoint);
}

size_t Transport::NormalConnectionsCount() const {
  return connection_manager_->NormalConnectionsCount();
}

bool Transport::IsIdle() const { return connection_manager_->NormalConnectionsCount() == 0U; }

bool Transport::IsAvailable() const {
  return detail::IsValid(multiplexer_->external_endpoint()) ||
         detail::IsValid(multiplexer_->local_endpoint());
}

void Transport::StartDispatch() {
  auto handler = strand_.wrap(std::bind(&Transport::HandleDispatch, shared_from_this(), args::_1));
  multiplexer_->AsyncDispatch(handler);
}

void Transport::HandleDispatch(const boost::system::error_code& /*ec*/) {
  if (!multiplexer_->IsOpen())
    return;

  StartDispatch();
}

NodeId Transport::node_id() const { return connection_manager_->node_id(); }

std::shared_ptr<asymm::PublicKey> Transport::public_key() const {
  return connection_manager_->public_key();
}

void Transport::SignalMessageReceived(const std::string& message) {
  // Dispatch the message outside the strand.
  strand_.get_io_service().post(
      std::bind(&Transport::DoSignalMessageReceived, shared_from_this(), message));
}

void Transport::DoSignalMessageReceived(const std::string& message) {
  OnMessage local_callback;
  {
    std::lock_guard<std::mutex> guard(callback_mutex_);
    local_callback = on_message_;
  }
  if (local_callback)
    local_callback(message);
}

void Transport::AddConnection(ConnectionPtr connection) {
  strand_.dispatch(std::bind(&Transport::DoAddConnection, shared_from_this(), connection));
}

void Transport::DoAddConnection(ConnectionPtr connection) {
  // Discard failure_functor
  connection->GetAndClearFailureFunctor();

  // For temporary connections, we only need to invoke on_connection_lost_ then finish.
  if (connection->state() != Connection::State::kTemporary) {
    auto result(connection_manager_->AddConnection(connection));
    if (result == kInvalidConnection) {
      LOG(kError) << "Failed to add " << connection->state() << " connection from " << ThisDebugId()
                  << " to " << connection->PeerDebugId();
      return connection->Close();
    } else if (result == kConnectionAlreadyExists) {
      LOG(kError) << "Connection is a duplicate.  Failed to add " << connection->state()
                  << " connection from " << ThisDebugId() << " to " << connection->PeerDebugId();
      // assert(false);
      return connection->MarkAsDuplicateAndClose(Connection::State::kExactDuplicate);
    }
  }

  LOG(kSuccess) << "Successfully made " << connection->state() << " connection from "
                << ThisDebugId() << " to " << connection->PeerDebugId();

  std::atomic<bool> is_duplicate_normal_connection(false);
  OnConnectionAdded local_callback;
  {
    std::lock_guard<std::mutex> guard(callback_mutex_);
    local_callback = on_connection_added_;
  }
  if (local_callback) {
    local_callback(connection->Socket().PeerNodeId(), shared_from_this(),
                   connection->state() == Connection::State::kTemporary,
                   is_duplicate_normal_connection);

    if (is_duplicate_normal_connection) {
      LOG(kError) << "Connection is a duplicate.  Failed to add " << connection->state()
                  << " connection from " << ThisDebugId() << " to " << connection->PeerDebugId();
      connection->MarkAsDuplicateAndClose(Connection::State::kDuplicate);
    }
  }

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
  if (connection->state() == Connection::State::kExactDuplicate)
    return;

  // The call to connection_manager_->RemoveConnection must come before the invocation of
  // on_connection_lost_ so that the transport can be assessed for IsIdle properly during the
  // execution of the functor.
  if (connection->state() != Connection::State::kTemporary)
    connection_manager_->RemoveConnection(connection);

  // If the connection has a failure_functor, invoke that, otherwise invoke on_connection_lost_.
  auto failure_functor(connection->GetAndClearFailureFunctor());
  if (failure_functor) {
    return failure_functor();
  }

  if (connection->state() != Connection::State::kDuplicate) {
    OnConnectionLost local_callback;
    {
      std::lock_guard<std::mutex> guard(callback_mutex_);
      local_callback = on_connection_lost_;
    }
    if (local_callback)
      local_callback(connection->Socket().PeerNodeId(), shared_from_this(),
                     connection->state() == Connection::State::kTemporary, timed_out);
#ifndef NDEBUG
    std::string s("\n************************\nRemoved ");
    s += boost::lexical_cast<std::string>(connection->state()) + " connection from ";
    s += ThisDebugId() + " to " + connection->PeerDebugId() + '\n';
    if (managed_connections_debug_printout_ && local_callback)
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
