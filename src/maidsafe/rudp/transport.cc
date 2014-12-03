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

namespace asio   = boost::asio;
namespace ip     = asio::ip;
namespace args   = std::placeholders;
namespace bptime = boost::posix_time;

namespace maidsafe { namespace rudp { namespace detail {

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
      managed_connections_debug_printout_()
  {}

Transport::~Transport() { Close(); }

void Transport::Bootstrap(const IdEndpointPairs&            bootstrap_peers,
                          const NodeId&                     this_node_id,
                          std::shared_ptr<asymm::PublicKey> this_public_key,
                          Endpoint                          local_endpoint,
                          bool                              bootstrap_off_existing_connection,
                          OnMessage                         on_message_slot,
                          OnConnectionAdded                 on_connection_added_slot,
                          OnConnectionLost                  on_connection_lost_slot,
                          const OnNatDetected&              on_nat_detection_requested_slot,
                          OnBootstrap                       on_bootstrap) {
  assert(on_nat_detection_requested_slot);
  assert(!multiplexer_->IsOpen());

  ReturnCode result = multiplexer_->Open(local_endpoint);

  if (result != kSuccess) {
    LOG(kError) << "Failed to open multiplexer.  Result: " << result;
    return strand_.dispatch([on_bootstrap, result]() { on_bootstrap(result, NodeId()); });
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

  TryBootstrapping(bootstrap_peers,
                   bootstrap_off_existing_connection,
                   on_bootstrap);
}

template<class Handler /* void(ReturnCode, NodeId) */>
void Transport::TryBootstrapping(const IdEndpointPairs& bootstrap_peers,
                                 bool                   bootstrap_off_existing_connection,
                                 Handler                handler) {
  bool try_connect(true);
  bptime::time_duration lifespan;

  if (bootstrap_off_existing_connection)
    try_connect = (nat_type_ != NatType::kSymmetric);
  else
    lifespan = Parameters::bootstrap_connection_lifespan;

  if (!try_connect) {
    LOG(kVerbose) << "Started new transport on " << multiplexer_->local_endpoint();
    return strand_.dispatch([handler]() { handler(kSuccess, NodeId()); });
  }

  for (auto peer : bootstrap_peers) {
    assert(multiplexer_->local_endpoint() != peer.second);
  }

  auto peers_copy = std::make_shared<IdEndpointPairs>(bootstrap_peers);

  auto on_bootstrap = [peers_copy, handler](const NodeId& peer_id) {
    handler(peer_id != NodeId() ? kSuccess : kNotConnectable,
            peer_id);
  };

  ConnectToBootstrapEndpoint(peers_copy->begin(),
                             peers_copy->end(),
                             lifespan,
                             strand_.wrap(on_bootstrap));
}

template<class Iterator, class Handler>
void Transport::ConnectToBootstrapEndpoint(Iterator begin,
                                           Iterator end,
                                           Duration lifespan,
                                           Handler  handler) {
  if (begin == end) {
    return handler(NodeId());
  }

  ConnectToBootstrapEndpoint(
      begin->first,
      begin->second,
      lifespan,
      [this, begin, end, lifespan, handler](const NodeId& peer_id) mutable {
        if (peer_id == NodeId()) {
          // Retry with the next peer.
          return ConnectToBootstrapEndpoint(std::next(begin), end, lifespan, handler);
        }

        LOG(kVerbose) << "Started new transport on " << multiplexer_->local_endpoint()
                      << " connected to " << DebugId(begin->first).substr(0, 7)
                      << " - " << begin->second;

        handler(peer_id);
      });
}

template<class Handler>
void Transport::ConnectToBootstrapEndpoint(const NodeId& bootstrap_node_id,
                                           const Endpoint& bootstrap_endpoint,
                                           const bptime::time_duration& lifespan,
                                           Handler handler) {
  if (!IsValid(bootstrap_endpoint)) {
    LOG(kError) << bootstrap_endpoint << " is an invalid endpoint.";
    return strand_.dispatch([handler]() mutable { handler(NodeId()); });
  }

  auto default_on_connect = MakeDefaultOnConnectHandler();

  auto on_connect = [this, handler, default_on_connect]
                    (const Error& error, const ConnectionPtr& connection) mutable {
    if (error) {
      return handler(NodeId());
    }

    default_on_connect(error, connection);

    auto peer_id = connection->Socket().PeerNodeId();

    auto on_nat_detected = [peer_id, handler]() mutable {
      handler(peer_id);
    };

    DetectNatType(peer_id, strand_.wrap(on_nat_detected));
  };

  connection_manager_->Connect(bootstrap_node_id, bootstrap_endpoint,
                               "",
                               Parameters::bootstrap_connect_timeout,
                               lifespan,
                               strand_.wrap(on_connect),
                               nullptr);
}

template<class Handler>
void Transport::DetectNatType(NodeId const& peer_id, Handler handler) {
  Endpoint nat_detection_endpoint(connection_manager_->RemoteNatDetectionEndpoint(peer_id));

  if (!IsValid(nat_detection_endpoint)) {
    return handler();
  }

  auto on_ping = [=](int result_in) mutable {
    if (result_in != kSuccess) {
      nat_type_ = NatType::kSymmetric;
    }
    return handler();
  };

  connection_manager_->Ping(peer_id,
                            nat_detection_endpoint,
                            strand_.wrap(on_ping));
}

void Transport::Close() {
  {
    std::lock_guard<std::mutex> guard(callback_mutex_);
    on_message_          = nullptr;
    on_connection_added_ = nullptr;
    on_connection_lost_  = nullptr;
  }

  auto connection_manager = connection_manager_;
  auto multiplexer        = multiplexer_;

  strand_.dispatch([connection_manager, multiplexer]() {
      if (connection_manager) { connection_manager->Close(); }
      if (multiplexer)        { multiplexer->Close(); }
      });
}

void Transport::Connect(const NodeId& peer_id, const EndpointPair& peer_endpoint_pair,
                        const std::string& validation_data) {
  strand_.dispatch(std::bind(&Transport::DoConnect, shared_from_this(), peer_id, peer_endpoint_pair,
                             validation_data));
}

Transport::OnConnect Transport::MakeDefaultOnConnectHandler() {
  std::weak_ptr<Transport> weak_self = shared_from_this();

  return [weak_self](const Error& error, const ConnectionPtr& connection) { // NOLINT
    if (error) return;

    if (auto self = weak_self.lock()) {
      self->AddConnection(connection);
    }
  };
}

void Transport::DoConnect(const NodeId& peer_id, const EndpointPair& peer_endpoint_pair,
                          const std::string& validation_data) {
  if (!multiplexer_->IsOpen())
    return;

  auto on_connect = MakeDefaultOnConnectHandler();

  if (IsValid(peer_endpoint_pair.external)) {
    std::function<void()> failure_functor;
    if (peer_endpoint_pair.local != peer_endpoint_pair.external) {
      failure_functor = [=] {
        if (!multiplexer_->IsOpen())
          return;
        connection_manager_->Connect(peer_id, peer_endpoint_pair.local, validation_data,
                                     Parameters::rendezvous_connect_timeout, bptime::pos_infin,
                                     on_connect, nullptr);
      };
    }
    connection_manager_->Connect(peer_id, peer_endpoint_pair.external, validation_data,
                                 Parameters::rendezvous_connect_timeout, bptime::pos_infin,
                                 on_connect, failure_functor);
  } else {
    connection_manager_->Connect(peer_id, peer_endpoint_pair.local, validation_data,
                                 Parameters::rendezvous_connect_timeout, bptime::pos_infin,
                                 on_connect, nullptr);
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

Transport::Endpoint Transport::external_endpoint() const {
  return multiplexer_->external_endpoint();
}

Transport::Endpoint Transport::local_endpoint() const { return multiplexer_->local_endpoint(); }

Transport::Endpoint Transport::ThisEndpointAsSeenByPeer(const NodeId& peer_id) {
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
  std::weak_ptr<Transport> weak_self = shared_from_this();

  auto handler = strand_.wrap([weak_self](const Error& error) {
      if (auto self = weak_self.lock()) {
        self->HandleDispatch(error);
      }
      });

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
      LOG(kWarning) << connection->state() << " connection from " << ThisDebugId() << " to "
                    << connection->PeerDebugId() << " is a duplicate. Ignoring.";
      return;
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
      connection->MarkAsDuplicateAndClose();
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
