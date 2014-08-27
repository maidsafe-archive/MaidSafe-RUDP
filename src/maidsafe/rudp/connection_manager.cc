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

#include "maidsafe/rudp/connection_manager.h"

#include <algorithm>
#include <cassert>
#include <utility>

#include "maidsafe/common/log.h"

#include "maidsafe/rudp/connection.h"
#include "maidsafe/rudp/transport.h"
#include "maidsafe/rudp/core/multiplexer.h"
#include "maidsafe/rudp/core/socket.h"
#include "maidsafe/rudp/packets/handshake_packet.h"
#include "maidsafe/rudp/parameters.h"
#include "maidsafe/rudp/utils.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

namespace detail {

namespace {

typedef boost::asio::ip::udp::endpoint Endpoint;

bool IsNormal(std::shared_ptr<Connection> connection) {
  return connection->state() == Connection::State::kPermanent ||
         connection->state() == Connection::State::kUnvalidated ||
         connection->state() == Connection::State::kBootstrapping;
}

}  // unnamed namespace

ConnectionManager::ConnectionManager(std::shared_ptr<Transport> transport,
                                     const boost::asio::io_service::strand& strand,
                                     MultiplexerPtr multiplexer, NodeId this_node_id,
                                     std::shared_ptr<asymm::PublicKey> this_public_key)
    : connections_(),
      mutex_(),
      transport_(transport),
      strand_(strand),
      multiplexer_(std::move(multiplexer)),
      kThisNodeId_(std::move(this_node_id)),
      this_public_key_(std::move(this_public_key)),
      sockets_() {
  multiplexer_->dispatcher_.SetConnectionManager(this);
}

ConnectionManager::~ConnectionManager() { Close(); }

void ConnectionManager::Close() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto connection : connections_)
      strand_.post(std::bind(&Connection::Close, connection));
  }
  // Ugly, but we must not reset dispatcher until he's done
  while (multiplexer_->dispatcher_.use_count()) std::this_thread::yield();
  multiplexer_->dispatcher_.SetConnectionManager(nullptr);
}

void ConnectionManager::Connect(const NodeId& peer_id, const Endpoint& peer_endpoint,
                                const std::string& validation_data,
                                const bptime::time_duration& connect_attempt_timeout,
                                const bptime::time_duration& lifespan,
                                const std::function<void()>& failure_functor) {
  if (std::shared_ptr<Transport> transport = transport_.lock()) {
    ConnectionPtr connection(std::make_shared<Connection>(transport, strand_, multiplexer_));
    connection->StartConnecting(peer_id, peer_endpoint, validation_data, connect_attempt_timeout,
                                lifespan, failure_functor);
  }
}

int ConnectionManager::AddConnection(ConnectionPtr connection) {
  assert(connection->state() != Connection::State::kPending);
  if (!IsNormal(connection))
    return kInvalidConnection;
  std::lock_guard<std::mutex> lock(mutex_);
  auto result(connections_.insert(connection));
  return result.second ? kSuccess : kConnectionAlreadyExists;
}

bool ConnectionManager::CloseConnection(const NodeId& peer_id) {
  std::unique_lock<std::mutex> lock(mutex_);
  auto itr(FindConnection(peer_id));
  if (itr == connections_.end()) {
    LOG(kWarning) << DebugId(kThisNodeId_) << " Not currently connected to " << DebugId(peer_id);
    return false;
  }

  ConnectionPtr connection(*itr);
  lock.unlock();
  strand_.dispatch([=] {
      LOG(kVerbose) << "closing connection to " << DebugId(peer_id);
      connection->Close();
  });  // NOLINT (Fraser)
  return true;
}

void ConnectionManager::RemoveConnection(ConnectionPtr connection) {
  std::lock_guard<std::mutex> lock(mutex_);
  assert(IsNormal(connection) || connection->state() == Connection::State::kDuplicate);
  connections_.erase(connection);
}

ConnectionManager::ConnectionPtr ConnectionManager::GetConnection(const NodeId& peer_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr(FindConnection(peer_id));
  if (itr == connections_.end()) {
    LOG(kInfo) << DebugId(kThisNodeId_) << " Not currently connected to " << DebugId(peer_id);
    return ConnectionPtr();
  }
  return *itr;
}

void ConnectionManager::Ping(const NodeId& peer_id, const Endpoint& peer_endpoint,
                             const std::function<void(int)>& ping_functor) {  // NOLINT (Fraser)
  if (std::shared_ptr<Transport> transport = transport_.lock()) {
    assert(ping_functor);
    ConnectionPtr connection(std::make_shared<Connection>(transport, strand_, multiplexer_));
    connection->Ping(peer_id, peer_endpoint, ping_functor);
  }
}

bool ConnectionManager::Send(const NodeId& peer_id, const std::string& message,
                             const std::function<void(int)>& message_sent_functor) {  // NOLINT
  std::unique_lock<std::mutex> lock(mutex_);
  auto itr(FindConnection(peer_id));
  if (itr == connections_.end()) {
    LOG(kWarning) << DebugId(kThisNodeId_) << " Not currently connected to " << DebugId(peer_id);
    return false;
  }

  ConnectionPtr connection(*itr);
  lock.unlock();
  strand_.dispatch([=] { connection->StartSending(message, message_sent_functor); });
  return true;
}

Socket* ConnectionManager::GetSocket(const asio::const_buffer& data, const Endpoint& endpoint) {
  uint32_t socket_id(0);
  if (!Packet::DecodeDestinationSocketId(&socket_id, data)) {
    LOG(kError) << DebugId(kThisNodeId_) << " Received a non-RUDP packet from " << endpoint;
    return nullptr;
  }
//  std::unique_lock<std::mutex> lock(mutex_);
  SocketMap::const_iterator socket_iter(sockets_.end());
  if (socket_id == 0) {
    HandshakePacket handshake_packet;
    if (!handshake_packet.Decode(data)) {
      LOG(kVerbose) << DebugId(kThisNodeId_) << " Failed to decode handshake packet from "
                    << endpoint;
      return nullptr;
    }
    if (handshake_packet.ConnectionReason() == Session::kNormal) {
      // This is a handshake packet on a newly-added socket
      LOG(kVerbose) << DebugId(kThisNodeId_)
                    << " This is a handshake packet on a newly-added socket from " << endpoint;
      socket_iter = std::find_if(sockets_.begin(), sockets_.end(),
                                 [endpoint](const SocketMap::value_type & socket_pair) {
        return socket_pair.second->PeerEndpoint() == endpoint && !socket_pair.second->IsConnected();
      });
      // If the socket wasn't found, this could be a connect attempt from a peer using symmetric
      // NAT, so the peer's port may be different to what this node was told to expect.
      if (socket_iter == sockets_.end()) {
        auto count(std::count_if(sockets_.begin(), sockets_.end(),
                                 [endpoint](const SocketMap::value_type & socket_pair) {
          return socket_pair.second->PeerEndpoint().address() == endpoint.address();
        }));
        if (count > 1) {
          LOG(kWarning) << "multiple vaults running on same machine " << count;
          // if running multiple vaults on same machine, shall not consider symmetric NAT situation
          return nullptr;
        }
        LOG(kVerbose) << "updating for symmetric";
        socket_iter = std::find_if(sockets_.begin(), sockets_.end(),
                                   [endpoint](const SocketMap::value_type & socket_pair) {
          return socket_pair.second->PeerEndpoint().address() == endpoint.address() &&
                 !OnPrivateNetwork(socket_pair.second->PeerEndpoint()) &&
                 !socket_pair.second->IsConnected();
        });
        if (socket_iter != sockets_.end()) {
          LOG(kVerbose) << DebugId(kThisNodeId_) << " Updating peer's endpoint from "
                        << socket_iter->second->PeerEndpoint() << " to " << endpoint;
          socket_iter->second->UpdatePeerEndpoint(endpoint);
        }
      }
    } else {  // Session::mode_ != kNormal
      socket_iter = std::find_if(sockets_.begin(), sockets_.end(),
                                 [endpoint](const SocketMap::value_type & socket_pair) {
        return socket_pair.second->PeerEndpoint() == endpoint;
      });
      if (socket_iter == sockets_.end()) {
        // This is a handshake packet from a peer trying to ping this node or join the network
        HandlePingFrom(handshake_packet, endpoint);
        return nullptr;
      } else {
        if (sockets_.size() == 1U) {
          // This is a handshake packet from a peer replying to this node's join attempt,
          // or from a peer starting a zero state network with this node
          LOG(kVerbose) << DebugId(kThisNodeId_) << " This is a handshake packet from " << endpoint
                        << " which is replying to a join request, or starting a new network";
        } else {
          LOG(kVerbose) << DebugId(kThisNodeId_) << " This is a handshake packet from " << endpoint
                        << " which is replying to a ping request";
        }
      }
    }
  } else {
    // This packet is intended for a specific connection.
    socket_iter = sockets_.find(socket_id);
  }

  if (socket_iter != sockets_.end()) {
    LOG(kVerbose) << DebugId(kThisNodeId_) << " find socket for endpoint " << endpoint;
    return socket_iter->second;
  } else {
    const unsigned char* p = asio::buffer_cast<const unsigned char*>(data);
    LOG(kVerbose) << DebugId(kThisNodeId_) << "  Received a packet \"0x" << std::hex
                  << static_cast<int>(*p) << std::dec << "\" for unknown connection " << socket_id
                  << " from " << endpoint;
    return nullptr;
  }
}

void ConnectionManager::HandlePingFrom(const HandshakePacket& handshake_packet,
                                       const Endpoint& endpoint) {
  LOG(kVerbose) << DebugId(kThisNodeId_) << " This is a handshake packet from " << endpoint
                << " which is trying to ping this node or join the network";
  if (handshake_packet.node_id() == kThisNodeId_) {
    LOG(kWarning) << DebugId(kThisNodeId_) << " is handshaking with another local transport.";
    return;
  }
  if (IsValid(endpoint)) {
    // Check if this joining node is already connected
    ConnectionPtr joining_connection;
    bool bootstrap_and_drop(handshake_packet.ConnectionReason() == Session::kBootstrapAndDrop);
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto itr(FindConnection(handshake_packet.node_id()));
      if (itr != connections_.end() && !bootstrap_and_drop)
        joining_connection = *itr;
    }
    if (joining_connection) {
      LOG(kWarning) << DebugId(kThisNodeId_) << " received another bootstrap connection request "
                    << "from currently connected peer " << DebugId(handshake_packet.node_id())
                    << " - " << endpoint << " - closing connection.";
      joining_connection->Close();
    } else {
      // Joining node is not already connected - start new bootstrap or temporary connection
      Connect(
          handshake_packet.node_id(), endpoint, "", Parameters::bootstrap_connect_timeout,
          bootstrap_and_drop ? bptime::time_duration() : Parameters::bootstrap_connection_lifespan);
    }
    return;
  }
}

bool ConnectionManager::MakeConnectionPermanent(const NodeId& peer_id, bool validated,
                                                Endpoint& peer_endpoint) {
  peer_endpoint = Endpoint();
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr(FindConnection(peer_id));
  if (itr == connections_.end()) {
    LOG(kWarning) << DebugId(kThisNodeId_) << " Not currently connected to " << DebugId(peer_id);
    return false;
  }
  (*itr)->MakePermanent(validated);
  // TODO(Fraser#5#): 2012-09-11 - Handle passing back peer_endpoint iff it's direct-connected.
  if (!OnPrivateNetwork((*itr)->Socket().PeerEndpoint()))
    peer_endpoint = (*itr)->Socket().PeerEndpoint();
  return true;
}

Endpoint ConnectionManager::ThisEndpoint(const NodeId& peer_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr(FindConnection(peer_id));
  if (itr == connections_.end())
    return Endpoint();
  return (*itr)->Socket().ThisEndpoint();
}

void ConnectionManager::SetBestGuessExternalEndpoint(const Endpoint& external_endpoint) {
  multiplexer_->best_guess_external_endpoint_ = external_endpoint;
}

Endpoint ConnectionManager::RemoteNatDetectionEndpoint(const NodeId& peer_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr(FindConnection(peer_id));
  if (itr == connections_.end())
    return Endpoint();
  return (*itr)->Socket().RemoteNatDetectionEndpoint();
}

uint32_t ConnectionManager::AddSocket(Socket* socket) {
  // Generate a new unique id for the socket.
  uint32_t id = 0;
  while (id == 0 || sockets_.find(id) != sockets_.end())
    id = RandomUint32();

  sockets_[id] = socket;
  return id;
}

void ConnectionManager::RemoveSocket(uint32_t id) {
//  std::unique_lock<std::mutex> lock(mutex_);
  LOG(kVerbose) << "removing socket " << id;
  if (id)
    sockets_.erase(id);
}

size_t ConnectionManager::NormalConnectionsCount() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return connections_.size();
}

ConnectionManager::ConnectionGroup::iterator ConnectionManager::FindConnection(
    const NodeId& peer_id) const {
  assert(!mutex_.try_lock());
  return std::find_if(connections_.begin(), connections_.end(),
                      [&peer_id](const ConnectionPtr & connection) {
    return connection->Socket().PeerNodeId() == peer_id;
  });
}

NodeId ConnectionManager::node_id() const { return kThisNodeId_; }

std::shared_ptr<asymm::PublicKey> ConnectionManager::public_key() const { return this_public_key_; }

std::string ConnectionManager::DebugString() {
  std::string s;
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto c : connections_) {
    s += "\t\tPeer " + c->PeerDebugId();
    s += std::string("  ") + boost::lexical_cast<std::string>(c->state());
    s += std::string("   Expires in ") + bptime::to_simple_string(c->ExpiresFromNow()) + "\n";
  }
  return s;
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
