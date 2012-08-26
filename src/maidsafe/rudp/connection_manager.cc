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

#include "maidsafe/rudp/connection_manager.h"

#include <algorithm>
#include <cassert>

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

namespace { typedef boost::asio::ip::udp::endpoint Endpoint; }


ConnectionManager::ConnectionManager(std::shared_ptr<Transport> transport,
                                     const boost::asio::io_service::strand& strand,
                                     MultiplexerPtr multiplexer,
                                     std::shared_ptr<asymm::PublicKey> this_public_key)
    : connections_(),
      mutex_(),
      transport_(transport),
      strand_(strand),
      multiplexer_(multiplexer),
      this_public_key_(this_public_key),
      sockets_() {
  multiplexer_->dispatcher_.SetConnectionManager(this);
}

ConnectionManager::~ConnectionManager() {
  Close();
}

void ConnectionManager::Close() {
  multiplexer_->dispatcher_.SetConnectionManager(nullptr);
  boost::mutex::scoped_lock lock(mutex_);
  for (auto it = connections_.begin(); it != connections_.end(); ++it)
    strand_.post(std::bind(&Connection::Close, *it));
}

void ConnectionManager::Connect(const Endpoint& peer_endpoint,
                                const std::string& validation_data,
                                const bptime::time_duration& lifespan) {
  if (std::shared_ptr<Transport> transport = transport_.lock()) {
    ConnectionPtr connection(std::make_shared<Connection>(transport, strand_, multiplexer_,
                                                          peer_endpoint));
    connection->StartConnecting(this_public_key_, validation_data, lifespan);
  }
}

int ConnectionManager::CloseConnection(const Endpoint& peer_endpoint) {
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(FindConnection(peer_endpoint));
  if (itr == connections_.end()) {
    LOG(kWarning) << "Not currently connected to " << peer_endpoint;
    return kInvalidConnection;
  }

  ConnectionPtr connection(*itr);
  strand_.dispatch([=] { connection->Close(); });  // NOLINT (Fraser)
  return kSuccess;
}

void ConnectionManager::Ping(const boost::asio::ip::udp::endpoint& peer_endpoint,
                             const std::function<void(int)> &ping_functor) {  // NOLINT (Fraser)
  if (std::shared_ptr<Transport> transport = transport_.lock()) {
    assert(ping_functor);
    ConnectionPtr connection(std::make_shared<Connection>(transport, strand_, multiplexer_,
                                                          peer_endpoint));
    connection->Ping(this_public_key_, ping_functor);
  }
}

void ConnectionManager::Send(const Endpoint& peer_endpoint,
                             const std::string& message,
                             const std::function<void(int)>& message_sent_functor) {  // NOLINT (Fraser)
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(FindConnection(peer_endpoint));
  if (itr == connections_.end()) {
    LOG(kWarning) << "Not currently connected to " << peer_endpoint;
    if (message_sent_functor) {
      strand_.get_io_service().dispatch([message_sent_functor] {
        message_sent_functor(kInvalidConnection);
      });
    }
    return;
  }

  ConnectionPtr connection(*itr);
  strand_.dispatch([=] { connection->StartSending(message, message_sent_functor); });  // NOLINT (Fraser)
}

Socket* ConnectionManager::GetSocket(const asio::const_buffer& data, const Endpoint& endpoint) {
  uint32_t id(0);
  if (!Packet::DecodeDestinationSocketId(&id, data)) {
    LOG(kError) << "Received a non-RUDP packet from " << endpoint;
    return nullptr;
  }

  SocketMap::const_iterator socket_iter(sockets_.end());
  if (id == 0) {
    // This is a handshake packet on a newly-added socket
    LOG(kVerbose) << "This is a handshake packet on a newly-added socket from " << endpoint;
    socket_iter = std::find_if(
        sockets_.begin(),
        sockets_.end(),
        [endpoint](const SocketMap::value_type& socket_pair) {
          return socket_pair.second->RemoteEndpoint() == endpoint;
        });
  } else if (id == 0xffffffff) {
    socket_iter = std::find_if(
        sockets_.begin(),
        sockets_.end(),
        [endpoint](const SocketMap::value_type& socket_pair) {
          return socket_pair.second->RemoteEndpoint() == endpoint;
        });
    if (socket_iter == sockets_.end()) {
      // This is a handshake packet from a peer trying to ping this node or join the network
      HandlePingFrom(data, endpoint);
      return nullptr;
    } else {
      if (sockets_.size() == 1U) {
        // This is a handshake packet from a peer replying to this node's join attempt,
        // or from a peer starting a zero state network with this node
        LOG(kVerbose) << "This is a handshake packet from " << endpoint
                      << " which is replying to a join request, or starting a new network";
      } else {
        LOG(kVerbose) << "This is a handshake packet from " << endpoint
                      << " which is replying to a ping request";
      }
    }
  } else {
    // This packet is intended for a specific connection.
    socket_iter = sockets_.find(id);
  }

  if (socket_iter != sockets_.end()) {
    return socket_iter->second/*->HandleReceiveFrom(data, endpoint)*/;
  } else {
    const unsigned char* p = asio::buffer_cast<const unsigned char*>(data);
    LOG(kInfo) << "Received a packet \"0x" << std::hex << static_cast<int>(*p) << std::dec
                << "\" for unknown connection " << id << " from " << endpoint;
    return nullptr;
  }
}

void ConnectionManager::HandlePingFrom(const asio::const_buffer& data, const Endpoint& endpoint) {
  HandshakePacket handshake_packet;
  if (!handshake_packet.Decode(data)) {
    LOG(kVerbose) << "Failed to decode handshake packet from " << endpoint
                  << " which is trying to ping this node or join the network";
    return;
  }

  LOG(kVerbose) << "This is a handshake packet from " << endpoint
                << " which is trying to ping this node or join the network";
  if (IsValid(endpoint)) {
    // Check if this joining node is already connected
    ConnectionPtr joining_connection;
    {
      boost::mutex::scoped_lock lock(mutex_);
      auto itr(FindConnection(endpoint));
      if (itr != connections_.end())
        joining_connection = *itr;
    }
    if (joining_connection) {
      if (!joining_connection->IsTemporary()) {
        LOG(kWarning) << "Received another bootstrap connection request from currently "
                      << "connected endpoint " << endpoint << " - closing connection.";
        joining_connection->Close();
      }
    } else {
      // Joining node is not already connected - start new temporary connection
      Connect(endpoint, "", Parameters::bootstrap_disconnection_timeout);
    }
    return;
  }
}

bool ConnectionManager::IsTemporaryConnection(const Endpoint& peer_endpoint) {
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(FindConnection(peer_endpoint));
  if (itr == connections_.end())
    return false;
  return (*itr)->IsTemporary();
}

bool ConnectionManager::MakeConnectionPermanent(const Endpoint& peer_endpoint,
                                                const std::string& validation_data) {
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(FindConnection(peer_endpoint));
  if (itr == connections_.end()) {
    LOG(kWarning) << "Not currently connected to " << peer_endpoint;
    return false;
  }

  ConnectionPtr connection(*itr);
  connection->MakePermanent();
  strand_.dispatch([=] {
      connection->StartSending(validation_data,
          [](int result) {
              if (result != kSuccess) {
                LOG(kWarning) << "Failed to send validation data while making permanent.  Result: "
                              << result;
              }
          });
      });
  return true;
}

Endpoint ConnectionManager::ThisEndpoint(const Endpoint& peer_endpoint) {
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(FindConnection(peer_endpoint));
  if (itr == connections_.end())
    return ip::udp::endpoint();
  return (*itr)->Socket().ThisEndpoint();
}

uint32_t ConnectionManager::AddSocket(Socket* socket) {
  // Generate a new unique id for the socket.
  uint32_t id = 0;
  while (id == 0 || id == 0xffffffff || sockets_.find(id) != sockets_.end())
    id = RandomUint32();

  sockets_[id] = socket;
  return id;
}

void ConnectionManager::RemoveSocket(uint32_t id) {
  if (id)
    sockets_.erase(id);
}

size_t ConnectionManager::size() const {
  boost::mutex::scoped_lock lock(mutex_);
  return connections_.size();
}

void ConnectionManager::InsertConnection(ConnectionPtr connection) {
  boost::mutex::scoped_lock lock(mutex_);
  connections_.insert(connection);
}

void ConnectionManager::RemoveConnection(ConnectionPtr connection,
                                         bool& connections_empty,
                                         bool& temporary_connection) {
  boost::mutex::scoped_lock lock(mutex_);
  connections_.erase(connection);
  connections_empty = connections_.empty();
  temporary_connection = connection->IsTemporary();
}

ConnectionManager::ConnectionSet::iterator ConnectionManager::FindConnection(
    const Endpoint& peer_endpoint) {
  assert(!mutex_.try_lock());
  return std::find_if(connections_.begin(),
                      connections_.end(),
                      [&peer_endpoint](const ConnectionPtr& connection) {
                        return connection->Socket().RemoteEndpoint() == peer_endpoint;
                      });
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
