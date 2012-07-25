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
#include "maidsafe/rudp/packets/handshake_packet.h"
#include "maidsafe/rudp/parameters.h"
#include "maidsafe/rudp/utils.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace bptime = boost::posix_time;


namespace maidsafe {

namespace rudp {

namespace { typedef boost::asio::ip::udp::endpoint Endpoint; }


ConnectionManager::ConnectionManager(std::shared_ptr<Transport> transport,
                                     const boost::asio::io_service::strand& strand,
                                     MultiplexerPtr multiplexer)
    : transport_(transport),
      strand_(strand),
      multiplexer_(multiplexer) {
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
    connection->StartConnecting(validation_data, lifespan);
  }
}

int ConnectionManager::CloseConnection(const Endpoint& peer_endpoint) {
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(FindConnection(peer_endpoint));
  if (itr == connections_.end()) {
    LOG(kWarning) << "Not currently connected to " << peer_endpoint;
    return kInvalidConnection;
  }

  strand_.dispatch([=] { (*itr)->Close(); });  // NOLINT (Fraser)
  return kSuccess;
}

void ConnectionManager::Send(const Endpoint& peer_endpoint,
                             const std::string& message,
                             const std::function<void(bool)>& message_sent_functor) {  // NOLINT (Fraser)
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(FindConnection(peer_endpoint));
  if (itr == connections_.end()) {
    LOG(kWarning) << "Not currently connected to " << peer_endpoint;
    if (message_sent_functor) {
      strand_.get_io_service().dispatch([message_sent_functor] {
        message_sent_functor(false);
      });
    }
    return;
  }

  strand_.dispatch([=] { (*itr)->StartSending(message, message_sent_functor); });  // NOLINT (Fraser)
}

void ConnectionManager::HandleReceiveFrom(const asio::const_buffer &data,
                                          const Endpoint &joining_peer_endpoint) {
  detail::HandshakePacket handshake_packet;
  if (!handshake_packet.Decode(data)) {
    LOG(kVerbose) << "Failed to decode handshake packet from " << joining_peer_endpoint
                  << " which is trying to ping this node or join the network";
    return;
  }

  LOG(kVerbose) << "This is a handshake packet from " << joining_peer_endpoint
                << " which is trying to ping this node or join the network";
  if (IsValid(joining_peer_endpoint)) {
    // Check if this joining node is already connected
    ConnectionPtr joining_connection;
    {
      boost::mutex::scoped_lock lock(mutex_);
      auto itr(FindConnection(joining_peer_endpoint));
      if (itr != connections_.end())
        joining_connection = *itr;
    }
    if (joining_connection) {
      if (!joining_connection->IsTemporary()) {
        LOG(kWarning) << "Received another bootstrap connection request from currently "
                      << "connected endpoint " << joining_peer_endpoint << " - closing connection.";
        joining_connection->Close();
      }
    } else {
      // Joining node is not already connected - start new temporary connection
      Connect(joining_peer_endpoint, "", Parameters::bootstrap_disconnection_timeout);
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

void ConnectionManager::MakeConnectionPermanent(const Endpoint& peer_endpoint,
                                                const std::string& validation_data) {
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(FindConnection(peer_endpoint));
  if (itr == connections_.end()) {
    LOG(kWarning) << "Not currently connected to " << peer_endpoint;
    return;
  }
  (*itr)->MakePermanent();
  strand_.dispatch([=] { (*itr)->StartSending(validation_data, std::function<void(bool)>()); });  // NOLINT (Fraser)
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


}  // namespace rudp

}  // namespace maidsafe
