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

#include "maidsafe/rudp/core/dispatcher.h"

#include <cassert>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/connection_manager.h"
#include "maidsafe/rudp/packets/packet.h"
#include "maidsafe/rudp/core/socket.h"

namespace asio = boost::asio;
namespace ip = asio::ip;

namespace maidsafe {

namespace rudp {

namespace detail {

Dispatcher::Dispatcher() : sockets_(), connection_manager_(nullptr) {}

void Dispatcher::SetConnectionManager(ConnectionManager* connection_manager) {
  connection_manager_ = connection_manager;
}

uint32_t Dispatcher::AddSocket(Socket *socket) {
  // Generate a new unique id for the socket.
  uint32_t id = 0;
  while (id == 0 || id == 0xffffffff || sockets_.find(id) != sockets_.end())
    id = RandomUint32();

  sockets_[id] = socket;
  return id;
}

void Dispatcher::RemoveSocket(uint32_t id) {
  if (id)
    sockets_.erase(id);
}

void Dispatcher::HandleReceiveFrom(const asio::const_buffer &data,
                                   const ip::udp::endpoint &endpoint) {
  uint32_t id(0);
  if (!Packet::DecodeDestinationSocketId(&id, data)) {
    LOG(kError) << "Received a non-RUDP packet from " << endpoint;
    return;
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
      if (connection_manager_)
        connection_manager_->HandleReceiveFrom(data, endpoint);
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
    socket_iter->second->HandleReceiveFrom(data, endpoint);
  } else {
    const unsigned char* p = asio::buffer_cast<const unsigned char*>(data);
    LOG(kInfo) << "Received a packet \"0x" << std::hex << static_cast<int>(*p) << std::dec
                << "\" for unknown connection " << id << " from " << endpoint;
  }
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
