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

#ifndef MAIDSAFE_RUDP_CORE_PEER_H_
#define MAIDSAFE_RUDP_CORE_PEER_H_

#include <cstdint>

#include "boost/asio/ip/udp.hpp"
#include "maidsafe/common/log.h"
#include "maidsafe/common/node_id.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/rudp/core/multiplexer.h"


namespace maidsafe {

namespace rudp {

namespace detail {

class Peer {
 public:
  explicit Peer(Multiplexer& multiplexer)
      : multiplexer_(multiplexer),
        peer_endpoint_(),
        this_endpoint_(),
        socket_id_(0),
        node_id_(),
        public_key_(),
        peer_guessed_port_(0) {}

  // Endpoint of peer
  const boost::asio::ip::udp::endpoint& PeerEndpoint() const { return peer_endpoint_; }
  void SetPeerEndpoint(const boost::asio::ip::udp::endpoint& ep) { peer_endpoint_ = ep; }

  // This node's endpoint as viewed by peer
  const boost::asio::ip::udp::endpoint& ThisEndpoint() const { return this_endpoint_; }
  void SetThisEndpoint(const boost::asio::ip::udp::endpoint& ep) { this_endpoint_ = ep; }

  uint32_t SocketId() const { return socket_id_; }
  void SetSocketId(uint32_t id) { socket_id_ = id; }

  NodeId node_id() const { return node_id_; }
  void set_node_id(NodeId node_id) { node_id_ = node_id; }

  std::shared_ptr<asymm::PublicKey> public_key() const { return public_key_; }
  void SetPublicKey(std::shared_ptr<asymm::PublicKey> public_key) {
    assert(asymm::ValidateKey(*public_key));
    public_key_ = public_key;
  }

  uint16_t PeerGuessedPort() const { return peer_guessed_port_; }
  void SetPeerGuessedPort() { peer_guessed_port_ = peer_endpoint_.port(); }

  template <typename Packet>
  ReturnCode Send(const Packet& packet) { return multiplexer_.SendTo(packet, peer_endpoint_); }

 private:
  // Disallow copying and assignment.
  Peer(const Peer&);
  Peer& operator=(const Peer&);

  // The multiplexer used to send and receive UDP packets.
  Multiplexer& multiplexer_;
  // The remote socket's endpoint.
  boost::asio::ip::udp::endpoint peer_endpoint_;
  // This node's socket endpoint as seen by peer.
  boost::asio::ip::udp::endpoint this_endpoint_;
  // The remote socket's identifier.
  uint32_t socket_id_;
  // The remote peer's NodeId.
  NodeId node_id_;
  // The remote peer's PublicKey.
  std::shared_ptr<asymm::PublicKey> public_key_;
  // The port originally guessed by the peer when passing its details to this node.  This will be
  // set by the ConnectionManager if it detects that the peer's actual external port is different to
  // the one provided by the peer as its best guess.
  uint16_t peer_guessed_port_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CORE_PEER_H_
