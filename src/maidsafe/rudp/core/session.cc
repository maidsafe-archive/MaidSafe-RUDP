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

#include "maidsafe/rudp/core/session.h"

#include <cassert>
#include "maidsafe/common/log.h"

#include "maidsafe/rudp/packets/data_packet.h"
#include "maidsafe/rudp/core/peer.h"
#include "maidsafe/rudp/core/sliding_window.h"
#include "maidsafe/rudp/core/tick_timer.h"
#include "maidsafe/rudp/nat_type.h"
#include "maidsafe/rudp/utils.h"

namespace bptime = boost::posix_time;


namespace maidsafe {

namespace rudp {

namespace detail {

Session::Session(Peer& peer,  // NOLINT (Fraser)
                 TickTimer& tick_timer,
                 boost::asio::ip::udp::endpoint& this_external_endpoint,
                 std::mutex& this_external_endpoint_mutex,
                 const boost::asio::ip::udp::endpoint& this_local_endpoint,
                 NatType& nat_type)
    : peer_(peer),
      tick_timer_(tick_timer),
      this_external_endpoint_(this_external_endpoint),
      this_external_endpoint_mutex_(this_external_endpoint_mutex),
      kThisLocalEndpoint_(this_local_endpoint),
      nat_type_(nat_type),
      this_node_id_(),
      this_public_key_(),
      id_(0),
      sending_sequence_number_(0),
      receiving_sequence_number_(0),
      peer_connection_type_(0),
      peer_requested_nat_detection_port_(false),
      peer_nat_detection_endpoint_(),
      mode_(kNormal),
      state_(kClosed),
      on_nat_detection_requested_(),
      signal_connection_() {}

void Session::Open(uint32_t id,
                   NodeId this_node_id,
                   std::shared_ptr<asymm::PublicKey> this_public_key,
                   uint32_t sequence_number,
                   Mode mode,
                   const OnNatDetectionRequested::slot_type& on_nat_detection_requested_slot) {
  assert(id != 0);
  assert(this_public_key);
  id_ = id;
  this_node_id_ = this_node_id;
  this_public_key_ = this_public_key;
  sending_sequence_number_ = sequence_number;
  mode_ = mode;
  state_ = kProbing;
  signal_connection_ = on_nat_detection_requested_.connect(on_nat_detection_requested_slot);
  SendConnectionRequest();
}

bool Session::IsOpen() const {
  return state_ != kClosed;
}

bool Session::IsConnected() const {
  return state_ == kConnected;
}

uint32_t Session::Id() const {
  return id_;
}

uint32_t Session::ReceivingSequenceNumber() const {
  return receiving_sequence_number_;
}

uint32_t Session::PeerConnectionType() const {
  return peer_connection_type_;
}

void Session::Close() {
  signal_connection_.disconnect();
  state_ = kClosed;
}

void Session::HandleHandshake(const HandshakePacket& packet) {
  if (peer_.SocketId() == 0)
    peer_.SetSocketId(packet.SocketId());

  if (packet.node_id() == NodeId()) {
    LOG(kError) << "ZeroId passed in handshake packet from peer " << DebugId(peer_.node_id());
    return;
  }

  if (peer_.node_id() == NodeId()) {
    peer_.set_node_id(packet.node_id());
  } else if (peer_.node_id() != packet.node_id()) {
    LOG(kError) << "Expected handshake from " << DebugId(peer_.node_id())
                << " but got handshake from " << DebugId(packet.node_id());
    return;
  }

  // TODO(Fraser#5#): 2012-04-04 - Handle SynCookies
  if (state_ == kProbing) {
//    if (packet.ConnectionType() == 1 && packet.SynCookie() == 0)
    state_ = kHandshaking;
    peer_requested_nat_detection_port_ = packet.RequestNatDetectionPort();
    SendCookie();
  } else if (state_ == kHandshaking) {
    if (packet.InitialPacketSequenceNumber() == 0) {
      LOG(kVerbose) << "Received duplicate ConnectionRequest from " << peer_.PeerEndpoint()
                    << "  Waiting for Cookie.";
      return;
    }

//    if (packet.SynCookie() == 1) {
    peer_.SetThisEndpoint(packet.PeerEndpoint());
    if (!CalculateEndpoint())
      return;

    if (!packet.PublicKey()) {
      LOG(kError) << "Handshake packet is missing peer's public key";
      state_ = kClosed;
      return;
    }

    state_ = kConnected;
    peer_connection_type_ = packet.ConnectionType();
    receiving_sequence_number_ = packet.InitialPacketSequenceNumber();
    peer_.SetPublicKey(packet.PublicKey());
    if (packet.NatDetectionPort() != 0) {
      peer_nat_detection_endpoint_ = boost::asio::ip::udp::endpoint(peer_.PeerEndpoint().address(),
                                                                    packet.NatDetectionPort());
    }

    if (mode_ == kBootstrapAndDrop)
      return;

    if (packet.ConnectionReason() != kNormal && mode_ == kNormal)
      mode_ = static_cast<Mode>(packet.ConnectionReason());
    if (packet.ConnectionReason() == kBootstrapAndDrop && mode_ == kBootstrapAndKeep)
      mode_ = kBootstrapAndDrop;

    SendCookie();
//    }
  }
}

bool Session::CalculateEndpoint() {
  if (!IsValid(peer_.ThisEndpoint())) {
    LOG(kError) << "Invalid reported external endpoint in handshake: " << peer_.ThisEndpoint();
    state_ = kClosed;
    return false;
  }

  std::lock_guard<std::mutex> lock(this_external_endpoint_mutex_);
  if (!IsValid(this_external_endpoint_)) {
    if (!OnSameLocalNetwork(kThisLocalEndpoint_, peer_.PeerEndpoint())) {
      // This is the first non-local connection on this transport.
      this_external_endpoint_ = peer_.ThisEndpoint();
      LOG(kVerbose) << "Setting this external endpoint to " << this_external_endpoint_
                    << " as viewed by peer at " << peer_.PeerEndpoint();
    } else {
      LOG(kVerbose) << "Can't establish external endpoint, peer on same network as this node.";
    }
  } else {
    if (this_external_endpoint_ == peer_.ThisEndpoint()) {
      if (nat_type_ == NatType::kSymmetric) {
        LOG(kError) << "NAT type has been set to symmetric, but peer at " << peer_.PeerEndpoint()
                    << " is reporting our endpoint as " << peer_.ThisEndpoint()
                    << " which is what it's already been reported as by another peer.";
      }
      nat_type_ = NatType::kOther;
    } else {
      // Check to see if our external address has changed
      if (OnSameLocalNetwork(kThisLocalEndpoint_, peer_.PeerEndpoint())) {
        LOG(kError) << "This external address is currently " << this_external_endpoint_
                    << " and local is " << kThisLocalEndpoint_ << ", but peer at "
                    << peer_.PeerEndpoint() << " is reporting our endpoint as "
                    << peer_.ThisEndpoint();
      } else {
        // This external address has possibly changed (or the peer is lying), but probably this
        // means this node is behind symmetric NAT.
        LOG(kWarning) << "This external address is currently " << this_external_endpoint_
                      << ", but peer at " << peer_.PeerEndpoint()
                      << " is reporting our endpoint as " << peer_.ThisEndpoint()
                      << " - setting NAT type to symmetric.";
        nat_type_ = NatType::kSymmetric;
      }
    }
  }
  return true;
}

void Session::HandleTick() {
  if (state_ == kProbing) {
    SendConnectionRequest();
  } else if (state_ == kHandshaking) {
    SendCookie();
  }
}

void Session::SendConnectionRequest() {
  HandshakePacket packet;
  packet.SetRudpVersion(4);
  packet.SetSocketType(HandshakePacket::kStreamSocketType);
  packet.SetSocketId(id_);
  packet.set_node_id(this_node_id_);
  packet.SetPeerEndpoint(peer_.PeerEndpoint());
  packet.SetDestinationSocketId(0);
  packet.SetConnectionType(1);
  packet.SetConnectionReason(mode_);
  packet.SetRequestNatDetectionPort(nat_type_ == NatType::kUnknown &&
                                    !OnPrivateNetwork(peer_.PeerEndpoint()));

  int result(peer_.Send(packet));
  if (result != kSuccess)
    LOG(kError) << "Failed to send handshake to " << peer_.PeerEndpoint();

  // Schedule another connection request.
  tick_timer_.TickAfter(bptime::milliseconds(250));
}

void Session::SendCookie() {
  HandshakePacket packet;
  packet.SetPeerEndpoint(peer_.PeerEndpoint());
  packet.SetDestinationSocketId(peer_.SocketId());
  packet.SetRudpVersion(4);
  packet.SetSocketType(HandshakePacket::kStreamSocketType);
  packet.SetInitialPacketSequenceNumber(sending_sequence_number_);
  packet.SetMaximumPacketSize(Parameters::max_size);
  packet.SetMaximumFlowWindowSize(Parameters::maximum_window_size);
  packet.SetConnectionType(Parameters::connection_type);
  packet.SetSocketId(id_);
  packet.set_node_id(this_node_id_);
  packet.SetSynCookie(1);  // TODO(Team) calculate cookie
  packet.SetRequestNatDetectionPort(false);
  uint16_t port(0);
  if (peer_requested_nat_detection_port_)
    on_nat_detection_requested_(kThisLocalEndpoint_, peer_.node_id(), peer_.PeerEndpoint(), port);
  packet.SetNatDetectionPort(port);
  packet.SetPublicKey(this_public_key_);

  int result(peer_.Send(packet));
  if (result != kSuccess)
    LOG(kError) << "Failed to send cookie to " << peer_.PeerEndpoint();

  // Schedule another cookie send.
  tick_timer_.TickAfter(bptime::milliseconds(250));
}

void Session::MakePermanent() {
  mode_ = kNormal;
}

Session::Mode Session::mode() const {
  return mode_;
}

boost::asio::ip::udp::endpoint Session::RemoteNatDetectionEndpoint() const {
  return peer_nat_detection_endpoint_;
}


}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
