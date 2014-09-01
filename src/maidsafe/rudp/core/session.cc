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

#include "maidsafe/rudp/core/session.h"

#include <cassert>

#include "maidsafe/common/log.h"

#include "maidsafe/rudp/utils.h"
#include "maidsafe/rudp/core/peer.h"
#include "maidsafe/rudp/core/sliding_window.h"
#include "maidsafe/rudp/core/tick_timer.h"
#include "maidsafe/rudp/packets/data_packet.h"
#include "maidsafe/rudp/packets/handshake_packet.h"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

namespace detail {

Session::Session(Peer& peer, TickTimer& tick_timer,
                 boost::asio::ip::udp::endpoint& this_external_endpoint,
                 std::mutex& this_external_endpoint_mutex,
                 boost::asio::ip::udp::endpoint this_local_endpoint, NatType& nat_type)
    : peer_(peer),
      tick_timer_(tick_timer),
      this_external_endpoint_(this_external_endpoint),
      this_external_endpoint_mutex_(this_external_endpoint_mutex),
      kThisLocalEndpoint_(std::move(this_local_endpoint)),
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
      his_estimated_state_(kClosed),
      cookie_retries_togo_(0),
      my_cookie_syn_(0),
      his_cookie_syn_(0),
      on_nat_detection_requested_(),
      signal_connection_() {}

uint32_t Session::Open(uint32_t id, NodeId this_node_id,
                   std::shared_ptr<asymm::PublicKey> this_public_key, uint32_t sequence_number,
                   Mode mode, uint32_t cookie_syn,
                   const OnNatDetectionRequested::slot_type& on_nat_detection_requested_slot) {
  assert(id != 0);
  assert(this_public_key);
  if (state_ != kClosed) {
    LOG(kError) << "FATAL EXIT: Session was opened when not closed. Something is wrong, so "
    "terminating process in case someone is trying to hijack the connection.";
    std::terminate();
  }
  id_ = id;
  this_node_id_ = this_node_id;
  this_public_key_ = this_public_key;
  sending_sequence_number_ = sequence_number;
  mode_ = mode;
  cookie_retries_togo_ = Parameters::maximum_handshake_failures;
  // Ping requests may, rarely, connect before the main connection, thus upsetting the
  // SYN cookie.
  if (cookie_syn) {
    my_cookie_syn_ = cookie_syn;
  } else {
    crypto::random_number_generator().GenerateBlock(reinterpret_cast<uint8_t *>(&my_cookie_syn_),
                                                    sizeof(my_cookie_syn_));
    if (!my_cookie_syn_) my_cookie_syn_ = 0xdeadbeef;
  }
  his_cookie_syn_ = 0;
  signal_connection_ = on_nat_detection_requested_.connect(on_nat_detection_requested_slot);
  LOG(kInfo) << "Session::Open(" << id << ", " << DebugId(this_node_id) << ", key, "
             << sequence_number << ", " << mode << ", " << cookie_syn << ", " <<
             on_nat_detection_requested_slot.slot_function() << ") @ " << this << ", will "
             "use cookie syn " << my_cookie_syn_ << " and NAT type " << nat_type_;

  // 2014-8-25 ned: This must remain below everything else, otherwise a race appears
  //                where the other side may set a syn cookie and received an initial
  //                handshake with the wrong syn cookie before I have set the syn cookie.
  his_estimated_state_ = kProbing;
  state_ = kProbing;
  SendConnectionRequest();
  return my_cookie_syn_;
}

bool Session::IsOpen() const { return state_ != kClosed; }

bool Session::IsConnected() const { return state_ == kConnected; }

uint32_t Session::Id() const { return id_; }

uint32_t Session::ReceivingSequenceNumber() const { return receiving_sequence_number_; }

uint32_t Session::PeerConnectionType() const { return peer_connection_type_; }

void Session::Close() {
  LOG(kInfo) << "Closing session to peer " << DebugId(peer_.node_id());
  signal_connection_.disconnect();
  state_ = kClosed;
}

void Session::HandleHandshakeWhenProbing(const HandshakePacket& packet) {
  if (packet.ConnectionType() == 2)  // is connected handshake
    return;
  else if (packet.ConnectionType() == 1) {  // is initial handshake
    if (his_cookie_syn_) {
      if (his_cookie_syn_ != packet.SynCookie())
        LOG(kWarning) << "Received initial handshake from "
          << DebugId(peer_.node_id()) << " with unrecognised cookie syn "
          << packet.SynCookie() << ", so ignoring the handshake.";
      return;
    }
    if (!his_cookie_syn_) {
      LOG(kInfo) << "Received valid and expected initial handshake from "
        << DebugId(peer_.node_id()) << " with cookie syn " << packet.SynCookie();
      his_cookie_syn_ = packet.SynCookie();
    }
    state_ = kHandshaking;
    peer_requested_nat_detection_port_ = packet.RequestNatDetectionPort();
    SendCookie();
  } else {  // is second stage handshake
    if (his_cookie_syn_ && packet.SynCookie() != my_cookie_syn_) {
      LOG(kWarning) << "Ignoring handshake packet from peer "
        << DebugId(peer_.node_id()) << " which did not use my cookie syn, cookie_retries="
        << cookie_retries_togo_;
      return;
    } else if (!his_cookie_syn_) {
      LOG(kWarning) << "Received second stage handshake from "
        << DebugId(peer_.node_id()) << " before receiving an "
        "initial handshake. As we don't have their syn cookie we cannot "
        "communicate with them, so ignoring the handshake.";
      return;
    }
    // Falls through if his_cookie_syn_ and packet cookie matches mine
    HandleHandshakeWhenHandshaking(packet);
  }
}

void Session::HandleHandshakeWhenHandshaking(const HandshakePacket& packet) {
  if (packet.InitialPacketSequenceNumber() == 0) {
    LOG(kVerbose) << "Received duplicate ConnectionRequest of type "
                  << packet.ConnectionType() << " from " << peer_.PeerEndpoint();
  }

  peer_.SetThisEndpoint(packet.PeerEndpoint());
  if (!CalculateEndpoint())
    return;

  if (!packet.PublicKey()) {
    LOG(kError) << "Handshake packet is missing peer's public key";
    state_ = kClosed;
    return;
  }

  bool quick_cookie = (state_ != kConnected);
  state_ = kConnected;
  if (his_estimated_state_ < kHandshaking)
    his_estimated_state_ = kHandshaking;
  peer_connection_type_ = packet.ConnectionType();
  receiving_sequence_number_ = packet.InitialPacketSequenceNumber();
  peer_.SetPublicKey(packet.PublicKey());
  if (packet.NatDetectionPort() != 0) {
    peer_nat_detection_endpoint_ =
        boost::asio::ip::udp::endpoint(peer_.PeerEndpoint().address(), packet.NatDetectionPort());
  }

  if (mode_ == kBootstrapAndDrop)
    return;

  if (packet.ConnectionReason() != kNormal && mode_ == kNormal)
    mode_ = static_cast<Mode>(packet.ConnectionReason());
  if (packet.ConnectionReason() == kBootstrapAndDrop && mode_ == kBootstrapAndKeep)
    mode_ = kBootstrapAndDrop;

  // For speed of connection under packet loss, if this was the first second stage handshake
  // received, immediately send a duplicate second stage handshake followed by stop handshaking
  if (quick_cookie) {
    SendCookie();
    SendConnected();
  }
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
    // This will happen if this node has assigned a proxy ID to peer.
    LOG(kError) << "Expected handshake from " << DebugId(peer_.node_id())
                << " but got handshake from " << DebugId(packet.node_id());
    state_ = kClosed;
    return;
  }

  if (state_ == kClosed) {
    LOG(kWarning) << "Ignoring handshake packet from " << DebugId(packet.node_id())
      << " as connection is closed.";
    return;
  }
  if (state_ != kConnected && cookie_retries_togo_ == 0) {
    LOG(kWarning) << "Number of handshakes from " << DebugId(peer_.node_id()) << " has "
      "exceeded limit without connection, closing connection in case this is a DDoS attempt.";
    state_ = kClosed;
    return;
  }

  if (his_estimated_state_ == kProbing) {
    // Should be an initial handshake packet with his syn cookie. We go to kHandshaking
    // state, send out second stage handshake packet with his syn cookie and await his
    // second stage handshake packet with our syn cookie.
    //
    // Note that if it isn't an initial handshaking packet, HandleHandshakeWhenProbing
    // will kill the connection.
    HandleHandshakeWhenProbing(packet);  // starts 250ms timer which sends handshake
    return;                              // until connected
  }

  // Ignore flood attacks or attempts to hijack the connection
  if (packet.SynCookie() != my_cookie_syn_) {
    LOG(kWarning) << "Ignoring second stage handshake packet from peer "
      << DebugId(peer_.node_id()) << " which did not use my cookie syn, cookie_retries="
      << cookie_retries_togo_;
    return;
  }
  if (!his_cookie_syn_) {
    LOG(kWarning) << "Ignoring second stage handshake from "
      << DebugId(peer_.node_id()) << " as we don't have their syn cookie.";
    return;
  }

  if (packet.ConnectionType() == 2) {  // is connected handshake
    LOG(kInfo) << "Received stop handshaking message from " << DebugId(peer_.node_id());
    his_estimated_state_ = kConnected;
  } else if (state_ == kHandshaking) {
    // Should be a second stage handshake packet, as if our second stage handshake
    // got lost it'll be another initial handshake packet which got filtered out above.
    // Let the timer retry the second stage packet resend for us.
    HandleHandshakeWhenHandshaking(packet);
  } else {
    LOG(kInfo) << "Received spurious "
      << ((packet.ConnectionType() == 1) ? "initial" : "second stage")
      << " handshake packet when my state is " << state_ << " from "
      << DebugId(peer_.node_id()) << ", cookie_retries=" << cookie_retries_togo_;
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
  if (cookie_retries_togo_) {
    if (state_ == kProbing || his_estimated_state_ == kProbing)
      SendConnectionRequest();
    if (state_ == kHandshaking || his_estimated_state_ == kHandshaking)
      SendCookie();
    if (state_ == kConnected && his_estimated_state_ == kHandshaking)
      SendConnected();
  }
}

void Session::SendConnectionRequest() {
  if (cookie_retries_togo_)
    --cookie_retries_togo_;
  HandshakePacket packet;
  packet.SetRudpVersion(4);
  packet.SetSocketType(HandshakePacket::kStreamSocketType);
  packet.SetSocketId(id_);
  packet.set_node_id(this_node_id_);
  packet.SetSynCookie(my_cookie_syn_);
  packet.SetPeerEndpoint(peer_.PeerEndpoint());
  packet.SetDestinationSocketId(0);
  packet.SetConnectionType(1);
  packet.SetConnectionReason(mode_);
  packet.SetRequestNatDetectionPort(nat_type_ == NatType::kUnknown &&
                                    !OnPrivateNetwork(peer_.PeerEndpoint()));

  LOG(kInfo) << "I am " << DebugId(this_node_id_) << " sending initial handshake packet to "
    << DebugId(peer_.node_id()) << " with my cookie syn " << my_cookie_syn_;
  int result(peer_.Send(packet));
  if (result != kSuccess)
    LOG(kError) << "Failed to send handshake to " << peer_.PeerEndpoint();

  // Schedule another connection request.
  tick_timer_.TickAfter(bptime::milliseconds(250));
}

void Session::SendCookie() {
  if (cookie_retries_togo_)
    --cookie_retries_togo_;
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
  packet.SetSynCookie(his_cookie_syn_);
  packet.SetRequestNatDetectionPort(false);
  uint16_t port(0);
  if (peer_requested_nat_detection_port_)
    on_nat_detection_requested_(kThisLocalEndpoint_, peer_.node_id(), peer_.PeerEndpoint(), port);
  packet.SetNatDetectionPort(port);
  packet.SetPublicKey(this_public_key_);

  LOG(kInfo) << "I am " << DebugId(this_node_id_) << " sending second stage handshake packet to "
    << DebugId(peer_.node_id()) << " with his cookie syn " << his_cookie_syn_;
  int result(peer_.Send(packet));
  if (result != kSuccess)
    LOG(kError) << "Failed to send cookie to " << peer_.PeerEndpoint();

  // Schedule another cookie send.
  tick_timer_.TickAfter(bptime::milliseconds(250));
}

void Session::SendConnected() {
  if (cookie_retries_togo_)
    --cookie_retries_togo_;
  HandshakePacket packet;
  packet.SetPeerEndpoint(peer_.PeerEndpoint());
  packet.SetDestinationSocketId(peer_.SocketId());
  packet.SetRudpVersion(4);
  packet.SetSocketType(HandshakePacket::kStreamSocketType);
  packet.SetSynCookie(his_cookie_syn_);
  packet.SetConnectionType(2);
  packet.SetSocketId(id_);
  packet.set_node_id(this_node_id_);
  packet.SetSynCookie(his_cookie_syn_);
  packet.SetRequestNatDetectionPort(false);

  LOG(kInfo) << "I am " << DebugId(this_node_id_) << " sending stop handshake packet to "
    << DebugId(peer_.node_id()) << " with his cookie syn " << his_cookie_syn_;
  int result(peer_.Send(packet));
  if (result != kSuccess)
    LOG(kError) << "Failed to send handshake to " << peer_.PeerEndpoint();

  // Schedule another connection request.
  tick_timer_.TickAfter(bptime::milliseconds(250));
}

void Session::MakeNormal() { mode_ = kNormal; }

Session::Mode Session::mode() const { return mode_; }

boost::asio::ip::udp::endpoint Session::RemoteNatDetectionEndpoint() const {
  return peer_nat_detection_endpoint_;
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
