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
#include "maidsafe/rudp/utils.h"

namespace bptime = boost::posix_time;


namespace maidsafe {

namespace rudp {

namespace detail {

Session::Session(Peer& peer,  // NOLINT (Fraser)
                 TickTimer& tick_timer,
                 boost::asio::ip::udp::endpoint& this_external_endpoint)
    : peer_(peer),
      tick_timer_(tick_timer),
      this_external_endpoint_(this_external_endpoint),
      id_(0),
      this_public_key_(),
      sending_sequence_number_(0),
      receiving_sequence_number_(0),
      peer_connection_type_(0),
      mode_(kNormal),
      state_(kClosed) {}

void Session::Open(uint32_t id,
                   std::shared_ptr<asymm::PublicKey> this_public_key,
                   uint32_t sequence_number,
                   Mode mode) {
  assert(id != 0);
  assert(this_public_key);
  id_ = id;
  this_public_key_ = this_public_key;
  sending_sequence_number_ = sequence_number;
  mode_ = mode;
  state_ = kProbing;
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
  state_ = kClosed;
}

void Session::HandleHandshake(const HandshakePacket& packet) {
  if (peer_.Id() == 0) {
    peer_.SetId(packet.SocketId());
  }

  // TODO(Fraser#5#): 2012-04-04 - Handle SynCookies
  if (state_ == kProbing) {
//    if (packet.ConnectionType() == 1 && packet.SynCookie() == 0)
    state_ = kHandshaking;
    SendCookie();
  } else if (state_ == kHandshaking) {
//    if (packet.SynCookie() == 1) {
    if (IsValid(packet.Endpoint())) {
      // TODO(Fraser#5#): 2012-07-16 - Check that if this_external_endpoint_ != packet.Endpoint(),
      //                  then either previous value for this_external_endpoint_ was set to the same
      //                  as "this local endpoint" (i.e. we connected to a peer on the same local
      //                  network), or this_external_endpoint_ was 0.0.0.0 (i.e. this is the first
      //                  connection on this transport).
      this_external_endpoint_ = packet.Endpoint();
    } else {
      LOG(kError) << "Invalid external endpoint in handshake: " << packet.Endpoint();
      state_ = kClosed;
      return;
    }

    if (!packet.PublicKey()) {
      LOG(kError) << "Handshake packet is missing peer's public key";
      state_ = kClosed;
      return;
    }

    state_ = kConnected;
    peer_connection_type_ = packet.ConnectionType();
    receiving_sequence_number_ = packet.InitialPacketSequenceNumber();
    peer_.SetPublicKey(packet.PublicKey());

    if (mode_ == kBootstrapAndDrop)
      return;

    SendCookie();
//    }
  }
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
  packet.SetEndpoint(peer_.Endpoint());
  packet.SetDestinationSocketId((mode_ == kNormal) ? 0 : 0xffffffff);
  packet.SetConnectionType(1);

  int result(peer_.Send(packet));
  if (result != kSuccess)
    LOG(kError) << "Failed to send handshake to " << peer_.Endpoint();

  // Schedule another connection request.
  tick_timer_.TickAfter(bptime::milliseconds(250));
}

void Session::SendCookie() {
  HandshakePacket packet;
  packet.SetEndpoint(peer_.Endpoint());
  packet.SetDestinationSocketId(peer_.Id());
  packet.SetRudpVersion(4);
  packet.SetSocketType(HandshakePacket::kStreamSocketType);
  packet.SetInitialPacketSequenceNumber(sending_sequence_number_);
  packet.SetMaximumPacketSize(Parameters::max_size);
  packet.SetMaximumFlowWindowSize(Parameters::maximum_window_size);
  packet.SetConnectionType(Parameters::connection_type);
  packet.SetSocketId(id_);
  packet.SetSynCookie(1);  // TODO(Team) calculate cookie
  packet.SetPublicKey(this_public_key_);

  int result(peer_.Send(packet));
  if (result != kSuccess)
    LOG(kError) << "Failed to send cookie to " << peer_.Endpoint();

  // Schedule another cookie send.
  tick_timer_.TickAfter(bptime::milliseconds(250));
}

void Session::MakePermanent() {
  mode_ = kNormal;
}

Session::Mode Session::mode() const {
  return mode_;
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
