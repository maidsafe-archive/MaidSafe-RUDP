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

#include "maidsafe/rudp/packets/data_packet.h"
#include "maidsafe/rudp/core/peer.h"
#include "maidsafe/rudp/core/sliding_window.h"
#include "maidsafe/rudp/core/tick_timer.h"

namespace bptime = boost::posix_time;


namespace maidsafe {

namespace rudp {

namespace detail {

Session::Session(Peer &peer, TickTimer &tick_timer)  // NOLINT (Fraser)
    : peer_(peer),
      tick_timer_(tick_timer),
      id_(0),
      sending_sequence_number_(0),
      receiving_sequence_number_(0),
      peer_connection_type_(0),
      state_(kClosed) {}

void Session::Open(uint32_t id, uint32_t sequence_number) {
  assert(id != 0);
  id_ = id;
  sending_sequence_number_ = sequence_number;
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

void Session::HandleHandshake(const HandshakePacket &packet) {
  if (peer_.Id() == 0) {
    peer_.SetId(packet.SocketId());
  }

  // TODO(Fraser#5#): 2012-04-04 - Check if we need to uncomment the lines below
  if (state_ == kProbing) {
//    if (packet.ConnectionType() == 1 && packet.SynCookie() == 0)
    SendCookie();
  } else if (state_ == kHandshaking) {
//    if (packet.SynCookie() == 1) {
    state_ = kConnected;
    peer_connection_type_ = packet.ConnectionType();
    receiving_sequence_number_ = packet.InitialPacketSequenceNumber();
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
  // TODO(Fraser#5#): 2012-04-04 - Check if we need to uncomment the lines below
//  packet.SetRudpVersion(4);
//  packet.SetSocketType(HandshakePacket::kStreamSocketType);
//  packet.SetSocketId(id_);
//  packet.SetIpAddress(peer_.Endpoint().address());
//  packet.SetDestinationSocketId(0);
//  packet.SetConnectionType(1);

  peer_.Send(packet);

  // Schedule another connection request.
  tick_timer_.TickAfter(bptime::milliseconds(250));
}

void Session::SendCookie() {
  state_ = kHandshaking;

  HandshakePacket packet;
  packet.SetIpAddress(peer_.Endpoint().address());
  packet.SetDestinationSocketId(peer_.Id());
  packet.SetRudpVersion(4);
  packet.SetSocketType(HandshakePacket::kStreamSocketType);
  packet.SetInitialPacketSequenceNumber(sending_sequence_number_);
  packet.SetMaximumPacketSize(Parameters::max_size);
  packet.SetMaximumFlowWindowSize(Parameters::maximum_window_size);
  packet.SetConnectionType(Parameters::connection_type);
  packet.SetSocketId(id_);
  packet.SetSynCookie(1);  // TODO(Team) calculate cookie

  peer_.Send(packet);

  // Schedule another cookie send.
  tick_timer_.TickAfter(bptime::milliseconds(250));
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
