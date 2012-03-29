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

namespace asio = boost::asio;
namespace ip = asio::ip;
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
    mode_(kClient),
    state_(kClosed) {
}

void Session::Open(boost::uint32_t id,
                   boost::uint32_t sequence_number,
                   Mode mode) {
  assert(id != 0);
  id_ = id;
  sending_sequence_number_ = sequence_number;
  mode_ = mode;
  if (mode_ == kClient) {
    state_ = kProbing;
    SendConnectionRequest();
  } else {
    state_ = kHandshaking;
    SendCookieChallenge();
  }
}

bool Session::IsOpen() const {
  return state_ != kClosed;
}

bool Session::IsConnected() const {
  return state_ == kConnected;
}

boost::uint32_t Session::Id() const {
  return id_;
}

boost::uint32_t Session::ReceivingSequenceNumber() const {
  return receiving_sequence_number_;
}

boost::uint32_t Session::PeerConnectionType() const {
  return peer_connection_type_;
}

void Session::Close() {
  state_ = kClosed;
}

void Session::HandleHandshake(const HandshakePacket &packet) {
  if (peer_.Id() == 0) {
    peer_.SetId(packet.SocketId());
  }

  if (mode_ == kClient) {
    if (state_ == kProbing || state_ == kHandshaking) {
      state_ = kHandshaking;
      if (packet.ConnectionType() == 0xffffffff) {
        state_ = kConnected;
        receiving_sequence_number_ = packet.InitialPacketSequenceNumber();
      } else {
        peer_connection_type_ = packet.ConnectionType();
        SendCookieResponse();
      }
    }
  } else {
    if (state_ == kConnected) {
      SendConnectionAccepted();
    } else if (packet.SynCookie() == 1) {
      state_ = kConnected;
      peer_connection_type_ = packet.ConnectionType();
      receiving_sequence_number_ = packet.InitialPacketSequenceNumber();
      SendConnectionAccepted();
    } else {
      SendCookieChallenge();
    }
  }
}

void Session::HandleTick() {
  if (mode_ == kClient) {
    if (state_ == kProbing) {
      SendConnectionRequest();
    } else if (state_ == kHandshaking) {
      SendCookieResponse();
    }
  }
}

void Session::SendConnectionRequest() {
  assert(mode_ == kClient);

  HandshakePacket packet;
  packet.SetRudpVersion(4);
  packet.SetSocketType(HandshakePacket::kStreamSocketType);
  packet.SetSocketId(id_);
  packet.SetIpAddress(peer_.Endpoint().address());
  packet.SetDestinationSocketId(0);
  packet.SetConnectionType(1);

  peer_.Send(packet);

  // Schedule another connection request.
  tick_timer_.TickAfter(bptime::milliseconds(250));
}

void Session::SendCookieChallenge() {
  assert(mode_ == kServer);

  HandshakePacket packet;
  packet.SetRudpVersion(4);
  packet.SetSocketType(HandshakePacket::kStreamSocketType);
  packet.SetSocketId(id_);
  packet.SetIpAddress(peer_.Endpoint().address());
  packet.SetDestinationSocketId(peer_.Id());
  packet.SetConnectionType(Parameters::connection_type);
  packet.SetSynCookie(1);  // TODO(Team) calculate cookie

  peer_.Send(packet);
}

void Session::SendCookieResponse() {
  assert(mode_ == kClient);

  HandshakePacket packet;
  packet.SetRudpVersion(4);
  packet.SetSocketType(HandshakePacket::kStreamSocketType);
  packet.SetInitialPacketSequenceNumber(sending_sequence_number_);
  packet.SetMaximumPacketSize(Parameters::max_size);
  packet.SetMaximumFlowWindowSize(Parameters::maximum_window_size);
  packet.SetSocketId(id_);
  packet.SetIpAddress(peer_.Endpoint().address());
  packet.SetDestinationSocketId(peer_.Id());
  packet.SetConnectionType(Parameters::connection_type);
  packet.SetSynCookie(1);  // TODO(Team) calculate cookie

  peer_.Send(packet);

  // Schedule another cookie response.
  tick_timer_.TickAfter(bptime::milliseconds(250));
}

void Session::SendConnectionAccepted() {
  assert(mode_ == kServer);

  HandshakePacket packet;
  packet.SetRudpVersion(4);
  packet.SetSocketType(HandshakePacket::kStreamSocketType);
  packet.SetInitialPacketSequenceNumber(sending_sequence_number_);
  packet.SetMaximumPacketSize(Parameters::max_size);
  packet.SetMaximumFlowWindowSize(Parameters::maximum_window_size);
  packet.SetSocketId(id_);
  packet.SetIpAddress(peer_.Endpoint().address());
  packet.SetDestinationSocketId(peer_.Id());
  packet.SetConnectionType(0xffffffff);
  packet.SetSynCookie(0);  // TODO(Team) calculate cookie

  peer_.Send(packet);
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
