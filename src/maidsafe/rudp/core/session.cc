/* Copyright (c) 2010 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// Author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#include "maidsafe/transport/rudp_session.h"

#include <cassert>

#include "maidsafe/transport/rudp_data_packet.h"
#include "maidsafe/transport/rudp_peer.h"
#include "maidsafe/transport/rudp_sliding_window.h"
#include "maidsafe/transport/rudp_tick_timer.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace transport {

RudpSession::RudpSession(RudpPeer &peer, RudpTickTimer &tick_timer)  // NOLINT (Fraser)
  : peer_(peer),
    tick_timer_(tick_timer),
    id_(0),
    sending_sequence_number_(0),
    receiving_sequence_number_(0),
    peer_connection_type_(0),
    mode_(kClient),
    state_(kClosed) {
}

void RudpSession::Open(boost::uint32_t id,
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

bool RudpSession::IsOpen() const {
  return state_ != kClosed;
}

bool RudpSession::IsConnected() const {
  return state_ == kConnected;
}

boost::uint32_t RudpSession::Id() const {
  return id_;
}

boost::uint32_t RudpSession::ReceivingSequenceNumber() const {
  return receiving_sequence_number_;
}

boost::uint32_t RudpSession::PeerConnectionType() const {
  return peer_connection_type_;
}

void RudpSession::Close() {
  state_ = kClosed;
}

void RudpSession::HandleHandshake(const RudpHandshakePacket &packet) {
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

void RudpSession::HandleTick() {
  if (mode_ == kClient) {
    if (state_ == kProbing) {
      SendConnectionRequest();
    } else if (state_ == kHandshaking) {
      SendCookieResponse();
    }
  }
}

void RudpSession::SendConnectionRequest() {
  assert(mode_ == kClient);

  RudpHandshakePacket packet;
  packet.SetRudpVersion(4);
  packet.SetSocketType(RudpHandshakePacket::kStreamSocketType);
  packet.SetSocketId(id_);
  packet.SetIpAddress(peer_.Endpoint().address());
  packet.SetDestinationSocketId(0);
  packet.SetConnectionType(1);

  peer_.Send(packet);

  // Schedule another connection request.
  tick_timer_.TickAfter(bptime::milliseconds(250));
}

void RudpSession::SendCookieChallenge() {
  assert(mode_ == kServer);

  RudpHandshakePacket packet;
  packet.SetRudpVersion(4);
  packet.SetSocketType(RudpHandshakePacket::kStreamSocketType);
  packet.SetSocketId(id_);
  packet.SetIpAddress(peer_.Endpoint().address());
  packet.SetDestinationSocketId(peer_.Id());
  packet.SetConnectionType(RudpParameters::connection_type);
  packet.SetSynCookie(1);  // TODO(Team) calculate cookie

  peer_.Send(packet);
}

void RudpSession::SendCookieResponse() {
  assert(mode_ == kClient);

  RudpHandshakePacket packet;
  packet.SetRudpVersion(4);
  packet.SetSocketType(RudpHandshakePacket::kStreamSocketType);
  packet.SetInitialPacketSequenceNumber(sending_sequence_number_);
  packet.SetMaximumPacketSize(RudpParameters::max_size);
  packet.SetMaximumFlowWindowSize(RudpParameters::maximum_window_size);
  packet.SetSocketId(id_);
  packet.SetIpAddress(peer_.Endpoint().address());
  packet.SetDestinationSocketId(peer_.Id());
  packet.SetConnectionType(RudpParameters::connection_type);
  packet.SetSynCookie(1);  // TODO(Team) calculate cookie

  peer_.Send(packet);

  // Schedule another cookie response.
  tick_timer_.TickAfter(bptime::milliseconds(250));
}

void RudpSession::SendConnectionAccepted() {
  assert(mode_ == kServer);

  RudpHandshakePacket packet;
  packet.SetRudpVersion(4);
  packet.SetSocketType(RudpHandshakePacket::kStreamSocketType);
  packet.SetInitialPacketSequenceNumber(sending_sequence_number_);
  packet.SetMaximumPacketSize(RudpParameters::max_size);
  packet.SetMaximumFlowWindowSize(RudpParameters::maximum_window_size);
  packet.SetSocketId(id_);
  packet.SetIpAddress(peer_.Endpoint().address());
  packet.SetDestinationSocketId(peer_.Id());
  packet.SetConnectionType(0xffffffff);
  packet.SetSynCookie(0);  // TODO(Team) calculate cookie

  peer_.Send(packet);
}

}  // namespace transport

}  // namespace maidsafe
