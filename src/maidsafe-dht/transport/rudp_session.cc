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

#include "maidsafe-dht/transport/rudp_session.h"

#include <cassert>

#include "maidsafe-dht/transport/rudp_data_packet.h"
#include "maidsafe-dht/transport/rudp_peer.h"
#include "maidsafe-dht/transport/rudp_tick_timer.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace transport {

RudpSession::RudpSession(RudpPeer &peer, RudpTickTimer &tick_timer)
  : peer_(peer),
    tick_timer_(tick_timer),
    id_(0),
    sequence_number_(0),
    mode_(kClient),
    connected_(false) {
}

void RudpSession::Open(boost::uint32_t id,
                       boost::uint32_t sequence_number,
                       Mode mode) {
  assert(id != 0);
  id_ = id;
  sequence_number_ = sequence_number;
  mode_ = mode;
  SendFirstPacket();
}

bool RudpSession::IsOpen() const {
  return id_ != 0;
}

bool RudpSession::IsConnected() const {
  return connected_;
}

boost::uint32_t RudpSession::Id() const {
  return id_;
}

void RudpSession::Close() {
  id_ = 0;
  connected_ = false;
}

void RudpSession::HandleHandshake(const RudpHandshakePacket &packet) {
  if (!connected_) {
    connected_ = true;
    if (mode_ == kClient) {
      peer_.SetId(packet.SocketId());
      RudpHandshakePacket response_packet(packet);
      response_packet.SetSocketId(id_);
      response_packet.SetIpAddress(peer_.Endpoint().address());
      response_packet.SetDestinationSocketId(peer_.Id());
      response_packet.SetConnectionType(0xffffffff);
      peer_.Send(response_packet);
    }
  }
}

void RudpSession::HandleTick() {
  if (mode_ == kClient)
    if (!connected_)
      SendFirstPacket();
}

void RudpSession::SendFirstPacket() {
  RudpHandshakePacket packet;
  packet.SetRudpVersion(4);
  packet.SetSocketType(RudpHandshakePacket::kStreamSocketType);
  packet.SetInitialPacketSequenceNumber(sequence_number_);
  packet.SetMaximumPacketSize(RudpDataPacket::kMaxSize);
  packet.SetMaximumFlowWindowSize(64); // Not used in this implementation.
  packet.SetSocketId(id_);
  packet.SetIpAddress(peer_.Endpoint().address());
  packet.SetDestinationSocketId(peer_.Id());
  packet.SetConnectionType(mode_ == kClient ? 1 : 0xffffffff);
  if (mode_ == kServer)
    packet.SetSynCookie(0); // TODO calculate cookie

  peer_.Send(packet);

  if (mode_ == kClient) {
    // Schedule another connection attempt.
    tick_timer_.TickAfter(bptime::milliseconds(500));
  }
}

}  // namespace transport

}  // namespace maidsafe
