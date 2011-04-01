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

#include "maidsafe-dht/transport/rudp_sender.h"

#include <algorithm>
#include <cassert>

#include "maidsafe-dht/transport/rudp_ack_of_ack_packet.h"
#include "maidsafe-dht/transport/rudp_peer.h"
#include "maidsafe-dht/transport/rudp_tick_timer.h"
#include "maidsafe/common/utils.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace transport {

RudpSender::RudpSender(RudpPeer &peer, RudpTickTimer &tick_timer)
  : peer_(peer),
    tick_timer_(tick_timer),
    unacked_packets_() {
}

boost::uint32_t RudpSender::GetNextPacketSequenceNumber() const {
  return unacked_packets_.End();
}

bool RudpSender::Flushed() const {
  return unacked_packets_.IsEmpty();
}

size_t RudpSender::AddData(const asio::const_buffer &data) {
  const unsigned char *begin = asio::buffer_cast<const unsigned char*>(data);
  const unsigned char *ptr = begin;
  const unsigned char *end = begin + asio::buffer_size(data);
  while (!unacked_packets_.IsFull() && (ptr < end)) {
    boost::uint32_t n = unacked_packets_.Append();
    UnackedPacket &p = unacked_packets_[n];
    p.packet.SetPacketSequenceNumber(n);
    p.packet.SetFirstPacketInMessage(true);
    p.packet.SetLastPacketInMessage(true);
    p.packet.SetInOrder(true);
    p.packet.SetMessageNumber(0);
    p.packet.SetTimeStamp(0);
    p.packet.SetDestinationSocketId(peer_.Id());
    size_t length = std::min<size_t>(kMaxDataSize, end - ptr);
    p.packet.SetData(ptr, ptr + length);
    p.lost = true; // Mark as lost so that DoSend() will send it.
    ptr += length;
  }
  DoSend();
  return ptr - begin;
}

void RudpSender::HandleAck(const RudpAckPacket &packet) {
  boost::uint32_t seqnum = packet.PacketSequenceNumber();

  RudpAckOfAckPacket response_packet;
  response_packet.SetDestinationSocketId(peer_.Id());
  response_packet.SetAckSequenceNumber(packet.AckSequenceNumber());
  peer_.Send(response_packet);

  if (unacked_packets_.Contains(seqnum) || unacked_packets_.End() == seqnum) {
    while (unacked_packets_.Begin() != seqnum)
      unacked_packets_.Remove();
    DoSend();
  }
}

void RudpSender::HandleNegativeAck(const RudpNegativeAckPacket &packet) {
  for (boost::uint32_t n = unacked_packets_.Begin();
       n != unacked_packets_.End();
       n = unacked_packets_.Next(n)) {
    if (packet.ContainsSequenceNumber(n)) {
      unacked_packets_[n].lost = true;
    }
  }

  DoSend();
}

void RudpSender::HandleTick() {
  for (boost::uint32_t n = unacked_packets_.Begin();
       n != unacked_packets_.End();
       n = unacked_packets_.Next(n)) {
    unacked_packets_[n].lost = true;
  }

  DoSend();

  if (!Flushed())
    tick_timer_.TickAfter(bptime::milliseconds(250));
}

void RudpSender::DoSend() {
  bptime::ptime now = tick_timer_.Now();
  for (boost::uint32_t n = unacked_packets_.Begin();
       n != unacked_packets_.End();
       n = unacked_packets_.Next(n)) {
    UnackedPacket &p = unacked_packets_[n];
    if (p.lost) {
      peer_.Send(p.packet);
      p.lost = false;
      p.last_send_time = now;
      tick_timer_.TickAt(now + bptime::milliseconds(250));
    }
  }
}

}  // namespace transport

}  // namespace maidsafe
