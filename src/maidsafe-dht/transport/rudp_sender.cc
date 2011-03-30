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
    unacked_packets_(GenerateSequenceNumber()) {
}

boost::uint32_t RudpSender::GetNextPacketSequenceNumber() const {
  return unacked_packets_.End();
}

size_t RudpSender::GetFreeSpace() const {
  return kMaxWriteBufferSize - write_buffer_.size();
}

size_t RudpSender::AddData(const asio::const_buffer &data) {
  size_t length = std::min(GetFreeSpace(), asio::buffer_size(data));
  const unsigned char* p = asio::buffer_cast<const unsigned char*>(data);
  write_buffer_.insert(write_buffer_.end(), p, p + length);
  DoSend();
  return length;
}

void RudpSender::HandleAck(const RudpAckPacket &packet) {
  boost::uint32_t seqnum = packet.PacketSequenceNumber();
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
      unacked_packets_[n].is_lost = true;
    }
  }
}

void RudpSender::HandleTick() {
}

boost::uint32_t RudpSender::GenerateSequenceNumber() {
  boost::uint32_t seqnum = 0;
  while (seqnum == 0)
    seqnum = (SRandomUint32() & 0x7fffffff);
  return seqnum;
}

void RudpSender::DoSend() {
  // Retransmit lost packets.
  for (boost::uint32_t n = unacked_packets_.Begin();
       n != unacked_packets_.End();
       n = unacked_packets_.Next(n)) {
    UnackedPacket &p = unacked_packets_[n];
    if (p.is_lost) {
      p.is_lost = false;
      p.last_send_time = tick_timer_.Now();
      peer_.Send(p.packet);
    }
  }

  // If we have some waiting application data, create new packets until the
  // sender's window is full.
  while (!write_buffer_.empty() && !unacked_packets_.IsFull()) {
    boost::uint32_t n = unacked_packets_.Append();
    UnackedPacket &p = unacked_packets_[n];
    p.packet.SetPacketSequenceNumber(n);
    p.packet.SetFirstPacketInMessage(true);
    p.packet.SetLastPacketInMessage(true);
    p.packet.SetInOrder(true);
    p.packet.SetMessageNumber(0);
    p.packet.SetTimeStamp(0);
    p.packet.SetDestinationSocketId(peer_.Id());
    size_t length = std::min<size_t>(kMaxDataSize, write_buffer_.size());
    p.packet.SetData(write_buffer_.begin(), write_buffer_.begin() + length);
    write_buffer_.erase(write_buffer_.begin(), write_buffer_.begin() + length);
    p.is_lost = false;
    p.last_send_time = tick_timer_.Now();
    peer_.Send(p.packet);
  }
}

}  // namespace transport

}  // namespace maidsafe
