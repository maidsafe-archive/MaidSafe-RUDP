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

#include <cassert>

#include "maidsafe-dht/transport/rudp_peer.h"
#include "maidsafe/common/utils.h"

namespace asio = boost::asio;
namespace ip = asio::ip;

namespace maidsafe {

namespace transport {

RudpSender::RudpSender(RudpPeer &peer)
  : peer_(peer),
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

//void HandleNegativeAck(const RudpNegativeAckPacket &packet);

//void HandleTick(const boost::posix_time::time_duration &time_since_epoch);

boost::uint32_t RudpSender::GenerateSequenceNumber() {
  boost::uint32_t seqnum = 0;
  while (seqnum == 0)
    seqnum = (SRandomUint32() & 0x7fffffff);
  return seqnum;
}

void RudpSender::DoSend() {
  // If the sender's loss list is not empty, retransmit the first packet in
  // the list and remove it from the loss list.
  if (!loss_list_.empty()) {
    boost::uint32_t seqnum = loss_list_.front();
    if (unacked_packets_.Contains(seqnum))
      peer_.Send(unacked_packets_.Packet(seqnum));
    loss_list_.pop_front();
  }

  // Otherwise, if we have some waiting application data, and the number of
  // unacknowledged packets is less than the window size, create a new packet
  // and send it.
  else if (!write_buffer_.empty() && !unacked_packets_.IsFull()) {
    boost::uint32_t seqnum = unacked_packets_.Append();
    RudpDataPacket &packet = unacked_packets_.Packet(seqnum);
    packet.SetPacketSequenceNumber(seqnum);
    packet.SetFirstPacketInMessage(true);
    packet.SetLastPacketInMessage(true);
    packet.SetInOrder(true);
    packet.SetMessageNumber(0);
    packet.SetTimeStamp(0);
    packet.SetDestinationSocketId(peer_.Id());
    size_t data_size = std::min<size_t>(kMaxDataSize, write_buffer_.size());
    packet.SetData(write_buffer_.begin(), write_buffer_.begin() + data_size);
    peer_.Send(packet);
  }
}

}  // namespace transport

}  // namespace maidsafe
