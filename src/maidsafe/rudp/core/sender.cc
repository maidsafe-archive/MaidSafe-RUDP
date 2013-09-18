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

#include "maidsafe/rudp/core/sender.h"

#include <algorithm>
#include <cassert>

#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/core/congestion_control.h"
#include "maidsafe/rudp/core/peer.h"
#include "maidsafe/rudp/core/tick_timer.h"
#include "maidsafe/rudp/packets/ack_packet.h"
#include "maidsafe/rudp/packets/ack_of_ack_packet.h"
#include "maidsafe/rudp/packets/keepalive_packet.h"
#include "maidsafe/rudp/packets/negative_ack_packet.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

namespace detail {

Sender::Sender(Peer& peer, TickTimer& tick_timer, CongestionControl& congestion_control)
    : peer_(peer),
      tick_timer_(tick_timer),
      congestion_control_(congestion_control),
      unacked_packets_(),
      send_timeout_(),
      current_message_number_(0) {}

uint32_t Sender::GetNextPacketSequenceNumber() const { return unacked_packets_.End(); }

bool Sender::Flushed() const { return unacked_packets_.IsEmpty(); }

size_t Sender::AddData(const asio::const_buffer& data, const uint32_t& message_number) {
  if ((congestion_control_.SendWindowSize() == 0) && (unacked_packets_.Size() == 0))
    unacked_packets_.SetMaximumSize(Parameters::default_window_size);
  else
    unacked_packets_.SetMaximumSize(congestion_control_.SendWindowSize());

  const unsigned char* begin = asio::buffer_cast<const unsigned char*>(data);
  const unsigned char* ptr = begin;
  const unsigned char* end = begin + asio::buffer_size(data);

  while (!unacked_packets_.IsFull() && (ptr < end)) {
    size_t length = std::min<size_t>(congestion_control_.SendDataSize(), end - ptr);
    uint32_t n = unacked_packets_.Append();

    UnackedPacket& p = unacked_packets_[n];
    p.packet.SetPacketSequenceNumber(n);
    p.packet.SetFirstPacketInMessage(current_message_number_ == message_number);
    current_message_number_ = message_number;
    p.packet.SetLastPacketInMessage(ptr + length == end);
    p.packet.SetInOrder(true);
    p.packet.SetMessageNumber(message_number);
    p.packet.SetTimeStamp(0);
    p.packet.SetDestinationSocketId(peer_.SocketId());
    p.packet.SetData(ptr, ptr + length);
    p.lost = true;  // Mark as lost so that DoSend() will send it.

    ptr += length;
  }

  DoSend();

  return ptr - begin;
}

void Sender::HandleAck(const AckPacket& packet, std::vector<uint32_t>& completed_message_numbers) {
  uint32_t seqnum = packet.PacketSequenceNumber();

  if (packet.HasOptionalFields()) {
    congestion_control_.OnAck(seqnum,
                              packet.RoundTripTime(),
                              packet.RoundTripTimeVariance(),
                              packet.AvailableBufferSize(),
                              packet.PacketsReceivingRate(),
                              packet.EstimatedLinkCapacity());
  } else {
    congestion_control_.OnAck(seqnum);
  }

  AckOfAckPacket response_packet;
  response_packet.SetDestinationSocketId(peer_.SocketId());
  response_packet.SetAckSequenceNumber(packet.AckSequenceNumber());
  peer_.Send(response_packet);

  if (unacked_packets_.Contains(seqnum) || unacked_packets_.End() == seqnum) {
    while (unacked_packets_.Begin() != seqnum) {
      if (unacked_packets_.Front().packet.LastPacketInMessage()) {
        completed_message_numbers.push_back(unacked_packets_.Front().packet.MessageNumber());
//        LOG(kVerbose) << "Received ACK for last packet in message "
//                      << unacked_packets_.Front().packet.MessageNumber();
      }
      unacked_packets_.Remove();
    }

    DoSend();
  }
}

void Sender::HandleNegativeAck(const NegativeAckPacket& packet) {
  // Mark the specified packets as lost.
  for (uint32_t n = unacked_packets_.Begin();
       n != unacked_packets_.End();
       n = unacked_packets_.Next(n)) {
    if (packet.ContainsSequenceNumber(n)) {
      congestion_control_.OnNegativeAck(n);
      unacked_packets_[n].lost = true;
    }
  }

  DoSend();
}

void Sender::HandleTick() {
  if (send_timeout_ <= tick_timer_.Now()) {
    // Clear timeout. Will be reset next time a data packet is sent.
    send_timeout_ = bptime::pos_infin;

    // Mark all timedout unacknowledged packets as lost.
    for (uint32_t n = unacked_packets_.Begin();
         n != unacked_packets_.End();
         n = unacked_packets_.Next(n)) {
      if ((unacked_packets_[n].last_send_time + congestion_control_.SendTimeout()) <
          tick_timer_.Now()) {
        congestion_control_.OnSendTimeout(n);
        unacked_packets_[n].lost = true;
        // LOG(kVerbose) << "Lost packet " << n;
      }
    }
  }

  DoSend();
}

void Sender::DoSend() {
  bptime::ptime now = tick_timer_.Now();

  for (uint32_t n = unacked_packets_.Begin();
       n != unacked_packets_.End();
       n = unacked_packets_.Next(n)) {
    UnackedPacket& p = unacked_packets_[n];
    if (p.lost) {
      // peer_.Send is a blockable function call, it will only returned when
      // the UDP socket sent out the packet successfully. So here the all
      // un-acked packets can be sent out one-by-one in a bunch, i.e. the whole
      // buffer (packet_size * window_size) will be sent out at once.
      // If we make the Send to be unblockable, i.e. handled by a seperate
      // thread, then we will need to first Check whether we are allowed to
      // send another packet at this time, and then once request a packet to be
      // sent, set the ticker to be with a fixed interval or
      // tick_timer_.TickAt(now + congestion_control_.SendDelay());
      if (peer_.Send(p.packet) == kSuccess) {
        p.lost = false;
        p.last_send_time = now;
        congestion_control_.OnDataPacketSent(n);
        tick_timer_.TickAt(now + congestion_control_.SendDelay());
        // LOG(kVerbose) << "Sent packet " << n;
        return;
      } else {
        LOG(kVerbose) << "DoSend - failed sending packet " << n;
      }
    }
  }
  // Set the send timeout so that unacknowledged packets can be marked as lost.
  if (!unacked_packets_.IsEmpty()) {
    send_timeout_ = unacked_packets_.Front().last_send_time + congestion_control_.SendTimeout();
  }
}

void Sender::NotifyClose() {
  ShutdownPacket shut_down_packet;
  shut_down_packet.SetDestinationSocketId(peer_.SocketId());
  peer_.Send(shut_down_packet);
}

void Sender::HandleKeepalive(const KeepalivePacket& packet) {
  if (!packet.IsRequest())
    return;
  KeepalivePacket response_packet;
  response_packet.SetSequenceNumber(packet.SequenceNumber() + 1);
  response_packet.SetDestinationSocketId(peer_.SocketId());
  SendKeepalive(response_packet);
}

ReturnCode Sender::SendKeepalive(const KeepalivePacket& keepalive_packet) {
  assert(keepalive_packet.SequenceNumber());
  return peer_.Send(keepalive_packet);
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
