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

#include "maidsafe/transport/rudp_sender.h"

#include <algorithm>
#include <cassert>

#include "maidsafe/transport/rudp_ack_of_ack_packet.h"
#include "maidsafe/transport/rudp_congestion_control.h"
#include "maidsafe/transport/rudp_peer.h"
#include "maidsafe/transport/rudp_tick_timer.h"
#include "maidsafe/common/utils.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace transport {

RudpSender::RudpSender(RudpPeer &peer,  // NOLINT (Fraser)
                       RudpTickTimer &tick_timer,
                       RudpCongestionControl &congestion_control)
  : peer_(peer),
    tick_timer_(tick_timer),
    congestion_control_(congestion_control),
    unacked_packets_(),
    send_timeout_() {}

boost::uint32_t RudpSender::GetNextPacketSequenceNumber() const {
  return unacked_packets_.End();
}

bool RudpSender::Flushed() const {
  return unacked_packets_.IsEmpty();
}

size_t RudpSender::AddData(const asio::const_buffer &data) {
  if ((congestion_control_.SendWindowSize() == 0) &&
      (unacked_packets_.Size() == 0)) {
    unacked_packets_.SetMaximumSize(RudpParameters::default_window_size);
  } else {
    unacked_packets_.SetMaximumSize(congestion_control_.SendWindowSize());
  }
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
    size_t length = std::min<size_t>(congestion_control_.SendDataSize(),
                                     end - ptr);
    p.packet.SetData(ptr, ptr + length);
    p.lost = true;  // Mark as lost so that DoSend() will send it.

    ptr += length;
  }

  DoSend();

  return ptr - begin;
}

void RudpSender::HandleAck(const RudpAckPacket &packet) {
  boost::uint32_t seqnum = packet.PacketSequenceNumber();

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
  // Mark the specified packets as lost.
  for (boost::uint32_t n = unacked_packets_.Begin();
       n != unacked_packets_.End();
       n = unacked_packets_.Next(n)) {
    if (packet.ContainsSequenceNumber(n)) {
      congestion_control_.OnNegativeAck(n);
      unacked_packets_[n].lost = true;
    }
  }

  DoSend();
}

void RudpSender::HandleTick() {
  if (send_timeout_ <= tick_timer_.Now()) {
    // Clear timeout. Will be reset next time a data packet is sent.
    send_timeout_ = bptime::pos_infin;

    // Mark all timedout unacknowledged packets as lost.
    for (boost::uint32_t n = unacked_packets_.Begin();
        n != unacked_packets_.End();
        n = unacked_packets_.Next(n)) {
      if ((unacked_packets_[n].last_send_time
           + congestion_control_.SendTimeout()) < tick_timer_.Now()) {
        congestion_control_.OnSendTimeout(n);
        unacked_packets_[n].lost = true;
      }
    }
  }

  DoSend();
}

void RudpSender::DoSend() {
  bptime::ptime now = tick_timer_.Now();

  for (boost::uint32_t n = unacked_packets_.Begin();
       n != unacked_packets_.End();
       n = unacked_packets_.Next(n)) {
    UnackedPacket &p = unacked_packets_[n];
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
        return;
      }
    }
  }
  // Set the send timeout so that unacknowledged packets can be marked as lost.
  if (!unacked_packets_.IsEmpty()) {
    send_timeout_ = unacked_packets_.Front().last_send_time +
                    congestion_control_.SendTimeout();
  }
}

void RudpSender::NotifyClose() {
  RudpShutdownPacket shut_down_packet;
  shut_down_packet.SetDestinationSocketId(peer_.Id());
  peer_.Send(shut_down_packet);
}

}  // namespace transport

}  // namespace maidsafe
