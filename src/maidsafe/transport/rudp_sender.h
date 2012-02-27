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

#ifndef MAIDSAFE_TRANSPORT_RUDP_SENDER_H_
#define MAIDSAFE_TRANSPORT_RUDP_SENDER_H_

#include "boost/asio/buffer.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/cstdint.hpp"
#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "maidsafe/transport/rudp_ack_packet.h"
#include "maidsafe/transport/rudp_data_packet.h"
#include "maidsafe/transport/rudp_negative_ack_packet.h"
#include "maidsafe/transport/rudp_shutdown_packet.h"
#include "maidsafe/transport/rudp_sliding_window.h"

namespace maidsafe {

namespace transport {

class RudpCongestionControl;
class RudpPeer;
class RudpTickTimer;

class RudpSender {
 public:
  explicit RudpSender(RudpPeer &peer,  // NOLINT (Fraser)
                      RudpTickTimer &tick_timer,
                      RudpCongestionControl &congestion_control);

  // Get the sequence number that will be used for the next packet.
  boost::uint32_t GetNextPacketSequenceNumber() const;

  // Determine whether all data has been transmitted to the peer.
  bool Flushed() const;

  // Adds some application data to be sent. Returns number of bytes copied.
  size_t AddData(const boost::asio::const_buffer &data);

  // Notify the other side that the current connection is to be dropped
  void NotifyClose();

  // Handle an acknowlegement packet.
  void HandleAck(const RudpAckPacket &packet);

  // Handle an negative acknowlegement packet.
  void HandleNegativeAck(const RudpNegativeAckPacket &packet);

  // Handle a tick in the system time.
  void HandleTick();

 private:
  // Disallow copying and assignment.
  RudpSender(const RudpSender&);
  RudpSender &operator=(const RudpSender&);

  // Send waiting packets.
  void DoSend();

  // The peer with which we are communicating.
  RudpPeer &peer_;

  // The timer used to generate tick events.
  RudpTickTimer &tick_timer_;

  // The congestion control information associated with the connection.
  RudpCongestionControl &congestion_control_;

  struct UnackedPacket {
    UnackedPacket() : packet(),
                      lost(false),
                      last_send_time() {}
    RudpDataPacket packet;
    bool lost;
    boost::posix_time::ptime last_send_time;
  };

  // The sender's window of unacknowledged packets.
  typedef RudpSlidingWindow<UnackedPacket> UnackedPacketWindow;
  UnackedPacketWindow unacked_packets_;

  // The next time at which all unacked packets will be considered lost.
  boost::posix_time::ptime send_timeout_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_SENDER_H_
