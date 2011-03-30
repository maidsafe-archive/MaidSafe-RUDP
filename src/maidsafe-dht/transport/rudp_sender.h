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

#ifndef MAIDSAFE_DHT_TRANSPORT_RUDP_SENDER_H_
#define MAIDSAFE_DHT_TRANSPORT_RUDP_SENDER_H_

#include <deque>

#include "boost/asio/buffer.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/cstdint.hpp"
#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "maidsafe-dht/transport/rudp_ack_packet.h"
#include "maidsafe-dht/transport/rudp_data_packet.h"
#include "maidsafe-dht/transport/rudp_negative_ack_packet.h"
#include "maidsafe-dht/transport/rudp_sliding_window.h"

namespace maidsafe {

namespace transport {

class RudpPeer;
class RudpTickTimer;

class RudpSender {
 public:
  explicit RudpSender(RudpPeer &peer, RudpTickTimer &tick_timer);

  // Get the sequence number that will be used for the next packet.
  boost::uint32_t GetNextPacketSequenceNumber() const;

  // Returns how much data can be written to without blocking. Asynchronous
  // writes can complete immediately provided there is available free space.
  size_t GetFreeSpace() const;

  // Adds some application data to be sent. Returns number of bytes copied.
  size_t AddData(const boost::asio::const_buffer &data);

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

  // Various constants that probably should be configurable.
  enum { kMaxWriteBufferSize = 65536 };
  enum { kMaxDataSize = 1024 };

  // Helper function to generate an initial sequence number.
  static boost::uint32_t GenerateSequenceNumber();

  // Send waiting packets.
  void DoSend();

  // The peer with which we are communicating.
  RudpPeer &peer_;

  // The timer used to generate tick events.
  RudpTickTimer &tick_timer_;

  // The buffer used to store application data that is waiting to be sent.
  std::deque<unsigned char> write_buffer_;

  struct UnackedPacket {
    UnackedPacket() : is_lost(false) {}
    RudpDataPacket packet;
    bool is_lost;
    boost::posix_time::ptime last_send_time;
  };

  // The sender's window of unacknowledged packets.
  typedef RudpSlidingWindow<UnackedPacket> UnackedPacketWindow;
  UnackedPacketWindow unacked_packets_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_TRANSPORT_RUDP_SENDER_H_
