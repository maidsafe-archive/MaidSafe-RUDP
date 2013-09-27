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

#ifndef MAIDSAFE_RUDP_CORE_SENDER_H_
#define MAIDSAFE_RUDP_CORE_SENDER_H_

#include <cstdint>
#include <vector>

#include "boost/asio/buffer.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/date_time/posix_time/posix_time_types.hpp"

#include "maidsafe/rudp/return_codes.h"
#include "maidsafe/rudp/core/sliding_window.h"
#include "maidsafe/rudp/packets/data_packet.h"
#include "maidsafe/rudp/packets/shutdown_packet.h"

namespace maidsafe {

namespace rudp {

namespace detail {

class AckPacket;
class CongestionControl;
class KeepalivePacket;
class NegativeAckPacket;
class Peer;
class TickTimer;

class Sender {
 public:
  explicit Sender(Peer& peer, TickTimer& tick_timer, CongestionControl& congestion_control);

  // Get the sequence number that will be used for the next packet.
  uint32_t GetNextPacketSequenceNumber() const;

  // Determine whether all data has been transmitted to the peer.
  bool Flushed() const;

  // Adds some application data to be sent. Returns number of bytes copied.
  size_t AddData(const boost::asio::const_buffer& data, uint32_t message_number);

  // Notify the other side that the current connection is to be dropped
  void NotifyClose();

  // Handle an acknowlegement packet.  Inserts the message_number for any completed messages
  // received so their sent functors can be invoked by Socket.
  void HandleAck(const AckPacket& packet, std::vector<uint32_t>& completed_message_numbers);

  // Handle an negative acknowlegement packet.
  void HandleNegativeAck(const NegativeAckPacket& packet);

  // Handle a tick in the system time.
  void HandleTick();

  // Handle a keepalive packet.
  void HandleKeepalive(const KeepalivePacket& packet);

  // Send a keepalive packet to the other side.
  ReturnCode SendKeepalive(const KeepalivePacket& keepalive_packet);

 private:
  // Disallow copying and assignment.
  Sender(const Sender&);
  Sender& operator=(const Sender&);

  // Send waiting packets.
  void DoSend();

  // Called to mark unacked packets that have expired and should be
  // proactively resent
  void MarkExpiredPackets();
  void MarkExpiredPackets(boost::posix_time::ptime expire_time);

  // The peer with which we are communicating.
  Peer& peer_;

  // The timer used to generate tick events.
  TickTimer& tick_timer_;

  // The congestion control information associated with the connection.
  CongestionControl& congestion_control_;

  struct UnackedPacket {
    UnackedPacket() : packet(), lost(false), ackd(false), last_send_time() {}
    DataPacket packet;
    bool lost;
    bool ackd;
    boost::posix_time::ptime last_send_time;
  };

  // The sender's window of unacknowledged packets.
  typedef SlidingWindow<UnackedPacket> UnackedPacketWindow;
  UnackedPacketWindow unacked_packets_;

  // The next time at which all unacked packets will be considered lost.
  boost::posix_time::ptime send_timeout_;

  uint32_t current_message_number_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CORE_SENDER_H_
