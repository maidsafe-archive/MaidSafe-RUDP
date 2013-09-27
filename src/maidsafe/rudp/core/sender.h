/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

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
