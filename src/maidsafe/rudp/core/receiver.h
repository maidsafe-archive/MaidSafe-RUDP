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

#ifndef MAIDSAFE_RUDP_CORE_RECEIVER_H_
#define MAIDSAFE_RUDP_CORE_RECEIVER_H_

#include <cstdint>
#include <deque>

#include "boost/asio/buffer.hpp"
#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/date_time/posix_time/posix_time_types.hpp"

#include "maidsafe/rudp/packets/ack_packet.h"
#include "maidsafe/rudp/packets/data_packet.h"
#include "maidsafe/rudp/core/sliding_window.h"


namespace maidsafe {

namespace rudp {

namespace detail {

class AckOfAckPacket;
class CongestionControl;
class NegativeAckPacket;
class Peer;
class TickTimer;

class Receiver {
 public:
  explicit Receiver(Peer& peer, TickTimer& tick_timer, CongestionControl& congestion_control);

  // Reset receiver so that it is ready to start receiving data from the specified sequence number.
  void Reset(uint32_t initial_sequence_number);

  // Determine whether all acknowledgements have been processed.
  bool Flushed() const;

  // Reads some application data. Returns number of bytes copied.
  size_t ReadData(const boost::asio::mutable_buffer& data);

  // Handle a data packet.
  void HandleData(const DataPacket& packet);

  // Handle an acknowledgement of an acknowledgement packet.
  void HandleAckOfAck(const AckOfAckPacket& packet);

  // Handle a tick in the system time.
  void HandleTick();

 private:
  // Disallow copying and assignment.
  Receiver(const Receiver&);
  Receiver& operator=(const Receiver&);

  // Helper function to decide the addition of an ack packet to the sliding window
  void AddAckToWindow(const boost::posix_time::ptime& now);

  // Helper function to add the sequence numbers of missing packets to a negative ack packet
  void AddMissingSequenceNumbersToNegAck(NegativeAckPacket& negative_ack);

  // Helper function to calculate the available buffer size.
  uint32_t AvailableBufferSize() const;

  // Calculate the sequence number which should be sent in an acknowledgement.
  uint32_t AckPacketSequenceNumber() const;

  // The peer with which we are communicating.
  Peer& peer_;

  // The timer used to generate tick events.
  TickTimer& tick_timer_;

  // The congestion control information associated with the connection.
  CongestionControl& congestion_control_;

  struct UnreadPacket {
    UnreadPacket()
        : packet(),
          lost(true),
          bytes_read(0),
          reserve_time(boost::asio::deadline_timer::traits_type::now()) {}
    DataPacket packet;
    bool lost;
    size_t bytes_read;
    boost::posix_time::ptime reserve_time;

    bool Missing(boost::posix_time::time_duration time_out) {
      boost::posix_time::ptime now = boost::asio::deadline_timer::traits_type::now();
      return (lost && ((reserve_time + time_out) < now));
    }
  };

  // The receiver's window of unread packets. If this window fills up, any new data packets are
  // dropped. The application needs to read data regularly to ensure that more data can be received.
  typedef SlidingWindow<UnreadPacket> UnreadPacketWindow;
  UnreadPacketWindow unread_packets_;

  struct Ack {
    Ack() : packet(), send_time(boost::asio::deadline_timer::traits_type::now()) {}
    AckPacket packet;
    boost::posix_time::ptime send_time;
  };

  // The receiver's window of acknowledgements. New acks are generated on a regular basis, so if
  // this window fills up the oldest entries are removed.
  typedef SlidingWindow<Ack> AckWindow;
  AckWindow acks_;

  // The last packet sequence number to have been acknowledged.
  uint32_t last_ack_packet_sequence_number_;

  // Next time the ack packet shall be sent
  boost::posix_time::ptime ack_sent_time_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CORE_RECEIVER_H_
