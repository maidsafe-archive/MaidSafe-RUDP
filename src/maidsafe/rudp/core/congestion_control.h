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

#ifndef MAIDSAFE_RUDP_CORE_CONGESTION_CONTROL_H_
#define MAIDSAFE_RUDP_CORE_CONGESTION_CONTROL_H_

#include <cstdint>
#include <deque>

#include "boost/date_time/posix_time/posix_time_types.hpp"

#include "maidsafe/rudp/core/sliding_window.h"
#include "maidsafe/rudp/packets/data_packet.h"
#include "maidsafe/rudp/core/tick_timer.h"
#include "maidsafe/rudp/parameters.h"

namespace maidsafe {

namespace rudp {

namespace detail {

class CongestionControl {
 public:
  CongestionControl();

  // Event notifications.
  void OnOpen(uint32_t send_seqnum, uint32_t receive_seqnum);
  void OnClose();
  void OnDataPacketSent(uint32_t seqnum);
  void OnDataPacketReceived(uint32_t seqnum);
  void OnGenerateAck(uint32_t seqnum);
  void OnAck(uint32_t seqnum);
  void OnAck(uint32_t seqnum,
             uint32_t round_trip_time,
             uint32_t round_trip_time_variance,
             uint32_t available_buffer_size,
             uint32_t packets_receiving_rate,
             uint32_t estimated_link_capacity);
  void OnNegativeAck(uint32_t seqnum);
  void OnSendTimeout(uint32_t seqnum);
  void OnAckOfAck(uint32_t round_trip_time);

  // Calculated values.
  uint32_t RoundTripTime() const;
  uint32_t RoundTripTimeVariance() const;
  uint32_t PacketsReceivingRate() const;
  uint32_t EstimatedLinkCapacity() const;

  // Parameters that are altered based on level of congestion.
  size_t SendWindowSize() const;
  size_t ReceiveWindowSize() const;
  size_t SendDataSize() const;
  boost::posix_time::time_duration SendDelay() const;
  boost::posix_time::time_duration SendTimeout() const;
  boost::posix_time::time_duration ReceiveDelay() const;
  boost::posix_time::time_duration ReceiveTimeout() const;
  boost::posix_time::time_duration AckDelay() const;
  boost::posix_time::time_duration AckTimeout() const;
  uint32_t AckInterval() const;
//  boost::posix_time::time_duration AckInterval() const;

  // Return the best read-buffer size
  int32_t BestReadBufferSize() const;

  // Connection type related
  void SetPeerConnectionType(uint32_t connection_type);
  size_t AllowedLost() const;

  // Calculate if the transmission speed is too slow
  bool IsSlowTransmission(size_t length);

 private:
  // Disallow copying and assignment.
  CongestionControl(const CongestionControl&);
  CongestionControl& operator=(const CongestionControl&);

  bool slow_start_phase_;

  uint32_t round_trip_time_;
  uint32_t round_trip_time_variance_;
  uint32_t packets_receiving_rate_;
  uint32_t estimated_link_capacity_;

  size_t send_window_size_;
  size_t receive_window_size_;
  size_t send_data_size_;
  boost::posix_time::time_duration send_delay_;
  boost::posix_time::time_duration send_timeout_;
  boost::posix_time::time_duration receive_delay_;
  boost::posix_time::time_duration receive_timeout_;
  boost::posix_time::time_duration ack_delay_;
  boost::posix_time::time_duration ack_timeout_;
  uint32_t ack_interval_;

  size_t lost_packets_;
  size_t corrupted_packets_;

  enum { kMaxArrivalTimes = 16 + 1 };
  std::deque<boost::posix_time::ptime> arrival_times_;

  enum { kMaxPacketPairIntervals = 16 + 1 };
  std::deque<boost::posix_time::time_duration> packet_pair_intervals_;

  // The peer's connection type
  uint32_t peer_connection_type_;

  // Allowed num of lost packets between two ack packets
  size_t allowed_lost_;

  // Speed calculation related;
  uintmax_t transmitted_bytes_, bits_per_second_;
  boost::posix_time::ptime last_record_transmit_time_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CORE_CONGESTION_CONTROL_H_
