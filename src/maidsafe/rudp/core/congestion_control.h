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

#ifndef MAIDSAFE_RUDP_CORE_CONGESTION_CONTROL_H_
#define MAIDSAFE_RUDP_CORE_CONGESTION_CONTROL_H_

#include <deque>

#include "boost/cstdint.hpp"
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
  void OnOpen(boost::uint32_t send_seqnum,
              boost::uint32_t receive_seqnum);
  void OnClose();
  void OnDataPacketSent(boost::uint32_t seqnum);
  void OnDataPacketReceived(boost::uint32_t seqnum);
  void OnGenerateAck(boost::uint32_t seqnum);
  void OnAck(boost::uint32_t seqnum);
  void OnAck(boost::uint32_t seqnum,
             boost::uint32_t round_trip_time,
             boost::uint32_t round_trip_time_variance,
             boost::uint32_t available_buffer_size,
             boost::uint32_t packets_receiving_rate,
             boost::uint32_t estimated_link_capacity);
  void OnNegativeAck(boost::uint32_t seqnum);
  void OnSendTimeout(boost::uint32_t seqnum);
  void OnAckOfAck(boost::uint32_t round_trip_time);

  // Calculated values.
  boost::uint32_t RoundTripTime() const;
  boost::uint32_t RoundTripTimeVariance() const;
  boost::uint32_t PacketsReceivingRate() const;
  boost::uint32_t EstimatedLinkCapacity() const;

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
  boost::posix_time::time_duration AckInterval() const;
//   boost::uint32_t AckInterval() const;

  // Return the best read-buffer size
  boost::uint32_t BestReadBufferSize();

  // Connection type related
  void SetPeerConnectionType(boost::uint32_t connection_type);
  size_t AllowedLost() const;

  // Calculate if the transmission speed is too slow
  bool IsSlowTransmission(size_t length);
  // In b/s
  boost::uint32_t TransmissionSpeed() const;

 private:
  // Disallow copying and assignment.
  CongestionControl(const CongestionControl&);
  CongestionControl &operator=(const CongestionControl&);

  bool slow_start_phase_;

  boost::uint32_t round_trip_time_;
  boost::uint32_t round_trip_time_variance_;
  boost::uint32_t packets_receiving_rate_;
  boost::uint32_t estimated_link_capacity_;

  size_t send_window_size_;
  size_t receive_window_size_;
  size_t send_data_size_;
  boost::posix_time::time_duration send_delay_;
  boost::posix_time::time_duration send_timeout_;
  boost::posix_time::time_duration receive_delay_;
  boost::posix_time::time_duration receive_timeout_;
  boost::posix_time::time_duration ack_delay_;
  boost::posix_time::time_duration ack_timeout_;
  boost::uint32_t ack_interval_;

  size_t lost_packets_;
  size_t corrupted_packets_;

  enum { kMaxArrivalTimes = 16 + 1 };
  std::deque<boost::posix_time::ptime> arrival_times_;

  enum { kMaxPacketPairIntervals = 16 + 1 };
  std::deque<boost::posix_time::time_duration> packet_pair_intervals_;

  // The peer's connection type
  boost::uint32_t peer_connection_type_;

  // Allowed num of lost packets between two ack packets
  size_t allowed_lost_;

  // Speed calculation related;
  boost::uint32_t transmitted_bits_;
  boost::posix_time::ptime last_record_transmit_time_;
  // in b/s
  boost::uint32_t transmission_speed_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CORE_CONGESTION_CONTROL_H_
