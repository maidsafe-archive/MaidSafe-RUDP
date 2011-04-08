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

#ifndef MAIDSAFE_DHT_TRANSPORT_RUDP_CONGESTION_CONTROL_H_
#define MAIDSAFE_DHT_TRANSPORT_RUDP_CONGESTION_CONTROL_H_

#include <deque>

#include "boost/cstdint.hpp"
#include "boost/date_time/posix_time/posix_time_types.hpp"

#include "rudp_sliding_window.h"
#include "rudp_data_packet.h"
#include "rudp_tick_timer.h"

namespace maidsafe {

namespace transport {

class RudpCongestionControl {
 public:
  RudpCongestionControl();

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
  boost::posix_time::time_duration SendDelay() const;
  boost::posix_time::time_duration SendTimeout() const;
  boost::posix_time::time_duration AckDelay() const;
  boost::posix_time::time_duration AckTimeout() const;
  boost::uint32_t AckInterval() const;

 private:
  // Disallow copying and assignment.
  RudpCongestionControl(const RudpCongestionControl&);
  RudpCongestionControl &operator=(const RudpCongestionControl&);

  bool slow_start_phase_;

  boost::uint32_t round_trip_time_;
  boost::uint32_t round_trip_time_variance_;
  boost::uint32_t packets_receiving_rate_;
  boost::uint32_t estimated_link_capacity_;

  size_t send_window_size_;
  size_t receive_window_size_;
  boost::posix_time::time_duration send_delay_;
  boost::posix_time::time_duration send_timeout_;
  boost::posix_time::time_duration ack_delay_;
  boost::posix_time::time_duration ack_timeout_;
  boost::uint32_t ack_interval_;

  enum { kMaxArrivalTimes = 16 + 1 };
  std::deque<boost::posix_time::ptime> arrival_times_;

  enum { kMaxPacketPairIntervals = 16 + 1 };
  std::deque<boost::posix_time::time_duration> packet_pair_intervals_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_TRANSPORT_RUDP_CONGESTION_CONTROL_H_
