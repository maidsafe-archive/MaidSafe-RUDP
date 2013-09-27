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

#include <algorithm>
#include <cmath>
#include <limits>
#include <vector>

#include "boost/assert.hpp"

#include "maidsafe/rudp/core/congestion_control.h"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

namespace detail {

static const bptime::time_duration kSynPeriod = bptime::milliseconds(10);

CongestionControl::CongestionControl()
  : slow_start_phase_(true),
    round_trip_time_(0),
    round_trip_time_variance_(0),
    packets_receiving_rate_(0),
    estimated_link_capacity_(0),
    send_window_size_(Parameters::default_window_size),
    receive_window_size_(Parameters::default_window_size),
    send_data_size_(Parameters::default_data_size),
    send_delay_(Parameters::default_send_delay),
    send_timeout_(Parameters::default_send_timeout),
    receive_delay_(Parameters::default_receive_delay),
    receive_timeout_(Parameters::default_receive_timeout),
    ack_delay_(bptime::milliseconds(10)),
    ack_timeout_(Parameters::default_ack_timeout),
    ack_interval_(Parameters::maximum_segment_size),
    lost_packets_(0),
    corrupted_packets_(0),
    arrival_times_(),
    packet_pair_intervals_(),
    peer_connection_type_(0),
    allowed_lost_(0),
    transmitted_bytes_(std::numeric_limits<uintmax_t>::max()),
    bits_per_second_(0),
    last_record_transmit_time_() {}

void CongestionControl::OnOpen(uint32_t /*send_seqnum*/, uint32_t /*receive_seqnum*/) {
  transmitted_bytes_ = std::numeric_limits<uintmax_t>::max();
}

void CongestionControl::OnClose() {
  transmitted_bytes_ = std::numeric_limits<uintmax_t>::max();
}

void CongestionControl::OnDataPacketSent(uint32_t /*seqnum*/) {
}

void CongestionControl::OnDataPacketReceived(uint32_t seqnum) {
  bptime::ptime now = TickTimer::Now();

  if ((seqnum % 16 == 1) && !arrival_times_.empty()) {
    // The pushed in interval is the interval between every 16 arrived packets
    // mjc : this doesn't do what the comment says. seqnum can come out-of-order
    //       and even be missed completely due to the nature of UDP.
    packet_pair_intervals_.push_back(now - arrival_times_.back());
    while (packet_pair_intervals_.size() > kMaxPacketPairIntervals)
      packet_pair_intervals_.pop_front();
  }

  arrival_times_.push_back(now);
  while (arrival_times_.size() > kMaxArrivalTimes)
    arrival_times_.pop_front();
}

void CongestionControl::OnGenerateAck(uint32_t /*seqnum*/) {
  // Need to have received at least 8 packets to calculate receiving rate.
  if (arrival_times_.size() <= 8)
    return;

  // Calculate all packet arrival intervals.
  std::vector<uint64_t> intervals;
  for (auto iter = arrival_times_.begin() + 1; iter != arrival_times_.end(); ++iter)
    intervals.push_back((*iter - *(iter - 1)).total_microseconds());

  // Find the median packet arrival interval.
  std::sort(intervals.begin(), intervals.end());
  uint64_t median = intervals[intervals.size() / 2];

  // Calculate average of all intervals in range (median / 8) to (median * 8).
  size_t num_valid_intervals = 0;
  uint64_t total = 0;
  for (auto& item : intervals) {
    if ((median / 8 <= item) && (item <= median * 8)) {
      ++num_valid_intervals;
      total += item;
    }
  }

  // Determine packet arrival speed only if we had more than 8 valid values.
  if ((total > 0) && (num_valid_intervals > 8)) {
    assert(num_valid_intervals <= std::numeric_limits<uint64_t>::max() / 1000000);
    assert((1000000 * num_valid_intervals) / total <= std::numeric_limits<uint32_t>::max());
    packets_receiving_rate_ = static_cast<uint32_t>(((1000000 * num_valid_intervals) / total));
  } else {
    packets_receiving_rate_ = 0;
  }

  // Need to have recorded some packet pair intervals to be able to calculate
  // the estimated link capacity.
  if (!packet_pair_intervals_.empty()) {
    // Calculate the estimated link capacity by determining the median of the
    // packet pair intervals, and from that determining the number of packets
    // per second.
    std::vector<uint64_t> packet_pair_intervals;
    for (auto& item : packet_pair_intervals_)
      packet_pair_intervals.push_back(item.total_microseconds());
    std::sort(packet_pair_intervals.begin(), packet_pair_intervals.end());
    uint64_t packet_pair_median = packet_pair_intervals[packet_pair_intervals.size() / 2];
    estimated_link_capacity_ =
        (packet_pair_median > 0) ? static_cast<uint32_t>(1000000 / packet_pair_median) : 0;
  }

  // TODO(qi.ma@maidsafe.net) : The receive_window_size shall be based on the
  // local processing power, i.e. the reading speed of the data flow
  receive_window_size_ = Parameters::maximum_window_size;
//   receive_window_size_ = (packets_receiving_rate_ * round_trip_time_) / 1000000;
//   // The speed of generating Ack Packets shall be considered
//   receive_window_size_ *= (1000 / Parameters::ack_interval.total_milliseconds());
//   receive_window_size_ = std::max(receive_window_size_, Parameters::default_window_size);
//   receive_window_size_ = std::min(receive_window_size_, Parameters::maximum_window_size);
  // TODO(Team) calculate SND (send_delay_).
}

void CongestionControl::OnAck(uint32_t /*seqnum*/) {
}

void CongestionControl::OnAck(uint32_t /*seqnum*/,
                              uint32_t round_trip_time,
                              uint32_t round_trip_time_variance,
                              uint32_t available_buffer_size,
                              uint32_t packets_receiving_rate,
                              uint32_t estimated_link_capacity) {
  round_trip_time_ = round_trip_time;
  round_trip_time_variance_ = round_trip_time_variance;

  ack_delay_ = bptime::microseconds(UINT64_C(4) * round_trip_time_);
  ack_delay_ += bptime::microseconds(round_trip_time_variance_);
  ack_delay_ += kSynPeriod;

  if (packets_receiving_rate) {
    uint64_t tmp = packets_receiving_rate_ * UINT64_C(7);
    tmp = (tmp + packets_receiving_rate) / 8;
    packets_receiving_rate_ = static_cast<uint32_t>(tmp);
  }

  if (estimated_link_capacity) {
    uint64_t tmp = estimated_link_capacity_ * UINT64_C(7);
    tmp = (tmp + estimated_link_capacity) / 8;
    estimated_link_capacity_ = static_cast<uint32_t>(tmp);
  }
  // Each time an ack packet received, we check whether during this interval,
  // any packet reported to be lost or corrupted. If none, increase size,
  // otherwise decrease size
  if ((corrupted_packets_ + lost_packets_) > AllowedLost()) {
    send_data_size_ = static_cast<size_t>(0.9 * send_data_size_);
    send_data_size_ = std::max(static_cast<size_t>(Parameters::default_data_size), send_data_size_);
  } else {
    send_data_size_ = static_cast<size_t>(1.5 * send_data_size_);
    send_data_size_ = std::min(static_cast<size_t>(Parameters::max_data_size), send_data_size_);
  }
  corrupted_packets_ = 0;
  lost_packets_ = 0;

  // The send_window_size is adjusted based on the receiver's available buffer.
  // The window size will grow and shrink in increments of the maximum_segment_size.
  //
  // Growth occurs one maximum_segment_size at a time when the receiver has enough
  //    room to hold a full maximum_segment_size of data.
  //
  // The send_window_size_ will decrease by a maximum_segment_size when the receiver
  // has less than 50% maximum_segment_size headroom.
  //
  if (available_buffer_size >= (send_data_size_ * Parameters::maximum_segment_size)) {
    send_window_size_ += Parameters::maximum_segment_size;
    send_window_size_ = std::min(send_window_size_,
                                 static_cast<size_t>(Parameters::maximum_window_size));
  } else if (available_buffer_size < (send_data_size_ * Parameters::maximum_segment_size/2)) {
    send_window_size_ -= Parameters::maximum_segment_size;
    send_window_size_ = std::max(send_window_size_,
                                 static_cast<size_t>(Parameters::default_window_size));
  }

}

void CongestionControl::OnNegativeAck(uint32_t /*seqnum*/) {
  ++corrupted_packets_;
}

void CongestionControl::OnSendTimeout(uint32_t /*seqnum*/) {
  ++lost_packets_;
}

void CongestionControl::OnAckOfAck(uint32_t round_trip_time) {
  uint32_t diff = (round_trip_time < round_trip_time_) ? (round_trip_time_ - round_trip_time) :
                                                         (round_trip_time - round_trip_time_);

  uint32_t tmp = round_trip_time_ * UINT64_C(7);
  tmp = (tmp + round_trip_time) / 8;
  round_trip_time_ = static_cast<uint32_t>(tmp);

  tmp = round_trip_time_variance_ * UINT64_C(3);
  tmp = (tmp + diff) / 4;
  round_trip_time_variance_ = static_cast<uint32_t>(tmp);

  ack_delay_ = bptime::microseconds(UINT64_C(4) * round_trip_time_);
  ack_delay_ += bptime::microseconds(round_trip_time_variance_);
  ack_delay_ += kSynPeriod;
}

void CongestionControl::SetPeerConnectionType(uint32_t connection_type) {
  peer_connection_type_ = connection_type;
  uint32_t local_connection_type = Parameters::connection_type;
  uint32_t worst_connection_type = std::min(peer_connection_type_, local_connection_type);
  if (worst_connection_type <= Parameters::kWireless) {
    allowed_lost_ = 5;
  } else if (worst_connection_type <= Parameters::kE1) {
    allowed_lost_ = 2;
  } else if (worst_connection_type <= Parameters::k1GEthernet) {
    allowed_lost_ = 1;
  }
}

bool CongestionControl::IsSlowTransmission(size_t /*length*/) {
//  // if length keeps to be zero, socket will have timeout eventually
//  // so don't need to worry about all 0 situation here
//  if (transmitted_bytes_ == std::numeric_limits<uintmax_t>::max()) {
//    transmitted_bytes_ = length;
//    last_record_transmit_time_ = TickTimer::Now();
//  } else {
//    boost::posix_time::ptime now(TickTimer::Now());
//    transmitted_bytes_ += length;
//    // only calculate speed every calculation interval
//    boost::posix_time::time_duration duration = now - last_record_transmit_time_;
//    if (duration > Parameters::speed_calculate_inverval) {
//      assert(transmitted_bytes_ < std::numeric_limits<uintmax_t>::max() / 1000);
//      bits_per_second_ = (1000 * transmitted_bytes_) / duration.total_milliseconds();
//      // be different to the initial state
//      transmitted_bytes_ = 0;
//      last_record_transmit_time_ = now;
//      if (bits_per_second_ < Parameters::slow_speed_threshold)
//        return true;
//    }
//  }
  return false;
}

size_t CongestionControl::AllowedLost() const {
  return allowed_lost_;
}

uint32_t CongestionControl::RoundTripTime() const {
  return round_trip_time_;
}

uint32_t CongestionControl::RoundTripTimeVariance() const {
  return round_trip_time_variance_;
}

uint32_t CongestionControl::PacketsReceivingRate() const {
  return packets_receiving_rate_;
}

uint32_t CongestionControl::EstimatedLinkCapacity() const {
  return estimated_link_capacity_;
}

size_t CongestionControl::SendWindowSize() const {
  return send_window_size_;
}

size_t CongestionControl::ReceiveWindowSize() const {
  return receive_window_size_;
}

size_t CongestionControl::SendDataSize() const {
  return send_data_size_;
}

int32_t CongestionControl::BestReadBufferSize() const {
  assert(static_cast<int32_t>(receive_window_size_ * Parameters::max_data_size) > 0);
  return static_cast<int32_t>(receive_window_size_ * Parameters::max_data_size);
}

boost::posix_time::time_duration CongestionControl::SendDelay() const {
  return send_delay_;
}

boost::posix_time::time_duration CongestionControl::SendTimeout() const {
  return send_timeout_;
}

boost::posix_time::time_duration CongestionControl::ReceiveDelay() const {
  return receive_delay_;
}

boost::posix_time::time_duration CongestionControl::ReceiveTimeout() const {
  return receive_timeout_;
}

boost::posix_time::time_duration CongestionControl::AckDelay() const {
  return ack_delay_;
}

boost::posix_time::time_duration CongestionControl::AckTimeout() const {
  return ack_timeout_;
}

uint32_t CongestionControl::AckInterval() const {
  return ack_interval_;
}

//  boost::posix_time::time_duration CongestionControl::AckInterval() const {
//    return Parameters::ack_interval;
//  }

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
