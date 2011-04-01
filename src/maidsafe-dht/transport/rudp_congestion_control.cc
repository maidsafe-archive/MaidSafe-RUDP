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

#include "maidsafe-dht/transport/rudp_congestion_control.h"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace transport {

RudpCongestionControl::RudpCongestionControl()
  : round_trip_time_(0),
    round_trip_time_variance_(0),
    packets_receiving_rate_(0),
    estimated_link_capacity_(0),
    window_size_(16),
    send_delay_(bptime::milliseconds(0)),
    send_timeout_(bptime::milliseconds(100)),
    ack_delay_(bptime::milliseconds(10)),
    ack_timeout_(bptime::milliseconds(100)),
    ack_interval_(8) {
}

void RudpCongestionControl::OnOpen(boost::uint32_t send_seqnum,
                                   boost::uint32_t receive_seqnum) {
}

void RudpCongestionControl::OnClose() {
}

void RudpCongestionControl::OnDataPacketSent(boost::uint32_t seqnum) {
}

void RudpCongestionControl::OnDataPacketReceived(boost::uint32_t seqnum) {
}

void RudpCongestionControl::OnAck(boost::uint32_t seqnum) {
}

void RudpCongestionControl::OnAck(boost::uint32_t seqnum,
                                  boost::uint32_t round_trip_time,
                                  boost::uint32_t round_trip_time_variance,
                                  boost::uint32_t packets_receiving_rate,
                                  boost::uint32_t estimated_link_capacity) {
}

void RudpCongestionControl::OnNegativeAck(boost::uint32_t seqnum) {
}

void RudpCongestionControl::OnSendTimeout(boost::uint32_t seqnum) {
}

void RudpCongestionControl::OnAckOfAck(boost::uint32_t round_trip_time) {
}

boost::uint32_t RudpCongestionControl::RoundTripTime() const {
  return round_trip_time_;
}

boost::uint32_t RudpCongestionControl::RoundTripTimeVariance() const {
  return round_trip_time_variance_;
}

boost::uint32_t RudpCongestionControl::PacketsReceivingRate() const {
  return packets_receiving_rate_;
}

boost::uint32_t RudpCongestionControl::EstimatedLinkCapacity() const {
  return estimated_link_capacity_;
}

size_t RudpCongestionControl::WindowSize() const {
  return window_size_;
}

boost::posix_time::time_duration RudpCongestionControl::SendDelay() const {
  return send_delay_;
}

boost::posix_time::time_duration RudpCongestionControl::SendTimeout() const {
  return send_timeout_;
}

boost::posix_time::time_duration RudpCongestionControl::AckDelay() const {
  return ack_delay_;
}

boost::posix_time::time_duration RudpCongestionControl::AckTimeout() const {
  return ack_timeout_;
}

boost::uint32_t RudpCongestionControl::AckInterval() const {
  return ack_interval_;
}

}  // namespace transport

}  // namespace maidsafe
