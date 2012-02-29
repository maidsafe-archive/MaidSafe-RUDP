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

#include "boost/thread.hpp"
#include "maidsafe/transport/rudp_parameters.h"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace transport {

boost::uint32_t RudpParameters::default_window_size(16);
boost::uint32_t RudpParameters::maximum_window_size(512);
boost::uint32_t RudpParameters::default_size(1480);
boost::uint32_t RudpParameters::max_size(25980);
boost::uint32_t RudpParameters::default_data_size(1450);
boost::uint32_t RudpParameters::max_data_size(25950);
boost::posix_time::time_duration RudpParameters::default_send_timeout(
    bptime::milliseconds(1000));
boost::posix_time::time_duration RudpParameters::default_receive_timeout(
    bptime::milliseconds(200));
boost::posix_time::time_duration RudpParameters::default_send_delay(
    bptime::milliseconds(1000));
boost::posix_time::time_duration RudpParameters::default_receive_delay(
  bptime::milliseconds(100));
boost::posix_time::time_duration RudpParameters::default_ack_timeout(
    bptime::milliseconds(1000));
boost::posix_time::time_duration RudpParameters::ack_interval(
    bptime::milliseconds(100));
boost::posix_time::time_duration RudpParameters::speed_calculate_inverval(
    bptime::milliseconds(1000));
boost::uint32_t RudpParameters::slow_speed_threshold(1024);
boost::posix_time::time_duration RudpParameters::client_connect_timeout(
    bptime::milliseconds(1000));
RudpParameters::ConnectionType RudpParameters::connection_type(
    RudpParameters::kWireless);
}  // namespace transport

}  // namespace maidsafe

