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

#include "maidsafe/rudp/parameters.h"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

uint32_t Parameters::thread_count(1);
int Parameters::max_transports(10);
const uint32_t Parameters::maximum_segment_size(16);
uint32_t Parameters::default_window_size(4*Parameters::maximum_segment_size);
uint32_t Parameters::maximum_window_size(32*Parameters::maximum_segment_size);
uint32_t Parameters::default_burst_send_size(1);
uint32_t Parameters::default_size(1480);

// TODO(Fraser#5#): 2012-11-05 - Re-enable higher buffer limits on Windows once Session is able to
//                               set these on a per-connection basis during handshaking.
// #ifdef MAIDSAFE_WIN32
// uint32_t Parameters::max_size(25980);
// uint32_t Parameters::max_data_size(25950);
// #else
uint32_t Parameters::max_size(8192);
uint32_t Parameters::max_data_size(8162);
// #endif
uint32_t Parameters::default_data_size(1450);
Timeout Parameters::default_send_timeout(bptime::milliseconds(300));
Timeout Parameters::default_receive_timeout(bptime::milliseconds(500));
Timeout Parameters::default_send_delay(bptime::milliseconds(10));
Timeout Parameters::default_receive_delay(bptime::milliseconds(100));
Timeout Parameters::default_ack_timeout(bptime::seconds(1));
Timeout Parameters::ack_interval(bptime::milliseconds(100));
Timeout Parameters::speed_calculate_inverval(bptime::seconds(10));
uint32_t Parameters::slow_speed_threshold(1024);
Timeout Parameters::rendezvous_connect_timeout(bptime::seconds(15));
Timeout Parameters::bootstrap_connect_timeout(bptime::seconds(3));
Timeout Parameters::ping_timeout(bptime::seconds(2));
Timeout Parameters::keepalive_interval(bptime::milliseconds(500));
Timeout Parameters::keepalive_timeout(bptime::milliseconds(400));
uint32_t Parameters::maximum_keepalive_failures(20);
uint32_t Parameters::maximum_handshake_failures(40);
Timeout Parameters::bootstrap_connection_lifespan(bptime::minutes(10));
Timeout Parameters::disconnection_timeout(bptime::milliseconds(500));
Parameters::ConnectionType Parameters::connection_type(Parameters::kWireless);

}  // namespace rudp

}  // namespace maidsafe
