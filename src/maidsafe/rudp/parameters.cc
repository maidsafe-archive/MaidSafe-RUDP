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

#include "maidsafe/rudp/parameters.h"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

uint32_t Parameters::thread_count(2);
int Parameters::max_transports(10);
uint32_t Parameters::default_window_size(64);
uint32_t Parameters::maximum_window_size(512);
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
Timeout Parameters::default_send_timeout(bptime::milliseconds(500));
Timeout Parameters::default_receive_timeout(bptime::milliseconds(500));
Timeout Parameters::default_send_delay(bptime::milliseconds(10));
Timeout Parameters::default_receive_delay(bptime::milliseconds(100));
Timeout Parameters::default_ack_timeout(bptime::seconds(1));
Timeout Parameters::ack_interval(bptime::milliseconds(100));
Timeout Parameters::speed_calculate_inverval(bptime::seconds(10));
uint32_t Parameters::slow_speed_threshold(1024);
Timeout Parameters::rendezvous_connect_timeout(bptime::seconds(5));
Timeout Parameters::bootstrap_connect_timeout(bptime::seconds(2));
Timeout Parameters::ping_timeout(bptime::seconds(2));
Timeout Parameters::keepalive_interval(bptime::milliseconds(500));
Timeout Parameters::keepalive_timeout(bptime::milliseconds(400));
uint32_t Parameters::maximum_keepalive_failures(20);
Timeout Parameters::bootstrap_connection_lifespan(bptime::minutes(10));
Timeout Parameters::disconnection_timeout(bptime::milliseconds(500));
Parameters::ConnectionType Parameters::connection_type(Parameters::kWireless);
#ifdef TESTING
bool Parameters::rudp_encrypt(true);
#endif

}  // namespace rudp

}  // namespace maidsafe

