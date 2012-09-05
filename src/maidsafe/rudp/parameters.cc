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

#include "maidsafe/rudp/parameters.h"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

uint32_t Parameters::thread_count(2);
int Parameters::max_transports(10);
uint32_t Parameters::default_window_size(64);
uint32_t Parameters::maximum_window_size(512);
uint32_t Parameters::default_size(1480);
#ifdef MAIDSAFE_WIN32
uint32_t Parameters::max_size(25980);
uint32_t Parameters::max_data_size(25950);
#else
uint32_t Parameters::max_size(8192);
uint32_t Parameters::max_data_size(8162);
#endif
uint32_t Parameters::default_data_size(1450);
Timeout Parameters::default_send_timeout(bptime::milliseconds(500));
Timeout Parameters::default_receive_timeout(bptime::milliseconds(500));
Timeout Parameters::default_send_delay(bptime::seconds(1));
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
Timeout Parameters::disconnection_timeout(bptime::milliseconds(100));
Parameters::ConnectionType Parameters::connection_type(Parameters::kWireless);

}  // namespace rudp

}  // namespace maidsafe

