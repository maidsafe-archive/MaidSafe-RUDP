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

#include "boost/thread.hpp"
#include "maidsafe/rudp/parameters.h"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

boost::uint32_t Parameters::default_window_size(16);
boost::uint32_t Parameters::maximum_window_size(512);
boost::uint32_t Parameters::default_size(1480);
boost::uint32_t Parameters::max_size(25980);
boost::uint32_t Parameters::default_data_size(1450);
boost::uint32_t Parameters::max_data_size(25950);
boost::posix_time::time_duration Parameters::default_send_timeout(
    bptime::milliseconds(1000));
boost::posix_time::time_duration Parameters::default_receive_timeout(
    bptime::milliseconds(200));
boost::posix_time::time_duration Parameters::default_send_delay(
    bptime::milliseconds(1000));
boost::posix_time::time_duration Parameters::default_receive_delay(
  bptime::milliseconds(100));
boost::posix_time::time_duration Parameters::default_ack_timeout(
    bptime::milliseconds(1000));
boost::posix_time::time_duration Parameters::ack_interval(
    bptime::milliseconds(100));
boost::posix_time::time_duration Parameters::speed_calculate_inverval(
    bptime::milliseconds(1000));
boost::uint32_t Parameters::slow_speed_threshold(1024);
boost::posix_time::time_duration Parameters::client_connect_timeout(
    bptime::milliseconds(1000));
Parameters::ConnectionType Parameters::connection_type(Parameters::kWireless);
}  // namespace rudp

}  // namespace maidsafe

