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

