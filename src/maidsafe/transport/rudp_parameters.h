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

#ifndef MAIDSAFE_TRANSPORT_RUDP_PARAMETERS_H_
#define MAIDSAFE_TRANSPORT_RUDP_PARAMETERS_H_

#include <cassert>
#include <deque>

#include "boost/cstdint.hpp"
#include "maidsafe/common/utils.h"
#include "maidsafe/transport/version.h"

#if MAIDSAFE_TRANSPORT_VERSION != 104
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-transport library.
#endif

namespace maidsafe {

namespace transport {

// This class provides the configurability to all traffic related parameters.
struct RudpParameters {
 public:
  // Window size permitted in RUDP
  static boost::uint32_t default_window_size;
  static boost::uint32_t maximum_window_size;

  // Packet size permitted in RUDP
  // Shall not exceed the UDP payload, which is 65507
  static boost::uint32_t default_size;
  static boost::uint32_t max_size;
  enum { kUDPPayload = 65500 };

  // Data Payload size permitted in RUDP
  // Shall not exceed Packet Size defined
  static boost::uint32_t default_data_size;
  static boost::uint32_t max_data_size;

  // Timeout defined for a packet to be resent
  static boost::posix_time::time_duration default_send_timeout;

  // Timeout defined for a neg-ack packet to be resent to request resent of an
  // observed missing packet in receiver
  static boost::posix_time::time_duration default_receive_timeout;

  // Machine dependent parameter of send delay,
  // depending on computation power and I/O speed
  static boost::posix_time::time_duration default_send_delay;

  // Machine dependent parameter of receive delay,
  // depending on computation power and I/O speed
  static boost::posix_time::time_duration default_receive_delay;

  // Timeout defined for a Ack packet to be resent
  static boost::posix_time::time_duration default_ack_timeout;

  // Timeout defined the fixed interval between Ack packets
  static boost::posix_time::time_duration ack_interval;

  // Interval to calculate speed
  static boost::posix_time::time_duration speed_calculate_inverval;

  // Slow speed threshold to force the socket closed, in b/s
  static boost::uint32_t slow_speed_threshold;

  // Timeout during client connection establishment
  static boost::posix_time::time_duration client_connect_timeout;

  // Defined connection types
  enum ConnectionType {
    kWireless = 0x0fffffff,
    kT1 = 0xf0ffffff,
    kE1 = 0xf1ffffff,
    k10MEthernet = 0xff0fffff,
    k100MEthernet = 0xff1fffff,
    k1GEthernet = 0xff2fffff
  };
  static ConnectionType connection_type;

 private:
  // Disallow copying and assignment.
  RudpParameters(const RudpParameters&);
  RudpParameters &operator=(const RudpParameters&);
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_PARAMETERS_H_
