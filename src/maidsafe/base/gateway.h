/* Copyright (c) 2009 maidsafe.net limited
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

Created by Julian Cain on 11/3/09.

*/

#ifndef MAIDSAFE_BASE_GATEWAY_H_
#define MAIDSAFE_BASE_GATEWAY_H_

#include <boost/asio.hpp>
#include <vector>
#include "maidsafe/maidsafe-dht_config.h"
#include "maidsafe/base/network_interface.h"

#if (defined(MAIDSAFE_APPLE) || defined(MAIDSAFE_POSIX) || defined(__MACH__)) \
    && !defined(MAIDSAFE_LINUX)
struct rt_msghdr;
#elif defined(MAIDSAFE_LINUX)
struct nlmsghdr;
#endif

namespace base {

class Gateway {
 public:

/**
  * Returns the default gateway address.
  * @param ios
  * @param ec
  */
  static boost::asio::ip::address DefaultRoute(boost::asio::io_service & ios,
                                               boost::system::error_code & ec);

 private:

/**
  * Enumerates and returns ip routes.
  */
  static std::vector<NetworkInterface> Routes(boost::asio::io_service & ios,
                                              boost::system::error_code & ec);

 protected:

#if (defined(MAIDSAFE_APPLE) || defined(MAIDSAFE_POSIX) || defined(__MACH__)) \
    && !defined(MAIDSAFE_LINUX)
/**
  * Parse a rt_msghdr and assign it to rt_if.
  * @param rtm
  * @param rt_info
  */
  static bool ParseRtMsghdr(rt_msghdr * rtm, NetworkInterface & rt_if);
#elif defined(MAIDSAFE_LINUX)

/**
  * Reads the netlink socket.
  * @param sock The socket to read.
  * @param buf The buffer.
  * @param len The len of buffer in bytes.
  * @param seq The sequence.
  * @param pid The process id.
  */
  static int ReadNetlinkSock(int sock, char * buf, int len, int seq, int pid);

/**
  * Parse a nlmsghdr and assign it to rt_if.
  * @param nl_hdr
  * @param rt_info
  */
  static bool ParseNlmsghdr(nlmsghdr * nl_hdr, NetworkInterface & rt_if);
#endif
};

}  // namespace base

#endif  // MAIDSAFE_BASE_GATEWAY_H_
