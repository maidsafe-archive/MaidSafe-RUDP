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
*/

#include "maidsafe/transport/utils.h"
//#include <boost/date_time/posix_time/posix_time.hpp>
//#include <boost/lexical_cast.hpp>
//#include <boost/scoped_array.hpp>
//#include <boost/thread/mutex.hpp>
//#include <ctype.h>
//#include <maidsafe/cryptopp/integer.h>
//#include <maidsafe/cryptopp/osrng.h>
//#include <maidsafe/cryptopp/base32.h>
//#include <maidsafe/cryptopp/base64.h>
//#include <maidsafe/cryptopp/hex.h>
//#include <algorithm>
//#include <limits>
//#include <string>
#include "maidsafe/base/log.h"
#include "maidsafe/transport/network_interface.h"

namespace transport {

std::string IpAsciiToBytes(const std::string &decimal_ip) {
  try {
    boost::asio::ip::address ip =
        boost::asio::ip::address::from_string(decimal_ip);
    if (ip.is_v4()) {
      boost::asio::ip::address_v4::bytes_type addr = ip.to_v4().to_bytes();
      std::string result(addr.begin(), addr.end());
      return result;
    } else if (ip.is_v6()) {
      boost::asio::ip::address_v6::bytes_type addr = ip.to_v6().to_bytes();
      std::string result(addr.begin(), addr.end());
      return result;
    }
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << e.what() << " - Decimal IP: " << decimal_ip << std::endl;
  }
  return "";
}

std::string IpBytesToAscii(const std::string &bytes_ip) {
  try {
    if (bytes_ip.size() == 4) {
      boost::asio::ip::address_v4::bytes_type bytes_type_ip;
      for (int i = 0; i < 4; ++i)
        bytes_type_ip[i] = bytes_ip.at(i);
      boost::asio::ip::address_v4 address(bytes_type_ip);
      return address.to_string();
    } else if (bytes_ip.size() == 16) {
      boost::asio::ip::address_v6::bytes_type bytes_type_ip;
      for (int i = 0; i < 16; ++i)
        bytes_type_ip[i] = bytes_ip.at(i);
      boost::asio::ip::address_v6 address(bytes_type_ip);
      return address.to_string();
    }
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << e.what() << std::endl;
  }
  return "";
}

void IpNetToAscii(boost::uint32_t address, char *ip_buffer) {
  // TODO(Team): warning thrown on 64-bit machine
  const int sizer = 15;
  #ifdef __MSVC__
    _snprintf(ip_buffer, sizer, "%u.%u.%u.%u", (address>>24)&0xFF,
        (address>>16)&0xFF, (address>>8)&0xFF, (address>>0)&0xFF);
  #else
    snprintf(ip_buffer, sizer, "%u.%u.%u.%u", (address>>24)&0xFF,
        (address>>16)&0xFF, (address>>8)&0xFF, (address>>0)&0xFF);
  #endif
}

boost::uint32_t IpAsciiToNet(const char *buffer) {
  // net_server inexplicably doesn't have this function; so I'll just fake it
  boost::uint32_t ret = 0;
  int shift = 24;  //  fill out the MSB first
  bool startQuad = true;
  while ((shift >= 0) && (*buffer)) {
    if (startQuad) {
      unsigned char quad = (unsigned char) atoi(buffer);
      ret |= (((boost::uint32_t)quad) << shift);
      shift -= 8;
    }
    startQuad = (*buffer == '.');
    ++buffer;
  }
  return ret;
}

std::vector<IP> GetLocalAddresses() {
  // get all network interfaces
  std::vector<IP> ips;
  boost::system::error_code ec;
  std::vector<NetworkInterface> net_interfaces;
  net_interfaces = NetworkInterface::LocalList(ec);
  if (!ec) {
    for (std::vector<NetworkInterface>::iterator it = net_interfaces.begin();
         it != net_interfaces.end(); ++it) {
      if (!NetworkInterface::IsLoopback(it->destination) &&
          !NetworkInterface::IsMulticast(it->destination) &&
          !NetworkInterface::IsAny(it->destination)) {
        ips.push_back(it->destination);
      }
    }
  }
  return ips;
}

}  // namespace transport
