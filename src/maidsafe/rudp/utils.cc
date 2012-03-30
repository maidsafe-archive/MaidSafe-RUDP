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

#include "maidsafe/rudp/utils.h"
#include "maidsafe/rudp/log.h"
#include "maidsafe/rudp/network_interface.h"

namespace maidsafe {

namespace rudp {

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
    DLOG(ERROR) << e.what() << " - Decimal IP: " << decimal_ip;
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
    DLOG(ERROR) << e.what();
  }
  return "";
}

void IpNetToAscii(uint32_t address, char *ip_buffer) {
  // TODO(Team): warning thrown on 64-bit machine
  const int sizer = 15;
  #ifdef __MSVC__
    // N.B. first sizer value results from sizer * sizeof(char)
    _snprintf_s(ip_buffer, sizer, sizer, "%u.%u.%u.%u", (address>>24)&0xFF,
        (address>>16)&0xFF, (address>>8)&0xFF, (address>>0)&0xFF);
  #else
    snprintf(ip_buffer, sizer, "%u.%u.%u.%u", (address>>24)&0xFF,
        (address>>16)&0xFF, (address>>8)&0xFF, (address>>0)&0xFF);
  #endif
}

uint32_t IpAsciiToNet(const char *buffer) {
  // net_server inexplicably doesn't have this function; so I'll just fake it
  uint32_t ret = 0;
  int shift = 24;  //  fill out the MSB first
  bool startQuad = true;
  while ((shift >= 0) && (*buffer)) {
    if (startQuad) {
      unsigned char quad = (unsigned char) atoi(buffer);
      ret |= (((uint32_t)quad) << shift);
      shift -= 8;
    }
    startQuad = (*buffer == '.');
    ++buffer;
  }
  return ret;
}

std::vector<boost::asio::ip::address> GetLocalAddresses() {
  // get all network interfaces
  std::vector<boost::asio::ip::address> ips;
  boost::system::error_code ec;
  std::vector<NetworkInterface> net_interfaces;
  net_interfaces = NetworkInterface::LocalList(ec);
  if (!ec) {
    for (auto it = net_interfaces.begin(); it != net_interfaces.end(); ++it) {
      if (!NetworkInterface::IsLoopback(it->destination) &&
          !NetworkInterface::IsMulticast(it->destination) &&
          !NetworkInterface::IsAny(it->destination)) {
        ips.push_back(it->destination);
      }
    }
  }
  return ips;
}

}  // namespace rudp

}  // namespace maidsafe
