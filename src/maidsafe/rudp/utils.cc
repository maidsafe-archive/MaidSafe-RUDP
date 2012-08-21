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

#include <string>
#include <utility>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

namespace asio = boost::asio;
namespace ip = asio::ip;


namespace maidsafe {

namespace rudp {

namespace detail {

namespace {

ip::address_v4 NetworkPrefix(const ip::address_v4& address) {
  ip::address_v4::bytes_type network_prefix;
  for (int i(0); i != network_prefix.size(); ++i)
    network_prefix[i] = address.to_bytes()[i] & ip::address_v4::netmask(address).to_bytes()[i];
  return ip::address_v4(network_prefix);
}

const ip::address_v4 kMinClassA(ip::address_v4::from_string("10.0.0.0"));
const ip::address_v4 kMaxClassA(ip::address_v4::from_string("10.255.255.255"));
const ip::address_v4 kMinClassB(ip::address_v4::from_string("172.16.0.0"));
const ip::address_v4 kMaxClassB(ip::address_v4::from_string("172.31.255.255"));
const ip::address_v4 kMinClassC(ip::address_v4::from_string("192.168.0.0"));
const ip::address_v4 kMaxClassC(ip::address_v4::from_string("192.168.255.255"));

bool IsPrivateNetworkAddress(const ip::address_v4& address) {
  BOOST_ASSERT_MSG(!kMinClassA.is_unspecified(),
                   (kMinClassA.to_string() + " (kMinClassA) is unspecified.").c_str());
  BOOST_ASSERT_MSG(!kMaxClassA.is_unspecified(),
                   (kMaxClassA.to_string() + " (kMaxClassA) is unspecified.").c_str());
  BOOST_ASSERT_MSG(!kMinClassB.is_unspecified(),
                   (kMinClassB.to_string() + " (kMinClassB) is unspecified.").c_str());
  BOOST_ASSERT_MSG(!kMaxClassB.is_unspecified(),
                   (kMaxClassB.to_string() + " (kMaxClassB) is unspecified.").c_str());
  BOOST_ASSERT_MSG(!kMinClassC.is_unspecified(),
                   (kMinClassC.to_string() + " (kMinClassC) is unspecified.").c_str());
  BOOST_ASSERT_MSG(!kMaxClassC.is_unspecified(),
                   (kMaxClassC.to_string() + " (kMaxClassC) is unspecified.").c_str());
  if (address <= kMaxClassA)
    return address >= kMinClassA;
  if (address <= kMaxClassB)
    return address >= kMinClassB;
  if (address < kMinClassC)
    return false;
  return address <= kMaxClassC;
}

}  // unnamed namespace

ip::address GetLocalIp(ip::udp::endpoint peer_endpoint) {
  asio::io_service io_service;
  ip::udp::socket socket(io_service);
  try {
    socket.connect(peer_endpoint);
    if (socket.local_endpoint().address().is_unspecified() ||
        socket.local_endpoint().address().is_loopback())
      return ip::address();
    return socket.local_endpoint().address();
  }
  catch(const std::exception& e) {
    LOG(kError) << "Failed trying to connect to " << peer_endpoint << " - " << e.what();
    return ip::address();
  }
}

bool IsValid(const ip::udp::endpoint& endpoint) {
  return endpoint.port() > 1024U && !endpoint.address().is_unspecified();
}

bool OnSameLocalNetwork(const ip::udp::endpoint& endpoint1, const ip::udp::endpoint& endpoint2) {
  if (endpoint1.address().is_v4() && endpoint2.address().is_v4()) {
    ip::address_v4 address1(endpoint1.address().to_v4()), address2(endpoint2.address().to_v4());
    return IsPrivateNetworkAddress(address1) && NetworkPrefix(address1) == NetworkPrefix(address2);
  } else if (endpoint1.address().is_v6() && endpoint2.address().is_v6()) {
    // TODO(Fraser#5#): 2012-07-30 - Handle IPv6 properly.
    return endpoint1.address().to_v6().is_link_local();
  } else if (endpoint1.address().is_v6() && endpoint1.address().to_v6().is_v4_compatible()) {
    return OnSameLocalNetwork(ip::udp::endpoint(endpoint1.address().to_v6().to_v4(),
                                                endpoint1.port()), endpoint2);
  } else if (endpoint2.address().is_v6() && endpoint2.address().to_v6().is_v4_compatible()) {
    return OnSameLocalNetwork(endpoint1, ip::udp::endpoint(endpoint2.address().to_v6().to_v4(),
                                                           endpoint2.port()));
  } else {
    return false;
  }
}

bool IsConnectable(const ip::udp::endpoint& peer_endpoint,
                   const ip::udp::endpoint& this_local_endpoint,
                   const ip::udp::endpoint& this_external_endpoint) {
  if (IsValid(this_external_endpoint)) {
    assert(this_external_endpoint.address().is_v4() ?
           !IsPrivateNetworkAddress(this_external_endpoint.address().to_v4()) :
           !this_external_endpoint.address().to_v6().is_link_local());
    // return true if peer_endpoint is external
    if (peer_endpoint.address().is_v4() &&
        !IsPrivateNetworkAddress(peer_endpoint.address().to_v4())) {
      return true;
    } else if (peer_endpoint.address().is_v6() &&
               !peer_endpoint.address().to_v6().is_link_local()) {
      return true;
    }
  }

  return OnSameLocalNetwork(peer_endpoint, this_local_endpoint);
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
