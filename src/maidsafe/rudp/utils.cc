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
  for (unsigned int i(0); i != network_prefix.size(); ++i)
    network_prefix[i] = address.to_bytes()[i] & ip::address_v4::netmask(address).to_bytes()[i];
  return ip::address_v4(network_prefix);
}

const ip::address_v4 kMinClassA(167772160U);   // 10.0.0.0
const ip::address_v4 kMaxClassA(184549375U);   // 10.255.255.255
const ip::address_v4 kMinClassB(2886729728U);  // 172.16.0.0
const ip::address_v4 kMaxClassB(2887778303U);  // 172.31.255.255
const ip::address_v4 kMinClassC(3232235520U);  // 192.168.0.0
const ip::address_v4 kMaxClassC(3232301055U);  // 192.168.255.255

bool IsPrivateNetworkAddress(const ip::address_v4& address) {
  assert(!kMinClassA.is_unspecified() &&
         (kMinClassA.to_string() + " (kMinClassA) is unspecified.").c_str());
  assert(!kMaxClassA.is_unspecified() &&
         (kMaxClassA.to_string() + " (kMaxClassA) is unspecified.").c_str());
  assert(!kMinClassB.is_unspecified() &&
         (kMinClassB.to_string() + " (kMinClassB) is unspecified.").c_str());
  assert(!kMaxClassB.is_unspecified() &&
         (kMaxClassB.to_string() + " (kMaxClassB) is unspecified.").c_str());
  assert(!kMinClassC.is_unspecified() &&
         (kMinClassC.to_string() + " (kMinClassC) is unspecified.").c_str());
  assert(!kMaxClassC.is_unspecified() &&
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
                                                endpoint1.port()),
                              endpoint2);
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

bool OnPrivateNetwork(const ip::udp::endpoint& endpoint) {
  if (endpoint.address().is_v4())
    return IsPrivateNetworkAddress(endpoint.address().to_v4());
  else
    // TODO(Fraser#5#): 2012-07-30 - Handle IPv6 properly.
    return endpoint.address().to_v6().is_link_local();
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
