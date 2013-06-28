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

#ifndef MAIDSAFE_RUDP_UTILS_H_
#define MAIDSAFE_RUDP_UTILS_H_

#include "boost/asio/ip/address.hpp"
#include "boost/asio/ip/udp.hpp"


namespace maidsafe {

namespace rudp {

namespace detail {

// Returns true if port > 1024 and the address is correctly specified.
bool IsValid(const boost::asio::ip::udp::endpoint& endpoint);

// Returns true if the two endpoints represent nodes on the same local network
bool OnSameLocalNetwork(const boost::asio::ip::udp::endpoint& endpoint1,
                        const boost::asio::ip::udp::endpoint& endpoint2);

// Returns true if peer_endpoint and this_external_endpoint are both non-local, or if
// peer_endpoint and this_local_endpoint are both potentially on the same local network.
bool IsConnectable(const boost::asio::ip::udp::endpoint& peer_endpoint,
                   const boost::asio::ip::udp::endpoint& this_local_endpoint,
                   const boost::asio::ip::udp::endpoint& this_external_endpoint);

// Returns true if the endpoint is within one of the ranges designated for private networks.
bool OnPrivateNetwork(const boost::asio::ip::udp::endpoint& endpoint);

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_UTILS_H_
