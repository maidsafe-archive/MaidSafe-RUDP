/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.novinet.com/license

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

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
