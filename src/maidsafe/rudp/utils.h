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
