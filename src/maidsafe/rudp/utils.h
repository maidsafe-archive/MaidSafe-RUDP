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

// Makes a UDP socket connection to peer_endpoint.  Note, no data is sent, so no information about
// the validity or availability of the peer is deduced.  If the retrieved local endpoint is
// unspecified or is the loopback address, the function returns a default-constructed (invalid)
// address.
boost::asio::ip::address GetLocalIp(
    boost::asio::ip::udp::endpoint peer_endpoint =
        boost::asio::ip::udp::endpoint(
            boost::asio::ip::address_v4::from_string("203.0.113.9"), 80));

// Returns true if port > 1024 and the address is correctly specified.
bool IsValid(const boost::asio::ip::udp::endpoint& endpoint);

// Returns true if the two endpoints represent nodes on the same local network
bool OnSameNetwork(const boost::asio::ip::udp::endpoint& endpoint1,
                   const boost::asio::ip::udp::endpoint& endpoint2);

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_UTILS_H_
