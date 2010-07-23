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

#ifndef MAIDSAFE_BASE_NETWORK_INTERFACE_H_
#define MAIDSAFE_BASE_NETWORK_INTERFACE_H_

#include <boost/asio.hpp>

#include <string>
#include <vector>

namespace base {

/**
  * Network interface utilities.
  */
struct NetworkInterface {
  NetworkInterface() : destination(), gateway(), netmask() {}
/**
  * Determines if the given ip address is local.
  * @param addr The ip address to check.
  */
  static bool IsLocal(const boost::asio::ip::address & addr);

/**
  * Determines if the given ip address is loopback.
  * @param addr The ip address to check.
  */
  static bool IsLoopback(const boost::asio::ip::address & addr);

/**
  * Determines if the given ip address is multicast.
  * @param addr The ip address to check.
  */
  static bool IsMulticast(const boost::asio::ip::address & addr);

/**
  * Determines if the given ip address is any.
  * @param addr The ip address to check.
  */
  static bool IsAny(const boost::asio::ip::address & addr);

/**
  * Takes an in_addr structure and returns a boost::asio::ip::address
  * object.
  * @param addr The in_addr struct to convert.
  */
  static boost::asio::ip::address InaddrToAddress(const in_addr * addr);

/**
  * Takes an in6_addr structure and returns a boost::asio::ip::address
  * object.
  * @param addr The in6_addr struct to convert.
  */
  static boost::asio::ip::address Inaddr6ToAddress(const in6_addr * addr);

/**
  * Takes an sockaddr structure and returns a boost::asio::ip::address
  * object.
  * @param addr The sockaddr struct to convert.
  */
  static boost::asio::ip::address SockaddrToAddress(const sockaddr * addr);

/**
  * Returns all the network interfaces on the local system.
  * @return An std::vector of NetworkInterface objects, one per
  * physical or virtual network interface.
  */
  static std::vector<NetworkInterface> LocalList(
      boost::system::error_code & ec);

/**
  * Returns the local ip address of the machine.
  * @note If the system is dualstack or multihomed this will return the
  * first valid network interface. Also this could be split into two
  * functions local_ipv4_address and local_ipv6_address respectively.
  */
  static boost::asio::ip::address LocalAddress();

/**
  * The destination ip address.
  */
  boost::asio::ip::address destination;

/**
  * The gateway ip address.
  */
  boost::asio::ip::address gateway;

/**
  * The netmask of the network interface.
  */
  boost::asio::ip::address netmask;

/**
  * The string representation of the network interface.
  */
  char name[64];
};

}  // namespace base

#endif  // MAIDSAFE_BASE_NETWORK_INTERFACE_H_
