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
// Created by Julian Cain on 11/3/09.

#ifndef MAIDSAFE_TRANSPORT_NETWORK_INTERFACE_H_
#define MAIDSAFE_TRANSPORT_NETWORK_INTERFACE_H_

#include <string>
#include <vector>
#include "boost/asio.hpp"

namespace maidsafe {

namespace transport {

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

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_NETWORK_INTERFACE_H_
