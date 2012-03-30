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


#include "maidsafe/rudp/endpoint.h"
#include "maidsafe/rudp/log.h"


namespace maidsafe {

namespace rudp {

Endpoint::Endpoint() : ip(), port(0) {}

Endpoint::Endpoint(const IP &ip_in, const Port &port_in)
    : ip(ip_in),
      port(port_in) {}

Endpoint::Endpoint(const std::string &ip_as_string, const Port &port_in)
    : ip(),
      port(port_in) {
  boost::system::error_code ec;
  ip = IP::from_string(ip_as_string, ec);
  if (ec) {
    DLOG(WARNING) << "Failed to construct Endpoint from string \""
                  << ip_as_string << "\": " << ec.message();
    port = 0;
  }
}

bool Endpoint::operator==(const Endpoint &other) const {
  return (ip == other.ip && port == other.port);
}

bool Endpoint::operator!=(const Endpoint &other) const {
  return !(*this == other);
}

bool Endpoint::operator<(const Endpoint &other) const {
  if (ip != other.ip)
    return (ip < other.ip);
  else
    return port < other.port;
}

bool Endpoint::operator>(const Endpoint &other) const {
  if (ip != other.ip)
    return (ip > other.ip);
  else
    return port > other.port;
}


bool IsValid(const Endpoint &endpoint) {
  return (endpoint.ip != IP()) && (endpoint.port != 0);
}

}  // namespace rudp

}  // namespace maidsafe
