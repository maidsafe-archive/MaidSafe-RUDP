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

bool IsValid(const Endpoint &endpoint) {
  return (endpoint.ip != IP()) && (endpoint.port != 0);
}

std::ostream& operator<<(std::ostream& output_stream,
                         const Endpoint& endpoint) {
  output_stream << endpoint.ip.to_string() << ":" << endpoint.port;
  return output_stream;
}

bool operator==(const Endpoint& lhs, const Endpoint& rhs) {
  return (lhs.ip == rhs.ip && lhs.port == rhs.port);
}

bool operator!=(const Endpoint& lhs, const Endpoint& rhs) {
  return !operator==(lhs, rhs);
}

bool operator<(const Endpoint& lhs, const Endpoint& rhs) {
  if (lhs.ip != rhs.ip)
    return (lhs.ip < rhs.ip);
  else
    return lhs.port < rhs.port;
}

bool operator>(const Endpoint& lhs, const Endpoint& rhs) {
  return operator< (rhs, lhs);
}


}  // namespace rudp

}  // namespace maidsafe
