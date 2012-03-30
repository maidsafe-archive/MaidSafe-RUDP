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

#ifndef MAIDSAFE_RUDP_ENDPOINT_H_
#define MAIDSAFE_RUDP_ENDPOINT_H_

#include <cstdint>
#include <string>


#include "maidsafe/rudp/version.h"

#if MAIDSAFE_RUDP_VERSION != 100
#  error This API is not compatible with the installed library.\
    Please update the maidsafe_rudp library.
#endif

namespace maidsafe {

namespace rudp {

typedef boost::asio::ip::address IP;
typedef uint16_t Port;

struct Endpoint {
  Endpoint();
  Endpoint(const IP &ip_in, const Port &port_in);
  Endpoint(const std::string &ip_as_string, const Port &port_in);
  bool operator==(const Endpoint &other) const;
  bool operator!=(const Endpoint &other) const;
  bool operator<(const Endpoint &other) const;
  bool operator>(const Endpoint &other) const;

  IP ip;
  Port port;
};


// Returns true if the IP is not default constructed, and the Port is not 0.
bool IsValid(const Endpoint &endpoint);

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_ENDPOINT_H_
