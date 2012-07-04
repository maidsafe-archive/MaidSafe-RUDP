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

#ifndef MAIDSAFE_RUDP_TESTS_FAKE_MANAGED_CONNECTIONS_H_
#define MAIDSAFE_RUDP_TESTS_FAKE_MANAGED_CONNECTIONS_H_

#ifndef FAKE_RUDP
#  error This file must only be included if FAKE_RUDP is defined.
#endif

#include <functional>
#include <string>
#include <vector>

#include "boost/asio/ip/udp.hpp"


namespace maidsafe {

namespace rudp {

typedef std::function<void(const std::string&)> MessageReceivedFunctor;
typedef std::function<void(const boost::asio::ip::udp::endpoint&)> ConnectionLostFunctor;
typedef std::function<void(bool)> MessageSentFunctor;

struct EndpointPair {
  EndpointPair() : local(), external() {}
  boost::asio::ip::udp::endpoint local, external;
};


class ManagedConnections {
 public:
  ManagedConnections();
  ~ManagedConnections();
  static int32_t kMaxMessageSize() { return 67108864; }
  boost::asio::ip::udp::endpoint Bootstrap(
      const std::vector<boost::asio::ip::udp::endpoint> &bootstrap_endpoints,
      MessageReceivedFunctor message_received_functor,
      ConnectionLostFunctor connection_lost_functor,
      boost::asio::ip::udp::endpoint local_endpoint = boost::asio::ip::udp::endpoint());
  int GetAvailableEndpoint(EndpointPair &endpoint_pair);
  int Add(const boost::asio::ip::udp::endpoint &this_endpoint,
          const boost::asio::ip::udp::endpoint &peer_endpoint,
          const std::string &validation_data);
  void Remove(const boost::asio::ip::udp::endpoint &peer_endpoint);
  void Send(const boost::asio::ip::udp::endpoint &peer_endpoint,
            const std::string &message,
            MessageSentFunctor message_sent_functor) const;
};

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_TESTS_FAKE_MANAGED_CONNECTIONS_H_
