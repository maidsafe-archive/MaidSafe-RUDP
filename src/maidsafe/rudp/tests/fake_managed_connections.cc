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

#include "maidsafe/rudp/tests/fake_managed_connections.h"


namespace maidsafe {

namespace rudp {

namespace {

typedef boost::asio::ip::udp::endpoint Endpoint;

}  // unnamed namespace

ManagedConnections::ManagedConnections() {
}

ManagedConnections::~ManagedConnections() {
}

Endpoint ManagedConnections::Bootstrap(
    const std::vector<Endpoint> &/*bootstrap_endpoints*/,
    MessageReceivedFunctor /*message_received_functor*/,
    ConnectionLostFunctor /*connection_lost_functor*/,
    boost::asio::ip::udp::endpoint /*local_endpoint*/) {
  return Endpoint();
}

int ManagedConnections::GetAvailableEndpoint(EndpointPair &/*endpoint_pair*/) {
  return -1;
}

int ManagedConnections::Add(const Endpoint &/*this_endpoint*/,
                            const Endpoint &/*peer_endpoint*/,
                            const std::string &/*validation_data*/) {
  return -1;
}

void ManagedConnections::Remove(const Endpoint &/*peer_endpoint*/) {
}

void ManagedConnections::Send(const Endpoint &/*peer_endpoint*/,
                              const std::string &/*message*/,
                              MessageSentFunctor /*message_sent_functor*/) const {
}

}  // namespace rudp

}  // namespace maidsafe
