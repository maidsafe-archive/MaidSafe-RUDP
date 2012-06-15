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

#include "maidsafe/rudp/tests/test_utils.h"

#include <set>
#include <thread>

#include "boost/lexical_cast.hpp"

#include "maidsafe/common/log.h"

#include "maidsafe/rudp/managed_connections.h"
#include "maidsafe/rudp/return_codes.h"
#include "maidsafe/rudp/utils.h"


namespace maidsafe {

namespace rudp {

namespace test {

uint16_t GetRandomPort() {
  static std::set<uint16_t> already_used_ports;
  bool unique(false);
  uint16_t port(0);
  do {
    port = (RandomUint32() % 48126) + 1025;
    unique = (already_used_ports.insert(port)).second;
  } while (!unique);
  return port;
}

testing::AssertionResult SetupNetwork(std::vector<NodePtr> &nodes,
                                      std::vector<Endpoint> &bootstrap_endpoints,
                                      const int &node_count) {
  if (node_count < 2)
    return testing::AssertionFailure() << "Network size must be greater than 1";

  nodes.clear();
  bootstrap_endpoints.clear();
  for (int i(0); i != node_count; ++i)
    nodes.push_back(std::make_shared<Node>(i));

  // Setting up first two nodes
  Endpoint endpoint0(GetLocalIp(), GetRandomPort()),
           endpoint1(GetLocalIp(), GetRandomPort()),
           chosen_endpoint;

  std::thread thread([&] {
    chosen_endpoint = nodes[0]->Bootstrap(std::vector<Endpoint>(1, endpoint1), endpoint0);
  });
  if (nodes[1]->Bootstrap(std::vector<Endpoint>(1, endpoint0), endpoint1) != endpoint0)
    return testing::AssertionFailure() << "Bootstrapping failed for Node 1";

  thread.join();
  if (chosen_endpoint != endpoint1)
    return testing::AssertionFailure() << "Bootstrapping failed for Node 0";

  LOG(kInfo) << "Calling Add from " << endpoint0 << " to " << endpoint1;
  if (nodes[0]->managed_connections()->Add(endpoint0, endpoint1, nodes[0]->kValidationData()) !=
      kSuccess) {
    return testing::AssertionFailure() << "Node 0 failed to add Node 1";
  }
  LOG(kInfo) << "Calling Add from " << endpoint1 << " to " << endpoint0;
  if (nodes[1]->managed_connections()->Add(endpoint1, endpoint0, nodes[1]->kValidationData()) !=
      kSuccess) {
    return testing::AssertionFailure() << "Node 1 failed to add Node 0";
  }
  bootstrap_endpoints.push_back(endpoint0);
  bootstrap_endpoints.push_back(endpoint1);

  LOG(kInfo) << "Setting up remaining " << (node_count - 2) << " nodes";
  for (int i = 2; i != node_count; ++i) {
    if (!IsValid(nodes[i]->Bootstrap(bootstrap_endpoints)))
      return testing::AssertionFailure() << "Bootstrapping failed for " << nodes[i]->kId();
  }

  // TODO(Prakash): Check for validation messages at each node
  // Adding nodes to each other
  EndpointPair endpoint_pair1, endpoint_pair2;
  for (uint16_t i = 2; i != node_count; ++i) {
    for (uint16_t j = 2; j != node_count; ++j) {
      if ((j > i)) {  //  connecting all combination of nodes
        LOG(kInfo) << "Calling GetAvailableEndpoint on " << nodes[i]->kId();
        int result(nodes[i]->managed_connections()->GetAvailableEndpoint(endpoint_pair1));
        if (result != kSuccess ||
            !IsValid(endpoint_pair1.local) ||
            !IsValid(endpoint_pair1.external)) {
          return testing::AssertionFailure() << "GetAvailableEndpoint failed for "
                                             << nodes[i]->kId() << " with result " << result
                                             << ".  Local: " << endpoint_pair1.local
                                             << "  External: " << endpoint_pair1.external;
        }
        LOG(kInfo) << "Calling GetAvailableEndpoint on " << nodes[j]->kId();
        result = nodes[j]->managed_connections()->GetAvailableEndpoint(endpoint_pair2);
        if (result != kSuccess ||
            !IsValid(endpoint_pair2.local) ||
            !IsValid(endpoint_pair2.external)) {
          return testing::AssertionFailure() << "GetAvailableEndpoint failed for "
                                             << nodes[j]->kId() << " with result " << result
                                             << ".  Local: " << endpoint_pair2.local
                                             << "  External: " << endpoint_pair2.external;
        }

        LOG(kInfo) << "Calling Add from " << nodes[i]->kId() << " on "
                   << endpoint_pair1.external << " to " << nodes[j]->kId()
                   << " on " << endpoint_pair2.external;
        result = nodes[i]->managed_connections()->Add(endpoint_pair1.external,
                                                      endpoint_pair2.external,
                                                      nodes[i]->kValidationData());
        if (result != kSuccess) {
          return testing::AssertionFailure() << "Add failed for " << nodes[i]->kId()
                                             << " with result " << result;
        }

        LOG(kInfo) << "Calling Add from " << nodes[j]->kId() << " on "
                    << endpoint_pair2.external << " to " << nodes[i]->kId()
                    << " on " << endpoint_pair1.external;
        result = nodes[j]->managed_connections()->Add(endpoint_pair2.external,
                                                      endpoint_pair1.external,
                                                      nodes[j]->kValidationData());
        if (result != kSuccess) {
          return testing::AssertionFailure() << "Add failed for " << nodes[j]->kId()
                                             << " with result " << result;
        }
      }
      bootstrap_endpoints.push_back(endpoint_pair1.external);
    }
  }
  return testing::AssertionSuccess();
}


Node::Node(int id)
      : kId_("Node " + boost::lexical_cast<std::string>(id)),
        kValidationData_(kId_ + std::string("'s validation data")),
        mutex_(),
        connection_lost_endpoints_(),
        messages_(),
        managed_connections_(new ManagedConnections),
        promised_(false),
        total_message_count_expectation_(0),
        message_promise_() {}

std::vector<Endpoint> Node::connection_lost_endpoints() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return connection_lost_endpoints_;
}

std::vector<std::string> Node::messages() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return messages_;
}

Endpoint Node::Bootstrap(const std::vector<Endpoint> &bootstrap_endpoints,
                         Endpoint local_endpoint) {
  return managed_connections_->Bootstrap(
      bootstrap_endpoints,
      [&](const std::string &message) {
        LOG(kInfo) << kId_ << " -- Received: " << message.substr(0, 20);
        std::lock_guard<std::mutex> guard(mutex_);
        messages_.emplace_back(message);
        SetPromiseIfDone();
      },
      [&](const Endpoint &endpoint) {
        LOG(kInfo) << kId_ << " -- Lost connection to " << endpoint;
        std::lock_guard<std::mutex> guard(mutex_);
        connection_lost_endpoints_.emplace_back(endpoint);
      },
      local_endpoint);
}

void Node::ResetCount() {
  std::lock_guard<std::mutex> guard(mutex_);
  connection_lost_endpoints_.clear();
  messages_.clear();
  total_message_count_expectation_ = 0;
}

std::future<std::vector<std::string>> Node::GetFutureForMessages(const uint16_t &message_count) {
  BOOST_ASSERT(message_count > 0);
  total_message_count_expectation_ = message_count;
  promised_ = true;
  std::promise<std::vector<std::string>> message_promise;
  message_promise_.swap(message_promise);
  return message_promise_.get_future();
}

void Node::SetPromiseIfDone() {
  if (promised_ && messages_.size() >= total_message_count_expectation_) {
    message_promise_.set_value(messages_);
    promised_ = false;
    total_message_count_expectation_ = 0;
  }
}


}  // namespace test

}  // namespace rudp

}  // namespace maidsafe
