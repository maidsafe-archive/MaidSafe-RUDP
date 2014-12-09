/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#include "maidsafe/rudp/tests/test_utils.h"

#include <thread>
#include <set>
#include <boost/asio/use_future.hpp>

#include "boost/lexical_cast.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/managed_connections.h"
#include "maidsafe/rudp/parameters.h"
#include "maidsafe/rudp/return_codes.h"
#include "maidsafe/rudp/utils.h"
#include "maidsafe/rudp/nat_type.h"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

namespace test {

testing::AssertionResult SetupNetwork(std::vector<NodePtr>& nodes,
                                      std::vector<Contact>& bootstrap_endpoints, int node_count) {
  using boost::asio::use_future;
  using boost::system::system_error;

  LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 1";
  if (node_count < 2)
    return testing::AssertionFailure() << "Network size must be greater than 1";

  LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 2";
  nodes.clear();
  bootstrap_endpoints.clear();
  for (int i(0); i != node_count; ++i) {
    nodes.push_back(std::make_shared<Node>(i));
  }

  LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 3";
  // Setting up first two nodes
  EndpointPair endpoints0, endpoints1;
  endpoints0.local = Endpoint(GetLocalIp(), maidsafe::test::GetRandomPort());
  endpoints1.local = Endpoint(GetLocalIp(), maidsafe::test::GetRandomPort());
  Contact contacts[] = { Contact(nodes[0]->node_id(), endpoints0.local, *nodes[0]->public_key())
                       , Contact(nodes[1]->node_id(), endpoints1.local, *nodes[1]->public_key())
                       };

  Contact chosen_node_id, node1_chosen_bootstrap_contact;
  //int result0(0);

  LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 4";
  boost::thread thread([&] {
    //chosen_node_id = nodes[0]->Bootstrap(std::vector<Endpoint>(1, endpoints1.local),
    //                              chosen_node_id,
    //                              endpoints0.local);
    EXPECT_NO_THROW(chosen_node_id
                     = nodes[0]->Bootstrap(std::vector<Contact>(1, contacts[1]), endpoints0.local));
  });

  EXPECT_NO_THROW(node1_chosen_bootstrap_contact
                   = nodes[1]->Bootstrap(std::vector<Contact>(1, contacts[0]), endpoints1.local));

  //node1_chosen_bootstrap_contact = nodes[1]->Bootstrap(std::vector<Endpoint>(1, endpoints0.local),
  //                                node1_chosen_bootstrap_contact,
  //                                endpoints1.local);
  LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 4.5";
  thread.join();

  LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 5 ";
  //if (result0 == kBindError || result1 == kBindError) {
  //  // The endpoints were taken by some other program, retry...
  //  return SetupNetwork(nodes, bootstrap_endpoints, node_count);
  //}

  LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 6 ";
  if (node1_chosen_bootstrap_contact.id != nodes[0]->node_id())
    return testing::AssertionFailure() << "Bootstrapping failed for Node 1.";
  LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 7";
  if (chosen_node_id.id != nodes[1]->node_id())
    return testing::AssertionFailure() << "Bootstrapping failed for Node 0.";

  LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 8";
  EndpointPair endpoint_pair0, endpoint_pair1;
  //NatType nat_type0(NatType::kUnknown), nat_type1(NatType::kUnknown);
  endpoint_pair1 = endpoints1;
  Sleep(std::chrono::milliseconds(250));

  //nodes[0]->managed_connections()->GetAvailableEndpoints(
  //    nodes[1]->node_id(),
  //    [](std::error_code, EndpointPair) {
  //    });

  LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 9";

  //EXPECT_EQ(kBootstrapConnectionAlreadyExists,
  //          nodes[0]->managed_connections()->GetAvailableEndpoints(
  //              nodes[1]->node_id(), endpoint_pair1, endpoint_pair0, nat_type0));
  // FIXME: Expect particular error
  EXPECT_ANY_THROW(nodes[0]->managed_connections()->GetAvailableEndpoints
                         (nodes[1]->node_id(), use_future).get());
  LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 10 ";

  //EXPECT_EQ(kBootstrapConnectionAlreadyExists,
  //          nodes[1]->managed_connections()->GetAvailableEndpoints(
  //              nodes[0]->node_id(), endpoint_pair0, endpoint_pair1, nat_type1));
  // FIXME: Expect particular error
  EXPECT_ANY_THROW(nodes[1]->managed_connections()->GetAvailableEndpoints
                         (nodes[0]->node_id(), use_future).get());

  LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 11 ";

  //auto futures0(nodes[0]->GetFutureForMessages(1));
  //auto futures1(nodes[1]->GetFutureForMessages(1));
  //LOG(kInfo) << "Calling Add from " << endpoints0.local << " to " << endpoints1.local;
  //if (nodes[0]->managed_connections()->Add(nodes[1]->node_id(), endpoints1,
  //                                         nodes[0]->validation_data()) != kSuccess) {
  //  return testing::AssertionFailure() << "Node 0 failed to add Node 1";
  //}
  EXPECT_THROW( nodes[0]->managed_connections()->Add(contacts[1], use_future).get()
              , boost::system::system_error);


  nodes[0]->AddConnectedNodeId(nodes[1]->node_id());
  //LOG(kInfo) << "Calling Add from " << endpoints1.local << " to " << endpoints0.local;
  //if (nodes[1]->managed_connections()->Add(nodes[0]->node_id(), endpoints0,
  //                                         nodes[1]->validation_data()) != kSuccess) {
  //  return testing::AssertionFailure() << "Node 1 failed to add Node 0";
  //}
  EXPECT_THROW( nodes[1]->managed_connections()->Add(contacts[0], use_future).get()
              , boost::system::system_error);
  nodes[1]->AddConnectedNodeId(nodes[0]->node_id());

  LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 12 ";
  //boost::chrono::milliseconds timeout(Parameters::rendezvous_connect_timeout.total_milliseconds());
  //if (futures0.wait_for(timeout) != boost::future_status::ready) {
  //  return testing::AssertionFailure() << "Failed waiting for " << nodes[0]->id() << " to receive "
  //                                     << nodes[1]->id() << "'s validation data.";
  //}
  //if (futures1.wait_for(timeout) != boost::future_status::ready) {
  //  return testing::AssertionFailure() << "Failed waiting for " << nodes[1]->id() << " to receive "
  //                                     << nodes[0]->id() << "'s validation data.";
  //}
  //auto messages0(futures0.get());
  //auto messages1(futures1.get());
  //if (messages0.size() != 1U) {
  //  return testing::AssertionFailure() << nodes[0]->id() << " has " << messages0.size()
  //                                     << " messages [should be 1].";
  //}
  //if (messages1.size() != 1U) {
  //  return testing::AssertionFailure() << nodes[1]->id() << " has " << messages1.size()
  //                                     << " messages [should be 1].";
  //}
  //if (messages0[0] != nodes[1]->validation_data()) {
  //  return testing::AssertionFailure() << nodes[0]->id() << " has received " << nodes[1]->id()
  //                                     << "'s validation data as " << messages0[0]
  //                                     << " [should be \"" << nodes[1]->validation_data() << "\"].";
  //}
  //if (messages1[0] != nodes[0]->validation_data()) {
  //  return testing::AssertionFailure() << nodes[1]->id() << " has received " << nodes[0]->id()
  //                                     << "'s validation data as " << messages1[0]
  //                                     << " [should be \"" << nodes[0]->validation_data() << "\"].";
  //}
  //Endpoint endpoint1, endpoint2;
  //int result(
  //    nodes[0]->managed_connections()->MarkConnectionAsValid(nodes[1]->node_id(), endpoint1));
  //if (result != kSuccess) {
  //  return testing::AssertionFailure() << nodes[0]->id() << " failed to mark connection to "
  //                                     << nodes[1]->id() << " as valid.";
  //}
  //result = nodes[1]->managed_connections()->MarkConnectionAsValid(nodes[0]->node_id(), endpoint2);
  //if (result != kSuccess) {
  //  return testing::AssertionFailure() << nodes[1]->id() << " failed to mark connection to "
  //                                     << nodes[0]->id() << " as valid.";
  //}

  //bootstrap_endpoints.push_back(endpoints0.local);
  //bootstrap_endpoints.push_back(endpoints1.local);
  bootstrap_endpoints.push_back(contacts[0]);
  bootstrap_endpoints.push_back(contacts[1]);
  nodes[0]->ResetData();
  nodes[1]->ResetData();

  if (node_count > 2)
    LOG(kInfo) << "Setting up remaining " << (node_count - 2) << " nodes";

  LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 13 ";
  // Adding nodes to each other
  for (int i = 2; i != node_count; ++i) {
    Contact chosen_node_id;
    EXPECT_NO_THROW(chosen_node_id = nodes[i]->Bootstrap(bootstrap_endpoints));

    LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 14 ";
    if (chosen_node_id.id == NodeId()) {
      return testing::AssertionFailure() << "Bootstrapping failed for " << nodes[i]->id();
    }

    LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 15 ";
    Contact empty_endpoint_pair, this_endpoint_pair, peer_endpoint_pair;
    //NatType nat_type;
    Sleep(std::chrono::milliseconds(250));
    for (int j(0); j != i; ++j) {
      LOG(kInfo) << "Starting attempt to connect " << nodes[i]->id() << " to " << nodes[j]->id();
      // Call GetAvailableEndpoint at each peer.
      nodes[i]->ResetData();
      nodes[j]->ResetData();
    //  int result(nodes[i]->managed_connections()->GetAvailableEndpoint(
    //      nodes[j]->node_id(), empty_endpoint_pair, this_endpoint_pair, nat_type));
    //  if (result != kSuccess && result != kBootstrapConnectionAlreadyExists) {
    //    return testing::AssertionFailure() << "GetAvailableEndpoint failed for " << nodes[i]->id()
    //                                       << " with result " << result
    //                                       << ".  Local: " << this_endpoint_pair.local
    //                                       << "  External: " << this_endpoint_pair.external;
    //  } else {
    //    LOG(kInfo) << "GetAvailableEndpoint on " << nodes[i]->id() << " to " << nodes[j]->id()
    //               << " with peer_id " << nodes[j]->debug_node_id() << " returned "
    //               << this_endpoint_pair.external << " / " << this_endpoint_pair.local;
    //  }
      try {
        nodes[i]->managed_connections()->GetAvailableEndpoints(nodes[j]->node_id(), use_future).get();
      }
      catch(system_error e) {
        EXPECT_EQ(e.code(), RudpErrors::already_connected);
      }
      break; // TODO: Debug break
    //  result = nodes[j]->managed_connections()->GetAvailableEndpoint(
    //      nodes[i]->node_id(), this_endpoint_pair, peer_endpoint_pair, nat_type);
    //  if (result != kSuccess && result != kBootstrapConnectionAlreadyExists) {
    //    return testing::AssertionFailure() << "GetAvailableEndpoint failed for " << nodes[j]->id()
    //                                       << " with result " << result
    //                                       << ".  Local: " << peer_endpoint_pair.local
    //                                       << "  External: " << peer_endpoint_pair.external
    //                                       << "  Peer: " << this_endpoint_pair.local;
    //  } else {
    //    LOG(kInfo) << "Calling GetAvailableEndpoint on " << nodes[j]->id() << " to "
    //               << nodes[i]->id() << " with peer_endpoint " << this_endpoint_pair.local
    //               << " returned " << peer_endpoint_pair.external << " / "
    //               << peer_endpoint_pair.local;
    //  }

    //  // Call Add at each peer.
    //  futures0 = nodes[i]->GetFutureForMessages(1);
    //  futures1 = nodes[j]->GetFutureForMessages(1);

    //  LOG(kInfo) << "Calling Add from " << nodes[j]->id() << " on " << peer_endpoint_pair.local
    //             << " to " << nodes[i]->id() << " on " << this_endpoint_pair.local;
    //  result = nodes[j]->managed_connections()->Add(nodes[i]->node_id(), this_endpoint_pair,
    //                                                nodes[j]->validation_data());
    //  nodes[j]->AddConnectedNodeId(nodes[i]->node_id());
    //  if (result != kSuccess) {
    //    return testing::AssertionFailure() << "Add failed for " << nodes[j]->id() << " with result "
    //                                       << result;
    //  }

    //  LOG(kInfo) << "Calling Add from " << nodes[i]->id() << " on " << this_endpoint_pair.local
    //             << " to " << nodes[j]->id() << " on " << peer_endpoint_pair.local;
    //  result = nodes[i]->managed_connections()->Add(nodes[j]->node_id(), peer_endpoint_pair,
    //                                                nodes[i]->validation_data());
    //  nodes[i]->AddConnectedNodeId(nodes[j]->node_id());
    //  if (result != kSuccess) {
    //    return testing::AssertionFailure() << "Add failed for " << nodes[i]->id() << " with result "
    //                                       << result;
    //  }

    //  // Check validation data was received correctly at each peer, and if so call
    //  // MarkConnectionAsValid.
    //  boost::chrono::milliseconds timeout(
    //      Parameters::rendezvous_connect_timeout.total_milliseconds());
    //  if (futures0.wait_for(timeout) != boost::future_status::ready) {
    //    return testing::AssertionFailure() << "Failed waiting for " << nodes[i]->id()
    //                                       << " to receive " << nodes[j]->id()
    //                                       << "'s validation data.";
    //  }
    //  if (futures1.wait_for(timeout) != boost::future_status::ready) {
    //    return testing::AssertionFailure() << "Failed waiting for " << nodes[j]->id()
    //                                       << " to receive " << nodes[i]->id()
    //                                       << "'s validation data.";
    //  }
    //  messages0 = futures0.get();
    //  messages1 = futures1.get();
    //  if (messages0.size() != 1U) {
    //    return testing::AssertionFailure() << nodes[i]->id() << " has " << messages0.size()
    //                                       << " messages [should be 1].";
    //  }
    //  if (messages1.size() != 1U) {
    //    return testing::AssertionFailure() << nodes[j]->id() << " has " << messages1.size()
    //                                       << " messages [should be 1].";
    //  }
    //  if (messages0[0] != nodes[j]->validation_data()) {
    //    return testing::AssertionFailure() << nodes[i]->id() << " has received " << nodes[j]->id()
    //                                       << "'s validation data as " << messages0[0]
    //                                       << " [should be \"" << nodes[j]->validation_data()
    //                                       << "\"].";
    //  }
    //  if (messages1[0] != nodes[i]->validation_data()) {
    //    return testing::AssertionFailure() << nodes[j]->id() << " has received " << nodes[i]->id()
    //                                       << "'s validation data as " << messages1[0]
    //                                       << " [should be \"" << nodes[i]->validation_data()
    //                                       << "\"].";
    //  }
    //  Endpoint endpoint1, endpoint2;
    //  result =
    //      nodes[i]->managed_connections()->MarkConnectionAsValid(nodes[j]->node_id(), endpoint1);
    //  if (result != kSuccess) {
    //    return testing::AssertionFailure() << nodes[i]->id() << " failed to mark connection to "
    //                                       << nodes[j]->id() << " as valid.";
    //  }
    //  result =
    //      nodes[j]->managed_connections()->MarkConnectionAsValid(nodes[i]->node_id(), endpoint2);
    //  if (result != kSuccess) {
    //    return testing::AssertionFailure() << nodes[j]->id() << " failed to mark connection to "
    //                                       << nodes[i]->id() << " as valid.";
    //  }
    }
    bootstrap_endpoints.push_back(this_endpoint_pair);
  }
  return testing::AssertionSuccess();
}

Node::Node(int id)
    : node_id_(RandomString(NodeId::kSize)),
      id_("Node " + boost::lexical_cast<std::string>(id)),
      key_pair_(asymm::GenerateKeyPair()),
      validation_data_(id_ + "'s validation data"),
      mutex_(),
      connection_lost_node_ids_(),
      connected_node_ids_(),
      messages_(),
      managed_connections_(new ManagedConnections),
      promised_(false),
      total_message_count_expectation_(0),
      message_promise_() {}

std::vector<NodeId> Node::connection_lost_node_ids() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return connection_lost_node_ids_;
}

std::vector<std::string> Node::messages() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return messages_;
}

Contact Node::Bootstrap(const std::vector<Contact>& bootstrap_endpoints, Endpoint local_endpoint) {
  //NatType nat_type(NatType::kUnknown);

  struct BootstrapListener : public ManagedConnections::Listener {
    Node& self;

    BootstrapListener(Node& self) : self(self) {}

    void MessageReceived(NodeId /*peer_id*/, ReceivedMessage message) override {
      bool is_printable(true);
      for (const auto& elem : message) {
        if (elem < 32) {
          is_printable = false;
          break;
        }
      }
      std::string message_str(message.begin(), message.end());
      LOG(kInfo) << self.id() << " -- Received: " << (is_printable ? message_str.substr(0, 30)
                                                                   : HexEncode(message_str.substr(0, 15)));
      std::lock_guard<std::mutex> guard(self.mutex_);
      self.messages_.emplace_back(message_str);
      self.SetPromiseIfDone();
    }

    void ConnectionLost(NodeId peer_id) override {
      LOG(kInfo) << self.id() << " -- Lost connection to " << DebugId(self.node_id_);
      std::lock_guard<std::mutex> guard(self.mutex_);
      self.connection_lost_node_ids_.emplace_back(peer_id);
      self.connected_node_ids_.erase(
          std::remove(self.connected_node_ids_.begin(), self.connected_node_ids_.end(), peer_id),
          self.connected_node_ids_.end());
    }
  };

  return managed_connections_->Bootstrap(
      bootstrap_endpoints,
      std::make_shared<BootstrapListener>(*this),
      node_id_,
      asymm::Keys(*private_key(), *public_key()),
      boost::asio::use_future,
      local_endpoint).get();

  //return managed_connections_->Bootstrap(
  //    bootstrap_endpoints,
  //    [this](const std::string & message) {
  //      bool is_printable(true);
  //      for (const auto& elem : message) {
  //        if (elem < 32) {
  //          is_printable = false;
  //          break;
  //        }
  //      }
  //      LOG(kInfo) << id() << " -- Received: " << (is_printable ? message.substr(0, 30)
  //                                                              : HexEncode(message.substr(0, 15)));
  //      std::lock_guard<std::mutex> guard(mutex_);
  //      messages_.emplace_back(message);
  //      SetPromiseIfDone();
  //    },
  //    [this](const NodeId & peer_id) {
  //      LOG(kInfo) << id() << " -- Lost connection to " << DebugId(node_id_);
  //      std::lock_guard<std::mutex> guard(mutex_);
  //      connection_lost_node_ids_.emplace_back(peer_id);
  //      connected_node_ids_.erase(
  //          std::remove(connected_node_ids_.begin(), connected_node_ids_.end(), peer_id),
  //          connected_node_ids_.end());
  //    },
  //    node_id_, private_key(), public_key(), chosen_bootstrap_contact, nat_type, local_endpoint);
}

int Node::GetReceivedMessageCount(const std::string& message) const {
  std::lock_guard<std::mutex> guard(mutex_);
  return static_cast<int>(std::count(messages_.begin(), messages_.end(), message));
}

void Node::ResetData() {
  std::lock_guard<std::mutex> guard(mutex_);
  connection_lost_node_ids_.clear();
  messages_.clear();
  total_message_count_expectation_ = 0;
}

boost::future<Node::messages_t> Node::GetFutureForMessages(uint32_t message_count) {
  std::lock_guard<std::mutex> guard(mutex_);
  assert(message_count > 0);
  total_message_count_expectation_ = message_count;
  promised_ = true;
  boost::promise<messages_t> message_promise;
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
