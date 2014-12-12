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
#include "asio/use_future.hpp"

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
  using asio::use_future;
  using std::system_error;

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

  LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 9";

  EXPECT_ANY_THROW(nodes[0]->managed_connections()->GetAvailableEndpoints
                         (nodes[1]->node_id(), use_future).get());
  LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 10 ";

  EXPECT_ANY_THROW(nodes[1]->managed_connections()->GetAvailableEndpoints
                         (nodes[0]->node_id(), use_future).get());

  LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 11 ";

  EXPECT_THROW( nodes[0]->managed_connections()->Add(contacts[1], use_future).get()
              , system_error);


  nodes[0]->AddConnectedNodeId(nodes[1]->node_id());
  //LOG(kInfo) << "Calling Add from " << endpoints1.local << " to " << endpoints0.local;
  //if (nodes[1]->managed_connections()->Add(nodes[0]->node_id(), endpoints0,
  //                                         nodes[1]->validation_data()) != kSuccess) {
  //  return testing::AssertionFailure() << "Node 1 failed to add Node 0";
  //}
  EXPECT_THROW( nodes[1]->managed_connections()->Add(contacts[0], use_future).get()
              , system_error);
  nodes[1]->AddConnectedNodeId(nodes[0]->node_id());

  LOG(kVerbose) << "peter aaaaaaaaaaaaaaaaaaaaaaa 12 ";
  bootstrap_endpoints.push_back(contacts[0]);
  bootstrap_endpoints.push_back(contacts[1]);
  nodes[0]->ResetData();
  nodes[1]->ResetData();

  if (node_count > 2)
    LOG(kInfo) << "Setting up remaining " << (node_count - 2) << " nodes";

  // Adding nodes to each other
  for (int i = 2; i != node_count; ++i) {
    Contact chosen_node_id;
    EXPECT_NO_THROW(chosen_node_id = nodes[i]->Bootstrap(bootstrap_endpoints));

    if (chosen_node_id.id == NodeId()) {
      return testing::AssertionFailure() << "Bootstrapping failed for " << nodes[i]->id();
    }

    EndpointPair ith_endpoint_pair;
    EndpointPair jth_endpoint_pair;

    //NatType nat_type;
    Sleep(std::chrono::milliseconds(250));
    for (int j(0); j != i; ++j) {
      LOG(kInfo) << "peter >>>>> Starting attempt to connect " << nodes[i]->id() << " to " << nodes[j]->id();
      // Call GetAvailableEndpoint at each peer.
      nodes[i]->ResetData();
      nodes[j]->ResetData();

      try {
        ith_endpoint_pair = nodes[i]->managed_connections()->GetAvailableEndpoints(nodes[j]->node_id(), use_future).get();
        LOG(kVerbose) << "peter Success";
      }
      catch(system_error e) {
        EXPECT_EQ(e.code(), RudpErrors::already_connected);
        LOG(kVerbose) << "peter Error " << e.what();
      }

      LOG(kInfo) << "peter >>>>> Starting attempt to connect " << nodes[j]->id() << " to " << nodes[i]->id();
      try {
        jth_endpoint_pair = nodes[j]->managed_connections()->GetAvailableEndpoints(nodes[i]->node_id(), use_future).get();
        LOG(kVerbose) << "peter Success";
      }
      catch(system_error e) {
        EXPECT_EQ(e.code(), RudpErrors::already_connected);
        LOG(kVerbose) << "peter Error " << e.what();
      }

      LOG(kInfo) << "peter >>>>> " << nodes[j]->id() << " Add " << nodes[i]->id();
      auto i_add = nodes[i]->managed_connections()->Add
                      ( Contact( nodes[j]->node_id(), jth_endpoint_pair, *nodes[j]->public_key())
                      , use_future);

      auto j_add = nodes[j]->managed_connections()->Add
                      ( Contact( nodes[i]->node_id(), ith_endpoint_pair, *nodes[i]->public_key())
                      , use_future);

      try {
        i_add.get();
        j_add.get();
        LOG(kVerbose) << "peter Success";
      }
      catch(system_error e) {
        EXPECT_EQ(e.code(), RudpErrors::already_connected);
        LOG(kVerbose) << "peter Error " << e.what();
      }

      nodes[j]->AddConnectedNodeId(nodes[i]->node_id());
      nodes[i]->AddConnectedNodeId(nodes[j]->node_id());
    }
    bootstrap_endpoints.push_back(Contact(nodes[i]->node_id(), ith_endpoint_pair, *nodes[i]->public_key()));
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

Node::messages_t Node::messages() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return messages_;
}

Contact Node::Bootstrap(const std::vector<Contact>& bootstrap_endpoints, Endpoint local_endpoint) {
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
      self.messages_.emplace_back(message);
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
      asymm::Keys{*private_key(), *public_key()},
      asio::use_future,
      local_endpoint).get();
}

int Node::GetReceivedMessageCount(const message_t& message) const {
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
