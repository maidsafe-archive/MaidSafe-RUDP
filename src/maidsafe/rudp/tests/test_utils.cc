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

#include "boost/lexical_cast.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

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

  if (node_count < 2)
    return testing::AssertionFailure() << "Network size must be greater than 1";

  LOG(kVerbose) << "peter ---------------------------------";
  nodes.clear();
  bootstrap_endpoints.clear();
  for (int i(0); i != node_count; ++i) {
    nodes.push_back(std::make_shared<Node>(i));
  }

  // Setting up first two nodes
  EndpointPair endpoints0, endpoints1;
  endpoints0.local = Endpoint(GetLocalIp(), maidsafe::test::GetRandomPort());
  endpoints1.local = Endpoint(GetLocalIp(), maidsafe::test::GetRandomPort());
  Contact contacts[] = { Contact(nodes[0]->node_id(), endpoints0.local, nodes[0]->public_key())
                       , Contact(nodes[1]->node_id(), endpoints1.local, nodes[1]->public_key())
                       };

  Contact chosen_node_id, node1_chosen_bootstrap_contact;

  LOG(kVerbose) << "peter ---------------------------------";
  boost::thread thread([&] {
    EXPECT_NO_THROW(chosen_node_id
                     = nodes[0]->Bootstrap(contacts[1], endpoints0.local));
  });

  EXPECT_NO_THROW(node1_chosen_bootstrap_contact
                   = nodes[1]->Bootstrap(contacts[0], endpoints1.local));

  thread.join();

  LOG(kVerbose) << "peter ---------------------------------";
  // FIXME: Retry if either of the two ports had been taken.
  //if (result0 == kBindError || result1 == kBindError) {
  //  // The endpoints were taken by some other program, retry...
  //  return SetupNetwork(nodes, bootstrap_endpoints, node_count);
  //}

  if (node1_chosen_bootstrap_contact.id != nodes[0]->node_id())
    return testing::AssertionFailure() << "Bootstrapping failed for Node 1.";

  if (chosen_node_id.id != nodes[1]->node_id())
    return testing::AssertionFailure() << "Bootstrapping failed for Node 0.";

  LOG(kVerbose) << "peter ---------------------------------";
  EndpointPair endpoint_pair0, endpoint_pair1;
  endpoint_pair1 = endpoints1;
  Sleep(std::chrono::milliseconds(250));

  EXPECT_ANY_THROW(nodes[0]->managed_connections()->GetAvailableEndpoints
                         (nodes[1]->node_id(), use_future).get());

  EXPECT_ANY_THROW(nodes[1]->managed_connections()->GetAvailableEndpoints
                         (nodes[0]->node_id(), use_future).get());

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

    LOG(kVerbose) << "peter ---------------------------------";
    //NatType nat_type;
    Sleep(std::chrono::milliseconds(250));
    for (int j(0); j != i; ++j) {
      // Call GetAvailableEndpoint at each peer.
      nodes[i]->ResetData();
      nodes[j]->ResetData();

      LOG(kVerbose) << "peter ---------------------------------";
      try {
        ith_endpoint_pair = nodes[i]->managed_connections()->GetAvailableEndpoints(nodes[j]->node_id(), use_future).get();
      }
      catch(system_error e) {
        EXPECT_EQ(e.code(), RudpErrors::already_connected);
      }

      LOG(kVerbose) << "peter ---------------------------------";
      try {
        jth_endpoint_pair = nodes[j]->managed_connections()->GetAvailableEndpoints(nodes[i]->node_id(), use_future).get();
      }
      catch(system_error e) {
        EXPECT_EQ(e.code(), RudpErrors::already_connected);
      }

      LOG(kVerbose) << "peter ---------------------------------";
      auto i_add = nodes[i]->managed_connections()->Add
                      ( Contact( nodes[j]->node_id(), jth_endpoint_pair, nodes[j]->public_key())
                      , use_future);

      auto j_add = nodes[j]->managed_connections()->Add
                      ( Contact( nodes[i]->node_id(), ith_endpoint_pair, nodes[i]->public_key())
                      , use_future);

      try {
        i_add.get();
        j_add.get();
      }
      catch(system_error e) {
        EXPECT_EQ(e.code(), RudpErrors::already_connected);
      }

      nodes[j]->AddConnectedNodeId(nodes[i]->node_id());
      nodes[i]->AddConnectedNodeId(nodes[j]->node_id());
    }
    bootstrap_endpoints.push_back(Contact(nodes[i]->node_id(), ith_endpoint_pair, nodes[i]->public_key()));
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

Contact Node::Bootstrap(Contact bootstrap_endpoint, Endpoint local_endpoint) {
  return Bootstrap(std::vector<Contact>(1, bootstrap_endpoint), local_endpoint);
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

  bootstrap_listener_ = std::make_shared<BootstrapListener>(*this);

  return managed_connections_->Bootstrap(
      bootstrap_endpoints,
      bootstrap_listener_,
      node_id_,
      keys(),
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
