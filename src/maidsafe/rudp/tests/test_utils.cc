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

  auto node_0_bootstrap = nodes[0]->Bootstrap(contacts[1], endpoints0.local);
  auto node_1_bootstrap = nodes[1]->Bootstrap(contacts[0], endpoints1.local);

  EXPECT_NO_THROW(chosen_node_id                 = node_0_bootstrap.get());
  EXPECT_NO_THROW(node1_chosen_bootstrap_contact = node_1_bootstrap.get());

  // FIXME: Retry if either of the two ports had been taken.
  //if (result0 == kBindError || result1 == kBindError) {
  //  // The endpoints were taken by some other program, retry...
  //  return SetupNetwork(nodes, bootstrap_endpoints, node_count);
  //}

  if (node1_chosen_bootstrap_contact.id != nodes[0]->node_id())
    return testing::AssertionFailure() << "Bootstrapping failed for Node 1.";

  if (chosen_node_id.id != nodes[1]->node_id())
    return testing::AssertionFailure() << "Bootstrapping failed for Node 0.";

  EndpointPair endpoint_pair0, endpoint_pair1;
  endpoint_pair1 = endpoints1;
  Sleep(std::chrono::milliseconds(250));

  auto get_0 = nodes[0]->GetAvailableEndpoints(nodes[1]->node_id());
  auto get_1 = nodes[1]->GetAvailableEndpoints(nodes[0]->node_id());
  EXPECT_ANY_THROW(get_0.get());
  EXPECT_ANY_THROW(get_1.get());

  EXPECT_THROW(nodes[0]->Add(contacts[1]).get(), system_error);
  nodes[0]->AddConnectedNodeId(nodes[1]->node_id());

  EXPECT_THROW(nodes[1]->Add(contacts[0]).get(), system_error);
  nodes[1]->AddConnectedNodeId(nodes[0]->node_id());

  bootstrap_endpoints.push_back(contacts[0]);
  bootstrap_endpoints.push_back(contacts[1]);
  nodes[0]->ResetLostConnections();
  nodes[1]->ResetLostConnections();

  if (node_count > 2)
    LOG(kInfo) << "Setting up remaining " << (node_count - 2) << " nodes";

  // Adding nodes to each other
  for (int i = 2; i != node_count; ++i) {
    Contact chosen_node_id;
    EXPECT_NO_THROW(chosen_node_id = nodes[i]->Bootstrap(bootstrap_endpoints).get());

    if (chosen_node_id.id == NodeId()) {
      return testing::AssertionFailure() << "Bootstrapping failed for " << nodes[i]->id();
    }

    EndpointPair ith_endpoint_pair;
    EndpointPair jth_endpoint_pair;

    Sleep(std::chrono::milliseconds(250));
    for (int j(0); j != i; ++j) {
      // Call GetAvailableEndpoint at each peer.
      auto get_i = nodes[i]->GetAvailableEndpoints(nodes[j]->node_id());

      try {
        ith_endpoint_pair = get_i.get();
        if (!detail::IsValid(ith_endpoint_pair.external)) {
          ith_endpoint_pair.external = ith_endpoint_pair.local;
        }
      }
      catch(system_error e) {
        EXPECT_EQ(e.code(), RudpErrors::already_connected);
      }

      auto get_j = nodes[j]->GetAvailableEndpoints(nodes[i]->node_id());

      try {
        jth_endpoint_pair = get_j.get();
        if (!detail::IsValid(jth_endpoint_pair.external)) {
          jth_endpoint_pair.external = jth_endpoint_pair.local;
        }
      }
      catch(system_error e) {
        EXPECT_EQ(e.code(), RudpErrors::already_connected);
      }

      auto i_add = nodes[i]->Add(nodes[j]->make_contact(jth_endpoint_pair));
      auto j_add = nodes[j]->Add(nodes[i]->make_contact(ith_endpoint_pair));

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

    bootstrap_endpoints.push_back(nodes[i]->make_contact(ith_endpoint_pair));
  }

  return testing::AssertionSuccess();
}

Node::Node(int id)
    : node_id_(RandomString(NodeId::kSize)),
      id_("Node " + boost::lexical_cast<std::string>(id)),
      key_pair_(asymm::GenerateKeyPair()),
      mutex_(),
      connection_lost_node_ids_(),
      connected_node_ids_(),
      managed_connections_(new ManagedConnections) {}

std::vector<NodeId> Node::connection_lost_node_ids() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return connection_lost_node_ids_;
}

std::future<Contact> Node::Bootstrap(Contact bootstrap_endpoint, Endpoint local_endpoint) {
  return Bootstrap(Contacts{bootstrap_endpoint}, local_endpoint);
}

std::future<Contact> Node::Bootstrap(const std::vector<Contact>& bootstrap_endpoints, Endpoint local_endpoint) {
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
      self.message_queue_.push(std::error_code(), message);
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

  return managed_connections_->Bootstrap(bootstrap_endpoints,
                                         bootstrap_listener_,
                                         node_id_,
                                         keys(),
                                         asio::use_future,
                                         local_endpoint);
}

void Node::ResetLostConnections() {
  std::lock_guard<std::mutex> guard(mutex_);
  connection_lost_node_ids_.clear();
}

}  // namespace test

}  // namespace rudp

}  // namespace maidsafe
