/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

#ifndef MAIDSAFE_RUDP_TESTS_TEST_UTILS_H_
#define MAIDSAFE_RUDP_TESTS_TEST_UTILS_H_

#include <cstdint>
#include <future>
#include <memory>
#include <string>
#include <vector>

#include "boost/asio/ip/udp.hpp"
#include "maidsafe/common/node_id.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"


namespace maidsafe {

namespace rudp {

class ManagedConnections;

typedef boost::asio::ip::udp::endpoint Endpoint;

typedef std::shared_ptr<ManagedConnections> ManagedConnectionsPtr;


namespace test {

class Node;
typedef std::shared_ptr<Node> NodePtr;

testing::AssertionResult SetupNetwork(std::vector<NodePtr> &nodes,
                                      std::vector<Endpoint> &bootstrap_endpoints,
                                      const int& node_count);


class Node {
 public:
  explicit Node(int id);
  std::vector<NodeId> connection_lost_node_ids() const;
  std::vector<std::string> messages() const;
  int Bootstrap(const std::vector<Endpoint> &bootstrap_endpoints,
                NodeId& chosen_bootstrap_peer,
                Endpoint local_endpoint = Endpoint());
  std::future<std::vector<std::string>> GetFutureForMessages(const uint32_t& message_count);
  std::string id() const { return id_; }
  NodeId node_id() const { return node_id_; }
  std::string debug_node_id() const { return DebugId(node_id_); }
  std::string validation_data() const { return validation_data_.string(); }
  std::shared_ptr<asymm::PrivateKey> private_key() const {
      return std::shared_ptr<asymm::PrivateKey>(new asymm::PrivateKey(key_pair_.private_key)); }
  std::shared_ptr<asymm::PublicKey> public_key() const {
      return std::shared_ptr<asymm::PublicKey>(new asymm::PublicKey(key_pair_.public_key)); }
  ManagedConnectionsPtr managed_connections() const { return managed_connections_; }
  int GetReceivedMessageCount(const std::string& message) const;
  void ResetData();
  std::vector<NodeId> GetConnectedNodeIds() { return connected_node_ids_; }
  void AddConnectedNodeId(const NodeId& connected_node_id) {
    connected_node_ids_.push_back(connected_node_id);
  }


 private:
  void SetPromiseIfDone();

  NodeId node_id_;
  std::string id_;
  asymm::Keys key_pair_;
  NonEmptyString validation_data_;
  mutable std::mutex mutex_;
  std::vector<NodeId> connection_lost_node_ids_;
  std::vector<NodeId> connected_node_ids_;
  std::vector<std::string> messages_;
  ManagedConnectionsPtr managed_connections_;
  bool promised_;
  uint32_t total_message_count_expectation_;
  std::promise<std::vector<std::string>> message_promise_;
};


}  // namespace test

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_TESTS_TEST_UTILS_H_
