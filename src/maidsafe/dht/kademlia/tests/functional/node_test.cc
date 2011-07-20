/* Copyright (c) 2009 maidsafe.net limited All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <cstdint>
#include <functional>
#include <exception>
#include <list>
#include <set>
#include <vector>

#include "boost/asio.hpp"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127)
#endif
#include "boost/date_time/posix_time/posix_time.hpp"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "boost/lexical_cast.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/dht/log.h"
// #include "maidsafe-dht/common/routing_table.h"
#include "maidsafe/dht/kademlia/config.h"
#include "maidsafe/dht/kademlia/node-api.h"
#include "maidsafe/dht/kademlia/node_impl.h"
#include "maidsafe/dht/transport/tcp_transport.h"
#include "maidsafe/dht/kademlia/message_handler.h"
#include "maidsafe/dht/kademlia/securifier.h"
#include "maidsafe/dht/kademlia/return_codes.h"
#include "maidsafe/dht/kademlia/tests/test_utils.h"
#include "maidsafe/dht/kademlia/node_container.h"
#include "maidsafe/dht/kademlia/tests/functional/test_node_environment.h"

namespace arg = std::placeholders;
namespace fs = boost::filesystem;
namespace bptime = boost::posix_time;

namespace maidsafe {
namespace dht {
namespace kademlia {
namespace test {

const int kProbes = 4;

class NodeTest : public testing::Test {
 protected:
  typedef std::shared_ptr<maidsafe::dht::kademlia::NodeContainer<Node>>
      NodeContainerPtr;
  NodeTest() : env_(NodesEnvironment<Node>::g_environment()),
               kTimeout_(bptime::seconds(10)) {}

  NodesEnvironment<Node>* env_;
  const bptime::time_duration kTimeout_;

//  NodeTest() : nodes_(),
//               kAlpha_(3),
//               kBeta_(2),
//               kReplicationFactor_(4),
//               kMeanRefreshInterval_(boost::posix_time::hours(1)),
//               bootstrap_contacts_(),
//               network_size_(8) {}
//
//  virtual void SetUp() {
//    size_t joined_nodes(0), failed_nodes(0);
//    crypto::RsaKeyPair key_pair;
//    key_pair.GenerateKeys(4096);
//    NodeId node_id(NodeId::kRandomId);
//    nodes_.push_back(std::shared_ptr<NodeContainer>(new NodeContainer(
//        node_id.String(), key_pair.public_key(), key_pair.private_key(), false,
//        kReplicationFactor_, kAlpha_, kBeta_, kMeanRefreshInterval_)));
//    JoinFunctor join_callback(std::bind(
//        &NodeTest::JoinCallback, this, 0, arg::_1, &mutex_, &cond_var_,
//        &joined_nodes, &failed_nodes));
//    dht::transport::Endpoint endpoint(kLocalIp, kStartingPort);
//    std::vector<dht::transport::Endpoint> local_endpoints;
//    local_endpoints.push_back(endpoint);
//    Contact contact(node_id, endpoint,
//                                   local_endpoints, endpoint, false, false,
//                                   node_id.String(), key_pair.public_key(), "");
//    bootstrap_contacts_.push_back(contact);
//    ASSERT_EQ(dht::transport::kSuccess,
//              nodes_[0]->transport->StartListening(endpoint));
//    nodes_[0]->node->Join(node_id, bootstrap_contacts_, join_callback);
//    for (size_t index = 1; index < network_size_; ++index) {
//      JoinFunctor join_callback(std::bind(
//          &NodeTest::JoinCallback, this, index, arg::_1, &mutex_, &cond_var_,
//          &joined_nodes, &failed_nodes));
//      crypto::RsaKeyPair tmp_key_pair;
//      tmp_key_pair.GenerateKeys(4096);
//      NodeId nodeid(NodeId::kRandomId);
//      nodes_.push_back(std::shared_ptr<NodeContainer>(new NodeContainer(
//          nodeid.String(), tmp_key_pair.public_key(),
//          tmp_key_pair.private_key(), false, kReplicationFactor_, kAlpha_,
//          kBeta_, kMeanRefreshInterval_)));
//      dht::transport::Endpoint endpoint(kLocalIp,
//          static_cast<dht::transport::Port>(kStartingPort + index));
//      ASSERT_EQ(dht::transport::kSuccess,
//                nodes_[index]->transport->StartListening(endpoint));
//      std::vector<Contact> bootstrap_contacts;
//      {
//        boost::mutex::scoped_lock lock(mutex_);
//        bootstrap_contacts = bootstrap_contacts_;
//      }
//      nodes_[index]->node->Join(nodeid, bootstrap_contacts, join_callback);
//      {
//        boost::mutex::scoped_lock lock(mutex_);
//        while (joined_nodes + failed_nodes <= index)
//          cond_var_.wait(lock);
//      }
//    }
//
//    {
//      boost::mutex::scoped_lock lock(mutex_);
//      while (joined_nodes + failed_nodes < network_size_)
//        cond_var_.wait(lock);
//    }
//    EXPECT_EQ(0, failed_nodes);
//  }
//
//  virtual void TearDown() {
//    for (auto itr(nodes_.begin()); itr != nodes_.end(); ++itr) {
//      if ((*itr)->node->joined()) {
////      DLOG(INFO) << "Shutting down client " << (index + 1) << " of "
////                 << nodes_.size() << " ...";
////      if (std::find(nodes_left_.begin(), nodes_left_.end(),
////          index) == nodes_left_.end()) {
//        (*itr)->node->Leave(NULL);
//        (*itr)->work.reset();
//        (*itr)->asio_service.stop();
//        (*itr)->thread_group->join_all();
//        (*itr)->thread_group.reset();
//      }
//    }
//  }
//
//  boost::mutex mutex_;
//  boost::condition_variable cond_var_;
//  std::vector<std::shared_ptr<NodeContainer> > nodes_;
//  boost::thread_group thread_group_;
//  const uint16_t kAlpha_;
//  const uint16_t kBeta_;
//  const uint16_t kReplicationFactor_;
//  const boost::posix_time::time_duration kMeanRefreshInterval_;
//  std::vector<Contact> bootstrap_contacts_;
//  std::vector<NodeId> nodes_id_;
//  size_t network_size_;
//  std::vector<int> nodes_left_;
};

TEST_F(NodeTest, FUNC_InvalidRequestDeleteValue) {
  Key key(Key::kRandomId);
  std::string value("I DO NOT EXIST, AND SHOULD NOT BE FOUND");
  size_t test_node_index(RandomUint32() % env_->node_containers_.size());
  NodeContainerPtr chosen_container(env_->node_containers_[test_node_index]);
  boost::mutex::scoped_lock lock(env_->mutex_);
  chosen_container->Delete(key, value, "", chosen_container->securifier());
  EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
              chosen_container->wait_for_delete_functor()));
  int result(kGeneralError);
  chosen_container->GetAndResetDeleteResult(&result);
  EXPECT_EQ(kDeleteTooFewNodes, result);
}

TEST_F(NodeTest, BEH_JoinClient) {
  NodeContainerPtr client_node_container(
      new maidsafe::dht::kademlia::NodeContainer<Node>());
  client_node_container->Init(3, SecurifierPtr(),
      AlternativeStorePtr(new TestNodeAlternativeStore), true, env_->k_,
      env_->alpha_, env_->beta_, env_->mean_refresh_interval_);
  client_node_container->MakeAllCallbackFunctors(&env_->mutex_,
                                                 &env_->cond_var_);
  std::vector<Contact> bootstrap_contacts;
  (*env_->node_containers_.rbegin())->node()->
      GetBootstrapContacts(&bootstrap_contacts);
  int result = client_node_container->Start(bootstrap_contacts, 0);
  ASSERT_EQ(kSuccess, result);
  ASSERT_TRUE(client_node_container->node()->joined());
}

//TEST_F(NodeTest, BEH_JoinedClientFindsValue) {
//  size_t joined_nodes(network_size_), failed_nodes(0);
//  for (size_t index = network_size_; index < network_size_ + 1; ++index) {
//    JoinFunctor join_callback(std::bind(
//        &NodeTest::JoinCallback, this, index, arg::_1, &mutex_, &cond_var_,
//        &joined_nodes, &failed_nodes));
//    crypto::RsaKeyPair key_pair;
//    key_pair.GenerateKeys(4096);
//    NodeId nodeid(Key::kRandomId);
//    nodes_.push_back(std::shared_ptr<NodeContainer>(new NodeContainer(
//        nodeid.String(), key_pair.public_key(), key_pair.private_key(), true,
//        kReplicationFactor_, kAlpha_, kBeta_, kMeanRefreshInterval_)));
//    std::vector<Contact> bootstrap_contacts;
//    {
//      boost::mutex::scoped_lock lock(mutex_);
//      bootstrap_contacts = bootstrap_contacts_;
//    }
//    nodes_[index]->node->Join(nodeid, bootstrap_contacts, join_callback);
//    {
//      boost::mutex::scoped_lock lock(mutex_);
//      while (joined_nodes + failed_nodes <= index)
//        cond_var_.wait(lock);
//    }
//  }
//
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    while (joined_nodes + failed_nodes < network_size_ + 1)
//      cond_var_.wait(lock);
//  }
//
//  EXPECT_EQ(0, failed_nodes);
//  const Key key(crypto::Hash<crypto::SHA512>("TESTUPDATE1234"));
//  const std::string value("I AM A HAPPY STRING!");
//  int result(0);
//  nodes_[0]->node->Store(key, value, "", boost::posix_time::pos_infin,
//      nodes_[0]->securifier, std::bind(&NodeTest::StoreCallback, this,
//                                       arg::_1, &mutex_, &cond_var_, &result));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//
//  std::vector<std::string> strings;
//  nodes_[network_size_]->node->FindValue(key, nodes_[network_size_]->securifier,
//      std::bind(&NodeTest::FindValueCallback, this, arg::_1, &mutex_,
//                &cond_var_, &result, &strings));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_FALSE(strings.empty());
//}
//
//TEST_F(NodeTest, FUNC_GetNodeContactDetails) {
//  size_t joined_nodes(network_size_), failed_nodes(0);
//  int result(0);
//  std::vector<Key> new_keys;
//  for (size_t index = network_size_; index < network_size_*2; ++index) {
//    JoinFunctor join_callback(std::bind(
//        &NodeTest::JoinCallback, this, index, arg::_1, &mutex_, &cond_var_,
//        &joined_nodes, &failed_nodes));
//    crypto::RsaKeyPair key_pair;
//    std::string key_string(63, '\0');
//    char last_char = static_cast<char>(60 + index);
//    key_string += last_char;
//    key_pair.GenerateKeys(4096);
//    NodeId node_id(key_string);
//    new_keys.push_back(node_id);
//    nodes_.push_back(std::shared_ptr<NodeContainer>(new NodeContainer(
//        node_id.String(), key_pair.public_key(), key_pair.private_key(), false,
//        kReplicationFactor_, kAlpha_, kBeta_, kMeanRefreshInterval_)));
//    dht::transport::Endpoint endpoint(kLocalIp,
//        static_cast<dht::transport::Port>(kStartingPort + index));
//    ASSERT_EQ(dht::transport::kSuccess,
//        nodes_[index]->transport->StartListening(endpoint));
//    std::vector<Contact> bootstrap_contacts;
//    {
//      boost::mutex::scoped_lock lock(mutex_);
//      bootstrap_contacts = bootstrap_contacts_;
//    }
//    nodes_[index]->node->Join(node_id, bootstrap_contacts, join_callback);
//    {
//      boost::mutex::scoped_lock lock(mutex_);
//      while (joined_nodes + failed_nodes <= index)
//        cond_var_.wait(lock);
//    }
//  }
//
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    while (joined_nodes + failed_nodes < network_size_*2)
//      cond_var_.wait(lock);
//  }
//  EXPECT_EQ(0, failed_nodes);
//  Contact contact;
//  int random_node = RandomUint32() % network_size_;
//  nodes_[0]->node->GetContact(new_keys[random_node],
//      std::bind(&NodeTest::GetContactCallback, this, arg::_1, arg::_2,
//                &mutex_, &cond_var_, &result, &contact));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_EQ(0, result);
//  EXPECT_EQ(contact.endpoint().port,
//            kStartingPort + random_node + network_size_);
//}
//
//TEST_F(NodeTest, FUNC_LoadNonExistingValue) {
//  std::vector<std::string> strings;
//  int result;
//  const Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432cc "
//      + boost::lexical_cast<std::string>(network_size_)));
//  const std::string value(boost::lexical_cast<std::string>(network_size_));
//  int random_source = RandomUint32() % network_size_;
//  nodes_[random_source]->node->FindValue(key, nodes_[random_source]->securifier,
//      std::bind(&NodeTest::FindValueCallback, this, arg::_1, &mutex_,
//                &cond_var_, &result, &strings));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_GT(0, result);
//}
//
//TEST_F(NodeTest, FUNC_FindDeadNode) {
//  int random_node = RandomUint32() % (network_size_ - 1) + 1;
//  Contact contact;
//  std::vector<Contact> closest_nodes;
//  contact = nodes_[random_node]->node->contact();
//  nodes_[random_node]->node->Leave(NULL);
//  nodes_[random_node]->work.reset();
//  nodes_[random_node]->asio_service.stop();
//  nodes_[random_node]->thread_group->join_all();
//  nodes_[random_node]->thread_group.reset();
//  nodes_left_.push_back(random_node);
//  nodes_[0]->node->FindNodes(contact.node_id(),
//                            std::bind(&NodeTest::FindNodesCallback, this,
//                                      arg::_1, arg::_2, &mutex_, &cond_var_,
//                                      &closest_nodes));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_TRUE(std::find(closest_nodes.begin(), closest_nodes.end(), contact)
//      == closest_nodes.end());
//}
//
//TEST_F(NodeTest, FUNC_StartStopNode)  {
//  size_t joined_nodes(network_size_), failed_nodes(0);
//  int random_node = RandomUint32() % (network_size_ - 1) + 1;
//  Contact contact;
//  JoinFunctor join_callback(std::bind(
//      &NodeTest::JoinCallback, this, random_node, arg::_1, &mutex_,
//      &cond_var_, &joined_nodes, &failed_nodes));
//  contact = nodes_[random_node]->node->contact();
//  EXPECT_TRUE(nodes_[random_node]->node->joined());
//  nodes_[random_node]->node->Leave(NULL);
//  EXPECT_FALSE(nodes_[random_node]->node->joined());
//  nodes_[random_node]->node->Join(contact.node_id(), bootstrap_contacts_,
//                                 join_callback);
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_EQ(0, failed_nodes);
//  EXPECT_TRUE(nodes_[random_node]->node->joined());
//}
//
//TEST_F(NodeTest, FUNC_StoreWithInvalidRequest) {
//  std::vector<std::string> found_values;
//  int random_node = RandomUint32() % network_size_;
//  int result(0);
//  const Key key(crypto::Hash<crypto::SHA512>("TESTUPDATE1234"));
//  const std::string value("I AM A STRING BEFORE BEING UPDATED!");
//  const std::string new_value("I AM THE STRING WHICH SHOULD NOT BE STORED!");
//  nodes_[random_node]->node->Store(key, value, "", boost::posix_time::pos_infin,
//    nodes_[random_node]->securifier, std::bind(&NodeTest::StoreCallback, this,
//                                               arg::_1, &mutex_, &cond_var_,
//                                               &result));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_EQ(0, result);
//  nodes_[random_node]->node->FindValue(key, nodes_[random_node]->securifier,
//      std::bind(&NodeTest::FindValueCallback, this, arg::_1, &mutex_,
//                &cond_var_, &result, &found_values));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_EQ(value, found_values[0]);
//  random_node = (random_node + 1) % network_size_;
//  nodes_[random_node]->node->Store(key, value, "", boost::posix_time::pos_infin,
//    nodes_[random_node]->securifier,
//    std::bind(&NodeTest::StoreCallback, this, arg::_1, &mutex_, &cond_var_,
//              &result));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_GT(0, result);
//}
//
///** This test is intentenally disabled as the public key of the sender is not
// * sent to the receiver and it is not able to validate the signed_value is 
// * encrypted by the public key of the sender
// */ 
//TEST_F(NodeTest, DISABLED_BEH_UpdateValue) {
//  std::vector<std::string> found_values;
//  int random_node = RandomUint32() % network_size_;
//  int result;
//  const Key key(crypto::Hash<crypto::SHA512>("TESTUPDATE1234"));
//  const std::string value("I AM A STRING BEFORE BEING UPDATED!");
//  const std::string new_value("I AM THE STRING AFTER BEING UPDATED!");
//  nodes_[random_node]->node->Store(key, value, "", boost::posix_time::pos_infin,
//    nodes_[random_node]->securifier, std::bind(&NodeTest::StoreCallback, this,
//                                        arg::_1, &mutex_, &cond_var_, &result));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_EQ(0, result);
//  nodes_[random_node]->node->FindValue(key, nodes_[random_node]->securifier,
//      std::bind(&NodeTest::FindValueCallback, this, arg::_1, &mutex_,
//                &cond_var_, &result, &found_values));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_EQ(value, found_values[0]);
//  nodes_[random_node]->node->Update(key, new_value, "", value, "",
//      nodes_[random_node]->securifier, boost::posix_time::pos_infin,
//      std::bind(&NodeTest::UpdateCallback, this, arg::_1, &mutex_, &cond_var_,
//                &result));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_EQ(0, result);
//  found_values.clear();
//  nodes_[0]->node->FindValue(key, nodes_[0]->securifier,
//      std::bind(&NodeTest::FindValueCallback, this, arg::_1, &mutex_,
//                &cond_var_, &result, &found_values));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_EQ(new_value, found_values[0]);
//}
//
//TEST_F(NodeTest, FUNC_StoreAndLoadSmallValue) {
//  int result(0);
//  int random_node = RandomUint32() % network_size_;
//  const Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432"));
//  const std::string value = RandomString(1024 * 5);  // 5KB
//  nodes_[random_node]->node->Store(key, value, "", boost::posix_time::pos_infin,
//    nodes_[random_node]->securifier, std::bind(&NodeTest::StoreCallback, this,
//                                        arg::_1, &mutex_, &cond_var_, &result));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_EQ(0, result);
//
//  std::vector<std::string> found_values;
//  nodes_[random_node]->node->FindValue(key, nodes_[random_node]->securifier,
//      std::bind(&NodeTest::FindValueCallback, this, arg::_1, &mutex_,
//                &cond_var_, &result, &found_values));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_EQ(0, value.compare(found_values[0]));
//}
//
//TEST_F(NodeTest, FUNC_StoreAndLoadBigValue) {
//  int result(0);
//  int random_node = RandomUint32() % network_size_;
//  const Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432"));
//  const std::string value = RandomString(1024 * 1024);  // 1 MB
//  nodes_[random_node]->node->Store(key, value, "", boost::posix_time::pos_infin,
//    nodes_[random_node]->securifier, std::bind(&NodeTest::StoreCallback, this,
//                                        arg::_1, &mutex_, &cond_var_, &result));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_EQ(0, result);
//
//  std::vector<std::string> found_values;
//  random_node = RandomUint32() % network_size_;
//  nodes_[random_node]->node->FindValue(key, nodes_[random_node]->securifier,
//      std::bind(&NodeTest::FindValueCallback, this, arg::_1, &mutex_,
//                &cond_var_, &result, &found_values));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_EQ(value, found_values[0]);
//}
//
//TEST_F(NodeTest, FUNC_FindClosestNodes) {
//  size_t joined_nodes(network_size_), failed_nodes(0);
//  std::vector<Key> new_keys;
//  std::string key_string(63, '\0');
//  char last_char = static_cast<char>(91 + network_size_);
//  key_string += last_char;
//  Key key(key_string);
//  for (size_t index = network_size_; index < network_size_*2; ++index) {
//    JoinFunctor join_callback(std::bind(
//        &NodeTest::JoinCallback, this, index, arg::_1, &mutex_, &cond_var_,
//        &joined_nodes, &failed_nodes));
//    crypto::RsaKeyPair key_pair;
//    std::string key_string(63, '\0');
//    char last_char = static_cast<char>(60 + index);
//    key_string += last_char;
//    key_pair.GenerateKeys(4096);
//    NodeId node_id(key_string);
//    nodes_.push_back(std::shared_ptr<NodeContainer>(new NodeContainer(
//        node_id.String(), key_pair.public_key(), key_pair.private_key(), false,
//        kReplicationFactor_, kAlpha_, kBeta_, kMeanRefreshInterval_)));
//    dht::transport::Endpoint endpoint(kLocalIp,
//        static_cast<dht::transport::Port>(kStartingPort + index));
//    ASSERT_EQ(dht::transport::kSuccess,
//        nodes_[index]->transport->StartListening(endpoint));
//    std::vector<Contact> bootstrap_contacts;
//    {
//      boost::mutex::scoped_lock lock(mutex_);
//      bootstrap_contacts = bootstrap_contacts_;
//    }
//    nodes_[index]->node->Join(node_id, bootstrap_contacts, join_callback);
//    {
//      boost::mutex::scoped_lock lock(mutex_);
//      while (joined_nodes + failed_nodes <= index)
//        cond_var_.wait(lock);
//    }
//  }
//
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    while (joined_nodes + failed_nodes < network_size_*2)
//      cond_var_.wait(lock);
//  }
//
//  EXPECT_EQ(0, failed_nodes);
//  std::vector<Contact> closest_nodes;
//  nodes_[0]->node->FindNodes(key, std::bind(&NodeTest::FindNodesCallback,
//      this, arg::_1, arg::_2, &mutex_, &cond_var_, &closest_nodes));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_TRUE(!closest_nodes.empty());
//}
//
//TEST_F(NodeTest, BEH_FindClosestNodeAnalysis) {
//  size_t joined_nodes(network_size_), failed_nodes(0);
//  std::vector<Key> new_keys;
//  std::string key_string(63, '\0');
//  char last_char = static_cast<char>(91 + network_size_);
//  key_string += last_char;
//  Key key(key_string);
//  for (size_t index = network_size_; index < network_size_*2; ++index) {
//    JoinFunctor join_callback(std::bind(
//        &NodeTest::JoinCallback, this, index, arg::_1, &mutex_, &cond_var_,
//        &joined_nodes, &failed_nodes));
//    crypto::RsaKeyPair key_pair;
//    std::string key_string(63, '\0');
//    char last_char = static_cast<char>(60 + index);
//    key_string += last_char;
//    key_pair.GenerateKeys(4096);
//    NodeId node_id(key_string);
//    new_keys.push_back(node_id);
//    nodes_.push_back(std::shared_ptr<NodeContainer>(new NodeContainer(
//        node_id.String(), key_pair.public_key(), key_pair.private_key(), false,
//        kReplicationFactor_, kAlpha_, kBeta_, kMeanRefreshInterval_)));
//    dht::transport::Endpoint endpoint(kLocalIp,
//        static_cast<dht::transport::Port>(kStartingPort + index));
//    ASSERT_EQ(dht::transport::kSuccess,
//        nodes_[index]->transport->StartListening(endpoint));
//    std::vector<Contact> bootstrap_contacts;
//    {
//      boost::mutex::scoped_lock lock(mutex_);
//      bootstrap_contacts = bootstrap_contacts_;
//    }
//    nodes_[index]->node->Join(node_id, bootstrap_contacts, join_callback);
//    {
//      boost::mutex::scoped_lock lock(mutex_);
//      while (joined_nodes + failed_nodes <= index)
//        cond_var_.wait(lock);
//    }
//  }
//
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    while (joined_nodes + failed_nodes < network_size_*2)
//      cond_var_.wait(lock);
//  }
//
//  EXPECT_EQ(0, failed_nodes);
//  std::vector<Contact> closest_nodes;
//  nodes_[0]->node->FindNodes(key, std::bind(&NodeTest::FindNodesCallback,
//      this, arg::_1, arg::_2, &mutex_, &cond_var_, &closest_nodes));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_TRUE((std::find(new_keys.begin(), new_keys.end(),
//                         closest_nodes[0].node_id()) != new_keys.end()));
//}
//
///** The test doubles up the number of nodes in the network, the 
// * newly added nodes are assigned close keys. Two nodes, not from the newly
// *  added ones, search for a node with a key close to the keys of the newly
// *  added nodes. The responses shoud be equal.*/
//TEST_F(NodeTest, BEH_MultipleNodesFindClosestNodes) {
//  size_t joined_nodes(network_size_), failed_nodes(0);
//  std::string key_string(63, '\0');
//  char last_char = static_cast<char>(91 + network_size_);
//  key_string += last_char;
//  Key key(key_string);
//  for (size_t index = network_size_; index < network_size_*2; ++index) {
//    JoinFunctor join_callback(std::bind(
//        &NodeTest::JoinCallback, this, index, arg::_1, &mutex_, &cond_var_,
//        &joined_nodes, &failed_nodes));
//    crypto::RsaKeyPair key_pair;
//    std::string key_string(63, '\0');
//    char last_char = static_cast<char>(60 + index);
//    key_string += last_char;
//    key_pair.GenerateKeys(4096);
//    NodeId node_id(key_string);
//    nodes_.push_back(std::shared_ptr<NodeContainer>(new NodeContainer(
//        node_id.String(), key_pair.public_key(), key_pair.private_key(), false,
//        kReplicationFactor_, kAlpha_, kBeta_, kMeanRefreshInterval_)));
//    dht::transport::Endpoint endpoint(kLocalIp,
//        static_cast<dht::transport::Port>(kStartingPort + index));
//    ASSERT_EQ(dht::transport::kSuccess,
//        nodes_[index]->transport->StartListening(endpoint));
//    std::vector<Contact> bootstrap_contacts;
//    {
//      boost::mutex::scoped_lock lock(mutex_);
//      bootstrap_contacts = bootstrap_contacts_;
//    }
//    nodes_[index]->node->Join(node_id, bootstrap_contacts, join_callback);
//    {
//      boost::mutex::scoped_lock lock(mutex_);
//      while (joined_nodes + failed_nodes <= index)
//        cond_var_.wait(lock);
//    }
//  }
//
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    while (joined_nodes + failed_nodes < network_size_*2)
//      cond_var_.wait(lock);
//  }
//
//  EXPECT_EQ(0, failed_nodes);
//  std::vector<Contact> closest_nodes0, closest_nodes1;
//  nodes_[0]->node->FindNodes(key, std::bind(&NodeTest::FindNodesCallback,
//      this, arg::_1, arg::_2, &mutex_, &cond_var_,  &closest_nodes0));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  nodes_[network_size_/2]->node->FindNodes(
//      key, std::bind(&NodeTest::FindNodesCallback, this, arg::_1, arg::_2,
//                     &mutex_, &cond_var_, &closest_nodes1));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  for (size_t index = 0; index < closest_nodes0.size(); ++index)
//    EXPECT_TRUE((std::find(closest_nodes0.begin(), closest_nodes0.end(),
//                           closest_nodes1[index]) != closest_nodes0.end()));
//}
//
//TEST_F(NodeTest, BEH_StoreAndLoad100Values) {
//  int result(0);
//  std::vector<Key> keys;
//  size_t count(100);
//  size_t random_node(0);
//  for (size_t index = 0; index < count; ++index) {
//    const Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432cc "
//        + boost::lexical_cast<std::string>(index)));
//    keys.push_back(key);
//    const std::string value(std::string(
//        boost::lexical_cast<std::string>(index)));
//    random_node = RandomUint32() % network_size_;
//    nodes_[random_node]->node->Store(key, value, "",
//        boost::posix_time::pos_infin, nodes_[random_node]->securifier,
//        std::bind(&NodeTest::StoreCallback, this, arg::_1, &mutex_, &cond_var_,
//                  &result));
//    {
//      boost::mutex::scoped_lock lock(mutex_);
//      cond_var_.wait(lock);
//    }
//  }
//  std::vector<std::string> found_values;
//  random_node = RandomUint32() % network_size_;
//  for (size_t index = 0; index < count; ++index) {
//    nodes_[random_node]->node->FindValue(keys[index],
//        nodes_[random_node]->securifier,
//      std::bind(&NodeTest::FindValueCallback, this, arg::_1, &mutex_,
//                &cond_var_, &result, &found_values));
//    {
//      boost::mutex::scoped_lock lock(mutex_);
//      cond_var_.wait(lock);
//    }
//    EXPECT_EQ(index, boost::lexical_cast<int>(found_values[0]));
//    found_values.clear();
//  }
//}
//
///** Kill all but one node storing the value and try to find the value.
// */
//TEST_F(NodeTest, FUNC_FindValueWithDeadNodes) {
//  int result(0);
//  int random_node = RandomUint32() % network_size_;
//  const Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432cc "
//      + boost::lexical_cast<std::string>(network_size_)));
//  const std::string value(boost::lexical_cast<std::string>(network_size_));
//  nodes_[random_node]->node->Store(key, value, "", boost::posix_time::pos_infin,
//    nodes_[random_node]->securifier, std::bind(&NodeTest::StoreCallback, this,
//                                        arg::_1, &mutex_, &cond_var_, &result));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_EQ(0, result);
//
//  std::vector<Contact> contacts;
//  nodes_[random_node]->node->FindNodes(key,
//      std::bind(&NodeTest::FindNodesCallback, this, arg::_1, arg::_2, &mutex_,
//                &cond_var_, &contacts));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//
//  std::vector<size_t> contacts_index;
//  contacts_index.resize(contacts.size() - 1);
//  for (size_t index = 0; index < contacts.size() - 1; ++index) {
//    contacts_index[index] = contacts[index].endpoint().port - kStartingPort;
//    nodes_[contacts_index[index]]->node->Leave(NULL);
//    nodes_[contacts_index[index]]->work.reset();
//    nodes_[contacts_index[index]]->asio_service.stop();
//    nodes_[contacts_index[index]]->thread_group->join_all();
//    nodes_[contacts_index[index]]->thread_group.reset();
//    nodes_left_.push_back(static_cast<int>(contacts_index[index]));
//  }
//  contacts.clear();
//  std::vector<std::string> strings;
//  nodes_[random_node]->node->FindValue(key, nodes_[random_node]->securifier,
//      std::bind(&NodeTest::FindValueCallback, this, arg::_1, &mutex_,
//                &cond_var_, &result, &strings));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//}
//
//TEST_F(NodeTest, BEH_MultipleNodesFindSingleValue) {
//  int result(0);
//  int found_nodes[kProbes];
//  std::vector<std::string> strings;
//  int random_target = RandomUint32() % network_size_;
//  int random_source = 0;
//  std::vector<Key> keys;
//  for (size_t index = 0; index < network_size_; ++index) {
//    const Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432cc "
//        + boost::lexical_cast<std::string>(index)));
//    keys.push_back(key);
//    const std::string value(std::string(
//        boost::lexical_cast<std::string>(index)));
//    nodes_[index]->node->Store(key, value, "", boost::posix_time::pos_infin,
//        nodes_[index]->securifier, std::bind(&NodeTest::StoreCallback, this,
//                                             arg::_1, &mutex_, &cond_var_,
//                                             &result));
//    {
//      boost::mutex::scoped_lock lock(mutex_);
//      cond_var_.wait(lock);
//    }
//    EXPECT_EQ(0, result);
//  }
//  for (int index = 0; index < kProbes; ++index) {
//    random_source = ((RandomUint32() % (network_size_ - 1))
//        + random_target + 1) % network_size_;
//    nodes_[random_source]->node->FindValue(keys[random_target],
//        nodes_[random_source]->securifier,
//        std::bind(&NodeTest::FindValueCallback, this, arg::_1, &mutex_,
//                  &cond_var_, &result, &strings));
//    {
//      boost::mutex::scoped_lock lock(mutex_);
//      cond_var_.wait(lock);
//    }
//    found_nodes[index] = boost::lexical_cast<int>(strings[0]);
//  }
//  for (int index = 1; index < kProbes; ++index)
//    EXPECT_EQ(found_nodes[0], found_nodes[index]);
//}
//
//TEST_F(NodeTest, FUNC_FindStoreDelete) {
//  int result(0);
//  for (size_t index = 0; index < network_size_; ++index) {
//    const Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432cc "
//        + boost::lexical_cast<std::string>(index)));
//    const std::string value(std::string(
//        boost::lexical_cast<std::string>(index)));
//    nodes_[index]->node->Store(key, value, "",
//        boost::posix_time::pos_infin, nodes_[index]->securifier,
//        std::bind(&NodeTest::StoreCallback, this, arg::_1, &mutex_, &cond_var_,
//                  &result));
//    {
//      boost::mutex::scoped_lock lock(mutex_);
//      cond_var_.wait(lock);
//    }
//    EXPECT_EQ(0, result);
//  }
//  std::vector<std::string> strings;
//  const Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432cc "
//      + boost::lexical_cast<std::string>(network_size_)));
//  const std::string value(std::string(
//      boost::lexical_cast<std::string>(network_size_)));
//  int random_source = RandomUint32() % network_size_;
//  nodes_[random_source]->node->FindValue(key, nodes_[random_source]->securifier,
//      std::bind(&NodeTest::FindValueCallback, this, arg::_1, &mutex_,
//                &cond_var_, &result, &strings));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_TRUE(strings.empty());
//  result = -1;
//  nodes_[random_source]->node->Store(key, value, "",
//      boost::posix_time::pos_infin, nodes_[random_source]->securifier,
//      std::bind(&NodeTest::StoreCallback, this, arg::_1, &mutex_, &cond_var_,
//                &result));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_EQ(0, result);
//  result = -1;
//  strings.clear();
//  nodes_[random_source]->node->FindValue(key, nodes_[random_source]->securifier,
//      std::bind(&NodeTest::FindValueCallback, this, arg::_1, &mutex_,
//                &cond_var_, &result, &strings));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_FALSE(strings[0].empty());
//
//  result = -1;
//  nodes_[random_source]->node->Delete(key, value, "",
//      nodes_[random_source]->securifier,
//      std::bind(&NodeTest::DeleteCallback, this, arg::_1, &mutex_, &cond_var_,
//                &result));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_EQ(0, result);
//
//  result = -1;
//  strings.clear();
//  nodes_[random_source]->node->FindValue(key, nodes_[random_source]->securifier,
//      std::bind(&NodeTest::FindValueCallback, this, arg::_1, &mutex_,
//                &cond_var_, &result, &strings));
//  {
//    boost::mutex::scoped_lock lock(mutex_);
//    cond_var_.wait(lock);
//  }
//  EXPECT_TRUE(strings.empty());
//}

}  // namespace test
}  // namespace kademlia
}  // namespace dht
}  // namespace maidsafe
