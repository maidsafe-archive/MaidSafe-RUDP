/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

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
#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/lexical_cast.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
// #include "maidsafe-dht/common/routing_table.h"
#include "maidsafe/dht/kademlia/node-api.h"
#include "maidsafe/dht/kademlia/node_impl.h"
#include "maidsafe/dht/transport/tcp_transport.h"
#include "maidsafe/dht/kademlia/message_handler.h"
#include "maidsafe/dht/kademlia/securifier.h"

namespace fs = boost::filesystem;
namespace arg = std::placeholders;

namespace maidsafe {

namespace kademlia {

namespace test_node {

const int kProbes = 4;
const int kStaringPort = 8000;
const std::string kLocalIp = "127.0.0.1";


struct NodeContainer {
  NodeContainer()
      : asio_service(),
        work(),
        thread_group(),
        securifier(),
        transport(),
        message_handler(),
        alternative_store(),
        node() {}
  NodeContainer(const std::string &key_id,
                const std::string &public_key,
                const std::string &private_key,
                bool client_only_node,
                uint16_t k,
                uint16_t alpha,
                uint16_t beta,
                const boost::posix_time::time_duration &mean_refresh_interval)
      : asio_service(),
        work(),
        thread_group(),
        securifier(),
        transport(),
        message_handler(),
        node() {
    // set up ASIO service and thread pool
    work.reset(
        new boost::asio::io_service::work(asio_service));
    thread_group.reset(new boost::thread_group());
    thread_group->create_thread(
        std::bind(&boost::asio::io_service::run, &asio_service));

    // set up data containers
    securifier.reset(new dht::Securifier(key_id, public_key, private_key));
    // set up and connect transport and message handler
    transport.reset(new dht::transport::TcpTransport(asio_service));
    message_handler.reset(new dht::kademlia::MessageHandler(securifier));
    transport->on_message_received()->connect(
        dht::transport::OnMessageReceived::element_type::slot_type(
            &dht::kademlia::MessageHandler::OnMessageReceived,
            message_handler.get(),
            _1, _2, _3, _4).track_foreign(message_handler));

    // create actual node
    node.reset(new dht::kademlia::Node(asio_service, transport, message_handler,
                                       securifier, alternative_store,
                                       client_only_node, k, alpha, beta,
                                       mean_refresh_interval));
  }
  boost::asio::io_service asio_service;
  std::shared_ptr<boost::asio::io_service::work> work;
  std::shared_ptr<boost::thread_group> thread_group;
  std::shared_ptr<dht::Securifier> securifier;
  std::shared_ptr<dht::transport::Transport> transport;
  std::shared_ptr<dht::kademlia::MessageHandler> message_handler;
  dht::kademlia::AlternativeStorePtr alternative_store;
  std::shared_ptr<dht::kademlia::Node> node;
};

class NodeTest : public testing::Test {
 public:
  void StoreCallback(int result, bool* done) {
    ASSERT_LT(0, result);
    *done = true;
  }

  void UpdateCallback(int result, bool* done) {
    ASSERT_LT(0, result);
    *done = true;
  }

  void DeleteCallback(int result, bool* done, int* index) {
    ASSERT_LT(0, result);
    *index = result;
    *done = true;
  }

  void FindNodesCallback(int results, std::vector<dht::kademlia::Contact> nodes,
                         bool* done,
                         std::vector<dht::kademlia::Contact>* out_contacts) {
    out_contacts->resize(nodes.size());
    std::copy(nodes.begin(), nodes.end(), out_contacts->begin());
    *done = true;
  }

  void FindValueCallback(int result, std::vector<std::string> values,
      std::vector<dht::kademlia::Contact> contacts,
      dht::kademlia::Contact node,
      dht::kademlia::Contact cache, bool* done, int* out_result,
      std::vector<std::string>* out_values) {
    *out_result = result;
    for (size_t index = 0; index < values.size(); ++index)
      out_values->push_back(values[index]);
    *done = true;
  }

  void JoinCallback(size_t index,
                    int result,
                    boost::mutex *mutex,
                    boost::condition_variable *cond_var,
                    size_t *joined_nodes,
                    size_t *failed_nodes) {
    boost::mutex::scoped_lock lock(*mutex);
    if (result >= 0) {
      if (index > 0 && index < kNetworkSize)
        bootstrap_contacts_.push_back(
            nodes_[index]->node->contact());
      DLOG(INFO) << "Node " << (index + 1) << " joined." << std::endl;
      ++(*joined_nodes);
    } else {
      DLOG(ERROR) << "Node " << (index + 1) << " failed to join." << std::endl;
      ++(*failed_nodes);
    }
    cond_var->notify_one();
  }

  void GetContactCallback(int result, dht::kademlia::Contact contact,
      dht::kademlia::Contact* out_contact, bool* done) {
    ASSERT_LT(0, result);
    *out_contact = contact;
    *done = true;
  }

 protected:
  NodeTest() :
    nodes_(),
    kAlpha_(3),
    kBeta_(2),
    kReplicationFactor_(4),
    kMeanRefreshInterval_(boost::posix_time::hours(1)),
    bootstrap_contacts_(),
    kNetworkSize(20) {
  }

  virtual void SetUp() {
    size_t joined_nodes(0), failed_nodes(0);
    crypto::RsaKeyPair key_pair;
    key_pair.GenerateKeys(4096);
    nodes_.resize(kNetworkSize);
    dht::kademlia::NodeId node_id(dht::kademlia::NodeId::kRandomId);
    nodes_[0] = std::shared_ptr<NodeContainer>(new NodeContainer(
                       node_id.String(), key_pair.public_key(),
                       key_pair.private_key(), false, kReplicationFactor_,
                       kAlpha_, kBeta_, kMeanRefreshInterval_));
    dht::kademlia::JoinFunctor join_callback(std::bind(
        &NodeTest::JoinCallback, this, 0, arg::_1, &mutex_,
        &cond_var_, &joined_nodes, &failed_nodes));
    dht::transport::Endpoint endpoint(kLocalIp, kStaringPort);
    std::vector<dht::transport::Endpoint> local_endpoints;
    local_endpoints.push_back(endpoint);
    dht::kademlia::Contact contact(node_id, endpoint,
                                   local_endpoints, endpoint, false, false,
                                   node_id.String(), key_pair.public_key(), "");
    bootstrap_contacts_.push_back(contact);
    ASSERT_EQ(dht::transport::kSuccess,
              nodes_[0]->transport->StartListening(endpoint));
    nodes_[0]->node->Join(node_id, bootstrap_contacts_, join_callback);
    for (size_t index = 1; index < kNetworkSize; ++index) {
      crypto::RsaKeyPair tmp_key_pair;
      tmp_key_pair.GenerateKeys(4096);
      dht::kademlia::NodeId nodeid(dht::kademlia::NodeId::kRandomId);
      nodes_[index] = std::shared_ptr<NodeContainer>(new NodeContainer(
                         nodeid.String(), tmp_key_pair.public_key(),
                         tmp_key_pair.private_key(), false,
                         kReplicationFactor_, kAlpha_, kBeta_,
                         kMeanRefreshInterval_);
      dht::transport::Endpoint endpoint(kLocalIp, kStaringPort + index);
      ASSERT_EQ(dht::transport::kSuccess,
                nodes_[index]->transport->StartListening(endpoint));
      std::vector<dht::kademlia::Contact> bootstrap_contacts;
      {
        boost::mutex::scoped_lock lock(mutex_);
        bootstrap_contacts = bootstrap_contacts_;
      }
      nodes_[index]->node->Join(nodeid, bootstrap_contacts, join_callback);
      {
        boost::mutex::scoped_lock lock(mutex_);
        while (joined_nodes + failed_nodes <= index)
          cond_var_.wait(lock);
      }
    }

    {
      boost::mutex::scoped_lock lock(mutex_);
      while (joined_nodes + failed_nodes < kNetworkSize)
        cond_var_.wait(lock);
    }
    ASSERT_EQ(0, failed_nodes);
  }

  virtual void TearDown() {
    for (size_t index = 0; index < kNetworkSize; ++index) {
      DLOG(INFO) << "Shutting down client " << (index + 1) << " of "
                 << kNetworkSize << " ..." << std::endl;
      if (std::find(nodes_left_.begin(), nodes_left_.end(),
          index) == nodes_left_.end()) {
        nodes_[index]->node->Leave(NULL);
        nodes_[index]->work.reset();
        nodes_[index]->asio_service.stop();
        nodes_[index]->thread_group->join_all();
        nodes_[index]->thread_group.reset();
      }
    }
  }

  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  std::vector<std::shared_ptr<NodeContainer>> nodes_;
  boost::thread_group thread_group_;
  const uint16_t kAlpha_;
  const uint16_t kBeta_;
  const uint16_t kReplicationFactor_;
  const boost::posix_time::time_duration kMeanRefreshInterval_;
  std::vector<dht::kademlia::Contact> bootstrap_contacts_;
  std::vector<dht::kademlia::NodeId> nodes_id_;
  size_t kNetworkSize;
  std::vector<int> nodes_left_;
};

/** tests failure on a client joining the network when using an invalid 
 */

TEST_F(NodeTest, BEH_KAD_Join_Client_Invalid_Bootstrap) {
  size_t joined_nodes(kNetworkSize), failed_nodes(0);
  nodes_.resize(kNetworkSize + 1);
  dht::kademlia::JoinFunctor join_callback(std::bind(
      &NodeTest::JoinCallback, this, 0, arg::_1, &mutex_,
      &cond_var_, &joined_nodes, &failed_nodes));
  crypto::RsaKeyPair key_pair;
  key_pair.GenerateKeys(4096);
  dht::kademlia::NodeId node_id(dht::kademlia::NodeId::kRandomId);
  nodes_[kNetworkSize] = std::shared_ptr<NodeContainer>(new NodeContainer(
      node_id.String(), key_pair.public_key(), key_pair.private_key(), true,
      kReplicationFactor_, kAlpha_, kBeta_, kMeanRefreshInterval_));
  std::vector<dht::kademlia::Contact> bootstrap_contacts;
  nodes_[kNetworkSize]->node->Join(node_id, bootstrap_contacts, join_callback);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (failed_nodes != 1)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(1, failed_nodes);
}

TEST_F(NodeTest, FUNC_KAD_Invalid_Request_Delete_Value) {
  bool done(false);
  int result(1);
  dht::kademlia::Key key(dht::kademlia::Key::kRandomId);
  std::string value("I DO NOT EXIST, AND SHOULD NOT BE FOUND");
  int random_source = RandomUint32() % kNetworkSize;
  nodes_[random_source].node->Delete(key, value, "",
      nodes_[random_source].securifier,
      std::bind(&NodeTest::DeleteCallback, this, arg::_1, &done, &result));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  ASSERT_GT(0, result);
}

TEST_F(NodeTest, BEH_KAD_Join_Client) {
  size_t joined_nodes(kNetworkSize), failed_nodes(0);
  nodes_.resize(kNetworkSize + 1);
  dht::kademlia::JoinFunctor join_callback(std::bind(
      &NodeTest::JoinCallback, this, 0, arg::_1, &mutex_,
      &cond_var_, &joined_nodes, &failed_nodes));
  crypto::RsaKeyPair key_pair;
  key_pair.GenerateKeys(4096);
  dht::kademlia::NodeId node_id(dht::kademlia::NodeId::kRandomId);
  nodes_[kNetworkSize] = std::shared_ptr<NodeContainer>(new NodeContainer(
      node_id.String(), key_pair.public_key(), key_pair.private_key(), true,
      kReplicationFactor_, kAlpha_, kBeta_, kMeanRefreshInterval_));
  std::vector<dht::kademlia::Contact> bootstrap_contacts;
  {
    boost::mutex::scoped_lock lock(mutex_);
    bootstrap_contacts = bootstrap_contacts_;
  }
  nodes_[kNetworkSize]->node->Join(node_id, bootstrap_contacts, join_callback);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (joined_nodes + failed_nodes <= kNetworkSize)
      cond_var_.wait(lock);
  }

  {
    boost::mutex::scoped_lock lock(mutex_);
    while (joined_nodes + failed_nodes < kNetworkSize + 1)
      cond_var_.wait(lock);
  }
  kNetworkSize += 1;
  ASSERT_EQ(0, failed_nodes);
}

TEST_F(NodeTest, BEH_KAD_Joined_Client_Finds_Value) {
  size_t joined_nodes(kNetworkSize), failed_nodes(0);
  bool done(false);
  nodes_.resize(kNetworkSize + 1);
  dht::kademlia::JoinFunctor join_callback(std::bind(
      &NodeTest::JoinCallback, this, 0, arg::_1, &mutex_,
      &cond_var_, &joined_nodes, &failed_nodes));
  for (size_t index = kNetworkSize; index < kNetworkSize + 1; ++index) {
    crypto::RsaKeyPair key_pair;
    key_pair.GenerateKeys(4096);
  dht::kademlia::NodeId node_id(dht::kademlia::NodeId::kRandomId);
  nodes_[index] = std::shared_ptr<NodeContainer>(new NodeContainer(
      node_id.String(), key_pair.public_key(), key_pair.private_key(), true,
      kReplicationFactor_, kAlpha_, kBeta_, kMeanRefreshInterval_));
  std::vector<dht::kademlia::Contact> bootstrap_contacts;
  {
    boost::mutex::scoped_lock lock(mutex_);
    bootstrap_contacts = bootstrap_contacts_;
  }
  nodes_[index]->node->Join(node_id, bootstrap_contacts, join_callback);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (joined_nodes + failed_nodes <= kNetworkSize)
      cond_var_.wait(lock);
  }

  {
    boost::mutex::scoped_lock lock(mutex_);
    while (joined_nodes + failed_nodes < kNetworkSize + 1)
      cond_var_.wait(lock);
  }

  ASSERT_EQ(0, failed_nodes);
  const dht::kademlia::Key key(crypto::Hash<crypto::SHA512>("TESTUPDATE1234"));
  const std::string value("I AM A HAPPY STRING!");
  nodes_[0]->node->Store(key, value, "", boost::posix_time::pos_infin,
      nodes_[0]->securifier, std::bind(&NodeTest::StoreCallback, this,
                                       arg::_1, &done));
  while (!done)
    Sleep(boost::posix_time::millisec(200));

  done = false;
  std::vector<std::string> strings;
  int result;
  nodes_[kNetworkSize]->node->FindValue(key, nodes_[kNetworkSize]->securifier,
      std::bind(&NodeTest::FindValueCallback, this, arg::_1, arg::_2,
                arg::_3, arg::_4, arg::_5, &done, &result, &strings));
  while (!done)
    Sleep(boost::posix_time::millisec(200));
  ASSERT_FALSE(strings.empty());
  kNetworkSize += 1;
}

TEST_F(NodeTest, FUNC_KAD_Get_Node_Contact_Details) {
  size_t joined_nodes(kNetworkSize), failed_nodes(0);
  bool done(false);
  std::vector<dht::kademlia::Key> new_keys;
  nodes_.resize(kNetworkSize*2);
  dht::kademlia::JoinFunctor join_callback(std::bind(
      &NodeTest::JoinCallback, this, 0, arg::_1, &mutex_,
      &cond_var_, &joined_nodes, &failed_nodes));
  for (size_t index = kNetworkSize; index < kNetworkSize*2; ++index) {
    crypto::RsaKeyPair key_pair;
    std::string key_string(63, '\0');
    char last_char = 60 + index;
    key_string += last_char;
    key_pair.GenerateKeys(4096);
    dht::kademlia::NodeId node_id(key_string);
    new_keys.push_back(node_id);
    nodes_[index] = std::shared_ptr<NodeContainer>(new NodeContainer(
        node_id.String(), key_pair.public_key(), key_pair.private_key(), false,
        kReplicationFactor_, kAlpha_, kBeta_, kMeanRefreshInterval_));
    dht::transport::Endpoint endpoint("127.0.0.1", kStaringPort + index);
    ASSERT_EQ(dht::transport::kSuccess,
        nodes_[index]->transport->StartListening(endpoint));
    std::vector<dht::kademlia::Contact> bootstrap_contacts;
    {
      boost::mutex::scoped_lock lock(mutex_);
      bootstrap_contacts = bootstrap_contacts_;
    }
    nodes_[index]->node->Join(node_id, bootstrap_contacts, join_callback);
    {
      boost::mutex::scoped_lock lock(mutex_);
      while (joined_nodes + failed_nodes <= index)
        cond_var_.wait(lock);
    }
  }

  {
    boost::mutex::scoped_lock lock(mutex_);
    while (joined_nodes + failed_nodes < kNetworkSize + 1)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(0, failed_nodes);
  dht::kademlia::Contact contact;
  int random_node = RandomUint32() % kNetworkSize;
  nodes_[0]->node->GetContact(new_keys[random_node],
      std::bind(&NodeTest::GetContactCallback, this, arg::_1, arg::_2, &contact,
                &done));
  while (!done)
      boost::this_thread::sleep(boost::posix_time::millisec(200));
  ASSERT_EQ(contact.endpoint().port, kStaringPort + random_node + kNetworkSize);
  kNetworkSize *= 2;
}

TEST_F(NodeTest, FUNC_KAD_LoadNonExistingValue) {
  bool done(false);
  std::vector<std::string> strings;
  int result;
  const dht::kademlia::Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432cc "
      + boost::lexical_cast<std::string>(kNetworkSize)));
  const std::string value(std::string(
      boost::lexical_cast<std::string>(kNetworkSize)));
  int random_source = RandomUint32() % kNetworkSize;
  nodes_[random_source]->node->FindValue(key, nodes_[random_source]->securifier,
      std::bind(&NodeTest::FindValueCallback, this, arg::_1, arg::_2,
                arg::_3, arg::_4, arg::_5, &done, &result, &strings));
  while (!done)
      boost::this_thread::sleep(boost::posix_time::millisec(200));
  ASSERT_GT(0, result);
}

TEST_F(NodeTest, FUNC_KAD_FindDeadNode) {
  bool done(false);
  int random_node = RandomUint32() % (kNetworkSize - 1) + 1;
  dht::kademlia::Contact contact;
  std::vector<dht::kademlia::Contact> closest_nodes;
  contact = nodes_[random_node]->node->contact();
  nodes_[random_node]->node->Leave(NULL);
  nodes_[random_node]->work.reset();
  nodes_[random_node]->asio_service.stop();
  nodes_[random_node]->thread_group->join_all();
  nodes_[random_node]->thread_group.reset();
  nodes_left_.push_back(random_node);
  nodes_[0]->node->FindNodes(contact.node_id(),
                            std::bind(&NodeTest::FindNodesCallback, this,
                                      arg::_1, arg::_2, &done, &closest_nodes));
  while (!done)
      boost::this_thread::sleep(boost::posix_time::millisec(200));
  ASSERT_TRUE(std::find(closest_nodes.begin(), closest_nodes.end(), contact)
      == closest_nodes.end());
}

TEST_F(NodeTest, FUNC_KAD_StartStopNode) {
  size_t joined_nodes(kNetworkSize), failed_nodes(0);
  int random_node = RandomUint32() % (kNetworkSize - 1) + 1;
  dht::kademlia::Contact contact;
  dht::kademlia::JoinFunctor join_callback(std::bind(
      &NodeTest::JoinCallback, this, 0, arg::_1, &mutex_,
      &cond_var_, &joined_nodes, &failed_nodes));
  contact = nodes_[random_node]->node->contact();
  ASSERT_TRUE(nodes_[random_node]->node->joined());
  nodes_[random_node]->node->Leave(NULL);
  ASSERT_FALSE(nodes_[random_node]->node->joined());
  nodes_[random_node]->node->Join(contact.node_id(), bootstrap_contacts_,
                                 join_callback);
  {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(0, failed_nodes);
  ASSERT_TRUE(nodes_[random_node]->node->joined());
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_UpdateValue) {
  bool done(false);
  std::vector<std::string> found_values;
  int random_node = RandomUint32() % kNetworkSize;
  int result;
  const dht::kademlia::Key key(crypto::Hash<crypto::SHA512>("TESTUPDATE1234"));
  const std::string value("I AM A STRING BEFORE BEING UPDATED!");
  const std::string new_value("I AM THE STRING AFTER BEING UPDATED!");
  nodes_[random_node]->node->Store(key, value, "", boost::posix_time::pos_infin,
    nodes_[random_node]->securifier, std::bind(&NodeTest::StoreCallback, this,
                                        arg::_1, &done));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  done = false;
  nodes_[random_node]->node->FindValue(key, nodes_[random_node]->securifier,
      std::bind(&NodeTest::FindValueCallback, this, arg::_1, arg::_2,
                arg::_3, arg::_4, arg::_5, &done, &result, &found_values));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  done = false;
  ASSERT_EQ(value, found_values[0]);
  nodes_[random_node]->node->Update(key, new_value, "", value, "",
                                   nodes_[random_node]->securifier,
                                   boost::posix_time::pos_infin,
                                   std::bind(&NodeTest::UpdateCallback, this,
                                             arg::_1, &done));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  done = false;
  found_values.clear();
  nodes_[0]->node->FindValue(key, nodes_[0]->securifier,
      std::bind(&NodeTest::FindValueCallback, this, arg::_1, arg::_2,
                arg::_3, arg::_4, arg::_5, &done, &result, &found_values));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  ASSERT_EQ(new_value, found_values[0]);
}

TEST_F(NodeTest, FUNC_KAD_StoreAndLoadSmallValue) {
  bool done(false);
  int result(0);
  int random_node = RandomUint32() % kNetworkSize;
  const dht::kademlia::Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432"));
  const std::string value = RandomString(1024 * 5);  // 5KB
  nodes_[random_node]->node->Store(key, value, "", boost::posix_time::pos_infin,
    nodes_[random_node]->securifier, std::bind(&NodeTest::StoreCallback, this,
                                        arg::_1, &done));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));

  done =false;
  std::vector<std::string> found_values;
  nodes_[random_node]->node->FindValue(key, nodes_[random_node]->securifier,
      std::bind(&NodeTest::FindValueCallback, this, arg::_1, arg::_2,
                arg::_3, arg::_4, arg::_5, &done, &result, &found_values));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  ASSERT_EQ(0, value.compare(found_values[0]));
}

TEST_F(NodeTest, FUNC_KAD_StoreAndLoadBigValue) {
  bool done(false);
  int result(0);
  int random_node = RandomUint32() % kNetworkSize;
  const dht::kademlia::Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432"));
  const std::string value = RandomString(1024 * 1024);  // 5KB
  nodes_[random_node]->node->Store(key, value, "", boost::posix_time::pos_infin,
    nodes_[random_node]->securifier, std::bind(&NodeTest::StoreCallback, this,
                                        arg::_1, &done));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));

  done =false;
  std::vector<std::string> found_values;
  random_node = RandomUint32() % kNetworkSize;
  nodes_[random_node]->node->FindValue(key, nodes_[random_node]->securifier,
      std::bind(&NodeTest::FindValueCallback, this, arg::_1, arg::_2,
                arg::_3, arg::_4, arg::_5, &done, &result, &found_values));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  ASSERT_EQ(value, found_values[0]);
}

TEST_F(NodeTest, FUNC_KAD_FindClosestNodes) {
  size_t joined_nodes(kNetworkSize), failed_nodes(0);
  bool done(false);
  std::vector<dht::kademlia::Key> new_keys;
  std::string key_string(63, '\0');
  char last_char = 91 + kNetworkSize;
  key_string += last_char;
  dht::kademlia::Key key(key_string);
  nodes_.resize(kNetworkSize*2);
  dht::kademlia::JoinFunctor join_callback(std::bind(
      &NodeTest::JoinCallback, this, 0, arg::_1, &mutex_,
      &cond_var_, &joined_nodes, &failed_nodes));
  for (size_t index = kNetworkSize; index < kNetworkSize*2; ++index) {
    crypto::RsaKeyPair key_pair;
    std::string key_string(63, '\0');
    char last_char = 60 + index;
    key_string += last_char;
    key_pair.GenerateKeys(4096);
    dht::kademlia::NodeId node_id(key_string);
    nodes_[index] = std::shared_ptr<NodeContainer>(new NodeContainer(
        node_id.String(), key_pair.public_key(), key_pair.private_key(), false,
        kReplicationFactor_, kAlpha_, kBeta_, kMeanRefreshInterval_));
    dht::transport::Endpoint endpoint("127.0.0.1", kStaringPort + index);
    ASSERT_EQ(dht::transport::kSuccess,
        nodes_[index]->transport->StartListening(endpoint));
    std::vector<dht::kademlia::Contact> bootstrap_contacts;
    {
      boost::mutex::scoped_lock lock(mutex_);
      bootstrap_contacts = bootstrap_contacts_;
    }
    nodes_[index]->node->Join(node_id, bootstrap_contacts, join_callback);
    {
      boost::mutex::scoped_lock lock(mutex_);
      while (joined_nodes + failed_nodes <= index)
        cond_var_.wait(lock);
    }
  }

  {
    boost::mutex::scoped_lock lock(mutex_);
    while (joined_nodes + failed_nodes < kNetworkSize*2)
      cond_var_.wait(lock);
  }

  ASSERT_EQ(0, failed_nodes);
  std::vector<dht::kademlia::Contact> closest_nodes;
  nodes_[0]->node->FindNodes(key, std::bind(&NodeTest::FindNodesCallback,
      this, arg::_1, arg::_2, &done, &closest_nodes));
  while (!done)
      boost::this_thread::sleep(boost::posix_time::millisec(200));
  kNetworkSize *= 2;
  ASSERT_TRUE(!closest_nodes.empty());
}

TEST_F(NodeTest, BEH_KAD_FindClosestNodeAnalysisTEST) {
  size_t joined_nodes(kNetworkSize), failed_nodes(0);
  bool done = false;
  std::vector<dht::kademlia::Key> new_keys;
  std::string key_string(63, '\0');
  char last_char = 91 + kNetworkSize;
  key_string += last_char;
  dht::kademlia::Key key(key_string);
  nodes_.resize(kNetworkSize*2);
  dht::kademlia::JoinFunctor join_callback(std::bind(
      &NodeTest::JoinCallback, this, 0, arg::_1, &mutex_,
      &cond_var_, &joined_nodes, &failed_nodes));
  for (size_t index = kNetworkSize; index < kNetworkSize*2; ++index) {
    crypto::RsaKeyPair key_pair;
    std::string key_string(63, '\0');
    char last_char = 60 + index;
    key_string += last_char;
    key_pair.GenerateKeys(4096);
    dht::kademlia::NodeId node_id(key_string);
    new_keys.push_back(node_id);
    nodes_[index] = std::shared_ptr<NodeContainer>(new NodeContainer(
        node_id.String(), key_pair.public_key(), key_pair.private_key(), false,
        kReplicationFactor_, kAlpha_, kBeta_, kMeanRefreshInterval_));
    dht::transport::Endpoint endpoint("127.0.0.1", kStaringPort + index);
    ASSERT_EQ(dht::transport::kSuccess,
        nodes_[index]->transport->StartListening(endpoint));
    std::vector<dht::kademlia::Contact> bootstrap_contacts;
    {
      boost::mutex::scoped_lock lock(mutex_);
      bootstrap_contacts = bootstrap_contacts_;
    }
    nodes_[index]->node->Join(node_id, bootstrap_contacts, join_callback);
    {
      boost::mutex::scoped_lock lock(mutex_);
      while (joined_nodes + failed_nodes <= index)
        cond_var_.wait(lock);
    }
  }

  {
    boost::mutex::scoped_lock lock(mutex_);
    while (joined_nodes + failed_nodes < kNetworkSize*2)
      cond_var_.wait(lock);
  }

  ASSERT_EQ(0, failed_nodes);
  std::vector<dht::kademlia::Contact> closest_nodes;
  nodes_[0]->node->FindNodes(key, std::bind(&NodeTest::FindNodesCallback,
      this, arg::_1, arg::_2, &done, &closest_nodes));
  while (!done)
      boost::this_thread::sleep(boost::posix_time::millisec(200));
  kNetworkSize *= 2;
  ASSERT_TRUE((std::find(new_keys.begin(), new_keys.end(),
                         closest_nodes[0].node_id()) != new_keys.end()));
}

/** The test doubles up the number of nodes in the network, the 
 * newly added nodes are assigned close keys. Two nodes, not from the newly
 *  added ones, search for a node with a key close to the keys of the newly
 *  added nodes. The responses shoud be equal.*/
TEST_F(NodeTest, BEH_KAD_MultipleNodesFindClosestNodesTEST) {
  size_t joined_nodes(kNetworkSize), failed_nodes(0);
  bool done(false);
  std::string key_string(63, '\0');
  char last_char = 91 + kNetworkSize;
  key_string += last_char;
  dht::kademlia::Key key(key_string);
  nodes_.resize(kNetworkSize*2);
  dht::kademlia::JoinFunctor join_callback(std::bind(
      &NodeTest::JoinCallback, this, 0, arg::_1, &mutex_,
      &cond_var_, &joined_nodes, &failed_nodes));
  for (size_t index = kNetworkSize; index < kNetworkSize*2; ++index) {
    crypto::RsaKeyPair key_pair;
    std::string key_string(63, '\0');
    char last_char = 60 + index;
    key_string += last_char;
    key_pair.GenerateKeys(4096);
    dht::kademlia::NodeId node_id(key_string);
    nodes_[index] = std::shared_ptr<NodeContainer>(new NodeContainer(
        node_id.String(), key_pair.public_key(), key_pair.private_key(), false,
        kReplicationFactor_, kAlpha_, kBeta_, kMeanRefreshInterval_));
    dht::transport::Endpoint endpoint("127.0.0.1", kStaringPort + index);
    ASSERT_EQ(dht::transport::kSuccess,
        nodes_[index]->transport->StartListening(endpoint));
    std::vector<dht::kademlia::Contact> bootstrap_contacts;
    {
      boost::mutex::scoped_lock lock(mutex_);
      bootstrap_contacts = bootstrap_contacts_;
    }
    nodes_[index]->node->Join(node_id, bootstrap_contacts, join_callback);
    {
      boost::mutex::scoped_lock lock(mutex_);
      while (joined_nodes + failed_nodes <= index)
        cond_var_.wait(lock);
    }
  }

  {
    boost::mutex::scoped_lock lock(mutex_);
    while (joined_nodes + failed_nodes < kNetworkSize*2)
      cond_var_.wait(lock);
  }

  ASSERT_EQ(0, failed_nodes);
  std::vector<dht::kademlia::Contact> closest_nodes0, closest_nodes1;
  nodes_[0]->node->FindNodes(key, std::bind(&NodeTest::FindNodesCallback,
      this, arg::_1, arg::_2, &done, &closest_nodes0));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  done = false;
  nodes_[kNetworkSize/2]->node->FindNodes(
      key, std::bind(&NodeTest::FindNodesCallback, this, arg::_1, arg::_2,
                     &done, &closest_nodes1));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  kNetworkSize *= 2;
  for (size_t index = 0; index < closest_nodes0.size(); ++index)
    ASSERT_TRUE((std::find(closest_nodes0.begin(), closest_nodes0.end(),
                           closest_nodes1[index]) != closest_nodes0.end()));
}

TEST_F(NodeTest, BEH_KAD_StoreAndLoad100Values) {
  bool done(false);
  std::vector<dht::kademlia::Key> keys;
  size_t count(100);
  size_t random_node(0);
  for (size_t index = 0; index < count; ++index) {
    const dht::kademlia::Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432cc "
        + boost::lexical_cast<std::string>(index)));
    keys.push_back(key);
    const std::string value(std::string(
        boost::lexical_cast<std::string>(index)));
    random_node = RandomUint32() % kNetworkSize;
    nodes_[random_node]->node->Store(key, value, "",
                                    boost::posix_time::pos_infin,
                                    nodes_[random_node]->securifier,
                                    std::bind(&NodeTest::StoreCallback, this,
                                              arg::_1, &done));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::millisec(200));
    done = false;
  }
  std::vector<std::string> found_values;
  int result(0);
  done = false;
  random_node = RandomUint32() % kNetworkSize;
  for (size_t index = 0; index < count; ++index) {
    nodes_[random_node]->node->FindValue(keys[index],
        nodes_[random_node]->securifier,
        std::bind(&NodeTest::FindValueCallback, this, arg::_1, arg::_2,
                  arg::_3, arg::_4, arg::_5, &done, &result, &found_values));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::millisec(200));
    ASSERT_EQ(index, boost::lexical_cast<int>(found_values[0]));
    found_values.clear();
    done = false;
  }
}

TEST_F(NodeTest, FUNC_KAD_FindValueWithDeadNodes) {
  // Kill all but one node storing the value
  // try to find the value.
  bool done(false);
  int random_node = RandomUint32() % kNetworkSize;
  const dht::kademlia::Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432cc "
      + boost::lexical_cast<std::string>(kNetworkSize)));
  const std::string value(boost::lexical_cast<std::string>(kNetworkSize));
  nodes_[random_node]->node->Store(key, value, "", boost::posix_time::pos_infin,
    nodes_[random_node]->securifier, std::bind(&NodeTest::StoreCallback, this,
                                        arg::_1, &done));
  while (!done) {
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  }
  done = false;

  std::vector<dht::kademlia::Contact> contacts;
  nodes_[random_node]->node->FindNodes(key,
      std::bind(&NodeTest::FindNodesCallback, this, arg::_1, arg::_2, &done,
                &contacts));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  done = false;

  std::vector<size_t> contacts_index;
  contacts_index.resize(contacts.size() - 1);
  for (size_t index = 0; index < contacts.size() - 1; ++index) {
    contacts_index[index] = contacts[index].endpoint().port - kStaringPort;
    nodes_[contacts_index[index]]->node->Leave(NULL);
    nodes_[contacts_index[index]]->work.reset();
    nodes_[contacts_index[index]]->asio_service.stop();
    nodes_[contacts_index[index]]->thread_group->join_all();
    nodes_[contacts_index[index]]->thread_group.reset();
    nodes_left_.push_back(contacts_index[index]);
  }
  contacts.clear();
  int result(0);
  std::vector<std::string> strings;
  nodes_[random_node]->node->FindValue(key, nodes_[random_node]->securifier,
      std::bind(&NodeTest::FindValueCallback, this, arg::_1, arg::_2,
                arg::_3, arg::_4, arg::_5, &done, &result, &strings));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  done = false;
}

TEST_F(NodeTest, BEH_KAD_MultipleNodesFindSingleValueTEST) {
  bool done(false);
  std::vector<dht::kademlia::Key> keys;
  for (size_t index = 0; index < kNetworkSize; ++index) {
    const dht::kademlia::Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432cc "
        + boost::lexical_cast<std::string>(index)));
    keys.push_back(key);
    const std::string value(std::string(
        boost::lexical_cast<std::string>(index)));
    nodes_[index]->node->Store(key, value, "", boost::posix_time::pos_infin,
      nodes_[index]->securifier, std::bind(&NodeTest::StoreCallback, this,
                                          arg::_1, &done));
    while (!done) {
      boost::this_thread::sleep(boost::posix_time::millisec(200));
    }
    done = false;
  }
  done = false;
  int found_nodes[kProbes];
  int result(0);
  std::vector<std::string> strings;
  int random_target = RandomUint32() % kNetworkSize;
  int random_source = 0;
  for (int index = 0; index < kProbes; ++index) {
    random_source = ((RandomUint32() % (kNetworkSize - 1))
        + random_target + 1) % kNetworkSize;
    nodes_[random_source]->node->FindValue(keys[random_target],
        nodes_[random_source]->securifier,
        std::bind(&NodeTest::FindValueCallback, this, arg::_1, arg::_2, arg::_3,
                  arg::_4, arg::_5, &done, &result, &strings));
    while (!done) {
      boost::this_thread::sleep(boost::posix_time::millisec(200));
    }
    found_nodes[index] = boost::lexical_cast<int>(strings[0]);
    done = false;
  }
  for (int index = 1; index < kProbes; ++index) {
    ASSERT_EQ(found_nodes[0], found_nodes[index]);
  }
}

TEST_F(NodeTest, BEH_KAD_FindStoreDeleteTEST) {
  bool done = false;
  for (size_t index = 0; index < kNetworkSize; ++index) {
    const dht::kademlia::Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432cc "
        + boost::lexical_cast<std::string>(index)));
    const std::string value(std::string(
        boost::lexical_cast<std::string>(index)));
    nodes_[index]->node->Store(key, value, "", boost::posix_time::pos_infin,
        nodes_[index]->securifier, std::bind(&NodeTest::StoreCallback, this,
                                            arg::_1, &done));
    while (!done) {
      boost::this_thread::sleep(boost::posix_time::millisec(200));
    }
    done = false;
  }
  done = false;
  int result = -1;
  std::vector<std::string> strings;
  const dht::kademlia::Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432cc "
      + boost::lexical_cast<std::string>(kNetworkSize)));
  const std::string value(std::string(
      boost::lexical_cast<std::string>(kNetworkSize)));
  int random_source = RandomUint32() % kNetworkSize;
  nodes_[random_source]->node->FindValue(key, nodes_[random_source]->securifier,
      std::bind(&NodeTest::FindValueCallback, this, arg::_1, arg::_2, arg::_3,
                arg::_4, arg::_5, &done, &result, &strings));
  while (!done)
      boost::this_thread::sleep(boost::posix_time::millisec(200));
  ASSERT_TRUE(strings.empty());

  done = false;
  result = -1;
  nodes_[random_source]->node->Store(key, value, "",
      boost::posix_time::pos_infin, nodes_[random_source]->securifier,
      std::bind(&NodeTest::StoreCallback, this, arg::_1, &done));
  while (!done) {
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  }

  done = false;
  result = -1;
  strings.clear();
  nodes_[random_source]->node->FindValue(key, nodes_[random_source]->securifier,
      std::bind(&NodeTest::FindValueCallback, this, arg::_1, arg::_2, arg::_3,
                arg::_4, arg::_5, &done, &result, &strings));
  while (!done)
      boost::this_thread::sleep(boost::posix_time::millisec(200));
  ASSERT_FALSE(strings[0].empty());

  done = false;
  result = -1;
  nodes_[random_source]->node->Delete(key, value, "",
      nodes_[random_source]->securifier,
      std::bind(&NodeTest::DeleteCallback, this, arg::_1, &done, &result));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  ASSERT_LT(0, result);

  done = false;
  result = -1;
  strings.clear();
  nodes_[random_source]->node->FindValue(key, nodes_[random_source]->securifier,
      std::bind(&NodeTest::FindValueCallback, this, arg::_1, arg::_2, arg::_3,
                arg::_4, arg::_5, &done, &result, &strings));
  while (!done)
      boost::this_thread::sleep(boost::posix_time::millisec(200));
  ASSERT_TRUE(strings.empty());
}

/** The test doubles up the number of nodes in the network, the 
 * newly added nodes are assigned close keys. Two nodes, not from the newly
 *  added ones, search for a node with a key close to the keys of the newly
 *  added nodes. The responses shoud be equal.*/
TEST_F(NodeTest, BEH_KAD_Multiple_Nodes_Find_Closest_Nodes) {
  size_t joined_nodes(kNetworkSize), failed_nodes(0);
  bool done(false);
  std::string key_string(63, '\0');
  char last_char = 91 + kNetworkSize;
  key_string += last_char;
  dht::kademlia::Key key(key_string);
  nodes_.resize(kNetworkSize*2);
  dht::kademlia::JoinFunctor join_callback(std::bind(
      &NodeTest::JoinCallback, this, 0, arg::_1, &mutex_,
      &cond_var_, &joined_nodes, &failed_nodes));
  for (size_t index = kNetworkSize; index < kNetworkSize*2; ++index) {
    crypto::RsaKeyPair key_pair;
    std::string key_string(63, '\0');
    char last_char = 60 + index;
    key_string += last_char;
    key_pair.GenerateKeys(4096);
    dht::kademlia::NodeId node_id(key_string);
    nodes_[index] = NodeContainer(node_id.String(), key_pair.public_key(),
                                  key_pair.private_key(), false,
                                  kReplicationFactor_, kAlpha_, kBeta_,
                                  kMeanRefreshInterval_);
    dht::transport::Endpoint endpoint(kLocalIp, kStaringPort + index);
    ASSERT_EQ(dht::transport::kSuccess,
        nodes_[index].transport->StartListening(endpoint));
    std::vector<dht::kademlia::Contact> bootstrap_contacts;
    {
      boost::mutex::scoped_lock lock(mutex_);
      bootstrap_contacts = bootstrap_contacts_;
    }
    nodes_[index].node->Join(node_id, bootstrap_contacts, join_callback);
    {
      boost::mutex::scoped_lock lock(mutex_);
      while (joined_nodes + failed_nodes <= index)
        cond_var_.wait(lock);
    }
  }

  {
    boost::mutex::scoped_lock lock(mutex_);
    while (joined_nodes + failed_nodes < kNetworkSize*2)
      cond_var_.wait(lock);
  }

  ASSERT_EQ(0, failed_nodes);
  std::vector<dht::kademlia::Contact> closest_nodes0, closest_nodes1;
  nodes_[0].node->FindNodes(key, std::bind(&NodeTest::FindNodesCallback,
      this, arg::_1, arg::_2, &done, &closest_nodes0));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  done = false;
  nodes_[kNetworkSize/2].node->FindNodes(
      key, std::bind(&NodeTest::FindNodesCallback, this, arg::_1, arg::_2,
                     &done, &closest_nodes1));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  kNetworkSize *= 2;
  for (size_t index = 0; index < closest_nodes0.size(); ++index)
    ASSERT_TRUE((std::find(closest_nodes0.begin(), closest_nodes0.end(),
                           closest_nodes1[index]) != closest_nodes0.end()));
}

TEST_F(NodeTest, BEH_KAD_Store_And_Load_100_Values) {
  bool done(false);
  std::vector<dht::kademlia::Key> keys;
  size_t count(100);
  size_t random_node(0);
  for (size_t index = 0; index < count; ++index) {
    const dht::kademlia::Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432cc "
        + boost::lexical_cast<std::string>(index)));
    keys.push_back(key);
    const std::string value(std::string(
        boost::lexical_cast<std::string>(index)));
    random_node = RandomUint32() % kNetworkSize;
    nodes_[random_node].node->Store(key, value, "",
                                    boost::posix_time::pos_infin,
                                    nodes_[random_node].securifier,
                                    std::bind(&NodeTest::StoreCallback, this,
                                              arg::_1, &done));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::millisec(200));
    done = false;
  }
  std::vector<std::string> found_values;
  int result(0);
  done = false;
  random_node = RandomUint32() % kNetworkSize;
  for (size_t index = 0; index < count; ++index) {
    nodes_[random_node].node->FindValue(keys[index],
        nodes_[random_node].securifier,
        std::bind(&NodeTest::FindValueCallback, this, arg::_1, arg::_2,
                  arg::_3, arg::_4, arg::_5, &done, &result, &found_values));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::millisec(200));
    ASSERT_EQ(index, boost::lexical_cast<int>(found_values[0]));
    found_values.clear();
    done = false;
  }
}

/** Kill all but one node storing the value and try to find the value.
 */
TEST_F(NodeTest, FUNC_KAD_Find_Value_With_Dead_Nodes) {
  bool done(false);
  int random_node = RandomUint32() % kNetworkSize;
  const dht::kademlia::Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432cc "
      + boost::lexical_cast<std::string>(kNetworkSize)));
  const std::string value(boost::lexical_cast<std::string>(kNetworkSize));
  nodes_[random_node].node->Store(key, value, "", boost::posix_time::pos_infin,
    nodes_[random_node].securifier, std::bind(&NodeTest::StoreCallback, this,
                                        arg::_1, &done));
  while (!done) {
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  }
  done = false;

  std::vector<dht::kademlia::Contact> contacts;
  nodes_[random_node].node->FindNodes(key,
      std::bind(&NodeTest::FindNodesCallback, this, arg::_1, arg::_2, &done,
                &contacts));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  done = false;

  std::vector<size_t> contacts_index;
  contacts_index.resize(contacts.size() - 1);
  for (size_t index = 0; index < contacts.size() - 1; ++index) {
    contacts_index[index] = contacts[index].endpoint().port - kStaringPort;
    nodes_[contacts_index[index]].node->Leave(NULL);
    nodes_[contacts_index[index]].work.reset();
    nodes_[contacts_index[index]].asio_service->stop();
    nodes_[contacts_index[index]].thread_group->join_all();
    nodes_[contacts_index[index]].thread_group.reset();
    nodes_left_.push_back(contacts_index[index]);
  }
  contacts.clear();
  int result(0);
  std::vector<std::string> strings;
  nodes_[random_node].node->FindValue(key, nodes_[random_node].securifier,
      std::bind(&NodeTest::FindValueCallback, this, arg::_1, arg::_2,
                arg::_3, arg::_4, arg::_5, &done, &result, &strings));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  done = false;
}

TEST_F(NodeTest, BEH_KAD_Multiple_Nodes_Find_Single_Value) {
  bool done(false);
  std::vector<dht::kademlia::Key> keys;
  for (size_t index = 0; index < kNetworkSize; ++index) {
    const dht::kademlia::Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432cc "
        + boost::lexical_cast<std::string>(index)));
    keys.push_back(key);
    const std::string value(std::string(
        boost::lexical_cast<std::string>(index)));
    nodes_[index].node->Store(key, value, "", boost::posix_time::pos_infin,
      nodes_[index].securifier, std::bind(&NodeTest::StoreCallback, this,
                                          arg::_1, &done));
    while (!done) {
      boost::this_thread::sleep(boost::posix_time::millisec(200));
    }
    done = false;
  }
  done = false;
  int found_nodes[kProbes];
  int result(0);
  std::vector<std::string> strings;
  int random_target = RandomUint32() % kNetworkSize;
  int random_source = 0;
  for (int index = 0; index < kProbes; ++index) {
    random_source = ((RandomUint32() % (kNetworkSize - 1))
        + random_target + 1) % kNetworkSize;
    nodes_[random_source].node->FindValue(keys[random_target],
        nodes_[random_source].securifier,
        std::bind(&NodeTest::FindValueCallback, this, arg::_1, arg::_2, arg::_3,
                  arg::_4, arg::_5, &done, &result, &strings));
    while (!done) {
      boost::this_thread::sleep(boost::posix_time::millisec(200));
    }
    found_nodes[index] = boost::lexical_cast<int>(strings[0]);
    done = false;
  }
  for (int index = 1; index < kProbes; ++index) {
    ASSERT_EQ(found_nodes[0], found_nodes[index]);
  }
}

TEST_F(NodeTest, BEH_KAD_Find_Store_Delete) {
  bool done = false;
  for (size_t index = 0; index < kNetworkSize; ++index) {
    const dht::kademlia::Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432cc "
        + boost::lexical_cast<std::string>(index)));
    const std::string value(std::string(
        boost::lexical_cast<std::string>(index)));
    nodes_[index].node->Store(key, value, "", boost::posix_time::pos_infin,
        nodes_[index].securifier, std::bind(&NodeTest::StoreCallback, this,
                                            arg::_1, &done));
    while (!done) {
      boost::this_thread::sleep(boost::posix_time::millisec(200));
    }
    done = false;
  }
  done = false;
  int result = -1;
  std::vector<std::string> strings;
  const dht::kademlia::Key key(crypto::Hash<crypto::SHA512>("dccxxvdeee432cc "
      + boost::lexical_cast<std::string>(kNetworkSize)));
  const std::string value(std::string(
      boost::lexical_cast<std::string>(kNetworkSize)));
  int random_source = RandomUint32() % kNetworkSize;
  nodes_[random_source].node->FindValue(key, nodes_[random_source].securifier,
      std::bind(&NodeTest::FindValueCallback, this, arg::_1, arg::_2, arg::_3,
                arg::_4, arg::_5, &done, &result, &strings));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  ASSERT_TRUE(strings.empty());

  done = false;
  result = -1;
  nodes_[random_source].node->Store(key, value, "",
      boost::posix_time::pos_infin, nodes_[random_source].securifier,
      std::bind(&NodeTest::StoreCallback, this, arg::_1, &done));
  while (!done) {
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  }

  done = false;
  result = -1;
  strings.clear();
  nodes_[random_source].node->FindValue(key, nodes_[random_source].securifier,
      std::bind(&NodeTest::FindValueCallback, this, arg::_1, arg::_2, arg::_3,
                arg::_4, arg::_5, &done, &result, &strings));
  while (!done)
      boost::this_thread::sleep(boost::posix_time::millisec(200));
  ASSERT_FALSE(strings[0].empty());

  done = false;
  result = -1;
  nodes_[random_source].node->Delete(key, value, "",
      nodes_[random_source].securifier,
      std::bind(&NodeTest::DeleteCallback, this, arg::_1, &done, &result));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  ASSERT_LT(0, result);

  done = false;
  result = -1;
  strings.clear();
  nodes_[random_source].node->FindValue(key, nodes_[random_source].securifier,
      std::bind(&NodeTest::FindValueCallback, this, arg::_1, arg::_2, arg::_3,
                arg::_4, arg::_5, &done, &result, &strings));
  while (!done)
    boost::this_thread::sleep(boost::posix_time::millisec(200));
  ASSERT_TRUE(strings.empty());
}

/*
static const uint16_t K = 8;
const int16_t kNetworkSize = test_node::K + 1;
const int16_t kTestK = test_node::K;

inline void create_rsakeys(std::string *pub_key, std::string *priv_key) {
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  *pub_key =  kp.public_key();
  *priv_key = kp.private_key();
}

inline void create_req(const std::string &pub_key, const std::string &priv_key,
                       const std::string &key, std::string *pub_key_val,
                       std::string *sig_req) {
}

std::string get_app_directory() {
  boost::filesystem::path app_path;
#if defined(MAIDSAFE_POSIX)
  app_path = boost::filesystem::path("/var/cache/maidsafe/");
#elif defined(MAIDSAFE_WIN32)
  TCHAR szpth[MAX_PATH];
  if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, 0, szpth))) {
    std::ostringstream stm;
    const std::ctype<char> &ctfacet =
        std::use_facet< std::ctype<char> >(stm.getloc());
    for (size_t i = 0; i < wcslen(szpth); ++i)
      stm << ctfacet.narrow(szpth[i], 0);
    app_path = boost::filesystem::path(stm.str());
    app_path /= "maidsafe";
  }
#elif defined(MAIDSAFE_APPLE)
  app_path = boost::filesystem::path("/Library/maidsafe/");
#endif
  return app_path.string();
}

void ConstructKcp(NodeConstructionParameters *kcp) {
  kcp->type = VAULT;
  kcp->alpha = kAlpha;
  kcp->beta = kBeta;
  kcp->k = test_node::K;
  kcp->port_forwarded = false;
  kcp->private_key = "";
  kcp->public_key = "";
  kcp->refresh_time = kRefreshTime;
  kcp->use_upnp = false;
}

class NodeTest: public testing::Test {
 protected:
  NodeTest() {}
  ~NodeTest() {}
};

std::string kad_config_file_;
std::vector<boost::shared_ptr<dht::transport::TcpTransport> > transports_;
std::vector<boost::shared_ptr<dht::kademlia::Node> > nodes_;
std::vector<std::string> dbs_;
// M maidsafe::crypto:: cry_obj_;
// M GeneralKadCallback cb_;
std::vector<dht::kademlia::NodeId> node_ids_;
std::set<uint16_t> ports_;
std::string test_dir_;
//M base::TestValidator validator;

class Env : public testing::Environment {
 public:
  Env() {
//    cry_obj_.set_symm_algorithm(crypto::AES_256);
//    cry_obj_.set_hash_algorithm(crypto::SHA_512);
  }

  virtual ~Env() {}

  virtual void SetUp() {
    test_dir_ = std::string("temp/NodeTest") +
                boost::lexical_cast<std::string>(RandomUint32());
    kad_config_file_ = test_dir_ + std::string("/.kadconfig");
    try {
      if (fs::exists(test_dir_))
        fs::remove_all(test_dir_);
      fs::create_directories(test_dir_);
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "filesystem error: " << e.what() << std::endl;
    }

    // setup the nodes without starting them
    std::string priv_key, pub_key;
    nodes_.resize(kNetworkSize);
    channel_managers_.resize(kNetworkSize);
    transports_.resize(kNetworkSize);
    transport_ports_.resize(kNetworkSize);
    NodeConstructionParameters kcp;
    ConstructKcp(&kcp);
    for (int16_t  i = 0; i < kNetworkSize; ++i) {
      transports_[i].reset(new transport::UdtTransport);
      transport::TransportCondition tc;
      transport_ports_[i] = transports_[i]->StartListening("", 0, &tc);
      ASSERT_EQ(transport::kSuccess, tc);
      ASSERT_LT(0, transport_ports_[i]);
      kcp.port = transport_ports_[i];
      channel_managers_[i].reset(
          new rpcprotocol::ChannelManager(transports_[i]));
      ASSERT_EQ(0, channel_managers_[i]->Start());

      std::string db_local(test_dir_ + std::string("/datastore") +
                           boost::lexical_cast<std::string>(i));
      boost::filesystem::create_directories(db_local);
      dbs_.push_back(db_local);

      create_rsakeys(&pub_key, &priv_key);
      kcp.public_key = pub_key;
      kcp.private_key = priv_key;
      nodes_[i]->reset(new Node(channel_managers_[i], transports_[i], kcp));
    }

    kad_config_file_ = dbs_[0] + "/.kadconfig";
    cb_.Reset();
    boost::asio::ip::address local_ip;
    ASSERT_TRUE(base::GetLocalAddress(&local_ip));
    nodes_[0]->JoinFirstNode(kad_config_file_, local_ip.to_string(),
                              transport_ports_[0],
                              boost::bind(&GeneralKadCallback::CallbackFunc,
                                          &cb_, _1));
    wait_result(&cb_);
    ASSERT_TRUE(cb_.result());
    ASSERT_TRUE(nodes_[0]->is_joined());
    nodes_[0]->set_signature_validator(&validator);
    DLOG(INFO) << "Node 0 joined "
              << nodes_[0]->node_id().ToStringEncoded(NodeId::kHex)
                 .substr(0, 12)
              << std::endl;
    node_ids_.push_back(nodes_[0]->node_id());
    base::KadConfig kad_config;
    base::KadConfig::Contact *kad_contact = kad_config.add_contact();
    kad_contact->set_node_id(
        nodes_[0]->node_id().ToStringEncoded(NodeId::kHex));
    kad_contact->set_ip(nodes_[0]->ip());
    kad_contact->set_port(nodes_[0]->port());
    kad_contact->set_local_ip(nodes_[0]->local_ip());
    kad_contact->set_local_port(nodes_[0]->local_port());

    for (int16_t i = 1; i < kNetworkSize; i++) {
      kad_config_file_ = dbs_[i] + "/.kadconfig";
      std::fstream output2(kad_config_file_.c_str(),
                           std::ios::out | std::ios::trunc | std::ios::binary);
      ASSERT_TRUE(kad_config.SerializeToOstream(&output2));
      output2.close();
    }

    // start the rest of the nodes (including node 1 again)
    for (int16_t  i = 1; i < kNetworkSize; ++i) {
      cb_.Reset();
      kad_config_file_ = dbs_[i] + "/.kadconfig";
      nodes_[i]->Join(kad_config_file_,
                       boost::bind(&GeneralKadCallback::CallbackFunc,
                                   &cb_, _1));
      wait_result(&cb_);
      ASSERT_TRUE(cb_.result());
      ASSERT_TRUE(nodes_[i]->is_joined());
      nodes_[i]->set_signature_validator(&validator);
      DLOG(INFO) << "Node " << i << " joined "
                << nodes_[i]->node_id().ToStringEncoded(NodeId::kHex)
                   .substr(0, 12)
                << std::endl;
      node_ids_.push_back(nodes_[i]->node_id());
    }
    cb_.Reset();
#ifdef WIN32
    HANDLE hconsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hconsole, 10 | 0 << 4);
#endif
    DLOG(INFO) << kNetworkSize << " local Kademlia nodes running" << std::endl;
#ifdef WIN32
    SetConsoleTextAttribute(hconsole, 11 | 0 << 4);
#endif
  }

  virtual void TearDown() {
    DLOG(INFO) << "TestNode, TearDown Starting..." << std::endl;
    Sleep(boost::posix_time::seconds(5));

#ifdef WIN32
    HANDLE hconsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hconsole, 7 | 0 << 4);
#endif
    for (int16_t i = kNetworkSize-1; i >= 0; i--) {
      DLOG(INFO) << "stopping node " << i << std::endl;
      cb_.Reset();
      nodes_[i]->Leave();
      EXPECT_FALSE(nodes_[i]->is_joined());
      transports_[i]->StopListening(transport_ports_[i]);
      channel_managers_[i]->Stop();
    }
    std::set<uint16_t>::iterator it;
    for (it = ports_.begin(); it != ports_.end(); it++) {
      // Deleting the DBs in the app dir
      fs::path db_dir(get_app_directory());
      db_dir /= boost::lexical_cast<std::string>(*it);
      try {
        if (fs::exists(db_dir))
          fs::remove_all(db_dir);
      }
      catch(const std::exception &e) {
        DLOG(ERROR) << "filesystem error: " << e.what() << std::endl;
      }
    }
    try {
      if (fs::exists(test_dir_))
        fs::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "filesystem error: " << e.what() << std::endl;
    }
    nodes_.clear();
    channel_managers_.clear();
    transports_.clear();
    transport_ports_.clear();
    dbs_.clear();
    node_ids_.clear();
    ports_.clear();
    DLOG(INFO) << "TestNode, TearDown Finished." << std::endl;
    transport::UdtTransport::CleanUp();
  }
};

TEST_F(NodeTest, DISABLED_FUNC_KAD_ClientNodeConnect) {
  NodeConstructionParameters kcp;
  ConstructKcp(&kcp);

  boost::shared_ptr<transport::UdtTransport> t1(new transport::UdtTransport);
  transport::TransportCondition tc;
  transport::Port p1 = t1->StartListening("", 0, &tc);
  ASSERT_EQ(transport::kSuccess, tc);
  ASSERT_LT(0, p1);
  kcp.port = p1;
  boost::shared_ptr<rpcprotocol::ChannelManager> cm1(
      new rpcprotocol::ChannelManager(t1));
  ASSERT_EQ(0, cm1->Start());

  std::string db_local(test_dir_ + std::string("/datastore") +
                       boost::lexical_cast<std::string>(kNetworkSize + 1));
  boost::filesystem::create_directories(db_local);

  std::string privkey, pubkey;
  create_rsakeys(&pubkey, &privkey);
  kcp.type = CLIENT;
  kcp.public_key = pubkey;
  kcp.private_key = privkey;
  Node node_local_1(cm1, t1, kcp);

  std::string config_file = db_local + "/.kadconfig";
  base::KadConfig conf;
  base::KadConfig::Contact *ctc1 = conf.add_contact();
  ctc1->set_node_id(nodes_[0]->node_id().ToStringEncoded(NodeId::kHex));
  ctc1->set_ip(nodes_[0]->ip());
  ctc1->set_port(nodes_[0]->port());
  ctc1->set_local_ip(nodes_[0]->local_ip());
  ctc1->set_local_port(nodes_[0]->local_port());
  std::fstream output2(config_file.c_str(),
                       std::ios::out | std::ios::trunc | std::ios::binary);
  ASSERT_TRUE(conf.SerializeToOstream(&output2));
  output2.close();
  ASSERT_EQ(kSymmetric, node_local_1.nat_type());
  node_local_1.Join(config_file,
                     boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1));
  wait_result(&cb_);
  ASSERT_TRUE(cb_.result());
  ASSERT_EQ(kClientId, node_local_1.node_id().String());
  ASSERT_EQ(kDirectConnected, node_local_1.nat_type());

  boost::shared_ptr<transport::UdtTransport> t2(new transport::UdtTransport);
  transport::Port p2 = t2->StartListening("", 0, &tc);
  ASSERT_EQ(transport::kSuccess, tc);
  ASSERT_LT(0, p2);
  kcp.port = p2;
  boost::shared_ptr<rpcprotocol::ChannelManager> cm2(
      new rpcprotocol::ChannelManager(t2));
  ASSERT_EQ(0, cm2->Start());

//  std::string privkey, pubkey;
  create_rsakeys(&pubkey, &privkey);
  kcp.type = CLIENT;
  kcp.public_key = pubkey;
  kcp.private_key = privkey;
  Node node_local_2(cm2, t2, kcp);
  db_local = test_dir_ + std::string("/datastore") +
             boost::lexical_cast<std::string>(kNetworkSize + 2);
  boost::filesystem::create_directories(db_local);
  config_file = db_local + "/.kadconfig";
  conf.Clear();
  base::KadConfig::Contact *ctc2 = conf.add_contact();
  ctc2->set_node_id(nodes_[0]->node_id().ToStringEncoded(NodeId::kHex));
  ctc2->set_ip(nodes_[0]->ip());
  ctc2->set_port(nodes_[0]->port());
  ctc2->set_local_ip(nodes_[0]->local_ip());
  ctc2->set_local_port(nodes_[0]->local_port());
  std::fstream output3(config_file.c_str(),
                       std::ios::out | std::ios::trunc | std::ios::binary);
  ASSERT_TRUE(conf.SerializeToOstream(&output3));
  output3.close();
  ports_.insert(node_local_2.port());
  ASSERT_EQ(kSymmetric, node_local_2.nat_type());
  cb_.Reset();
  node_local_2.Join(config_file,
                     boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1));
  wait_result(&cb_);
  ASSERT_TRUE(cb_.result());
  ASSERT_EQ(kClientId, node_local_2.node_id().String());
  ASSERT_EQ(kDirectConnected, node_local_2.nat_type());

  // Doing a storevalue
  NodeId key(cry_obj_.Hash("dccxxvdeee432cc", "", crypto::STRING_STRING, false));
  std::string value = base::RandomString(1024 * 10);  // 10KB
  SignedValue sig_value;
  StoreValueCallback cb_1;
  std::string pub_key_val, sig_req;
  create_rsakeys(&pubkey, &privkey);


  Validifier signer;


  sig_value.set_value(value);
  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", privkey,
                                                  crypto::STRING_STRING));
  std::string ser_sig_value = sig_value.SerializeAsString();
  SignedRequest req;
  req.set_signer_id(node_local_1.node_id().String());
  req.set_public_key(pubkey);
  req.set_public_key_validation(pub_key_val);
  req.set_request_signature(sig_req);
  node_local_1.StoreValue(key, sig_value, req, 24 * 3600,
                           boost::bind(&StoreValueCallback::CallbackFunc,
                                       &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());

  // loading the value with another existing node
  FindCallback cb_2;
  nodes_[kTestK / 2]->FindValue(key, false,
                                 boost::bind(&FindCallback::CallbackFunc,
                                             &cb_2, _1));
  wait_result(&cb_2);
  ASSERT_TRUE(cb_2.result());
  ASSERT_LE(1U, cb_2.signed_values().size());
  bool got_value = false;
  for (size_t i = 0; i < cb_2.signed_values().size(); i++) {
    if (value == cb_2.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value)
    FAIL();
  cb_2.Reset();

  // loading the value with the client
  node_local_1.FindValue(key, false,
                          boost::bind(&FindCallback::CallbackFunc, &cb_2, _1));
  wait_result(&cb_2);
  ASSERT_TRUE(cb_2.result());
  ASSERT_LE(1U, cb_2.signed_values().size());
  got_value = false;
  for (size_t i = 0; i < cb_2.signed_values().size(); i++) {
    if (value == cb_2.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value)
    FAIL();
  cb_2.Reset();

  // loading the value with the client2
  node_local_2.FindValue(key, false,
                          boost::bind(&FindCallback::CallbackFunc, &cb_2, _1));
  wait_result(&cb_2);
  ASSERT_TRUE(cb_2.result());
  ASSERT_LE(1U, cb_2.signed_values().size());
  got_value = false;
  for (size_t i = 0; i < cb_2.signed_values().size(); i++) {
    if (value == cb_2.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value)
    FAIL();
  cb_2.Reset();

  // Doing a find closest nodes with the client
  NodeId key1(cry_obj_.Hash("2evvnf3xssas21", "", crypto::STRING_STRING, false));
  FindCallback cb_3;
  node_local_1.FindKClosestNodes(key1,
                                  boost::bind(&FindCallback::CallbackFunc,
                                              &cb_3, _1));
  wait_result(&cb_3);
  // make sure the nodes returned are what we expect.
  ASSERT_TRUE(cb_3.result());
  ASSERT_FALSE(cb_3.closest_nodes().empty());
  std::list<std::string> closest_nodes_str;  // = cb_3.closest_nodes();
  for (size_t i = 0; i < cb_3.closest_nodes().size(); i++)
    closest_nodes_str.push_back(cb_3.closest_nodes()[i]);
  std::list<std::string>::iterator it;
  std::list<Contact> closest_nodes;
  for (it = closest_nodes_str.begin(); it != closest_nodes_str.end();
      it++) {
    Contact node;
    node.ParseFromString(*it);
    closest_nodes.push_back(node);
  }
  ASSERT_EQ(kTestK, closest_nodes.size());
  std::list<Contact> all_nodes;
  for (int16_t i = 0; i < kNetworkSize; i++) {
    Contact node(nodes_[i]->node_id(), nodes_[i]->ip(),
        nodes_[i]->port());
    all_nodes.push_back(node);
  }
  SortContactList(key1, &all_nodes);
  std::list<Contact>::iterator it1, it2;
  it2= closest_nodes.begin();
  for (it1 = closest_nodes.begin(); it1 != closest_nodes.end();
      it1++, it2++) {
    ASSERT_TRUE(it1->Equals(*it2));
  }

  // Checking no node has stored the clients node in its routing table
  for (int16_t i = 0; i < kNetworkSize; i++) {
    Contact client_node;
    ASSERT_FALSE(nodes_[i]->GetContact(node_local_1.node_id(), &client_node));
  }
  cb_.Reset();
  node_local_1.Leave();
  ASSERT_FALSE(node_local_1.is_joined());
  t1->StopListening(p1);
  cm1->Stop();

  node_local_2.Leave();
  ASSERT_FALSE(node_local_2.is_joined());
  t2->StopListening(p2);
  cm2->Stop();
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_FindClosestNodes) {
  NodeId key(cry_obj_.Hash("2evvnf3xssas21", "", crypto::STRING_STRING, false));
  FindCallback cb_1;
  nodes_[kTestK/2]->FindKClosestNodes(key,
                                       boost::bind(&FindCallback::CallbackFunc,
                                                   &cb_1, _1));
  wait_result(&cb_1);
  // make sure the nodes returned are what we expect.
  ASSERT_TRUE(cb_1.result());
  ASSERT_FALSE(cb_1.closest_nodes().empty());
  std::list<std::string> closest_nodes_str;  // = cb_1.closest_nodes();
  for (size_t i = 0; i < cb_1.closest_nodes().size(); i++)
    closest_nodes_str.push_back(cb_1.closest_nodes()[i]);
  std::list<std::string>::iterator it;
  std::list<Contact> closest_nodes;
  for (it = closest_nodes_str.begin(); it != closest_nodes_str.end();
      it++) {
    Contact node;
    node.ParseFromString(*it);
    closest_nodes.push_back(node);
  }
  ASSERT_EQ(kTestK, closest_nodes.size());
  std::list<Contact> all_nodes;
  for (int16_t i = 0; i < kNetworkSize; i++) {
    Contact node(nodes_[i]->node_id(), nodes_[i]->ip(),
        nodes_[i]->port(), nodes_[i]->local_ip(),
        nodes_[i]->local_port(), nodes_[i]->rendezvous_ip(),
        nodes_[i]->rendezvous_port());
    all_nodes.push_back(node);
  }
  SortContactList(key, &all_nodes);
  std::list<Contact>::iterator it1, it2;
  it2= closest_nodes.begin();
  for (it1 = closest_nodes.begin(); it1 != closest_nodes.end(); it1++, it2++) {
    ASSERT_TRUE(it1->Equals(*it2));
  }
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_StoreAndLoadSmallValue) {
  // prepare small size of values
  NodeId key(cry_obj_.Hash("dccxxvdeee432cc", "", crypto::STRING_STRING, false));
  std::string value = base::RandomString(1024 * 5);  // 5KB
  SignedValue sig_value;
  sig_value.set_value(value);
  // save key/value pair from a node
  StoreValueCallback cb_;
  std::string pub_key, priv_key, pub_key_val, sig_req;
  create_rsakeys(&pub_key, &priv_key);


  Validifier signer;


  SignedRequest req;
  req.set_signer_id(nodes_[kTestK / 2]->node_id().String());
  req.set_public_key(pub_key);
  req.set_public_key_validation(pub_key_val);
  req.set_request_signature(sig_req);

  nodes_[kTestK / 2]->StoreValue(key, sig_value, req, 24 * 3600,
                                  boost::bind(&StoreValueCallback::CallbackFunc,
                                              &cb_, _1));
  wait_result(&cb_);
  ASSERT_FALSE(cb_.result());
  cb_.Reset();

  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", priv_key,
      crypto::STRING_STRING));
  nodes_[kTestK / 2]->StoreValue(key, sig_value, req, 24 * 3600,
                                  boost::bind(&StoreValueCallback::CallbackFunc,
                                              &cb_, _1));
  wait_result(&cb_);
  ASSERT_TRUE(cb_.result());
  // calculate number of nodes which hold this key/value pair
  int16_t number(0);
  for (int16_t i = 0; i < kNetworkSize; i++) {
    std::vector<std::string> values;
    bool b = false;
    nodes_[i]->FindValueLocal(key, &values);
    if (!values.empty()) {
      for (uint32_t n = 0; n < values.size() && !b; ++n) {
        SignedValue sig_value;
        ASSERT_TRUE(sig_value.ParseFromString(values[n]));
        if (value == sig_value.value()) {
          number++;
          b = true;
        }
      }
    }
  }
  int16_t d = static_cast<int16_t>(kTestK * kMinSuccessfulPecentageStore);
  ASSERT_LE(d, number);
  // load the value from no.kNetworkSize-1 node
  cb_.Reset();
  FindCallback cb_1;
  nodes_[kNetworkSize - 2]->FindValue(key, false, boost::bind(
    &FindCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  ASSERT_LE(1U, cb_1.signed_values().size());
  bool got_value = false;
  for (size_t i = 0; i < cb_1.signed_values().size(); i++) {
    if (value == cb_1.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value) {
    FAIL() << "FAIL node " << kNetworkSize - 2;
  }
  // load the value from no.1 node
  cb_1.Reset();
  ASSERT_TRUE(nodes_[0]->is_joined());
  nodes_[0]->FindValue(key, false, boost::bind(&FakeCallback::CallbackFunc,
                                                &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  ASSERT_LE(1U, cb_1.signed_values().size());
  got_value = false;
  for (size_t i = 0; i < cb_1.signed_values().size(); i++) {
    if (value == cb_1.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value) {
    FAIL() << "FAIL node 0";
  }
  cb_1.Reset();
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_StoreAndLoadBigValue) {
  // prepare big size of values
  NodeId key(cry_obj_.Hash("vcdrer43dccdwwt", "", crypto::STRING_STRING, false));
  std::string value = base::RandomString(1024 * 1024);  // 1MB
  SignedValue sig_value;
  sig_value.set_value(value);
  // save key/value pair from a node
  StoreValueCallback cb_;
  std::string pub_key, priv_key, pub_key_val, sig_req;
  create_rsakeys(&pub_key, &priv_key);


  Validifier signer;


  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", priv_key,
                                                  crypto::STRING_STRING));
  SignedRequest req;
  req.set_signer_id(nodes_[kTestK / 3]->node_id().String());
  req.set_public_key(pub_key);
  req.set_public_key_validation(pub_key_val);
  req.set_request_signature(sig_req);
  nodes_[kTestK / 3]->StoreValue(key, sig_value, req, 24*3600,
                                  boost::bind(&StoreValueCallback::CallbackFunc,
                                              &cb_, _1));
  wait_result(&cb_);
  ASSERT_TRUE(cb_.result());
  // calculate number of nodes which hold this key/value pair
  int16_t number = 0;
  for (int16_t i = 0; i < kNetworkSize; i++) {
    bool b = false;
    std::vector<std::string> values;
    nodes_[i]->FindValueLocal(key, &values);
    if (!values.empty()) {
      for (uint32_t n = 0; n < values.size(); ++n) {
        SignedValue sig_value;
        ASSERT_TRUE(sig_value.ParseFromString(values[n]));
        if (value == sig_value.value()) {
          number++;
          b = true;
        }
      }
    }
  }
  int16_t d(static_cast<int16_t>
    (kTestK * kMinSuccessfulPecentageStore));
  ASSERT_LE(d, number);
  // load the value from the node
  FindCallback cb_1;
  nodes_[kTestK / 3]->FindValue(key, false,
                                 boost::bind(&FindCallback::CallbackFunc,
                                             &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  ASSERT_LE(1U, cb_1.signed_values().size());
  bool got_value = false;
  for (size_t i = 0; i < cb_1.signed_values().size(); i++) {
    if (value == cb_1.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value)
    FAIL();
  // load the value from another node
  FindCallback cb_2;
  nodes_[kTestK * 2 / 3]->FindValue(key, false,
                                     boost::bind(&FindCallback::CallbackFunc,
                                                 &cb_2, _1));
  wait_result(&cb_2);
  ASSERT_TRUE(cb_2.result());
  ASSERT_LE(1U, cb_2.signed_values().size());
  got_value = false;
  for (size_t i = 0; i < cb_1.signed_values().size(); i++) {
    if (value == cb_1.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value)
    FAIL();
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_StoreAndLoad100Values) {
  int16_t count(100);
  std::vector<NodeId> keys(count);
  std::vector<SignedValue> values(count);
  std::vector<StoreValueCallback> cbs(count);
  std::string pub_key, priv_key, pub_key_val, sig_req;
  create_rsakeys(&pub_key, &priv_key);
  DLOG(INFO) << "Store..." << std::endl;
  for (int16_t n = 0; n < count; ++n) {
    keys[n] = NodeId(cry_obj_.Hash("key" + base::IntToString(n), "",
                  crypto::STRING_STRING, false));
    values[n].set_value(base::RandomString(1024));


  Validifier signer;


    values[n].set_value_signature(cry_obj_.AsymSign(values[n].value(), "",
                                  priv_key, crypto::STRING_STRING));
    SignedRequest req;
    int a(n % (kNetworkSize - 1));
    req.set_signer_id(nodes_[a]->node_id().String());
    req.set_public_key(pub_key);
    req.set_public_key_validation(pub_key_val);
    req.set_request_signature(sig_req);
    nodes_[a]->StoreValue(keys[n], values[n], req, 24 * 3600,
                           boost::bind(&StoreValueCallback::CallbackFunc,
                                       &cbs[n], _1));
  }
  DLOG(INFO) << "Load..." << std::endl;
  for (int16_t p = 0; p < count; ++p) {
    wait_result(&cbs[p]);
    EXPECT_TRUE(cbs[p].result())
              << "Failed to store " << kMinSuccessfulPecentageStore
              << "% of K copies of the " << p << "th value";
  }
  for (int16_t p = 0; p < count; ++p) {
    FindCallback cb_1;
    nodes_[kTestK / 2]->FindValue(keys[p], false,
                                   boost::bind(&FindCallback::CallbackFunc,
                                               &cb_1, _1));
    wait_result(&cb_1);
    ASSERT_TRUE(cb_1.result())
              << "No copies of the " << p <<"th value where stored.";
    ASSERT_EQ(1U, cb_1.signed_values().size());
    ASSERT_EQ(values[p].value(), cb_1.signed_values()[0].value());
  }
  DLOG(INFO) << "Done." << std::endl;
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_LoadNonExistingValue) {
  NodeId key(cry_obj_.Hash("bbffddnnooo8822", "", crypto::STRING_STRING, false));
  // load the value from last node
  FindCallback cb_1;
  nodes_[kNetworkSize - 1]->FindValue(key, false,
                                       boost::bind(&FindCallback::CallbackFunc,
                                                   &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  ASSERT_FALSE(cb_1.closest_nodes().empty());
  ASSERT_TRUE(cb_1.values().empty());
  ASSERT_TRUE(cb_1.signed_values().empty());
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_GetNodeContactDetails) {
  // find an existing node
  NodeId node_id1(nodes_[kTestK / 3]->node_id());
  GetNodeContactDetailsCallback cb_1;
  nodes_[kNetworkSize-1]->GetNodeContactDetails(
      node_id1,
      boost::bind(&GetNodeContactDetailsCallback::CallbackFunc, &cb_1, _1),
      false);
  wait_result(&cb_1);
  ASSERT_FALSE(cb_1.result());
  Contact expect_node1;
  Contact target_node1(nodes_[kTestK / 3]->node_id(),
                            nodes_[kTestK / 3]->ip(),
                            nodes_[kTestK / 3]->port());
  expect_node1.ParseFromString(cb_1.contact());
  ASSERT_TRUE(target_node1.Equals(expect_node1));
  // find a non-existing node
  GetNodeContactDetailsCallback cb_2;
  NodeId node_id2(cry_obj_.Hash("bcdde34333", "", crypto::STRING_STRING, false));
  nodes_[kNetworkSize-1]->GetNodeContactDetails(
      node_id2,
      boost::bind(&GetNodeContactDetailsCallback::CallbackFunc, &cb_2, _1),
      false);
  wait_result(&cb_2);
  ASSERT_FALSE(cb_2.result());
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_Ping) {
  // ping by contact
  Contact remote(nodes_[kTestK * 3 / 4]->node_id(),
                      nodes_[kTestK * 3 / 4]->ip(),
                      nodes_[kTestK * 3 / 4]->port(),
                      nodes_[kTestK * 3 / 4]->local_ip(),
                      nodes_[kTestK * 3 / 4]->local_port());
  PingCallback cb_1;
  nodes_[kNetworkSize-1]->Ping(remote, boost::bind(&PingCallback::CallbackFunc,
                                                    &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  // ping by node id
  NodeId remote_id(nodes_[kTestK / 4]->node_id());
  PingCallback cb_2;
  nodes_[kNetworkSize-2]->Ping(remote_id,
                                boost::bind(&PingCallback::CallbackFunc,
                                            &cb_2, _1));
  wait_result(&cb_2);
  // ASSERT_EQ(kRpcResultSuccess, cb_2.result());
  if (!cb_2.result()) {
    for (int16_t i = 0; i < kNetworkSize; ++i) {
      Contact ctc;
      if (nodes_[i]->GetContact(remote_id, &ctc))
          DLOG(INFO) << "node " << i << " port " << nodes_[i]->port()
                     << "has node " << kTestK / 4 << std::endl;
    }
    NodeId zero_id;
    if (remote_id == zero_id)
      DLOG(INFO) << "remote id is a kClientId." << std::endl;
    if (remote_id == nodes_[kNetworkSize-2]->node_id())
      DLOG(INFO) << "remote_id == node_id of sender." << std::endl;
    FAIL();
  }
  // ping a dead node
  NodeId dead_id(cry_obj_.Hash("bb446dx", "", crypto::STRING_STRING, false));

  uint16_t port(4242);
  std::set<uint16_t>::iterator it;
  it = ports_.find(port);

  while (it != ports_.end()) {
    ++port;
    it = ports_.find(port);
  }

  Contact dead_remote(dead_id, kLocalIp, port);
  PingCallback cb_3;
  nodes_[kNetworkSize-1]->Ping(dead_remote,
                                boost::bind(&PingCallback::CallbackFunc,
                                            &cb_3, _1));
  wait_result(&cb_3);
  ASSERT_FALSE(cb_3.result());
  PingCallback cb_4;
  nodes_[kNetworkSize-1]->Ping(dead_id,
                                boost::bind(&PingCallback::CallbackFunc,
                                            &cb_4, _1));
  wait_result(&cb_4);
  ASSERT_FALSE(cb_4.result());
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_FindValueWithDeadNodes) {
  // Store a small value
  // prepair small size of values
  NodeId key(cry_obj_.Hash("rrvvdcccdd", "", crypto::STRING_STRING, false));
  std::string value = base::RandomString(3 * 1024);  // 3KB
  SignedValue sig_value;
  sig_value.set_value(value);
  // save key/value pair from no.8 node
  StoreValueCallback cb_1;
  std::string pub_key, priv_key, pub_key_val, sig_req;
  create_rsakeys(&pub_key, &priv_key);


  Validifier signer;


  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", priv_key,
                                                  crypto::STRING_STRING));
  SignedRequest req;
  req.set_signer_id(nodes_[kTestK * 3 / 4]->node_id().String());
  req.set_public_key(pub_key);
  req.set_public_key_validation(pub_key_val);
  req.set_request_signature(sig_req);
  nodes_[kTestK * 3 / 4]->StoreValue(key, sig_value, req, 24 * 3600,
                                      boost::bind(&FakeCallback::CallbackFunc,
                                                  &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  // kill k-1 nodes, there should be at least one node left which holds this
  // value
  for (int16_t i = 0; i < kTestK - 2 && i < kNetworkSize - 2; ++i) {
    nodes_[2 + i]->Leave();
    transports_[2 + i]->StopListening(transport_ports_[2 + i]);
    channel_managers_[2 + i]->Stop();
  }
  Sleep(boost::posix_time::seconds(2));
  // try to find value
  // load the value from no.20 node
  FindCallback cb_2;
  nodes_[kNetworkSize - 1]->FindValue(key, false,
                                       boost::bind(&FakeCallback::CallbackFunc,
                                                   &cb_2, _1));
  wait_result(&cb_2);
  ASSERT_TRUE(cb_2.result());
  ASSERT_LE(1U, cb_2.signed_values().size());
  bool got_value = false;
  for (size_t i = 0; i < cb_2.signed_values().size(); ++i) {
    if (value == cb_2.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value) {
    FAIL();
  }
  for (int16_t i = 0; i < kTestK - 2 && i < kNetworkSize - 2; ++i) {
    Contact ctc(nodes_[2 + i]->node_id(),
                     nodes_[2 + i]->ip(),
                     nodes_[2 + i]->port(),
                     nodes_[2 + i]->local_ip(),
                     nodes_[2 + i]->local_port());
    PingCallback ping_cb;
    nodes_[0]->Ping(ctc, boost::bind(&PingCallback::CallbackFunc,
                                      &ping_cb, _1));
    wait_result(&ping_cb);
    ASSERT_FALSE(ping_cb.result());
    ping_cb.Reset();
    nodes_[1]->Ping(ctc, boost::bind(&PingCallback::CallbackFunc,
                                      &ping_cb, _1));
    wait_result(&ping_cb);
    ASSERT_FALSE(ping_cb.result());
     ping_cb.Reset();
    nodes_[kNetworkSize - 1]->Ping(ctc,
                                    boost::bind(&PingCallback::CallbackFunc,
                                                &ping_cb, _1));
    wait_result(&ping_cb);
    ASSERT_FALSE(ping_cb.result());
  }
  // Restart dead nodes
  base::KadConfig kad_config;
  base::KadConfig::Contact *kad_contact = kad_config.add_contact();
  kad_contact->set_node_id(
      nodes_[0]->node_id().ToStringEncoded(NodeId::kHex));
  kad_contact->set_ip(nodes_[0]->ip());
  kad_contact->set_port(nodes_[0]->port());
  kad_contact->set_local_ip(nodes_[0]->local_ip());
  kad_contact->set_local_port(nodes_[0]->local_port());

  for (int16_t i = 0; i < kTestK - 2 && i < kNetworkSize - 2; ++i) {
    cb_.Reset();
    std::string conf_file = dbs_[2 + i] + "/.kadconfig";

    std::fstream output(conf_file.c_str(),
                        std::ios::out | std::ios::trunc | std::ios::binary);
    ASSERT_TRUE(kacod_config.SerializeToOstream(&output));
    output.close();

    transport::TransportCondition tc;
    transports_[i]->StartListening("", transport_ports_[2 + i], &tc);
    EXPECT_EQ(transport::kSuccess, tc);
    EXPECT_EQ(0, channel_managers_[2 + i]->Start());

    nodes_[2 + i]->Join(node_ids_[2 + i], conf_file,
                         boost::bind(&GeneralKadCallback::CallbackFunc,
                                     &cb_, _1));
    wait_result(&cb_);
    ASSERT_TRUE(cb_.result());
    ASSERT_TRUE(nodes_[2 + i]->is_joined());
    nodes_[2 + i]->set_signature_validator(&validator);
    ASSERT_TRUE(node_ids_[2 + i] == nodes_[2 + i]->node_id());
  }
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_Downlist) {
  Sleep(boost::posix_time::seconds(2));
  // select a random node from node 1 to node kNetworkSize
  int r_node = 1 + base::RandomInt32() % (kNetworkSize - 1);
  NodeId r_node_id(nodes_[r_node]->node_id());
  // Compute the sum of the nodes whose routing table contain r_node
  int sum_0 = 0;
  std::vector<int16_t> holders;
  for (int16_t i = 1; i < kNetworkSize; ++i) {
    if (i != r_node) {
      Contact test_contact;
      if (nodes_[i]->GetContact(r_node_id, &test_contact)) {
        if (test_contact.failed_rpc() == kFailedRpcTolerance) {
          ++sum_0;
          holders.push_back(i);
        }
      }
    }
  }
  cb_.Reset();
  // finding the closest node to the dead node
  int16_t closest_node(0);
  NodeId holder_id(nodes_[holders[0]]->node_id());
  NodeId smallest_distance = r_node_id ^ holder_id;
  for (size_t i = 0; i < holders.size(); i++) {
    NodeId distance = r_node_id ^ nodes_[holders[i]]->node_id();
    if (smallest_distance > distance) {
      smallest_distance = distance;
      closest_node = i;
    }
  }

  Contact holder(nodes_[holders[closest_node]]->node_id(),
                 nodes_[holders[closest_node]]->ip(),
                 nodes_[holders[closest_node]]->port(),
                 nodes_[holders[closest_node]]->local_ip(),
                 nodes_[holders[closest_node]]->local_port());
  PingCallback cb_3;
  nodes_[0]->Ping(holder, boost::bind(&PingCallback::CallbackFunc, &cb_3, _1));
  wait_result(&cb_3);
  ASSERT_TRUE(cb_3.result());

  GetNodeContactDetailsCallback cb_1;
  Contact dead_node(r_node_id, nodes_[r_node]->ip(),
                    nodes_[r_node]->port(),
                    nodes_[r_node]->local_ip(),
                    nodes_[r_node]->local_port());
  PingCallback cb_2;
  nodes_[0]->Ping(dead_node, boost::bind(&PingCallback::CallbackFunc,
                                          &cb_2, _1));
  wait_result(&cb_2);
  ASSERT_TRUE(cb_2.result());
  // Kill r_node
  GeneralKadCallback cb_;
  nodes_[r_node]->Leave();
  ASSERT_FALSE(nodes_[r_node]->is_joined());
  transports_[r_node]->StopListening(transport_ports_[r_node]);
  channel_managers_[r_node]->Stop();

  // Do a find node
  nodes_[0]->FindKClosestNodes(
      r_node_id, boost::bind(&GetNodeContactDetailsCallback::CallbackFunc,
                             &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  // Wait for a RPC timeout interval until the downlist are handled in the
  // network
  Sleep(boost::posix_time::seconds(11));
  // Compute the sum of the nodes whose routing table contain r_node again
  int16_t sum_1(0);
  for (int16_t i = 1; i < kNetworkSize; i++) {
    if (i != r_node) {
      Contact test_contact;
      if (nodes_[i]->GetContact(r_node_id, &test_contact)) {
        ++sum_1;
      } else {
        if (test_contact.failed_rpc() > kFailedRpcTolerance)
          ++sum_1;
      }
    }
  }
  // r_node should be removed from the routing tables of some nodes
  ASSERT_LT(sum_1, sum_0);

  // Restart dead node
  transport::TransportCondition tc;
  transports_[r_node]->StartListening("", transport_ports_[r_node], &tc);
  ASSERT_EQ(transport::kSuccess, tc);
  ASSERT_EQ(0, channel_managers_[r_node]->Start());
  cb_.Reset();
  std::string conf_file = dbs_[r_node] + "/.kadconfig";
  nodes_[r_node]->Join(node_ids_[r_node], conf_file,
                        boost::bind(&GeneralKadCallback::CallbackFunc,
                                    &cb_, _1));
  wait_result(&cb_);
  ASSERT_TRUE(cb_.result());
  ASSERT_TRUE(nodes_[r_node]->is_joined());
  nodes_[r_node]->set_signature_validator(&validator);
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_StoreWithInvalidRequest) {
  NodeId key(cry_obj_.Hash("dccxxvdeee432cc", "", crypto::STRING_STRING, false));
  std::string value(base::RandomString(1024));  // 1KB
  SignedValue sig_value;
  sig_value.set_value(value);
  // save key/value pair from no.8 node
  StoreValueCallback cb_;
  std::string pub_key, priv_key, pub_key_val, sig_req;
  create_rsakeys(&pub_key, &priv_key);


  Validifier signer;


  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", priv_key,
                                                  crypto::STRING_STRING));
  std::string ser_sig_value = sig_value.SerializeAsString();
  SignedRequest req;
  req.set_signer_id(nodes_[kTestK / 2]->node_id().String());
  req.set_public_key(pub_key);
  req.set_public_key_validation(pub_key_val);
  req.set_request_signature("bad request");

  nodes_[kTestK / 2]->StoreValue(key, sig_value, req, 24 * 3600,
                                  boost::bind(&StoreValueCallback::CallbackFunc,
                                              &cb_, _1));
  wait_result(&cb_);
  ASSERT_FALSE(cb_.result());
  std::string new_pub_key, new_priv_key;
  create_rsakeys(&new_pub_key, &new_priv_key);
  ASSERT_NE(pub_key, new_pub_key);
  cb_.Reset();
  req.set_request_signature(sig_req);
  req.set_public_key(new_pub_key);
  nodes_[kTestK / 2]->StoreValue(key, sig_value, req, 24 * 3600,
                                  boost::bind(&StoreValueCallback::CallbackFunc,
                                              &cb_, _1));
  wait_result(&cb_);
  ASSERT_FALSE(cb_.result());
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_AllDirectlyConnected) {
  for (int16_t i = 0; i < kNetworkSize; i++) {
    ASSERT_EQ(kDirectConnected, nodes_[i]->nat_type());
    std::vector<Contact> exclude_contacts;
    std::vector<Contact> contacts;
    nodes_[i]->GetRandomContacts(static_cast<size_t>(kNetworkSize),
                                  exclude_contacts, &contacts);
    ASSERT_FALSE(contacts.empty());
    for (size_t j = 0; j < contacts.size(); j++) {
      ASSERT_EQ(std::string(""), contacts[j].rendezvous_ip());
      ASSERT_EQ(0, contacts[j].rendezvous_port());
    }
  }
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_IncorrectNodeLocalAddrPing) {
  Contact remote(nodes_[kTestK * 3 / 4]->node_id(),
                      nodes_[kTestK * 3 / 4]->ip(),
                      nodes_[kTestK * 3 / 4]->port(),
                      nodes_[kTestK * 3 / 4]->local_ip(),
                      nodes_[kTestK * 3 / 4]->local_port());
  PingCallback cb_1;
  nodes_[kTestK / 4]->Ping(remote,
                            boost::bind(&PingCallback::CallbackFunc,
                                        &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());

  // now ping the node that has changed its local address
  Contact remote1(nodes_[kTestK / 4]->node_id(),
                       nodes_[kTestK / 4]->ip(),
                       nodes_[kTestK / 4]->port(),
                       nodes_[kTestK / 2]->local_ip(),
                       nodes_[kTestK / 2]->local_port());
  cb_1.Reset();
  nodes_[kTestK * 3 / 4]->Ping(remote1,
                                boost::bind(&PingCallback::CallbackFunc,
                                            &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_FindDeadNode) {
  // find an existing node that has gone down
  // select a random node from node 1 to node kNetworkSize
  uint16_t r_node = 1 + rand() % (kNetworkSize - 2);  // NOLINT (Fraser)
  DLOG(INFO) << "+++++++++++++++++ r_node = " << r_node << std::endl;
  NodeId r_node_id = nodes_[r_node]->node_id();
  uint16_t r_port = nodes_[r_node]->port();
  nodes_[r_node]->Leave();
  ASSERT_FALSE(nodes_[r_node]->is_joined());
  transports_[r_node]->StopListening(transport_ports_[r_node]);
  channel_managers_[r_node]->Stop();
  ports_.erase(r_port);
  // Do a find node
  DLOG(INFO) << "+++++++++++++++++ Node " << r_node << " stopped" << std::endl;
  GetNodeContactDetailsCallback cb_1;
  nodes_[kNetworkSize - 1]->GetNodeContactDetails(
      r_node_id, boost::bind(&GetNodeContactDetailsCallback::CallbackFunc,
                             &cb_1, _1),
      false);
  wait_result(&cb_1);
  ASSERT_FALSE(cb_1.result());
  Sleep(boost::posix_time::seconds(33));
  // Restart dead node
  DLOG(INFO) << "+++++++++++++++++ Restarting " << r_node << std::endl;
  transport::TransportCondition tc;
  transports_[r_node]->StartListening("", transport_ports_[r_node], &tc);
  ASSERT_EQ(transport::kSuccess, tc);
  ASSERT_EQ(0, channel_managers_[r_node]->Start());
  cb_.Reset();
  std::string conf_file = dbs_[r_node] + "/.kadconfig";
  nodes_[r_node]->Join(node_ids_[r_node], conf_file,
                        boost::bind(&GeneralKadCallback::CallbackFunc,
                                    &cb_, _1));
  wait_result(&cb_);
  ASSERT_TRUE(cb_.result());
  ASSERT_TRUE(nodes_[r_node]->is_joined());
  nodes_[r_node]->set_signature_validator(&validator);
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_StartStopNode) {
  uint16_t r_node = 1 + rand() % (kNetworkSize - 1);  // NOLINT (Fraser)
  std::string kadconfig_path(dbs_[r_node] + "/.kadconfig");
  nodes_[r_node]->Leave();
  EXPECT_FALSE(nodes_[r_node]->is_joined());
  // Checking kadconfig file
  base::KadConfig kconf;
  ASSERT_TRUE(boost::filesystem::exists(
      boost::filesystem::path(kadconfig_path)));
  std::ifstream kadconf_file(kadconfig_path.c_str(),
                             std::ios::in | std::ios::binary);
  ASSERT_TRUE(kconf.ParseFromIstream(&kadconf_file));
  kadconf_file.close();
  ASSERT_LT(0, kconf.contact_size());
  cb_.Reset();
  std::string conf_file = dbs_[r_node] + "/.kadconfig";
  ASSERT_EQ(kSymmetric, nodes_[r_node]->nat_type());
  nodes_[r_node]->Join(nodes_[r_node]->node_id(), conf_file,
                        boost::bind(&GeneralKadCallback::CallbackFunc,
                                    &cb_, _1));
  wait_result(&cb_);
  ASSERT_TRUE(cb_.result());
  ASSERT_TRUE(nodes_[r_node]->is_joined());
  ASSERT_EQ(kDirectConnected, nodes_[r_node]->nat_type());
  nodes_[r_node]->set_signature_validator(&validator);
  cb_.Reset();
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_DeleteValue) {
  // prepare small size of values
  NodeId key(cry_obj_.Hash(base::RandomString(5), "", crypto::STRING_STRING,
                          false));
  std::string value(base::RandomString(1024 * 5));  // 5KB
  SignedValue sig_value;
  sig_value.set_value(value);
  // save key/value pair from no.8 node
  StoreValueCallback cb_;
  std::string pub_key, priv_key, pub_key_val, sig_req;
  create_rsakeys(&pub_key, &priv_key);


  Validifier signer;


  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", priv_key,
                                                  crypto::STRING_STRING));
  SignedRequest req;
  req.set_signer_id(nodes_[kTestK / 2]->node_id().String());
  req.set_public_key(pub_key);
  req.set_public_key_validation(pub_key_val);
  req.set_request_signature(sig_req);

  nodes_[kTestK / 2]->StoreValue(key, sig_value, req, 24 * 3600,
                                  boost::bind(&StoreValueCallback::CallbackFunc,
                                              &cb_, _1));
  wait_result(&cb_);
  ASSERT_TRUE(cb_.result());
  // calculate number of nodes which hold this key/value pair
  uint16_t number = 0;
  for (uint16_t i = 0; i < kNetworkSize; i++) {
    std::vector<std::string> values;
    bool b = false;
    nodes_[i]->FindValueLocal(key, &values);
    if (!values.empty()) {
      for (size_t n = 0; n < values.size() && !b; ++n) {
        SignedValue sig_value;
        ASSERT_TRUE(sig_value.ParseFromString(values[n]));
        if (value == sig_value.value()) {
          number++;
          b = true;
        }
      }
    }
  }
  uint16_t d(static_cast<uint16_t>
    (kTestK * kMinSuccessfulPecentageStore));
  ASSERT_LE(d, number);
  // load the value from no.kNetworkSize-1 node
  cb_.Reset();
  FindCallback cb_1;
  nodes_[kNetworkSize - 2]->FindValue(key, false,
                                       boost::bind(&FindCallback::CallbackFunc,
                                                   &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  ASSERT_LE(1U, cb_1.signed_values().size());
  bool got_value = false;
  for (size_t i = 0; i < cb_1.signed_values().size(); i++) {
    if (value == cb_1.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value) {
    FAIL() << "FAIL node " << kNetworkSize - 2;
  }

  // Deleting Value
  DeleteValueCallback del_cb;
  nodes_[kTestK / 2]->DeleteValue(
      key, sig_value, req, boost::bind(&DeleteValueCallback::CallbackFunc,
                                       &del_cb, _1));
  wait_result(&del_cb);
  ASSERT_TRUE(del_cb.result());
  // Checking no node returns the value
  for (uint16_t i = 0; i < kNetworkSize; i++) {
    std::vector<std::string> values;
    ASSERT_FALSE(nodes_[i]->FindValueLocal(key, &values));
    ASSERT_TRUE(values.empty());
  }


  // trying to load the value from no.1 node
  cb_1.Reset();
  nodes_[0]->FindValue(key, false,
                        boost::bind(&FakeCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_FALSE(cb_1.result());
  ASSERT_TRUE(cb_1.values().empty());
  ASSERT_TRUE(cb_1.signed_values().empty());
  cb_1.Reset();
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_InvalidRequestDeleteValue) {
  // prepare small size of values
  NodeId key(cry_obj_.Hash(base::RandomString(5), "", crypto::STRING_STRING,
                          false));
  std::string value = base::RandomString(1024 * 5);  // 5KB
  SignedValue sig_value;
  sig_value.set_value(value);
  // save key/value pair from no.8 node
  StoreValueCallback cb_;
  std::string pub_key, priv_key, pub_key_val, sig_req;
  create_rsakeys(&pub_key, &priv_key);


  Validifier signer;


  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", priv_key,
                                                  crypto::STRING_STRING));
  SignedRequest req;
  req.set_signer_id(nodes_[kTestK / 3]->node_id().String());
  req.set_public_key(pub_key);
  req.set_public_key_validation(pub_key_val);
  req.set_request_signature(sig_req);

  nodes_[kTestK / 3]->StoreValue(key, sig_value, req, 24 * 3600,
                                  boost::bind(&StoreValueCallback::CallbackFunc,
                                              &cb_, _1));
  wait_result(&cb_);
  ASSERT_TRUE(cb_.result());

  // load the value from no.kNetworkSize-1 node
  cb_.Reset();
  FindCallback cb_1;
  nodes_[kNetworkSize - 2]->FindValue(key, false,
                                       boost::bind(&FindCallback::CallbackFunc,
                                                   &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  ASSERT_LE(1U, cb_1.signed_values().size());
  bool got_value = false;
  for (size_t i = 0; i < cb_1.signed_values().size(); i++) {
    if (value == cb_1.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value) {
    FAIL() << "FAIL node " << kNetworkSize - 2;
  }

  // Deleting Value
  std::string pub_key1, priv_key1, pub_key_val1, sig_req1;
  create_rsakeys(&pub_key1, &priv_key1);


  Validifier signer;


  req.Clear();
  req.set_signer_id(nodes_[kTestK / 2]->node_id().String());
  req.set_public_key(pub_key1);
  req.set_public_key_validation(pub_key_val1);
  req.set_request_signature(sig_req1);
  DeleteValueCallback del_cb;
  nodes_[kNetworkSize - 1]->DeleteValue(
      key, sig_value, req, boost::bind(&DeleteValueCallback::CallbackFunc,
                                       &del_cb, _1));
  wait_result(&del_cb);
  ASSERT_FALSE(del_cb.result());

  del_cb.Reset();
  req.Clear();
  req.set_signer_id(nodes_[kTestK / 2]->node_id().String());
  req.set_public_key(pub_key1);
  req.set_public_key_validation(pub_key_val);
  req.set_request_signature(sig_req);
  nodes_[kTestK / 3]->DeleteValue(
      key, sig_value, req, boost::bind(&DeleteValueCallback::CallbackFunc,
                                       &del_cb, _1));
  wait_result(&del_cb);
  ASSERT_FALSE(del_cb.result());

  del_cb.Reset();
  req.set_public_key(pub_key);
  sig_value.set_value("other value");
  nodes_[kTestK * 2 / 3]->DeleteValue(
      key, sig_value, req, boost::bind(&FakeCallback::CallbackFunc,
                                       &del_cb, _1));
  wait_result(&del_cb);
  ASSERT_FALSE(del_cb.result());

  // trying to load the value from no.1 node
  cb_1.Reset();
  nodes_[kNetworkSize - 2]->FindValue(key, false,
                                       boost::bind(&FakeCallback::CallbackFunc,
                                                   &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  ASSERT_LE(1U, cb_1.signed_values().size());
  got_value = false;
  for (size_t i = 0; i < cb_1.signed_values().size(); i++) {
    if (value == cb_1.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value) {
    FAIL() << "FAIL node " << kNetworkSize - 2;
  }
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_UpdateValue) {
  // prepare small size of values
  NodeId key(cry_obj_.Hash(base::RandomString(5), "", crypto::STRING_STRING,
                          false));
  std::string value(base::RandomString(1024 * 5));  // 5KB
  std::string pub_key, priv_key, pub_key_val, sig_req;
  create_rsakeys(&pub_key, &priv_key);


  Validifier signer;



  SignedValue sig_value;
  sig_value.set_value(value);
  StoreValueCallback svcb;
  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", priv_key,
                                                  crypto::STRING_STRING));
  SignedRequest req;
  req.set_signer_id(nodes_[kTestK / 2]->node_id().String());
  req.set_public_key(pub_key);
  req.set_public_key_validation(pub_key_val);
  req.set_request_signature(sig_req);

  nodes_[kTestK / 2]->StoreValue(key, sig_value, req, 24 * 3600,
                                  boost::bind(&StoreValueCallback::CallbackFunc,
                                              &svcb, _1));
  wait_result(&svcb);
  ASSERT_TRUE(svcb.result());

  // calculate number of nodes which hold this key/value pair
  uint16_t number(0);
  int16_t no_value_node(-1);
  for (uint16_t i = 0; i < kNetworkSize; i++) {
    std::vector<std::string> values;
    bool b(false);
    nodes_[i]->FindValueLocal(key, &values);
    if (!values.empty()) {
      for (size_t n = 0; n < values.size() && !b; ++n) {
        SignedValue sig_value;
        ASSERT_TRUE(sig_value.ParseFromString(values[n]));
        if (value == sig_value.value()) {
          ++number;
          b = true;
        }
      }
    } else {
      no_value_node = i;
    }
  }
  ASSERT_NE(-1, no_value_node);
  uint16_t d(static_cast<uint16_t>
                    (kTestK * kMinSuccessfulPecentageStore));
  ASSERT_LE(d, number);

  // load the value from no.kNetworkSize-1 node
  FindCallback cb_1;
  nodes_[no_value_node]->FindValue(key, false,
                                    boost::bind(&FindCallback::CallbackFunc,
                                                &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  ASSERT_LE(1U, cb_1.signed_values().size());
  bool got_value = false;
  for (size_t i = 0; i < cb_1.signed_values().size() && !got_value; i++)
    if (value == cb_1.signed_values()[i].value())
      got_value = true;

  if (!got_value) {
    FAIL() << "FAIL node " << kNetworkSize - 2;
  }

  // Deleting Value
  UpdateValueCallback update_cb;
  SignedValue new_sig_value;
  std::string new_value(base::RandomString(4 * 1024));  // 4KB
  new_sig_value.set_value(new_value);
  new_sig_value.set_value_signature(cry_obj_.AsymSign(new_value, "", priv_key,
                                                      crypto::STRING_STRING));
  nodes_[no_value_node]->UpdateValue(
      key, sig_value, new_sig_value, req, 86400,
      boost::bind(&UpdateValueCallback::CallbackFunc, &update_cb, _1));
  wait_result(&update_cb);
  ASSERT_TRUE(update_cb.result());
  number = 0;
  for (uint16_t i = 0; i < kNetworkSize; ++i) {
    std::vector<std::string> values;
    bool b(false);
    nodes_[i]->FindValueLocal(key, &values);
    if (!values.empty()) {
      for (size_t n = 0; n < values.size() && !b; ++n) {
        SignedValue sig_value;
        ASSERT_TRUE(sig_value.ParseFromString(values[n]));
        if (new_value == sig_value.value()) {
          ++number;
          b = true;
        }
      }
    }
  }
  d = static_cast<uint16_t>(kTestK * kMinSuccessfulPecentageStore);
  ASSERT_LE(d, number);

  // trying to load the value from no.1 node
  cb_1.Reset();
  nodes_[0]->FindValue(key, false,
                        boost::bind(&FindCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  ASSERT_TRUE(cb_1.values().empty());
  ASSERT_EQ(1U, cb_1.signed_values().size());
  SignedValue el_valiu = cb_1.signed_values()[0];
  ASSERT_EQ(new_sig_value.SerializeAsString(), el_valiu.SerializeAsString());
}

*/
}  // namespace test_node

}  // namespace kademlia

}  // namespace maidsafe

