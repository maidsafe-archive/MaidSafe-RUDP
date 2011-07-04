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
#include <exception>
#include <functional>
#include <list>
#include <set>
#include <vector>

#include "boost/asio.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/lexical_cast.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/dht/tests/functional_kademlia/test_node_environment.h"
#include "maidsafe/dht/tests/kademlia/test_utils.h"

namespace arg = std::placeholders;

namespace maidsafe {

namespace dht {

namespace kademlia {

namespace node_api_test {
const uint16_t kThreadGroupSize = 3;
}   // namespace node_api_test

namespace test {

extern uint16_t kK_;
extern std::vector<std::shared_ptr<Node>> nodes_;
extern std::vector<NodeId> node_ids_;
extern uint16_t kNetworkSize;
extern std::vector<Contact> bootstrap_contacts_;
extern std::vector<crypto::RsaKeyPair> crypto_key_pairs_;
std::vector<bool> dones;

class NodeApiTest: public testing::Test {
 protected:
  NodeApiTest()
      : rsa_key_pair_(),
        asio_service_(),
        work_(),
        thread_group_(),
        securifier_(),
        transport_(),
        message_handler_(),
        alternative_store_() {}

  void SetUp() {
    rsa_key_pair_.GenerateKeys(4096);
    work_.reset(new boost::asio::io_service::work(asio_service_));
    thread_group_.reset(new boost::thread_group());
    for (size_t i = 0; i < node_api_test::kThreadGroupSize; ++i)
      thread_group_->create_thread(std::bind(&boost::asio::io_service::run,
                                             &asio_service_));
    transport_.reset(new transport::TcpTransport(asio_service_));

    securifier_.reset(new Securifier("any_id",
                                     rsa_key_pair_.public_key(),
                                     rsa_key_pair_.private_key()));
    message_handler_.reset(new MessageHandler(securifier_));
  }

  void TearDown() {
    work_.reset();
    asio_service_.stop();
    thread_group_->join_all();
    thread_group_.reset();
  }

  crypto::RsaKeyPair rsa_key_pair_;
  AsioService asio_service_;
  WorkPtr work_;
  ThreadGroupPtr thread_group_;
  SecurifierPtr securifier_;
  TransportPtr transport_;
  MessageHandlerPtr message_handler_;
  AlternativeStorePtr alternative_store_;

 public:
  void Callback(const int &result, bool *done) {
    *done = true;
    EXPECT_LE(static_cast<int>(0), result);
  }

  void StoreCallback(const int &result, bool *done, boost::mutex *m) {
    boost::mutex::scoped_lock loch_lomond(*m);
    Callback(result, done);
    dones.push_back(*done);
  }

  void FindNodesCallback(const int &result,
                         std::vector<Contact> contacts,
                         const int &node_id_pos,
                         bool *done) {
    EXPECT_EQ(result, contacts.size());
    EXPECT_EQ(kK_, contacts.size());
    size_t i(0);
    bool own_contact_found(false);
    for (i = 0; i < contacts.size(); ++i) {
      auto it = std::find(node_ids_.begin(), node_ids_.end(),
                          contacts[i].node_id());
      if (node_ids_[node_id_pos] == contacts[i].node_id())
        own_contact_found = true;
      if (it == node_ids_.end())
        break;
    }
    EXPECT_EQ(i, contacts.size());
    EXPECT_TRUE(own_contact_found);
    *done = true;
  }

  void FindValueCallback(int result, std::vector<std::string> values,
                         std::vector<Contact> closest_contacts,
                         Contact alternative_value_holder,
                         Contact contact_to_cache,
                         bool *done, bool check_pass, boost::mutex *m) {
    boost::mutex::scoped_lock loch_lomond(*m);
    *done = true;
    dones.push_back(done);
    if (!check_pass) {
      EXPECT_EQ(static_cast<int>(-2), result);
      return;
    }
    EXPECT_LE(static_cast<int>(0), result);
    auto it = std::find(node_ids_.begin(), node_ids_.end(),
                          alternative_value_holder.node_id());
    if (result < 0) {
      if (it == node_ids_.end()) {
        EXPECT_EQ(size_t(0), values.size());
        EXPECT_GE(kK_, closest_contacts.size());
      } else {
        EXPECT_EQ(size_t(0), values.size());
        EXPECT_EQ(size_t(0), closest_contacts.size());
      }
    } else {
      EXPECT_EQ(it, node_ids_.end());
      EXPECT_LT(size_t(0), values.size());
    }
  }
};

TEST_F(NodeApiTest, BEH_KAD_Join_Client) {
  std::shared_ptr<Node> node;
  node.reset(new Node(asio_service_, transport_, message_handler_, securifier_,
                      alternative_store_, true, kK_, 3, 2,
                      bptime::seconds(3600)));
  NodeId node_id(NodeId::kRandomId);
  bool done(false);
  JoinFunctor jf = std::bind(&NodeApiTest::Callback, this, arg::_1, &done);
  node->Join(node_id, bootstrap_contacts_, jf);

  while (!done)
    Sleep(boost::posix_time::milliseconds(100));
  EXPECT_EQ(size_t(kNetworkSize), nodes_.size());
  ASSERT_TRUE(node->client_only_node());
  ASSERT_TRUE(node->joined());
  node->Leave(NULL);
}

TEST_F(NodeApiTest, BEH_KAD_Join_Server) {
  std::shared_ptr<Node> node;
  EXPECT_EQ(transport::kSuccess,
              transport_->StartListening(transport::Endpoint("127.0.0.1",
                                                             8000)));
  node.reset(new Node(asio_service_, transport_, message_handler_, securifier_,
                      alternative_store_, false, kK_, 3, 2,
                      bptime::seconds(3600)));
  NodeId node_id(NodeId::kRandomId);
  bool done(false);
  JoinFunctor jf = std::bind(&NodeApiTest::Callback, this, arg::_1, &done);
  node->Join(node_id, bootstrap_contacts_, jf);

  while (!done)
    Sleep(boost::posix_time::milliseconds(100));

  EXPECT_EQ(size_t(kNetworkSize), nodes_.size());

  ASSERT_FALSE(node->client_only_node());
  ASSERT_TRUE(node->joined());
  node->Leave(NULL);
}

TEST_F(NodeApiTest, BEH_KAD_Find_Nodes) {
  std::shared_ptr<Node> node;
  node.reset(new Node(asio_service_, transport_, message_handler_, securifier_,
                      alternative_store_, true, kK_, 3, 2,
                      bptime::seconds(3600)));
  NodeId node_id(NodeId::kRandomId);
  bool done(false);
  JoinFunctor jf = std::bind(&NodeApiTest::Callback, this, arg::_1, &done);
  node->Join(node_id, bootstrap_contacts_, jf);
  while (!done)
    Sleep(boost::posix_time::milliseconds(100));
  EXPECT_TRUE(node->joined());
  done = false;
  //  set node_id_pos for node to be searched and latter check for this node
  //  into list of output contacts
  int node_id_pos(0);
  FindNodesFunctor fnf = std::bind(&NodeApiTest::FindNodesCallback, this,
                                   arg::_1, arg::_2, node_id_pos, &done);
  node->FindNodes(nodes_[node_id_pos]->contact().node_id(), fnf);
  while (!done)
    Sleep(boost::posix_time::milliseconds(100));
  node->Leave(NULL);
}

TEST_F(NodeApiTest, BEH_KAD_Store) {
  std::shared_ptr<Node> node;
  node.reset(new Node(asio_service_, transport_, message_handler_, securifier_,
                      alternative_store_, true, kK_, 3, 2,
                      bptime::seconds(3600)));
  NodeId node_id(NodeId::kRandomId);
  bool done(false);
  JoinFunctor jf = std::bind(&NodeApiTest::Callback, this, arg::_1, &done);
  node->Join(node_id, bootstrap_contacts_, jf);
  while (!done)
    Sleep(boost::posix_time::milliseconds(100));
  EXPECT_TRUE(node->joined());
  done = false;
  boost::mutex m;
  int num_store_values(10);
  std::vector<KeyValueSignature> key_value_signatures;
  bptime::time_duration ttl(bptime::pos_infin);
  for (int i = 0; i < num_store_values; ++i) {
    KeyValueSignature key_value_signature = MakeKVS(rsa_key_pair_,
                                                    1111 + i, "", "");
    key_value_signatures.push_back(key_value_signature);
  }
  std::vector<StoreFunctor> sfs;
  for (size_t i = 0; i < key_value_signatures.size(); ++i) {
    done = false;
    StoreFunctor sf = std::bind(&NodeApiTest::StoreCallback, this, arg::_1,
                                &done, &m);
    sfs.push_back(sf);
    node->Store(NodeId(key_value_signatures[i].key),
                key_value_signatures[i].value,
                key_value_signatures[i].signature,
                ttl, securifier_, sfs[i]);
  }
  while (dones.size() != sfs.size())
    Sleep(boost::posix_time::milliseconds(100));

  for (size_t i = 0; i < dones.size(); ++i)
    EXPECT_TRUE(dones[i]);
  node->Leave(NULL);
  dones.clear();
}

TEST_F(NodeApiTest, BEH_KAD_Find_Value) {
  std::shared_ptr<Node> node;
  node.reset(new Node(asio_service_, transport_, message_handler_, securifier_,
                      alternative_store_, true, kK_, 3, 2,
                      bptime::seconds(3600)));
  NodeId node_id(NodeId::kRandomId);
  bool done(false);
  JoinFunctor jf = std::bind(&NodeApiTest::Callback, this, arg::_1, &done);
  node->Join(node_id, bootstrap_contacts_, jf);
  while (!done)
    Sleep(boost::posix_time::milliseconds(100));
  EXPECT_TRUE(node->joined());
  done = false;
  boost::mutex m;
  int num_store_values(10);
  std::vector<KeyValueSignature> key_value_signatures;
  bptime::time_duration ttl(bptime::pos_infin);
  for (int i = 0; i < num_store_values; ++i) {
    KeyValueSignature key_value_signature = MakeKVS(rsa_key_pair_,
                                                    1111 + i, "", "");
    key_value_signatures.push_back(key_value_signature);
  }
  std::vector<StoreFunctor> sfs;
  for (size_t i = 0; i < key_value_signatures.size(); ++i) {
    done = false;
    StoreFunctor sf = std::bind(&NodeApiTest::StoreCallback, this, arg::_1,
                                &done, &m);
    sfs.push_back(sf);
    node->Store(NodeId(key_value_signatures[i].key),
                key_value_signatures[i].value,
                key_value_signatures[i].signature,
                ttl, securifier_, sfs[i]);
  }
  while (dones.size() != sfs.size())
    Sleep(boost::posix_time::milliseconds(100));

  for (size_t i = 0; i < dones.size(); ++i)
    EXPECT_TRUE(dones[i]);
  dones.clear();
  done = false;
  std::vector<FindValueFunctor> fvfs;
  bool check_pass(true);
  for (size_t i = 0; i < key_value_signatures.size(); ++i) {
    FindValueFunctor fvf = std::bind(&NodeApiTest::FindValueCallback, this,
                                     arg::_1, arg::_2, arg::_3, arg::_4,
                                     arg::_5, &done, check_pass, &m);
    fvfs.push_back(fvf);
    node->FindValue(NodeId(key_value_signatures[0].key), securifier_, fvf);
  }
  while (dones.size() != fvfs.size())
    Sleep(boost::posix_time::milliseconds(100));

  for (size_t i = 0; i < dones.size(); ++i)
    EXPECT_TRUE(dones[i]);

  node->Leave(NULL);
  dones.clear();
}

TEST_F(NodeApiTest, BEH_KAD_Delete) {
  std::shared_ptr<Node> node;
  node.reset(new Node(asio_service_, transport_, message_handler_, securifier_,
                      alternative_store_, true, kK_, 3, 2,
                      bptime::seconds(3600)));
  NodeId node_id(NodeId::kRandomId);
  bool done(false);
  JoinFunctor jf = std::bind(&NodeApiTest::Callback, this, arg::_1, &done);
  node->Join(node_id, bootstrap_contacts_, jf);
  while (!done)
    Sleep(boost::posix_time::milliseconds(100));
  EXPECT_TRUE(node->joined());
  done = false;
  boost::mutex m;
  int num_store_values(10);
  std::vector<KeyValueSignature> key_value_signatures;
  bptime::time_duration ttl(bptime::pos_infin);
  for (int i = 0; i < num_store_values; ++i) {
    KeyValueSignature key_value_signature = MakeKVS(rsa_key_pair_,
                                                    1111 + i, "", "");
    key_value_signatures.push_back(key_value_signature);
  }
  std::vector<StoreFunctor> sfs;
  for (size_t i = 0; i < key_value_signatures.size(); ++i) {
    done = false;
    StoreFunctor sf = std::bind(&NodeApiTest::StoreCallback, this, arg::_1,
                                &done, &m);
    sfs.push_back(sf);
    node->Store(NodeId(key_value_signatures[i].key),
                key_value_signatures[i].value,
                key_value_signatures[i].signature,
                ttl, securifier_, sfs[i]);
  }
  while (dones.size() != sfs.size())
    Sleep(boost::posix_time::milliseconds(100));

  for (size_t i = 0; i < dones.size(); ++i)
    EXPECT_TRUE(dones[i]);
  done = false;
  DeleteFunctor df = std::bind(&NodeApiTest::Callback, this, arg::_1, &done);

  node->Delete(NodeId(key_value_signatures[0].key),
               key_value_signatures[0].value,
               key_value_signatures[0].signature,
               securifier_, df);
  while (!done)
    Sleep(boost::posix_time::milliseconds(100));
  node->Leave(NULL);
  dones.clear();
}

TEST_F(NodeApiTest, BEH_KAD_Alternate_API_Calls) {
  std::shared_ptr<Node> node;
  node.reset(new Node(asio_service_, transport_, message_handler_, securifier_,
                      alternative_store_, true, kK_, 3, 2,
                      bptime::seconds(3600)));
  NodeId node_id(NodeId::kRandomId);
  bool done(false);
  JoinFunctor jf = std::bind(&NodeApiTest::Callback, this, arg::_1, &done);
  node->Join(node_id, bootstrap_contacts_, jf);
  while (!done)
    Sleep(boost::posix_time::milliseconds(100));
  EXPECT_TRUE(node->joined());

  int num_store_values(10);
  std::vector<KeyValueSignature> key_value_signatures;
  bptime::time_duration ttl(bptime::pos_infin);
  for (int i = 0; i < num_store_values; ++i) {
    KeyValueSignature key_value_signature = MakeKVS(rsa_key_pair_,
                                                    1111 + i, "", "");
    key_value_signatures.push_back(key_value_signature);
  }
  done = false;
  boost::mutex m;
  //  Call FindValue when no value exist
  {
    bool check_pass(false);
    std::vector<FindValueFunctor> fvfs;
    for (size_t i = 0; i < key_value_signatures.size(); ++i) {
      FindValueFunctor fvf = std::bind(&NodeApiTest::FindValueCallback, this,
                                       arg::_1, arg::_2, arg::_3, arg::_4,
                                       arg::_5, &done, check_pass, &m);
      fvfs.push_back(fvf);
      node->FindValue(NodeId(key_value_signatures[0].key), securifier_, fvf);
    }
    while (dones.size() != fvfs.size())
    Sleep(boost::posix_time::milliseconds(100));

    for (size_t i = 0; i < dones.size(); ++i)
      EXPECT_TRUE(dones[i]);
    dones.clear();
  }

  std::vector<StoreFunctor> sfs;
  for (size_t i = 0; i < key_value_signatures.size(); ++i) {
    done = false;
    StoreFunctor sf = std::bind(&NodeApiTest::StoreCallback, this, arg::_1,
                                &done, &m);
    sfs.push_back(sf);
    node->Store(NodeId(key_value_signatures[i].key),
                key_value_signatures[i].value,
                key_value_signatures[i].signature,
                ttl, securifier_, sfs[i]);
  }
  while (dones.size() != sfs.size())
    Sleep(boost::posix_time::milliseconds(100));
  for (size_t i = 0; i < dones.size(); ++i)
      EXPECT_TRUE(dones[i]);
  dones.clear();
  //  Call FindValue when value exist
  {
    done = false;
    bool check_pass(true);
    std::vector<FindValueFunctor> fvfs;
    for (size_t i = 0; i < key_value_signatures.size(); ++i) {
      FindValueFunctor fvf = std::bind(&NodeApiTest::FindValueCallback, this,
                                       arg::_1, arg::_2, arg::_3, arg::_4,
                                       arg::_5, &done, check_pass, &m);
      fvfs.push_back(fvf);
      node->FindValue(NodeId(key_value_signatures[0].key), securifier_, fvf);
    }
    while (dones.size() != fvfs.size())
    Sleep(boost::posix_time::milliseconds(100));

    for (size_t i = 0; i < dones.size(); ++i)
      EXPECT_TRUE(dones[i]);
    dones.clear();
  }

  done = false;
  DeleteFunctor df = std::bind(&NodeApiTest::Callback, this, arg::_1, &done);

  node->Delete(NodeId(key_value_signatures[0].key),
               key_value_signatures[0].value,
               key_value_signatures[0].signature,
               securifier_, df);
  while (!done)
    Sleep(boost::posix_time::milliseconds(100));

  //  Call FindValue when value deleted
  {
    done = false;
    bool check_pass(false);
    FindValueFunctor fvf = std::bind(&NodeApiTest::FindValueCallback, this,
                                       arg::_1, arg::_2, arg::_3, arg::_4,
                                       arg::_5, &done, check_pass, &m);
    node->FindValue(NodeId(key_value_signatures[0].key), securifier_, fvf);
    while (!done)
      Sleep(boost::posix_time::milliseconds(100));
  }
  node->Leave(NULL);
  dones.clear();
}

}  // namespace test

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe
