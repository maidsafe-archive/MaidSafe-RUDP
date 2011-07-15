/* Copyright (c) 2010 maidsafe.net limited
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
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <array>
#include <bitset>

#include "boost/lexical_cast.hpp"
#include "boost/thread/thread.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/thread/condition_variable.hpp"
#include "gmock/gmock.h"
#include "maidsafe/common/test.h"

#include "maidsafe/common/alternative_store.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/dht/log.h"
#include "maidsafe/dht/kademlia/config.h"
#include "maidsafe/dht/kademlia/contact.h"
#include "maidsafe/dht/kademlia/datastore.h"
#include "maidsafe/dht/kademlia/message_handler.h"
#include "maidsafe/dht/kademlia/node_id.h"
#include "maidsafe/dht/kademlia/node_impl.h"
#include "maidsafe/dht/kademlia/routing_table.h"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/dht/kademlia/rpcs.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "maidsafe/dht/kademlia/rpcs.h"
#include "maidsafe/dht/kademlia/securifier.h"
#include "maidsafe/dht/kademlia/service.h"
#include "maidsafe/dht/transport/tcp_transport.h"
#include "maidsafe/dht/transport/utils.h"
#include "maidsafe/dht/tests/kademlia/test_utils.h"
#include "maidsafe/dht/kademlia/node_container.h"

namespace arg = std::placeholders;
namespace bptime = boost::posix_time;

namespace maidsafe {
namespace dht {
namespace kademlia {
namespace test {

namespace {
const uint16_t kTestK = 4;
const uint16_t kAlpha = 3;
const uint16_t kBeta = 2;
const size_t kNumberOfNodes = 6;
const uint16_t kThreadGroupSize = 3;
const int kPending(9999999);

// returns true if node_id is included in node_ids and is within kTestK closest.
bool WithinKClosest(const NodeId &node_id,
                    const Key &target_key,
                    std::vector<NodeId> node_ids) {
  // Put the k closest first (and sorted) in the vector.
  std::function<bool(const NodeId&, const NodeId&)> predicate =                 // NOLINT (Fraser)
      std::bind(static_cast<bool(*)(const NodeId&, const NodeId&,               // NOLINT (Fraser)
                                    const NodeId&)>(&NodeId::CloserToTarget),
                arg::_1, arg::_2, target_key);
  std::partial_sort(node_ids.begin(), node_ids.begin() + kTestK, node_ids.end(),
                    predicate);
  return (std::find(node_ids.begin(), node_ids.begin() + kTestK + 1, node_id) !=
          node_ids.begin() + kTestK + 1);
}

}  // unnamed namespace


class TestNodeAlternativeStore : public AlternativeStore {
 public:
  ~TestNodeAlternativeStore() {}
  bool Has(const std::string&) const { return false; }
};

class NodeImplTest : public testing::Test {
 public:
//  void FindNodesFunction(int /*result*/,
//                         std::vector<Contact> contacts,
//                         std::vector<Contact>& k_closest) {
//    k_closest = contacts;
//    found_nodes_ = true;
//  }
//
//  void StoreValueFunction(int result) {
//    std::cout << "StoreValueFunction " << result << std::endl;
//    store_count_ = result;
//    stored_value_ = true;
//  }
//
//  void FindValueFunction(int /*result*/,
//                         std::vector<std::string> /*values*/,
//                         std::vector<Contact> /*k_closest*/,
//                         Contact /*store_contact*/,
//                         Contact /*cache_contact*/) {
//    found_value_ = true;
//  }
//
//  void DeleteFunction(int result) {
//    std::cout << "DeleteFunction " << result << std::endl;
//    delete_count_ = result;
//    deleted_value_ = true;
//  }
//
//  void GetContactFunction(int /*result*/, Contact /*contact*/) {
//    found_contact_ = true;
//  }

  bool ResultReady(int *result) { return *result != kPending; }

 protected:
  typedef std::shared_ptr<NodeContainer<Node::Impl>> NodeContainerPtr;
  typedef std::function<bool()> WaitFunctor;
  NodeImplTest() : node_containers_(),
                   node_ids_(),
//                   found_nodes_(false),
//                   stored_value_(false),
//                   found_value_(false),
//                   deleted_value_(false),
//                   found_contact_(false),
//                   store_count_(0),
//                   delete_count_(0),
                   mutex_(),
                   cond_var_(),
                   kTimeout_(bptime::seconds(10)),
                   join_result_(kPending),
                   store_result_(kPending),
                   delete_result_(kPending),
                   update_result_(kPending),
                   find_nodes_result_(kPending),
                   get_contact_result_(kPending),
                   find_value_returns_(),
                   find_nodes_closest_nodes_(),
                   gotten_contact_(),
                   wait_for_join_functor_(),
                   wait_for_store_functor_(),
                   wait_for_delete_functor_(),
                   wait_for_update_functor_(),
                   wait_for_find_value_functor_(),
                   wait_for_find_nodes_functor_(),
                   wait_for_get_contact_functor_() {
    wait_for_join_functor_ = std::bind(&NodeImplTest::ResultReady, this,
                                       &join_result_);
    wait_for_store_functor_ = std::bind(&NodeImplTest::ResultReady, this,
                                        &store_result_);
    wait_for_delete_functor_ = std::bind(&NodeImplTest::ResultReady, this,
                                         &delete_result_);
    wait_for_update_functor_ = std::bind(&NodeImplTest::ResultReady, this,
                                         &update_result_);
    wait_for_find_value_functor_ = std::bind(&NodeImplTest::ResultReady, this,
                                             &find_value_returns_.return_code);
    wait_for_find_nodes_functor_ = std::bind(&NodeImplTest::ResultReady, this,
                                             &find_nodes_result_);
    wait_for_get_contact_functor_ = std::bind(&NodeImplTest::ResultReady, this,
                                              &get_contact_result_);
  }

  void SetUp() {
    std::vector<Contact> bootstrap_contacts;
    for (size_t i = 0; i != kNumberOfNodes; ++i) {
      NodeContainerPtr node_container(new NodeContainer<Node::Impl>());
      node_container->Init(kThreadGroupSize, SecurifierPtr(),
          AlternativeStorePtr(new TestNodeAlternativeStore), false, kTestK,
          kAlpha, kBeta, bptime::seconds(30));
      node_container->MakeJoinFunctor(&mutex_, &cond_var_, &join_result_);
      node_container->MakeStoreFunctor(&mutex_, &cond_var_, &store_result_);
      node_container->MakeDeleteFunctor(&mutex_, &cond_var_, &delete_result_);
      node_container->MakeUpdateFunctor(&mutex_, &cond_var_, &update_result_);
      node_container->MakeFindValueFunctor(&mutex_, &cond_var_,
                                           &find_value_returns_);
      node_container->MakeFindNodesFunctor(&mutex_, &cond_var_,
                                           &find_nodes_result_,
                                           &find_nodes_closest_nodes_);
      node_container->MakeGetContactFunctor(&mutex_, &cond_var_,
                                            &get_contact_result_,
                                            &gotten_contact_);

      int attempts(0), max_attempts(5), result(0);
      Port port(static_cast<Port>((RandomUint32() % 55535) + 10000));
      while ((result = node_container->Start(bootstrap_contacts, port)) < 0 &&
             (attempts != max_attempts)) {
        port = static_cast<Port>((RandomUint32() % 55535) + 10000);
        ++attempts;
      }
      ASSERT_EQ(0, result);
      ASSERT_TRUE(node_container->node()->joined());
      DLOG(INFO) << "Node " << i << " joined: " << DebugId(*node_container);
      bootstrap_contacts.push_back(node_container->node()->contact());
      node_containers_.push_back(node_container);
      node_ids_.push_back(node_container->node()->contact().node_id());
    }
    DLOG(INFO) << "----------------------------------------------";
    DLOG(INFO) << "----------------------------------------------";
  }

  void TearDown() {
    for (std::size_t i = kNumberOfNodes - 1; i != -1; --i)
      node_containers_[i]->Stop(NULL);
  }

  std::shared_ptr<DataStore> GetDataStore(
      std::shared_ptr<NodeContainer<Node::Impl>> node_container) {
    return node_container->node()->data_store_;
  }


  std::vector<std::shared_ptr<NodeContainer<Node::Impl>>> node_containers_;  // NOLINT (Fraser)
  std::vector<NodeId> node_ids_;
//  bool found_nodes_, stored_value_, found_value_, deleted_value_,
//       found_contact_;
//  int store_count_, delete_count_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  const bptime::time_duration kTimeout_;
  int join_result_, store_result_, delete_result_, update_result_,
      find_nodes_result_, get_contact_result_;
  FindValueReturns find_value_returns_;
  std::vector<Contact> find_nodes_closest_nodes_;
  Contact gotten_contact_;
  WaitFunctor wait_for_join_functor_;
  WaitFunctor wait_for_store_functor_;
  WaitFunctor wait_for_delete_functor_;
  WaitFunctor wait_for_update_functor_;
  WaitFunctor wait_for_find_value_functor_;
  WaitFunctor wait_for_find_nodes_functor_;
  WaitFunctor wait_for_get_contact_functor_;
};


TEST_F(NodeImplTest, BEH_KAD_FindNodes) {
  for (std::size_t i = 0; i != kNumberOfNodes; ++i) {
    find_nodes_result_ = kPending;
    NodeId node_id(node_containers_[i]->node()->contact().node_id());
    {
      boost::mutex::scoped_lock lock(mutex_);
      node_containers_[i]->FindNodes(node_id);
      ASSERT_TRUE(cond_var_.timed_wait(lock, kTimeout_,
                                       wait_for_find_nodes_functor_));
    }
    SortContacts(node_id, &find_nodes_closest_nodes_);
    for (std::size_t j = 1; j != kTestK; ++j) {
      ASSERT_TRUE(CloserToTarget(find_nodes_closest_nodes_[j-1],
                                 find_nodes_closest_nodes_[j], node_id));
    }
  }
  find_nodes_closest_nodes_.clear();
  NodeId node_id(NodeId::kRandomId);
  for (std::size_t i = 0; i != kNumberOfNodes; ++i) {
    find_nodes_result_ = kPending;
    {
      boost::mutex::scoped_lock lock(mutex_);
      node_containers_[i]->FindNodes(node_id);
      ASSERT_TRUE(cond_var_.timed_wait(lock, kTimeout_,
                                       wait_for_find_nodes_functor_));
    }
    SortContacts(node_id, &find_nodes_closest_nodes_);
    for (std::size_t j = 1; j != kTestK; ++j) {
      ASSERT_TRUE(CloserToTarget(find_nodes_closest_nodes_[j-1],
                                 find_nodes_closest_nodes_[j], node_id));
    }
  }
}

TEST_F(NodeImplTest, BEH_KAD_Store) {
  Key key(NodeId::kRandomId);
  std::string value = RandomString(RandomUint32() % 1024);
  bptime::time_duration duration(bptime::minutes(1));
  size_t test_node_index(RandomUint32() % node_containers_.size());
  DLOG(INFO) << "Node " << test_node_index << " - "
             << DebugId(*node_containers_[test_node_index])
             << " performing store operation.";
  {
    boost::mutex::scoped_lock lock(mutex_);
    node_containers_[test_node_index]->Store(key, value, "", duration,
                                             SecurifierPtr());
    ASSERT_TRUE(cond_var_.timed_wait(lock, kTimeout_, wait_for_store_functor_));
  }
  EXPECT_EQ(0, store_result_);

//  Sleep(bptime::milliseconds(1000));

  for (size_t i = 0; i != kNumberOfNodes; ++i) {
    if (WithinKClosest(node_containers_[i]->node()->contact().node_id(), key,
                       node_ids_)) {
//        std::cout << DebugId(*node_containers_[i]) << ": ";
      EXPECT_TRUE(GetDataStore(node_containers_[i])->HasKey(key.String()));
    } else {
      EXPECT_FALSE(GetDataStore(node_containers_[i])->HasKey(key.String()));
    }
  }
}

TEST_F(NodeImplTest, BEH_KAD_FindValue) {
  Key key(NodeId::kRandomId);
  std::string value = RandomString(RandomUint32() % 1024);
  bptime::time_duration duration(bptime::minutes(1));
  size_t test_node_index(RandomUint32() % node_containers_.size());
  {
    boost::mutex::scoped_lock lock(mutex_);
    node_containers_[test_node_index]->Store(key, value, "", duration,
                                             SecurifierPtr());
    ASSERT_TRUE(cond_var_.timed_wait(lock, kTimeout_, wait_for_store_functor_));
  }

//  Sleep(bptime::milliseconds(1000));

  // Get a node which hasn't stored the value
  size_t not_got_value(0);
  for (size_t i = 0; i != kNumberOfNodes; ++i) {
    if (!WithinKClosest(node_containers_[i]->node()->contact().node_id(), key,
                        node_ids_)) {
      not_got_value = i;
      break;
    }
  }

  for (size_t i = 0; i != kTestK; ++i) {
    {
      boost::mutex::scoped_lock lock(mutex_);
      node_containers_[not_got_value]->FindValue(key, SecurifierPtr());
      ASSERT_TRUE(cond_var_.timed_wait(lock, kTimeout_,
                                       wait_for_find_value_functor_));
    }
    EXPECT_EQ(0, find_value_returns_.return_code);
    ASSERT_FALSE(find_value_returns_.values.empty());
    EXPECT_EQ(value, find_value_returns_.values.front());
    // TODO(Fraser#5#): 2011-07-14 - Handle other return fields

    // Stop nodes holding value one at a time and retry getting value
    for (size_t j = 0; j != kNumberOfNodes; ++j) {
      if (WithinKClosest(node_containers_[j]->node()->contact().node_id(), key,
                         node_ids_) &&
          node_containers_[j]->node()->joined()) {
        node_containers_[j]->Stop(NULL);
        break;
      }
    }
  }
  {
    boost::mutex::scoped_lock lock(mutex_);
    node_containers_[not_got_value]->FindValue(key, SecurifierPtr());
    ASSERT_TRUE(cond_var_.timed_wait(lock, kTimeout_,
                                      wait_for_find_value_functor_));
  }
  EXPECT_EQ(-1, find_value_returns_.return_code);
  EXPECT_TRUE(find_value_returns_.values.empty());
  // TODO(Fraser#5#): 2011-07-14 - Handle other return fields

}

//TEST_F(NodeImplTest, BEH_KAD_Ping) {
//  
//}
//
//TEST_F(NodeImplTest, BEH_KAD_Delete) {
//  std::function<void(int)> store_value = std::bind(
//      &NodeImplTest::StoreValueFunction, this, arg::_1);
//  std::function<void(int)> delete_value = std::bind(
//      &NodeImplTest::DeleteFunction, this, arg::_1);
//  maidsafe::crypto::RsaKeyPair rsa_key_pair;
//  bptime::time_duration duration(bptime::seconds(30));
// 
//  std::size_t size = RandomUint32() % 1024;
//  std::string value = RandomString(size);
//  rsa_key_pair.GenerateKeys(4096);
//  std::shared_ptr<Securifier> securifier;
//  NodeId node_id(NodeId::kRandomId);
//  std::vector<NodeId> nodeids(node_ids_);
//  SortIds(node_id, &nodeids);
//  std::size_t i = 0;
//  for (; i != kNumberOfNodes; ++i)
//    if (node_containers_[i]->node()->contact().node_id() == nodeids.back())
//      break;
//  node_containers_[i]->node()->Store(node_id, value, "", duration, securifier, store_value);
//  while (!stored_value_)
//    Sleep(bptime::milliseconds(100));
//  stored_value_ = false;
//  node_containers_[i]->node()->Delete(node_id, value, "", securifier, delete_value);
//  while (!deleted_value_)
//    Sleep(bptime::milliseconds(100));
//  deleted_value_ = false;
//  ASSERT_EQ(store_count_, delete_count_);
//}
//
//TEST_F(NodeImplTest, BEH_KAD_StoreRefresh) {
//  std::function<void(int)> store_value = std::bind(
//      &NodeImplTest::StoreValueFunction, this, arg::_1);
//  maidsafe::crypto::RsaKeyPair rsa_key_pair;
//  bptime::seconds duration(-1);
//  std::size_t size = RandomUint32() % 1024;
//  std::string value = RandomString(size);
//  rsa_key_pair.GenerateKeys(4096);
//  std::shared_ptr<Securifier> securifier;
//  NodeId node_id(NodeId::kRandomId);
//  std::vector<NodeId> nodeids(node_ids_);
//  SortIds(node_id, &nodeids);
//  std::size_t i = 0;
//  for (; i != kNumberOfNodes; ++i)
//    if (node_containers_[i]->node()->contact().node_id() == nodeids.back())
//      break;
//  // Store the value via node_containers_[i]->node()...
//  node_containers_[i]->node()->Store(node_id, value, "", duration, securifier, store_value);
//  while (!stored_value_)
//    Sleep(bptime::milliseconds(100));
//  stored_value_ = false;
//  
//  size = RandomUint32() % (kTestK - 1);
//  std::size_t count = kNumberOfNodes + 1;
//  std::array<std::size_t, kTestK+1> nodevals1, nodevals2; 
//  // Ensure k closest hold the value and tag the one to leave...
//  for (size_t i = 0; i != kTestK; ++i) {
//    for (size_t j = 0; j != kNumberOfNodes; ++j) {
//      if (node_containers_[j]->node()->contact().node_id() == nodeids[i]) {
//        if (i == size)
//          count = j;
//        ASSERT_TRUE(node_containers_[j]->node()->data_store_->HasKey(node_id.String()));
//        nodevals1[i] = j;
//        break;
//      }
//    }
//  }
//  // Let tagged node leave...
//  ASSERT_NE(count, kNumberOfNodes + 1); 
//  std::vector<Contact> bootstrap_contacts;
//  node_containers_[count]->node()->Leave(&bootstrap_contacts);
//  // Having set refresh time to 30 seconds, wait for 60 seconds...
//  Sleep(bptime::seconds(60)); 
//  // The kTestK element of nodeids should now hold the value if a refresh
//  // has occurred...
//  /*for (size_t j = 0; j != kNumberOfNodes; ++j) {
//    if (node_containers_[j]->node()->contact().node_id() == nodeids[kTestK]) {
//      ASSERT_TRUE(node_containers_[j]->node()->data_store_->HasKey(node_id.String()));
//      break;
//    }
//  }*/
//  for (size_t i = 0, j = 0; j != kNumberOfNodes; ++j) {
//    if (node_containers_[j]->node()->data_store_->HasKey(node_id.String())) {
//      nodevals2[i] = j;
//      ++i;
//    }
//  }
//  //for (size_t i = 0; i != kTestK; ++i) {
//  //  for (size_t j = 0; j != kNumberOfNodes; ++j) {
//  //    //if (j == count)
//  //    //  continue;
//  //    if (node_containers_[j]->node()->contact().node_id() == nodeids[i]) {
//  //      ASSERT_TRUE(node_containers_[j]->node()->data_store_->HasKey(node_id.String()));
//  //      nodevals2[i] = j;
//  //      break;
//  //    }
//  //  }
//  //}
//  ASSERT_NE(nodevals1, nodevals2);
//}
//
//TEST_F(NodeImplTest, BEH_KAD_DeleteRefresh) {
//  std::function<void(int)> store_value = std::bind(
//      &NodeImplTest::StoreValueFunction, this, arg::_1);
//  std::function<void(int)> delete_value = std::bind(
//      &NodeImplTest::DeleteFunction, this, arg::_1);
//  maidsafe::crypto::RsaKeyPair rsa_key_pair;
//  bptime::seconds duration(-1);
//  std::size_t size = RandomUint32() % 1024;
//  std::string value = RandomString(size);
//  rsa_key_pair.GenerateKeys(4096);
//  std::shared_ptr<Securifier> securifier;
//  NodeId node_id(NodeId::kRandomId);
//  std::vector<NodeId> nodeids(node_ids_);
//  SortIds(node_id, &nodeids);
//  std::size_t i = 0, storing_node;
//  for (; i != kNumberOfNodes; ++i)
//    if (node_containers_[i]->node()->contact().node_id() == nodeids.back())
//      break;
//  // Store the value via node_containers_[i]->node()...
//  storing_node = i;
//  node_containers_[storing_node]->node()->Store(node_id, value, "", duration,
//                                                securifier, store_value);
//  while (!stored_value_)
//    Sleep(bptime::milliseconds(100));
//  stored_value_ = false;
//  
//  size = RandomUint32() % (kTestK - 1);
//  std::size_t leave_node = kNumberOfNodes + 1;
//  std::array<std::size_t, kTestK+1> nodevals1;
//  // Ensure k closest hold the value and tag the one to leave...
//  for (size_t i = 0; i != kTestK; ++i) {
//    for (size_t j = 0; j != kNumberOfNodes; ++j) {
//      if (node_containers_[j]->node()->contact().node_id() == nodeids[i]) {
//        if (i == size)
//          leave_node = j;
//        ASSERT_TRUE(node_containers_[j]->node()->data_store_->HasKey(node_id.String()))
//          << node_containers_[j]->node()->
//             contact().node_id().ToStringEncoded(NodeId::kHex).substr(0, 8);
//        nodevals1[i] = j;
//        break;
//      }
//    }
//  }
//  // Let tagged node leave...
//  ASSERT_NE(leave_node, kNumberOfNodes + 1); 
//  std::vector<Contact> bootstrap_contacts;
//  node_containers_[leave_node]->node()->Leave(&bootstrap_contacts);
//  // Delete the value...
//  node_containers_[storing_node]->node()->Delete(node_id, value, "", securifier,
//                                                 delete_value);
//  // Ensure no currently joined node claims to have the value...
//  std::vector<std::pair<std::string, std::string>> values;
//  for (size_t i = 0; i != kNumberOfNodes; ++i) {
//    if (i != leave_node) {
//      ASSERT_FALSE(GetDataStore(node_containers_[i])->GetValues(
//          node_id.String(), &values));
//    }
//  }
//  // Ensure no currently joined node has the value...
////  for (size_t j = 0; j != kNumberOfNodes; ++j)
////    if (j != leave_node)
////      ASSERT_FALSE(node_containers_[j]->node()->data_store_->HasKey(node_id.String()));
//  // Allow node to rejoin the network...
//  int join_result(kPending);
//  std::function<bool()> wait_functor =
//      std::bind(&NodeImplTest::ResultReady, this, &join_result);
//  std::vector<Contact> contacts;
//  for (size_t j = 0; j != kNumberOfNodes; ++j) {
//    if (node_containers_[leave_node]->node()->contact().node_id() ==
//        nodeids[i]) {
//      join_result = kPending;
//      node_containers_[leave_node]->node()->GetBootstrapContacts(&contacts);
//      JoinFunctor join_functor = node_containers_[leave_node]->MakeJoinFunctor(
//          &mutex_, &cond_var_, &join_result);
//      {
//        boost::mutex::scoped_lock lock(mutex_);
//        node_containers_[leave_node]->node()->Join(node_ids_[i], contacts,
//                                                   join_functor);
//        ASSERT_TRUE(cond_var_.timed_wait(lock, kTimeout_, wait_functor));
//      }
//      ASSERT_EQ(transport::kSuccess, join_result);
//      ASSERT_TRUE(node_containers_[leave_node]->node()->joined());
//      break;
//    }
//  }
//  // Sleep for a while...
//  Sleep(bptime::seconds(360));
//  // Now make sure the value has been deleted from all nodes in network...
//  for (size_t j = 0; j != kNumberOfNodes; ++j) {
//    ASSERT_FALSE(GetDataStore(node_containers_[j])->HasKey(node_id.String()));
//  }
//}
//
//TEST_F(NodeImplTest, BEH_KAD_Downlist) {
//  FAIL();
//}

}  // namespace test
}  // namespace kademlia
}  // namespace dht
}  // namespace maidsafe
