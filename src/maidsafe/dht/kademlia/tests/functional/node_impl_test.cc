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
#include "maidsafe/dht/kademlia/tests/test_utils.h"
#include "maidsafe/dht/kademlia/node_container.h"
#include "maidsafe/dht/kademlia/tests/functional/test_node_environment.h"

namespace arg = std::placeholders;
namespace bptime = boost::posix_time;

namespace maidsafe {
namespace dht {
namespace kademlia {
namespace test {

class NodeImplTest : public testing::Test {
 protected:
  NodeImplTest()
     : env_(NodesEnvironment<NodeImpl>::g_environment()) {}
  void SetUp() {}
  void TearDown() {}
  std::shared_ptr<DataStore> GetDataStore(
      std::shared_ptr<maidsafe::dht::kademlia::NodeContainer<NodeImpl>>
          node_container) {
    return node_container->node()->data_store_;
  }

  NodesEnvironment<NodeImpl>* env_;
};


TEST_F(NodeImplTest, BEH_KAD_FindNodes) {
  for (std::size_t i = 0; i != env_->num_full_nodes_; ++i) {
    env_->find_nodes_result_ = kPendingResult;
    NodeId node_id(env_->node_containers_[i]->node()->contact().node_id());
    {
      boost::mutex::scoped_lock lock(env_->mutex_);
      env_->node_containers_[i]->FindNodes(node_id);
      ASSERT_TRUE(env_->cond_var_.timed_wait(lock, env_->kTimeout_,
                  env_->wait_for_find_nodes_functor_));
    }
    SortContacts(node_id, &env_->find_nodes_closest_nodes_);
    for (std::size_t j = 1; j != env_->k_; ++j) {
      ASSERT_TRUE(CloserToTarget(env_->find_nodes_closest_nodes_[j-1],
                                 env_->find_nodes_closest_nodes_[j], node_id));
    }
  }
  env_->find_nodes_closest_nodes_.clear();
  NodeId node_id(NodeId::kRandomId);
  for (std::size_t i = 0; i != env_->num_full_nodes_; ++i) {
    env_->find_nodes_result_ = kPendingResult;
    {
      boost::mutex::scoped_lock lock(env_->mutex_);
      env_->node_containers_[i]->FindNodes(node_id);
      ASSERT_TRUE(env_->cond_var_.timed_wait(lock, env_->kTimeout_,
                  env_->wait_for_find_nodes_functor_));
    }
    SortContacts(node_id, &env_->find_nodes_closest_nodes_);
    for (std::size_t j = 1; j != env_->k_; ++j) {
      ASSERT_TRUE(CloserToTarget(env_->find_nodes_closest_nodes_[j-1],
                                 env_->find_nodes_closest_nodes_[j], node_id));
    }
  }
}

TEST_F(NodeImplTest, BEH_KAD_Store) {
  Key key(NodeId::kRandomId);
  std::string value = RandomString(RandomUint32() % 1024);
  bptime::time_duration duration(bptime::minutes(1));
  size_t test_node_index(RandomUint32() % env_->node_containers_.size());
  DLOG(INFO) << "Node " << test_node_index << " - "
             << DebugId(*env_->node_containers_[test_node_index])
             << " performing store operation.";
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    env_->node_containers_[test_node_index]->Store(key, value, "", duration,
                                                   SecurifierPtr());
    ASSERT_TRUE(env_->cond_var_.timed_wait(lock, env_->kTimeout_,
                                           env_->wait_for_store_functor_));
  }
  EXPECT_EQ(0, env_->store_result_);

//  Sleep(bptime::milliseconds(1000));

  for (size_t i = 0; i != env_->num_full_nodes_; ++i) {
    if (WithinKClosest(env_->node_containers_[i]->node()->contact().node_id(),
                       key, env_->node_ids_, env_->k_)) {
//        std::cout << DebugId(*node_containers_[i]) << ": ";
      EXPECT_TRUE(GetDataStore(env_->node_containers_[i])->
                  HasKey(key.String()));
    } else {
      EXPECT_FALSE(GetDataStore(env_->node_containers_[i])->
                   HasKey(key.String()));
    }
  }
}

TEST_F(NodeImplTest, BEH_KAD_FindValue) {
  Key key(NodeId::kRandomId);
  std::string value = RandomString(RandomUint32() % 1024);
  bptime::time_duration duration(bptime::minutes(1));
  size_t test_node_index(RandomUint32() % env_->node_containers_.size());
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    env_->node_containers_[test_node_index]->Store(key, value, "", duration,
                                                   SecurifierPtr());
    ASSERT_TRUE(env_->cond_var_.timed_wait(lock, env_->kTimeout_,
                                           env_->wait_for_store_functor_));
  }

//  Sleep(bptime::milliseconds(1000));

  // Get a node which hasn't stored the value
  size_t not_got_value(0);
  for (size_t i = 0; i != env_->num_full_nodes_; ++i) {
    if (!WithinKClosest(env_->node_containers_[i]->node()->contact().node_id(),
                        key, env_->node_ids_, env_->k_)) {
      not_got_value = i;
      break;
    }
  }

  for (size_t i = 0; i != env_->k_; ++i) {
    {
      boost::mutex::scoped_lock lock(env_->mutex_);
      env_->node_containers_[not_got_value]->FindValue(key, SecurifierPtr());
      ASSERT_TRUE(env_->cond_var_.timed_wait(lock, env_->kTimeout_,
                  env_->wait_for_find_value_functor_));
    }
    EXPECT_EQ(kSuccess, env_->find_value_returns_.return_code);
    ASSERT_FALSE(env_->find_value_returns_.values.empty());
    EXPECT_EQ(value, env_->find_value_returns_.values.front());
    // TODO(Fraser#5#): 2011-07-14 - Handle other return fields

    // Stop nodes holding value one at a time and retry getting value
    for (size_t j = 0; j != env_->num_full_nodes_; ++j) {
      if (WithinKClosest(env_->node_containers_[j]->node()->contact().node_id(),
                         key, env_->node_ids_, env_->k_) &&
          env_->node_containers_[j]->node()->joined()) {
        env_->node_containers_[j]->Stop(NULL);
        break;
      }
    }
  }
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    env_->node_containers_[not_got_value]->FindValue(key, SecurifierPtr());
    ASSERT_TRUE(env_->cond_var_.timed_wait(lock, env_->kTimeout_,
                env_->wait_for_find_value_functor_));
  }
  EXPECT_EQ(-1, env_->find_value_returns_.return_code);
  EXPECT_TRUE(env_->find_value_returns_.values.empty());
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
//  for (; i != env_->num_full_nodes_; ++i)
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
//  for (; i != env_->num_full_nodes_; ++i)
//    if (node_containers_[i]->node()->contact().node_id() == nodeids.back())
//      break;
//  // Store the value via node_containers_[i]->node()...
//  node_containers_[i]->node()->Store(node_id, value, "", duration, securifier, store_value);
//  while (!stored_value_)
//    Sleep(bptime::milliseconds(100));
//  stored_value_ = false;
//  
//  size = RandomUint32() % (env_->k_ - 1);
//  std::size_t count = env_->num_full_nodes_ + 1;
//  std::array<std::size_t, env_->k_+1> nodevals1, nodevals2; 
//  // Ensure k closest hold the value and tag the one to leave...
//  for (size_t i = 0; i != env_->k_; ++i) {
//    for (size_t j = 0; j != env_->num_full_nodes_; ++j) {
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
//  ASSERT_NE(count, env_->num_full_nodes_ + 1); 
//  std::vector<Contact> bootstrap_contacts;
//  node_containers_[count]->node()->Leave(&bootstrap_contacts);
//  // Having set refresh time to 30 seconds, wait for 60 seconds...
//  Sleep(bptime::seconds(60)); 
//  // The env_->k_ element of nodeids should now hold the value if a refresh
//  // has occurred...
//  /*for (size_t j = 0; j != env_->num_full_nodes_; ++j) {
//    if (node_containers_[j]->node()->contact().node_id() == nodeids[env_->k_]) {
//      ASSERT_TRUE(node_containers_[j]->node()->data_store_->HasKey(node_id.String()));
//      break;
//    }
//  }*/
//  for (size_t i = 0, j = 0; j != env_->num_full_nodes_; ++j) {
//    if (node_containers_[j]->node()->data_store_->HasKey(node_id.String())) {
//      nodevals2[i] = j;
//      ++i;
//    }
//  }
//  //for (size_t i = 0; i != env_->k_; ++i) {
//  //  for (size_t j = 0; j != env_->num_full_nodes_; ++j) {
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
//  for (; i != env_->num_full_nodes_; ++i)
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
//  size = RandomUint32() % (env_->k_ - 1);
//  std::size_t leave_node = env_->num_full_nodes_ + 1;
//  std::array<std::size_t, env_->k_+1> nodevals1;
//  // Ensure k closest hold the value and tag the one to leave...
//  for (size_t i = 0; i != env_->k_; ++i) {
//    for (size_t j = 0; j != env_->num_full_nodes_; ++j) {
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
//  ASSERT_NE(leave_node, env_->num_full_nodes_ + 1); 
//  std::vector<Contact> bootstrap_contacts;
//  node_containers_[leave_node]->node()->Leave(&bootstrap_contacts);
//  // Delete the value...
//  node_containers_[storing_node]->node()->Delete(node_id, value, "", securifier,
//                                                 delete_value);
//  // Ensure no currently joined node claims to have the value...
//  std::vector<std::pair<std::string, std::string>> values;
//  for (size_t i = 0; i != env_->num_full_nodes_; ++i) {
//    if (i != leave_node) {
//      ASSERT_FALSE(GetDataStore(node_containers_[i])->GetValues(
//          node_id.String(), &values));
//    }
//  }
//  // Ensure no currently joined node has the value...
////  for (size_t j = 0; j != env_->num_full_nodes_; ++j)
////    if (j != leave_node)
////      ASSERT_FALSE(node_containers_[j]->node()->data_store_->HasKey(node_id.String()));
//  // Allow node to rejoin the network...
//  int join_result(kPendingResult);
//  std::function<bool()> wait_functor =
//      std::bind(&NodeImplTest::ResultReady, this, &join_result);
//  std::vector<Contact> contacts;
//  for (size_t j = 0; j != env_->num_full_nodes_; ++j) {
//    if (node_containers_[leave_node]->node()->contact().node_id() ==
//        nodeids[i]) {
//      join_result = kPendingResult;
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
//  for (size_t j = 0; j != env_->num_full_nodes_; ++j) {
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
