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

#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "gmock/gmock.h"
#include "maidsafe/common/test.h"

#include "maidsafe/dht/log.h"
#include "maidsafe/dht/kademlia/node_impl.h"
#include "maidsafe/dht/kademlia/tests/test_utils.h"
#include "maidsafe/dht/kademlia/node_container.h"
#include "maidsafe/dht/kademlia/tests/functional/test_node_environment.h"

namespace bptime = boost::posix_time;

namespace maidsafe {
namespace dht {
namespace kademlia {
namespace test {

class NodeImplTest : public testing::Test {
 protected:
  typedef std::shared_ptr<maidsafe::dht::kademlia::NodeContainer<NodeImpl>>
      NodeContainerPtr;
  NodeImplTest() : env_(NodesEnvironment<NodeImpl>::g_environment()),
                   kTimeout_(bptime::seconds(10)) {}
  std::shared_ptr<DataStore> GetDataStore(
      std::shared_ptr<maidsafe::dht::kademlia::NodeContainer<NodeImpl>>
          node_container) {
    return node_container->node()->data_store_;
  }

  NodesEnvironment<NodeImpl>* env_;
  const bptime::time_duration kTimeout_;
};


TEST_F(NodeImplTest, BEH_KAD_FindNodes) {
  for (std::size_t i = 0; i != env_->num_full_nodes_; ++i) {
    NodeId node_id(env_->node_containers_[i]->node()->contact().node_id());
    int result;
    std::vector<Contact> closest_nodes;
    {
      boost::mutex::scoped_lock lock(env_->mutex_);
      env_->node_containers_[i]->FindNodes(node_id);
      ASSERT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                  env_->node_containers_[i]->wait_for_find_nodes_functor()));
      env_->node_containers_[i]->GetAndResetFindNodesResult(&result,
                                                            &closest_nodes);
    }
    SortContacts(node_id, &closest_nodes);
    for (std::size_t j = 1; j != env_->k_; ++j) {
      ASSERT_TRUE(CloserToTarget(closest_nodes[j - 1], closest_nodes[j],
                                 node_id));
    }
  }

  NodeId node_id(NodeId::kRandomId);
  for (std::size_t i = 0; i != env_->num_full_nodes_; ++i) {
    int result;
    std::vector<Contact> closest_nodes;
    {
      boost::mutex::scoped_lock lock(env_->mutex_);
      env_->node_containers_[i]->FindNodes(node_id);
      ASSERT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                  env_->node_containers_[i]->wait_for_find_nodes_functor()));
      env_->node_containers_[i]->GetAndResetFindNodesResult(&result,
                                                            &closest_nodes);
    }
    SortContacts(node_id, &closest_nodes);
    for (std::size_t j = 1; j != env_->k_; ++j) {
      ASSERT_TRUE(CloserToTarget(closest_nodes[j - 1], closest_nodes[j],
                                 node_id));
    }
  }
}

TEST_F(NodeImplTest, BEH_KAD_Store) {
  Key key(NodeId::kRandomId);
  std::string value = RandomString(RandomUint32() % 1024);
  bptime::time_duration duration(bptime::minutes(1));
  size_t test_node_index(RandomUint32() % env_->node_containers_.size());
  NodeContainerPtr chosen_container(env_->node_containers_[test_node_index]);
  DLOG(INFO) << "Node " << test_node_index << " - "
             << DebugId(*chosen_container) << " performing store operation.";
  int result(kPendingResult);
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    chosen_container->Store(key, value, "", duration,
                            chosen_container->securifier());
    ASSERT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                chosen_container->wait_for_store_functor()));
    chosen_container->GetAndResetStoreResult(&result);
  }
  EXPECT_EQ(kSuccess, result);

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
  NodeContainerPtr putting_container(env_->node_containers_[test_node_index]);
  int result(kPendingResult);
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    putting_container->Store(key, value, "", duration,
                             putting_container->securifier());
    ASSERT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                putting_container->wait_for_store_functor()));
    putting_container->GetAndResetStoreResult(&result);
  }
  ASSERT_EQ(kSuccess, result);

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
  NodeContainerPtr getting_container(env_->node_containers_[not_got_value]);

  FindValueReturns find_value_returns;
  for (size_t i = 0; i != env_->k_; ++i) {
    {
      boost::mutex::scoped_lock lock(env_->mutex_);
      getting_container->FindValue(key, getting_container->securifier());
      ASSERT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                  getting_container->wait_for_find_value_functor()));
      getting_container->GetAndResetFindValueResult(&find_value_returns);
    }
    EXPECT_EQ(kSuccess, find_value_returns.return_code);
    ASSERT_FALSE(find_value_returns.values.empty());
    EXPECT_EQ(value, find_value_returns.values.front());
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
    getting_container->FindValue(key, getting_container->securifier());
    ASSERT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                getting_container->wait_for_find_value_functor()));
    getting_container->GetAndResetFindValueResult(&find_value_returns);
  }
  EXPECT_EQ(-1, find_value_returns.return_code);
  EXPECT_TRUE(find_value_returns.values.empty());
  // TODO(Fraser#5#): 2011-07-14 - Handle other return fields

}

TEST_F(NodeImplTest, BEH_KAD_Ping) {
  FAIL() << "Not implemented.";
}

TEST_F(NodeImplTest, BEH_KAD_Delete) {
  Key key(NodeId::kRandomId);
  std::string value = RandomString(RandomUint32() % 1024);
  bptime::time_duration duration(bptime::minutes(1));
  size_t test_node_index(RandomUint32() % env_->node_containers_.size());
  NodeContainerPtr chosen_container(env_->node_containers_[test_node_index]);
  boost::mutex::scoped_lock lock(env_->mutex_);
  chosen_container->Store(key, value, "", duration,
                          chosen_container->securifier());
  EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
              chosen_container->wait_for_store_functor()));
  chosen_container->Delete(key, value, "", chosen_container->securifier());
  EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
              chosen_container->wait_for_delete_functor()));
}

TEST_F(NodeImplTest, BEH_KAD_StoreRefresh) {
  Key key(NodeId::kRandomId);
  std::string value = RandomString(RandomUint32() % 1024);
  bptime::time_duration duration(bptime::seconds(20));
  size_t test_node_index(RandomUint32() % env_->node_containers_.size());
  NodeContainerPtr chosen_container(env_->node_containers_[test_node_index]);
  DLOG(INFO) << "Node " << test_node_index << " - "
             << DebugId(*chosen_container) << " performing store operation.";
  int result(kPendingResult);
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    chosen_container->Store(key, value, "", duration,
                            chosen_container->securifier());
    ASSERT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                chosen_container->wait_for_store_functor()));
    chosen_container->GetAndResetStoreResult(&result);
  }
  EXPECT_EQ(kSuccess, result);

  // Ensure k closest hold the value and tag the one to leave
  auto itr(env_->node_containers_.begin()), node_to_leave(itr);
  for (; itr != env_->node_containers_.end(); ++itr) {
    if (WithinKClosest((*itr)->node()->contact().node_id(), key,
                       env_->node_ids_, env_->k_)) {
      EXPECT_TRUE(GetDataStore(*itr)->HasKey(key.String()));
      node_to_leave = itr;
    }
  }
  auto id_itr = std::find(env_->node_ids_.begin(), env_->node_ids_.end(),
                          (*node_to_leave)->node()->contact().node_id());
  ASSERT_NE(env_->node_ids_.end(), id_itr);
  (*node_to_leave)->Stop(NULL);
  env_->node_containers_.erase(node_to_leave);
  env_->node_ids_.erase(id_itr);

  // Having set refresh time to 20 seconds, wait for 30 seconds
  Sleep(bptime::seconds(30));

  // If a refresh has happened, the current k closest should hold the value
  for (itr = env_->node_containers_.begin();
       itr != env_->node_containers_.end(); ++itr) {
    if (WithinKClosest((*itr)->node()->contact().node_id(), key,
                       env_->node_ids_, env_->k_)) {
      EXPECT_TRUE(GetDataStore(*itr)->HasKey(key.String()));
    }
  }
}

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
