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

class NodeImplTest : public testing::TestWithParam<bool> {
 protected:
  typedef std::shared_ptr<maidsafe::dht::kademlia::NodeContainer<NodeImpl>>
      NodeContainerPtr;
  NodeImplTest()
      : env_(NodesEnvironment<NodeImpl>::g_environment()),
        kTimeout_(bptime::seconds(10)),
        client_only_node_(GetParam()),
        debug_msg_(client_only_node_ ? "Client node." : "Full node."),
        test_container_(new maidsafe::dht::kademlia::NodeContainer<NodeImpl>()),
        bootstrap_contacts_() {}

  void SetUp() {
    test_container_->Init(3, SecurifierPtr(),
        AlternativeStorePtr(new TestNodeAlternativeStore), client_only_node_,
        env_->k_, env_->alpha_, env_->beta_, env_->mean_refresh_interval_);
    test_container_->MakeAllCallbackFunctors(&env_->mutex_, &env_->cond_var_);
    (*env_->node_containers_.rbegin())->node()->GetBootstrapContacts(
        &bootstrap_contacts_);
    int result(kPendingResult);
    if (client_only_node_) {
      result = test_container_->Start(bootstrap_contacts_, 0);
    } else {
      int attempts(0), max_attempts(5);
      Port port(static_cast<Port>((RandomUint32() % 55535) + 10000));
      while ((result = test_container_->Start(bootstrap_contacts_, port)) !=
              kSuccess && (attempts != max_attempts)) {
        port = static_cast<Port>((RandomUint32() % 55535) + 10000);
        ++attempts;
      }
    }
    ASSERT_EQ(kSuccess, result) << debug_msg_;
    ASSERT_TRUE(test_container_->node()->joined()) << debug_msg_;
  }

  std::shared_ptr<DataStore> GetDataStore(
      std::shared_ptr<maidsafe::dht::kademlia::NodeContainer<NodeImpl>>
          node_container) {
    return node_container->node()->data_store_;
  }

  NodesEnvironment<NodeImpl>* env_;
  const bptime::time_duration kTimeout_;
  bool client_only_node_;
  std::string debug_msg_;
  NodeContainerPtr test_container_;
  std::vector<Contact> bootstrap_contacts_;

 private:
  NodeImplTest(const NodeImplTest&);
  NodeImplTest &operator=(const NodeImplTest&);
};

TEST_P(NodeImplTest, FUNC_JoinLeave) {
  NodeContainerPtr node_container(
      new maidsafe::dht::kademlia::NodeContainer<NodeImpl>());
  node_container->Init(3, SecurifierPtr(),
      AlternativeStorePtr(new TestNodeAlternativeStore), client_only_node_,
      env_->k_, env_->alpha_, env_->beta_, env_->mean_refresh_interval_);
  node_container->MakeAllCallbackFunctors(&env_->mutex_, &env_->cond_var_);
  std::vector<Contact> bootstrap_contacts;
  (*env_->node_containers_.rbegin())->node()->GetBootstrapContacts(
      &bootstrap_contacts);

  // Get state of all nodes' routing tables before bootstrapping
  std::vector<std::vector<Contact>> all_nodes_contacts_before;
  for (auto it(env_->node_containers_.begin());
        it != env_->node_containers_.end(); ++it) {
    std::vector<Contact> contacts;
    (*it)->node()->GetAllContacts(&contacts);
    all_nodes_contacts_before.push_back(contacts);
  }

  // For client, start without listening, for full try to start with listening
  int result(kPendingResult);
  if (client_only_node_) {
    result = node_container->Start(bootstrap_contacts, 0);
  } else {
    int attempts(0), max_attempts(5);
    Port port(static_cast<Port>((RandomUint32() % 55535) + 10000));
    while ((result = node_container->Start(bootstrap_contacts, port)) !=
            kSuccess && (attempts != max_attempts)) {
      port = static_cast<Port>((RandomUint32() % 55535) + 10000);
      ++attempts;
    }
  }
  EXPECT_EQ(kSuccess, result) << debug_msg_;
  EXPECT_TRUE(node_container->node()->joined()) << debug_msg_;

  // Get state of all nodes' routing tables after bootstrapping
  std::vector<std::vector<Contact>> all_nodes_contacts_after;
  for (auto it(env_->node_containers_.begin());
        it != env_->node_containers_.end(); ++it) {
    std::vector<Contact> contacts;
    (*it)->node()->GetAllContacts(&contacts);
    all_nodes_contacts_after.push_back(contacts);
  }

  // In case of client bootstrap, check nodes' routing tables don't contain
  // client's details.  In case of full node, check at least k nodes know the
  // new node.
  ASSERT_EQ(all_nodes_contacts_before.size(),
            all_nodes_contacts_after.size()) << debug_msg_;
  auto it_before(all_nodes_contacts_before.begin());
  auto it_after(all_nodes_contacts_after.begin());
  size_t instance_count(0);
  for (; it_before != all_nodes_contacts_before.end();
        ++it_before, ++it_after) {
    for (auto itr((*it_after).begin()); itr != (*it_after).end(); ++itr) {
      if (*itr == node_container->node()->contact())
        ++instance_count;
    }
  }
  if (client_only_node_)
    EXPECT_EQ(0U, instance_count) << debug_msg_;
  else
    EXPECT_LE(env_->k_, instance_count) << debug_msg_;

  // Check new node has at least k contacts in its routing table
  std::vector<Contact> new_nodes_contacts;
  node_container->node()->GetAllContacts(&new_nodes_contacts);
  EXPECT_LE(env_->k_, new_nodes_contacts.size()) << debug_msg_;

  // Leave
  node_container->node()->Leave(&bootstrap_contacts);
  EXPECT_FALSE(node_container->node()->joined()) << debug_msg_;
  EXPECT_FALSE(bootstrap_contacts.empty()) << debug_msg_;

  // Re-join
  result = kPendingResult;
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    node_container->Join(
        node_container->node()->contact().node_id(),
        node_container->bootstrap_contacts());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                node_container->wait_for_join_functor())) << debug_msg_;
    node_container->GetAndResetJoinResult(&result);
    EXPECT_EQ(kSuccess, result) << debug_msg_;
    EXPECT_TRUE(node_container->node()->joined()) << debug_msg_;
  }
}

TEST_P(NodeImplTest, FUNC_FindNodes) {
  NodeId target_id(NodeId::kRandomId);
  std::vector<Contact> closest_nodes, prior_closest_nodes;
  int result(kPendingResult);
  for (std::size_t i = 0; i != env_->num_full_nodes_; ++i) {
    {
      boost::mutex::scoped_lock lock(env_->mutex_);
      env_->node_containers_[i]->FindNodes(target_id);
      EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                  env_->node_containers_[i]->wait_for_find_nodes_functor()))
                  << debug_msg_;
      env_->node_containers_[i]->GetAndResetFindNodesResult(&result,
                                                            &closest_nodes);
    }

    // Check the returned Contacts are in order of closeness to target_id
    ASSERT_EQ(env_->k_, closest_nodes.size()) << debug_msg_;
    for (std::size_t j = 1; j != env_->k_; ++j) {
      EXPECT_TRUE(CloserToTarget(closest_nodes[j - 1], closest_nodes[j],
                                 target_id)) << debug_msg_;
    }

    // Check this node returns identical Contacts to the previously-asked one
    if (i != 0) {
      for (auto it(closest_nodes.begin()),
           prior_it(prior_closest_nodes.begin()); it != closest_nodes.end();
           ++it, ++prior_it) {
        EXPECT_EQ(*prior_it, *it) << debug_msg_;
      }
    }
    prior_closest_nodes = closest_nodes;
  }

  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    test_container_->FindNodes(target_id);
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                test_container_->wait_for_find_nodes_functor())) << debug_msg_;
    test_container_->GetAndResetFindNodesResult(&result, &closest_nodes);
  }

  // Check the returned Contacts are in order of closeness to target_id
  ASSERT_EQ(env_->k_, closest_nodes.size()) << debug_msg_;
  for (std::size_t j = 1; j != env_->k_; ++j) {
    EXPECT_TRUE(CloserToTarget(closest_nodes[j - 1], closest_nodes[j],
                                target_id)) << debug_msg_;
  }

  // Check this node returns identical Contacts to the previously-asked one
  for (auto it(closest_nodes.begin()),
        prior_it(prior_closest_nodes.begin()); it != closest_nodes.end();
        ++it, ++prior_it) {
    EXPECT_EQ(*prior_it, *it) << debug_msg_;
  }
}

TEST_P(NodeImplTest, FUNC_Store) {
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

TEST_P(NodeImplTest, FUNC_FindValue) {
  Key key(NodeId::kRandomId);
  std::vector<std::string> values;
  const int kNumValues(4);
  for (int i = 0; i != kNumValues; ++i)
    values.push_back(RandomString(RandomUint32() % 1024));
  bptime::time_duration duration(bptime::minutes(1));
  size_t test_node_index(RandomUint32() % env_->node_containers_.size());
  NodeContainerPtr putting_container(env_->node_containers_[test_node_index]);
  int result(kPendingResult);
  for (int i = 0; i != kNumValues; ++i) {
    result = kPendingResult;
    {
      boost::mutex::scoped_lock lock(env_->mutex_);
      putting_container->Store(key, values[i], "", duration,
                             putting_container->securifier());
      ASSERT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                             putting_container->wait_for_store_functor()));
      putting_container->GetAndResetStoreResult(&result);
    }
    ASSERT_EQ(kSuccess, result);
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
    ASSERT_EQ(values.size(), find_value_returns.values.size());
    for (size_t i = 0; i != values.size(); ++i)
      EXPECT_EQ(values[i], find_value_returns.values[i]);
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
  EXPECT_EQ(kSuccess, find_value_returns.return_code);
  EXPECT_TRUE(find_value_returns.values.empty());
  EXPECT_EQ(env_->k_, find_value_returns.closest_nodes.size());
  // TODO(Fraser#5#): 2011-07-14 - Handle other return fields
}

TEST_P(NodeImplTest, FUNC_Delete) {
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

TEST_P(NodeImplTest, FUNC_Update) {
  FAIL() << "Not implemented.";
}

TEST_P(NodeImplTest, FUNC_StoreRefresh) {
  Key key(NodeId::kRandomId);
  std::string value = RandomString(RandomUint32() % 1024);
  bptime::time_duration duration(bptime::seconds(20));
  size_t test_node_index(RandomUint32() % env_->node_containers_.size());
  NodeContainerPtr chosen_container(env_->node_containers_[test_node_index]);
  int result(kPendingResult);
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    chosen_container->Store(key, value, "", duration,
                            chosen_container->securifier());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                chosen_container->wait_for_store_functor()));
    chosen_container->GetAndResetStoreResult(&result);
  }
  ASSERT_EQ(kSuccess, result);

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

TEST_P(NodeImplTest, FUNC_DeleteRefresh) {
  Key key(NodeId::kRandomId);
  std::string value = RandomString(RandomUint32() % 1024);
  bptime::time_duration duration(bptime::seconds(20));
  size_t test_node_index(RandomUint32() % env_->node_containers_.size());
  NodeContainerPtr chosen_container(env_->node_containers_[test_node_index]);

  // Store the value
  int result(kPendingResult);
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    chosen_container->Store(key, value, "", duration,
                            chosen_container->securifier());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                chosen_container->wait_for_store_functor()));
    chosen_container->GetAndResetStoreResult(&result);
  }
  ASSERT_EQ(kSuccess, result);

  // Delete the value
  result = kPendingResult;
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    chosen_container->Delete(key, value, "", chosen_container->securifier());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                chosen_container->wait_for_delete_functor()));
    chosen_container->GetAndResetStoreResult(&result);
  }
  ASSERT_EQ(kSuccess, result);

  // Ensure k closest hold the value (albeit marked as deleted) and tag the one
  // to leave
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
  // (albeit marked as deleted)
  for (itr = env_->node_containers_.begin();
       itr != env_->node_containers_.end(); ++itr) {
    if (WithinKClosest((*itr)->node()->contact().node_id(), key,
                       env_->node_ids_, env_->k_)) {
      EXPECT_TRUE(GetDataStore(*itr)->HasKey(key.String()));
    }
  }
}

TEST_P(NodeImplTest, FUNC_GetContact) {
  FAIL() << "Not implemented.";
}

// TODO(Fraser#5#): 2011-07-27 - Change "testing::Values(true, false)" to
//                          "testing::Bool()" once Common v0.10.01 is available.
INSTANTIATE_TEST_CASE_P(FullOrClient, NodeImplTest,
                        testing::Values(true, false));

}  // namespace test
}  // namespace kademlia
}  // namespace dht
}  // namespace maidsafe
