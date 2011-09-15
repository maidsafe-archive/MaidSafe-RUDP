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

class TestAlternativeStoreReturnsTrue : public AlternativeStore {
 public:
  ~TestAlternativeStoreReturnsTrue() {}
  virtual bool Has(const std::string&) const { return true; }
};

class NodeImplTest : public testing::TestWithParam<bool> {
 protected:
  typedef std::shared_ptr<maidsafe::dht::kademlia::NodeContainer<NodeImpl>>
      NodeContainerPtr;
  NodeImplTest()
      : env_(NodesEnvironment<NodeImpl>::g_environment()),
        kTimeout_(transport::kDefaultInitialTimeout +
                  transport::kDefaultInitialTimeout),
        client_only_node_(GetParam()),
        debug_msg_(client_only_node_ ? "Client node." : "Full node."),
        test_container_(new maidsafe::dht::kademlia::NodeContainer<NodeImpl>()),
        bootstrap_contacts_(),
        far_key_() {}

  void SetUp() {
    // Clear all DataStores and restart any stopped nodes.
    for (size_t i = 0; i != env_->num_full_nodes_; ++i) {
      if (!env_->node_containers_[i]->node()->joined()) {
        boost::mutex::scoped_lock lock(env_->mutex_);
        env_->node_containers_[i]->Join(
            env_->node_containers_[i]->node()->contact().node_id(),
            env_->node_containers_[i]->bootstrap_contacts());
        env_->cond_var_.timed_wait(lock, kTimeout_,
            env_->node_containers_[i]->wait_for_join_functor());
        int result;
        env_->node_containers_[i]->GetAndResetJoinResult(&result);
        // ping the other environment containers to make sure their contact info
        // is up to date
        for (size_t j = 0; j != env_->num_full_nodes_; ++j) {
          if (i != j) {
            env_->node_containers_[i]->Ping(
                env_->node_containers_[j]->node()->contact());
            env_->cond_var_.timed_wait(lock, kTimeout_,
                env_->node_containers_[i]->wait_for_ping_functor());
            env_->node_containers_[i]->GetAndResetPingResult(&result);
          }
        }
      }
      boost::unique_lock<boost::shared_mutex> lock(
          GetDataStore(env_->node_containers_[i])->shared_mutex_);
      GetDataStore(env_->node_containers_[i])->key_value_index_->clear();
    }
    test_container_->Init(3, SecurifierPtr(), MessageHandlerPtr(),
                          AlternativeStorePtr(), client_only_node_, env_->k_,
                          env_->alpha_, env_->beta_,
                          env_->mean_refresh_interval_);
    test_container_->MakeAllCallbackFunctors(&env_->mutex_, &env_->cond_var_);
    (*env_->node_containers_.rbegin())->node()->GetBootstrapContacts(
        &bootstrap_contacts_);
    int result(kPendingResult);
    if (client_only_node_) {
      result = test_container_->StartClient(bootstrap_contacts_);
    } else {
      std::pair<Port, Port> port_range(8000, 65535);
      result = test_container_->Start(bootstrap_contacts_, port_range);
    }
    ASSERT_EQ(kSuccess, result) << debug_msg_;
    ASSERT_TRUE(test_container_->node()->joined()) << debug_msg_;
    // make far_key_ as far as possible from test_container_'s ID
    far_key_ = test_container_->node()->contact().node_id() ^
               NodeId(std::string(kKeySizeBytes, static_cast<char>(-1)));
  }

  std::shared_ptr<DataStore> GetDataStore(
      std::shared_ptr<maidsafe::dht::kademlia::NodeContainer<NodeImpl>>
          node_container) {
    return node_container->node()->data_store_;
  }

  bool IsKeyValueInDataStore(std::shared_ptr<DataStore> data_store,
                             std::string key, std::string value) {
    std::vector<ValueAndSignature> values_and_signatures;
    data_store->GetValues(key, &values_and_signatures);
    for (size_t i = 0; i < values_and_signatures.size(); ++i) {
      if (values_and_signatures[i].first == value)
        return true;
    }
    return false;
  }

  std::shared_ptr<LocalNetwork<NodeImpl> > env_;
  const bptime::time_duration kTimeout_;
  bool client_only_node_;
  std::string debug_msg_;
  NodeContainerPtr test_container_;
  std::vector<Contact> bootstrap_contacts_;
  Key far_key_;

 private:
  NodeImplTest(const NodeImplTest&);
  NodeImplTest &operator=(const NodeImplTest&);
};

TEST_P(NodeImplTest, FUNC_JoinLeave) {
  NodeContainerPtr node_container(
      new maidsafe::dht::kademlia::NodeContainer<NodeImpl>());
  node_container->Init(3, SecurifierPtr(), MessageHandlerPtr(),
                       AlternativeStorePtr(), client_only_node_, env_->k_,
                       env_->alpha_, env_->beta_, env_->mean_refresh_interval_);
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
    result = node_container->StartClient(bootstrap_contacts);
  } else {
    std::pair<Port, Port> port_range(8000, 65535);
    result = node_container->Start(bootstrap_contacts, port_range);
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
  Sleep(bptime::milliseconds(1000));
  // Node that has left shouldn't be able to send/ recieve RPCs
  if (!client_only_node_) {
    boost::mutex::scoped_lock lock(env_->mutex_);
    (*env_->node_containers_.rbegin())->Ping(node_container->node()->contact());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                  (*env_->node_containers_.rbegin())->wait_for_ping_functor()))
                  << debug_msg_;
    result = kPendingResult;
    (*env_->node_containers_.rbegin())->GetAndResetPingResult(&result);
    EXPECT_EQ(transport::kReceiveFailure, result) << debug_msg_;
  }
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    node_container->Ping((*env_->node_containers_.rbegin())->node()->contact());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                  node_container->wait_for_ping_functor()))
                  << debug_msg_;
    result = kPendingResult;
    node_container->GetAndResetPingResult(&result);
    EXPECT_EQ(kNotJoined, result) << debug_msg_;
  }
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
  // Node that has re-joined should be able to send/recieve RPCs
  if (!client_only_node_) {
    boost::mutex::scoped_lock lock(env_->mutex_);
    (*env_->node_containers_.rbegin())->Ping(node_container->node()->contact());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                  (*env_->node_containers_.rbegin())->wait_for_ping_functor()))
                  << debug_msg_;
    result = kPendingResult;
    (*env_->node_containers_.rbegin())->GetAndResetPingResult(&result);
    EXPECT_EQ(kSuccess, result) << debug_msg_;
  }
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    node_container->Ping((*env_->node_containers_.rbegin())->node()->contact());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                  node_container->wait_for_ping_functor()))
                  << debug_msg_;
    result = kPendingResult;
    node_container->GetAndResetPingResult(&result);
    EXPECT_EQ(kSuccess, result) << debug_msg_;
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

  // verify n > k number of nodes are returned on request
  {
    const uint16_t kExtras(3);
    boost::mutex::scoped_lock lock(env_->mutex_);
    for (size_t i = 0; i < env_->num_full_nodes_; i++) {
      closest_nodes.clear();
      env_->node_containers_[i]->FindNodes(
          test_container_->node()->contact().node_id(), kExtras);
      EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                  env_->node_containers_[i]->wait_for_find_nodes_functor()))
                      << debug_msg_;
      env_->node_containers_[i]->GetAndResetFindNodesResult(&result,
                                                            &closest_nodes);
      EXPECT_EQ(kSuccess, result);
      EXPECT_EQ(env_->k_ + kExtras, closest_nodes.size());
    }
  }

  // verify a node which has left isn't included in the returned list
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    test_container_->Stop(NULL);
    for (size_t i = 0; i < env_->num_full_nodes_; i++) {
      closest_nodes.clear();
      env_->node_containers_[i]->FindNodes(
          test_container_->node()->contact().node_id());
      EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                  env_->node_containers_[i]->wait_for_find_nodes_functor()))
                      << debug_msg_;
      env_->node_containers_[i]->GetAndResetFindNodesResult(&result,
                                                            &closest_nodes);
      EXPECT_EQ(kSuccess, result);
      EXPECT_EQ(closest_nodes.end(),
                std::find(closest_nodes.begin(),
                          closest_nodes.end(),
                          test_container_->node()->contact()));
    }
  }
}

TEST_P(NodeImplTest, FUNC_Store) {
  std::string value = RandomString(RandomUint32() % 1024),
      value1 = RandomString(RandomUint32() % 1024);
  bptime::time_duration duration(bptime::pos_infin);
  size_t test_node_index(RandomUint32() % env_->node_containers_.size());
  NodeContainerPtr chosen_container(env_->node_containers_[test_node_index]);
  DLOG(INFO) << "Node " << test_node_index << " - "
             << DebugId(*chosen_container) << " performing store operation.";
  int result(kPendingResult);
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    chosen_container->Store(far_key_, value, "", duration,
                            chosen_container->securifier());
    ASSERT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                chosen_container->wait_for_store_functor()));
    chosen_container->GetAndResetStoreResult(&result);
  }
  EXPECT_EQ(kSuccess, result);

  for (size_t i = 0; i != env_->num_full_nodes_; ++i) {
    if (WithinKClosest(env_->node_containers_[i]->node()->contact().node_id(),
                       far_key_, env_->node_ids_, env_->k_)) {
      bptime::time_duration total_sleep_time(bptime::milliseconds(0));
      const bptime::milliseconds kIterSleep(100);
      while (!GetDataStore(env_->node_containers_[i])->HasKey(far_key_.String())
             && total_sleep_time < kTimeout_) {
        total_sleep_time += kIterSleep;
        Sleep(kIterSleep);
      }
      EXPECT_TRUE(GetDataStore(env_->node_containers_[i])->
                  HasKey(far_key_.String()));
    } else {
      EXPECT_FALSE(GetDataStore(env_->node_containers_[i])->
                   HasKey(far_key_.String()));
    }
  }

  //  verify re-storing an existing key,value succeeds for original storing node
  result = kPendingResult;
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    chosen_container->Store(far_key_, value, "", duration,
                            chosen_container->securifier());
    ASSERT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                chosen_container->wait_for_store_functor()));
    chosen_container->GetAndResetStoreResult(&result);
  }
  EXPECT_EQ(kSuccess, result);

  //  verify storing a second value to a given key fails for different storing
  //  node
  size_t index = (test_node_index + 1 +
                  RandomUint32() % (env_->node_containers_.size() - 1)) %
                      (env_->node_containers_.size());
  result = kPendingResult;
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    env_->node_containers_[index]->Store(far_key_, value1, "", duration,
        env_->node_containers_[index]->securifier());
    ASSERT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                env_->node_containers_[index]->wait_for_store_functor()));
    env_->node_containers_[index]->GetAndResetStoreResult(&result);
  }
  EXPECT_NE(kSuccess, result);

  // verify storing a second value to a given key succeeds for original
  // storing node
  result = kPendingResult;
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    chosen_container->Store(far_key_, value1, "", duration,
                            chosen_container->securifier());
    ASSERT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                chosen_container->wait_for_store_functor()));
    chosen_container->GetAndResetStoreResult(&result);
  }
  EXPECT_EQ(kSuccess, result);

  for (size_t i = 0; i != env_->num_full_nodes_; ++i) {
    if (WithinKClosest(env_->node_containers_[i]->node()->contact().node_id(),
                       far_key_, env_->node_ids_, env_->k_)) {
      bptime::time_duration total_sleep_time(bptime::milliseconds(0));
      const bptime::milliseconds kIterSleep(100);
      bool found_all(false);
      while (!found_all && total_sleep_time < kTimeout_) {
        found_all =
            IsKeyValueInDataStore(GetDataStore(env_->node_containers_[i]),
                                  far_key_.String(), value) &&
            IsKeyValueInDataStore(GetDataStore(env_->node_containers_[i]),
                                  far_key_.String(), value1);
        total_sleep_time += kIterSleep;
        Sleep(kIterSleep);
      }
      EXPECT_TRUE(GetDataStore(
          env_->node_containers_[i])->HasKey(far_key_.String()));
      EXPECT_TRUE(IsKeyValueInDataStore(GetDataStore(env_->node_containers_[i]),
                                        far_key_.String(), value));
      EXPECT_TRUE(IsKeyValueInDataStore(GetDataStore(env_->node_containers_[i]),
                                        far_key_.String(), value1));
    } else {
      EXPECT_FALSE(GetDataStore(env_->node_containers_[i])->
          HasKey(far_key_.String()));
    }
  }
}

TEST_P(NodeImplTest, FUNC_FindValue) {
  {
    // Attempt to find value for a non-existent key
    Key nonexistent_key(NodeId::kRandomId);
    FindValueReturns find_value_returns_nonexistent_key;
    boost::mutex::scoped_lock lock(env_->mutex_);
    test_container_->FindValue(nonexistent_key,
                               test_container_->securifier());
    ASSERT_TRUE(env_->cond_var_.timed_wait(
        lock, kTimeout_, test_container_->wait_for_find_value_functor()));
    test_container_->GetAndResetFindValueResult(
        &find_value_returns_nonexistent_key);
    EXPECT_EQ(kFailedToFindValue,
              find_value_returns_nonexistent_key.return_code);
    EXPECT_TRUE(
        find_value_returns_nonexistent_key.values_and_signatures.empty());
    EXPECT_EQ(env_->k_,
              find_value_returns_nonexistent_key.closest_nodes.size());
  }

  std::vector<std::string> values;
  const int kNumValues(4);
  for (int i = 0; i != kNumValues; ++i)
    values.push_back(RandomString(RandomUint32() % 1024));
  bptime::time_duration duration(bptime::pos_infin);
  int result(kPendingResult);
  for (int i = 0; i != kNumValues; ++i) {
    result = kPendingResult;
    {
      boost::mutex::scoped_lock lock(env_->mutex_);
      test_container_->Store(far_key_, values[i], "", duration,
                             test_container_->securifier());
      ASSERT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                             test_container_->wait_for_store_functor()));
      test_container_->GetAndResetStoreResult(&result);
    }
    ASSERT_EQ(kSuccess, result);
  }

  // Assert test_container_ didn't store the value
  if (!client_only_node_)
    ASSERT_FALSE(GetDataStore(test_container_)->HasKey(far_key_.String()));

  FindValueReturns find_value_returns;
  for (size_t i = 0; i != env_->k_; ++i) {
    {
      boost::mutex::scoped_lock lock(env_->mutex_);
      test_container_->FindValue(far_key_, test_container_->securifier());
      ASSERT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                  test_container_->wait_for_find_value_functor()));
      test_container_->GetAndResetFindValueResult(&find_value_returns);
    }
    EXPECT_EQ(kSuccess, find_value_returns.return_code);
    ASSERT_FALSE(find_value_returns.values_and_signatures.empty());
    ASSERT_EQ(values.size(), find_value_returns.values_and_signatures.size());
    size_t num_values(std::min(values.size(),
                      find_value_returns.values_and_signatures.size()));
    for (size_t k = 0; k != num_values; ++k) {
      EXPECT_EQ(values[k], find_value_returns.values_and_signatures[k].first);
      EXPECT_TRUE(test_container_->securifier()->Validate(values[k],
                  find_value_returns.values_and_signatures[k].second, "",
                  test_container_->securifier()->kSigningPublicKey(), "", ""));
    }
    // TODO(Fraser#5#): 2011-07-14 - Handle other return fields

    // Stop nodes holding value one at a time and retry getting value
    for (size_t j = 0; j != env_->num_full_nodes_; ++j) {
      if (WithinKClosest(env_->node_containers_[j]->node()->contact().node_id(),
                         far_key_, env_->node_ids_, env_->k_) &&
          env_->node_containers_[j]->node()->joined()) {
        env_->node_containers_[j]->node()->Leave(NULL);
        DLOG(INFO) << "\t\tSTOPPED "
                   << DebugId(env_->node_containers_[j]->node()->contact());
        break;
      }
    }
  }
  find_value_returns = FindValueReturns();
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    test_container_->FindValue(far_key_, test_container_->securifier());
    ASSERT_TRUE(env_->cond_var_.timed_wait(lock, bptime::minutes(1),
                test_container_->wait_for_find_value_functor()));
    test_container_->GetAndResetFindValueResult(&find_value_returns);
  }
  EXPECT_EQ(kFailedToFindValue, find_value_returns.return_code);
  EXPECT_TRUE(find_value_returns.values_and_signatures.empty());
  EXPECT_EQ(env_->k_, find_value_returns.closest_nodes.size());
  // TODO(Fraser#5#): 2011-07-14 - Handle other return fields

  // Restart stopped nodes.
  for (size_t i = 0; i != env_->num_full_nodes_; ++i) {
    if (!env_->node_containers_[i]->node()->joined()) {
      std::pair<Port, Port> port_range(8000, 65535);
      EXPECT_EQ(kSuccess, env_->node_containers_[i]->Start(
                env_->node_containers_[i]->bootstrap_contacts(), port_range));
    }
  }

  // Test that a node with a key in its alternative store returns itself as a
  // holder for that key when queried
  NodeContainerPtr alternative_container(
      new maidsafe::dht::kademlia::NodeContainer<NodeImpl>());
  alternative_container->Init(3, SecurifierPtr(), MessageHandlerPtr(),
      AlternativeStorePtr(new TestAlternativeStoreReturnsTrue), false, env_->k_,
      env_->alpha_, env_->beta_, env_->mean_refresh_interval_);
  alternative_container->MakeAllCallbackFunctors(&env_->mutex_,
                                                 &env_->cond_var_);
  (*env_->node_containers_.rbegin())->node()->GetBootstrapContacts(
        &bootstrap_contacts_);
  result = kPendingResult;
  {
    std::pair<Port, Port> port_range(8000, 65535);
    result = alternative_container->Start(bootstrap_contacts_, port_range);
    ASSERT_EQ(kSuccess, result) << debug_msg_;
    ASSERT_TRUE(alternative_container->node()->joined()) << debug_msg_;
  }
  FindValueReturns alternative_find_value_returns;
  {
    // Attempt to FindValue using the ID of the alternative
    // store container as the key
    boost::mutex::scoped_lock lock(env_->mutex_);
    test_container_->FindValue(
        alternative_container->node()->contact().node_id(),
        test_container_->securifier());
    ASSERT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                test_container_->wait_for_find_value_functor()));
    test_container_->GetAndResetFindValueResult(
        &alternative_find_value_returns);
    EXPECT_TRUE(alternative_find_value_returns.values_and_signatures.empty());
    EXPECT_EQ(alternative_container->node()->contact().node_id(),
        alternative_find_value_returns.alternative_store_holder.node_id())
        << "Expected: " << DebugId(alternative_container->node()->contact())
        << "\tFound: "
        << DebugId(alternative_find_value_returns.alternative_store_holder);
    alternative_container->node()->Leave(&bootstrap_contacts_);
  }

  // Verify that a FindValue on a key that is in every node returns an empty
  // needs_cache_copy field
  Key saturation_key(NodeId::kRandomId);
  std::string saturation_value = RandomString(RandomUint32() % 1024);
  maidsafe::crypto::RsaKeyPair crypto_key;
  crypto_key.GenerateKeys(4096);
  KeyValueTuple kvt = MakeKVT(crypto_key, saturation_value.size(), duration,
                              saturation_key.String(), saturation_value);
  for (auto it(env_->node_containers_.begin());
        it != env_->node_containers_.end(); ++it) {
    ASSERT_EQ(kSuccess, (GetDataStore(*it))->StoreValue(kvt.key_value_signature,
        duration, kvt.request_and_signature, false));
  }
  FindValueReturns saturation_find_value_returns;
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    result = kPendingResult;
    test_container_->FindValue(saturation_key, test_container_->securifier());
    ASSERT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                test_container_->wait_for_find_value_functor()));
    test_container_->GetAndResetFindValueResult(&saturation_find_value_returns);
    EXPECT_EQ(kSuccess, saturation_find_value_returns.return_code);
    ASSERT_EQ(saturation_find_value_returns.needs_cache_copy, Contact());
  }

  // TODO(Fraser#5#): 2011-08-30 - Uncomment once caching is in place.

  // Verify that the container in the needs_cache_copy field does not initially
  // hold the key, but holds it within kTimeout_ of FindValue returning
//  FindValueReturns need_cache_copy_returns;
//  Key needs_cache_copy_key(NodeId::kRandomId);
//  std::string needs_cache_copy_value = RandomString(RandomUint32() % 1024);
//  {
//    boost::mutex::scoped_lock lock(env_->mutex_);
//    result = kPendingResult;
//    test_container_->Store(needs_cache_copy_key, needs_cache_copy_value, "",
//                           duration, test_container_->securifier());
//    ASSERT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
//                             test_container_->wait_for_store_functor()));
//    test_container_->GetAndResetStoreResult(&result);
//  }
//  {
//    std::deque<bool> had_key;
//    for (auto it(env_->node_containers_.begin());
//         it != env_->node_containers_.end(); ++it) {
//      had_key.push_back(
//          GetDataStore(*it)->HasKey(needs_cache_copy_key.String()));
//    }
//    boost::mutex::scoped_lock lock(env_->mutex_);
//    result = kPendingResult;
//    test_container_->FindValue(needs_cache_copy_key,
//                               test_container_->securifier());
//    ASSERT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
//                test_container_->wait_for_find_value_functor()));
//    test_container_->GetAndResetFindValueResult(&need_cache_copy_returns);
//    EXPECT_EQ(kSuccess, need_cache_copy_returns.return_code);
//    test_container_->node()->Leave(&bootstrap_contacts_);
//
//    Contact needs_contact = need_cache_copy_returns.needs_cache_copy;
//    NodeContainerPtr needs_container;
//    bool node_had_key(true);
//    for (auto it(env_->node_containers_.begin());
//         it != env_->node_containers_.end(); ++it) {
//      node_had_key = had_key.front();
//      had_key.pop_front();
//      if ((*it)->node()->contact() == needs_contact) {
//        needs_container = *it;
//        break;
//      }
//    }
//    ASSERT_TRUE(needs_container ? true : false);
//    ASSERT_FALSE(node_had_key);
//    bool node_now_has_key =
//        GetDataStore(needs_container)->HasKey(needs_cache_copy_key.String());
//    boost::posix_time::time_duration short_duration(kTimeout_/1000);
//    for (int timeout(0); timeout != 1000 && !node_now_has_key; ++timeout) {
//      Sleep(short_duration);
//      node_now_has_key =
//        GetDataStore(needs_container)->HasKey(needs_cache_copy_key.String());
//    }
//    ASSERT_TRUE(node_now_has_key);
//  }
}

TEST_P(NodeImplTest, FUNC_Delete) {
  int result(kPendingResult);
  FindValueReturns find_value_returns;
  Key key(NodeId::kRandomId);
  std::string value = RandomString(RandomUint32() % 1000 + 24);
  bptime::time_duration duration(bptime::pos_infin);
  size_t test_node_index(RandomUint32() % env_->node_containers_.size());
  NodeContainerPtr chosen_container(env_->node_containers_[test_node_index]);
  boost::mutex::scoped_lock lock(env_->mutex_);
  chosen_container->Store(key, value, "", duration,
                          chosen_container->securifier());
  EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
              chosen_container->wait_for_store_functor()));
  chosen_container->GetAndResetStoreResult(&result);
  EXPECT_EQ(kSuccess, result);
  result = kPendingResult;
  chosen_container->Delete(key, value, "", chosen_container->securifier());
  EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
              chosen_container->wait_for_delete_functor()));
  chosen_container->GetAndResetDeleteResult(&result);
  EXPECT_EQ(kSuccess, result);
  result = kPendingResult;
  chosen_container->FindValue(key, chosen_container->securifier());
  EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
              chosen_container->wait_for_find_value_functor()));
  chosen_container->GetAndResetFindValueResult(&find_value_returns);
  EXPECT_NE(kSuccess, find_value_returns.return_code);
  // verify that the original storer can re-store the deleted value
  result = kPendingResult;
  chosen_container->Store(key, value, "", duration,
                          chosen_container->securifier());
  EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
              chosen_container->wait_for_store_functor()));
  chosen_container->GetAndResetStoreResult(&result);
  EXPECT_EQ(kSuccess, result);
  result = kPendingResult;
  chosen_container->FindValue(key, chosen_container->securifier());
  EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
              chosen_container->wait_for_find_value_functor()));
  chosen_container->GetAndResetFindValueResult(&find_value_returns);
  EXPECT_EQ(kSuccess, find_value_returns.return_code);
  EXPECT_EQ(value, find_value_returns.values_and_signatures[0].first);
  EXPECT_TRUE(chosen_container->securifier()->Validate(value,
              find_value_returns.values_and_signatures[0].second, "",
              chosen_container->securifier()->kSigningPublicKey(), "", ""));
}

TEST_P(NodeImplTest, FUNC_Update) {
  int result(kPendingResult);
  FindValueReturns find_value_returns;
  std::string value = RandomString(RandomUint32() % 1000 + 24),
      new_value = RandomString(RandomUint32() % 1000 + 24);
  Key key(NodeId::kRandomId);
  bptime::time_duration duration(bptime::pos_infin);
  size_t test_node_index(RandomUint32() % env_->node_containers_.size());
  NodeContainerPtr chosen_container(env_->node_containers_[test_node_index]);
  //  verify updating an existing key,value to the same value succeeds
  // for original storing node
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    chosen_container->Store(key, value, "", duration,
                            chosen_container->securifier());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                chosen_container->wait_for_store_functor()));
    chosen_container->GetAndResetStoreResult(&result);
  }
  EXPECT_EQ(kSuccess, result);
  result = kPendingResult;
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    chosen_container->Update(key, value, "", value, "",
        duration, chosen_container->securifier());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                chosen_container->wait_for_update_functor()));
    chosen_container->GetAndResetUpdateResult(&result);
  }
  EXPECT_EQ(kSuccess, result);
  result = kPendingResult;
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    chosen_container->FindValue(key, chosen_container->securifier());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                chosen_container->wait_for_find_value_functor()));
    chosen_container->GetAndResetFindValueResult(&find_value_returns);
  }
  EXPECT_EQ(kSuccess, find_value_returns.return_code);
  EXPECT_EQ(value, find_value_returns.values_and_signatures[0].first);
  EXPECT_TRUE(chosen_container->securifier()->Validate(value,
              find_value_returns.values_and_signatures[0].second, "",
              chosen_container->securifier()->kSigningPublicKey(), "", ""));

  //  verify updating fails for all but the original storer
  for (size_t i = 0; i < env_->node_containers_.size(); ++i) {
    {
      boost::mutex::scoped_lock lock(env_->mutex_);
      env_->node_containers_[i]->Update(key, new_value, "", value, "",
          duration, env_->node_containers_[i]->securifier());
      EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                  env_->node_containers_[i]->wait_for_update_functor()));
      env_->node_containers_[i]->GetAndResetUpdateResult(&result);
    }
    if (test_node_index == i)
      EXPECT_EQ(kSuccess, result);
    else
      EXPECT_NE(kSuccess, result);
  }

  // verify updating a deleted key,value succeeds for original storing node
  result = kPendingResult;
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    chosen_container->Delete(key, new_value, "",
                             chosen_container->securifier());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
              chosen_container->wait_for_delete_functor()));
    chosen_container->GetAndResetDeleteResult(&result);
  }
  EXPECT_EQ(kSuccess, result);
  result = kPendingResult;
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    chosen_container->Update(key, value, "", new_value, "",
        duration, chosen_container->securifier());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                chosen_container->wait_for_update_functor()));
    chosen_container->GetAndResetUpdateResult(&result);
  }
  EXPECT_EQ(kSuccess, result);
  result = kPendingResult;
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    chosen_container->FindValue(key, chosen_container->securifier());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                chosen_container->wait_for_find_value_functor()));
    chosen_container->GetAndResetFindValueResult(&find_value_returns);
  }
  EXPECT_EQ(kSuccess, find_value_returns.return_code);
  EXPECT_EQ(value, find_value_returns.values_and_signatures[0].first);
  EXPECT_TRUE(chosen_container->securifier()->Validate(value,
              find_value_returns.values_and_signatures[0].second, "",
              chosen_container->securifier()->kSigningPublicKey(), "", ""));

  // verify single value is updated correctly out of multiple values
  // stored under a key
  std::vector<std::string> values;
  size_t values_size(5);
  for (size_t index = 0; index < values_size; ++index)
     values.push_back(RandomString(RandomUint32() % 1000 + 24));
  for (size_t index = 0; index < values_size; ++index) {
    {
      boost::mutex::scoped_lock lock(env_->mutex_);
      chosen_container->Store(key, values[index], "", duration,
                              chosen_container->securifier());
      EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                  chosen_container->wait_for_store_functor()));
      chosen_container->GetAndResetStoreResult(&result);
    }
    EXPECT_EQ(kSuccess, result);
    result = kPendingResult;
  }
  size_t index = RandomUint32() % values_size;
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    chosen_container->Update(key, new_value, "", values[index], "", duration,
                             chosen_container->securifier());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                chosen_container->wait_for_update_functor()));
    chosen_container->GetAndResetUpdateResult(&result);
  }
  EXPECT_EQ(kSuccess, result);
  result = kPendingResult;
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    chosen_container->FindValue(key, chosen_container->securifier());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                chosen_container->wait_for_find_value_functor()));
    chosen_container->GetAndResetFindValueResult(&find_value_returns);
    EXPECT_EQ(kSuccess, find_value_returns.return_code);
    std::vector<std::string> returned_values;
    for (size_t i(0); i != find_value_returns.values_and_signatures.size(); ++i)
      returned_values.push_back(
          find_value_returns.values_and_signatures.at(i).first);
    EXPECT_NE(returned_values.end(), std::find(returned_values.begin(),
                                               returned_values.end(),
                                               new_value));
    EXPECT_EQ(returned_values.end(), std::find(returned_values.begin(),
                                               returned_values.end(),
                                               values[index]));
    for (size_t i = 0; i < values_size; ++i) {
      if (i != index) {
        EXPECT_NE(returned_values.end(), std::find(returned_values.begin(),
                                                   returned_values.end(),
                                                   values[i]));
      }
    }
  }
}

TEST_P(NodeImplTest, FUNC_StoreRefresh) {
  auto itr(env_->node_containers_.begin()), refresh_node(itr);
  for (; itr != env_->node_containers_.end(); ++itr) {
    if (WithinKClosest((*itr)->node()->contact().node_id(), far_key_,
                       env_->node_ids_, env_->k_)) {
      refresh_node = itr;
      break;
    }
  }

  const_cast<bptime::seconds&>(GetDataStore(*refresh_node)->kRefreshInterval_) =
      bptime::seconds(10);

  std::vector<std::string> values;
  const int kNumValues(4);
  for (int i = 0; i != kNumValues; ++i)
    values.push_back(RandomString(RandomUint32() % 1024));
  bptime::time_duration duration(bptime::pos_infin);
  int result(kPendingResult);
  for (int i = 0; i != kNumValues; ++i) {
    result = kPendingResult;
    {
      boost::mutex::scoped_lock lock(env_->mutex_);
      test_container_->Store(far_key_, values[i], "", duration,
                             test_container_->securifier());
      EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                             test_container_->wait_for_store_functor()));
      test_container_->GetAndResetStoreResult(&result);
    }
    EXPECT_EQ(kSuccess, result);
  }

  // Assert test_container_ didn't store the value
  if (!client_only_node_)
    ASSERT_FALSE(GetDataStore(test_container_)->HasKey(far_key_.String()));

  // Ensure k closest hold the value and tag the one to leave
  itr = env_->node_containers_.begin();
  auto node_to_leave(itr);
  for (; itr != env_->node_containers_.end(); ++itr) {
    if (WithinKClosest((*itr)->node()->contact().node_id(), far_key_,
                       env_->node_ids_, env_->k_)) {
      EXPECT_TRUE(GetDataStore(*itr)->HasKey(far_key_.String()));
      node_to_leave = itr;
    }
  }
  auto id_itr = std::find(env_->node_ids_.begin(), env_->node_ids_.end(),
                          (*node_to_leave)->node()->contact().node_id());
  ASSERT_NE(env_->node_ids_.end(), id_itr);
  (*node_to_leave)->node()->Leave(NULL);

  const_cast<bptime::seconds&>(GetDataStore(*refresh_node)->kRefreshInterval_) =
      bptime::seconds(3600);

  // Having set refresh time to 20 seconds, wait for 30 seconds
  Sleep(bptime::seconds(30));

  // If a refresh has happened, the current k closest should hold the value
  for (itr = env_->node_containers_.begin();
       itr != env_->node_containers_.end(); ++itr) {
    if (WithinKClosest((*itr)->node()->contact().node_id(), far_key_,
                       env_->node_ids_, env_->k_ + 1)) {
      // TODO(Fraser#5#): 2011-09-06 - Check values and deleted states.
      if (itr != node_to_leave)
        EXPECT_TRUE(GetDataStore(*itr)->HasKey(far_key_.String()));
    }
  }
}

TEST_P(NodeImplTest, FUNC_StoreRefreshInvalidSigner) {
  auto itr(env_->node_containers_.begin()), refresh_node(itr);
  for (; itr != env_->node_containers_.end(); ++itr) {
    if (WithinKClosest((*itr)->node()->contact().node_id(), far_key_,
                       env_->node_ids_, env_->k_)) {
      refresh_node = itr;
      break;
    }
  }

  std::shared_ptr<DataStore> data_store(GetDataStore(*refresh_node));
  const_cast<bptime::seconds&>(data_store->kRefreshInterval_) =
      bptime::seconds(10);

  std::vector<std::string> values;
  const int kNumValues(4);
  for (int i = 0; i != kNumValues; ++i)
    values.push_back(RandomString(RandomUint32() % 1024));
  bptime::time_duration duration(bptime::pos_infin);
  int result(kPendingResult);
  for (int i = 0; i != kNumValues; ++i) {
    result = kPendingResult;
    {
      boost::mutex::scoped_lock lock(env_->mutex_);
      test_container_->Store(far_key_, values[i], "", duration,
                             test_container_->securifier());
      EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                             test_container_->wait_for_store_functor()));
      test_container_->GetAndResetStoreResult(&result);
    }
    EXPECT_EQ(kSuccess, result);
  }

  // Assert test_container_ didn't store the value
  if (!client_only_node_)
    ASSERT_FALSE(GetDataStore(test_container_)->HasKey(far_key_.String()));

  // sign the message in datasore with a node which is not the original signer
  auto itr1(data_store->key_value_index_->get<TagKey>().find(
      far_key_.String()));
  if (itr1 != data_store->key_value_index_->end()) {
    const Key key((*itr1).key_value_signature.key);
    const bptime::seconds seconds(3600);
    std::pair<std::string, std::string> request_and_signature =
        (*refresh_node)->node()->rpcs_->MakeStoreRequestAndSignature(
            key,
            (*itr1).key_value_signature.value,
            (*itr1).key_value_signature.signature,
            seconds,
            (*refresh_node)->securifier());
    bptime::ptime now(bptime::microsec_clock::universal_time());
    KeyValueTuple tuple((*itr1).key_value_signature, now + duration,
                        now + data_store->kRefreshInterval_,
                        request_and_signature, false);
    data_store->key_value_index_->erase(itr1);
    // Try to insert key,value
    KeyValueIndex::index<TagKeyValue>::type& index_by_key_value =
        data_store->key_value_index_->get<TagKeyValue>();
    index_by_key_value.insert(tuple);
  }

  itr = env_->node_containers_.begin();
  auto node_to_leave = itr;
  for (; itr != env_->node_containers_.end(); ++itr) {
    if (WithinKClosest((*itr)->node()->contact().node_id(), far_key_,
                       env_->node_ids_, env_->k_)) {
      EXPECT_TRUE(GetDataStore(*itr)->HasKey(far_key_.String()));
      node_to_leave = itr;
    }
  }
  auto id_itr = std::find(env_->node_ids_.begin(), env_->node_ids_.end(),
                          (*node_to_leave)->node()->contact().node_id());
  ASSERT_NE(env_->node_ids_.end(), id_itr);
  (*node_to_leave)->node()->Leave(NULL);

  const_cast<bptime::seconds&>(data_store->kRefreshInterval_) =
      bptime::seconds(3600);

  // Having set refresh time to 20 seconds, wait for 30 seconds
  Sleep(bptime::seconds(30));

  bool not_refreshed(false);

  // If a refresh has happened, the current k closest should hold the value,
  // k-1 nodes should have kNumValues entries, and the new joined node
  // kNumValues - 1 entries.
  for (itr = env_->node_containers_.begin();
       itr != env_->node_containers_.end(); ++itr) {
    if (WithinKClosest((*itr)->node()->contact().node_id(), far_key_,
                       env_->node_ids_, env_->k_ + 1)) {
      if (itr != node_to_leave &&
          (GetDataStore(*itr)->key_value_index_->size() == kNumValues - 1))
        not_refreshed = true;
    }
  }
  ASSERT_TRUE(not_refreshed);
}

TEST_P(NodeImplTest, FUNC_DeleteRefresh) {
  auto itr(env_->node_containers_.begin()), refresh_node(itr);
  for (; itr != env_->node_containers_.end(); ++itr) {
    if (WithinKClosest((*itr)->node()->contact().node_id(), far_key_,
                       env_->node_ids_, env_->k_)) {
      refresh_node = itr;
      break;
    }
  }

  const_cast<bptime::seconds&>(GetDataStore(*refresh_node)->kRefreshInterval_) =
      bptime::seconds(10);

  std::vector<std::string> values;
  const int kNumValues(4);
  for (int i = 0; i != kNumValues; ++i)
    values.push_back(RandomString(RandomUint32() % 1024));
  bptime::time_duration duration(bptime::pos_infin);

  // Store the values
  int result(kPendingResult);
  for (int i = 0; i != kNumValues; ++i) {
    result = kPendingResult;
    {
      boost::mutex::scoped_lock lock(env_->mutex_);
      test_container_->Store(far_key_, values[i], "", duration,
                             test_container_->securifier());
      EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                             test_container_->wait_for_store_functor()));
      test_container_->GetAndResetStoreResult(&result);
    }
    EXPECT_EQ(kSuccess, result);
  }

  // Assert test_container_ didn't store the value
  if (!client_only_node_)
    ASSERT_FALSE(GetDataStore(test_container_)->HasKey(far_key_.String()));

  const_cast<bptime::seconds&>(GetDataStore(*refresh_node)->kRefreshInterval_) =
      bptime::seconds(10);

  // Delete all but the last value
  for (int i = 0; i != kNumValues - 1; ++i) {
    result = kPendingResult;
    {
      boost::mutex::scoped_lock lock(env_->mutex_);
      test_container_->Delete(far_key_, values[i], "",
                              test_container_->securifier());
      EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                  test_container_->wait_for_delete_functor()));
      test_container_->GetAndResetDeleteResult(&result);
    }
    EXPECT_EQ(kSuccess, result);
  }

  // Ensure k closest hold the value (albeit marked as deleted) and tag the one
  // to leave
  itr = env_->node_containers_.begin();
  auto node_to_leave(itr);
  for (; itr != env_->node_containers_.end(); ++itr) {
    if (WithinKClosest((*itr)->node()->contact().node_id(), far_key_,
                       env_->node_ids_, env_->k_)) {
      EXPECT_TRUE(GetDataStore(*itr)->HasKey(far_key_.String()));
      node_to_leave = itr;
    }
  }
  auto id_itr = std::find(env_->node_ids_.begin(), env_->node_ids_.end(),
                          (*node_to_leave)->node()->contact().node_id());
  ASSERT_NE(env_->node_ids_.end(), id_itr);
  (*node_to_leave)->node()->Leave(NULL);
  const_cast<bptime::seconds&>(GetDataStore(*refresh_node)->kRefreshInterval_) =
      bptime::seconds(3600);


  // Having set refresh time to 20 seconds, wait for 30 seconds
  Sleep(bptime::seconds(30));

  // If a refresh has happened, the current k closest should hold the value
  // (albeit marked as deleted)
  for (itr = env_->node_containers_.begin();
       itr != env_->node_containers_.end(); ++itr) {
    if (WithinKClosest((*itr)->node()->contact().node_id(), far_key_,
                       env_->node_ids_, env_->k_ + 1)) {
      // TODO(Fraser#5#): 2011-09-06 - Check values and deleted states.
      if (itr != node_to_leave)
        EXPECT_TRUE(GetDataStore(*itr)->HasKey(far_key_.String()));
    }
  }
}

TEST_P(NodeImplTest, FUNC_GetContact) {
  int result(kPendingResult);
  std::vector<Contact> contacts;
  test_container_->node()->GetAllContacts(&contacts);
  Contact not_in_rt_contact = *(contacts.begin());
  // Remove contact from routing table by incrementing failed rpc count
  for (int i = 0; i <= kFailedRpcTolerance; ++i) {
    test_container_->node()->IncrementFailedRpcs(not_in_rt_contact);
  }

  // Test that getting an online contact not held in the test container's
  // routing table succeeds
  {
    Contact contact;
    boost::mutex::scoped_lock lock(env_->mutex_);
    test_container_->GetContact(not_in_rt_contact.node_id());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                              test_container_->wait_for_get_contact_functor()));
    test_container_->GetAndResetGetContactResult(&result, &contact);
    EXPECT_EQ(not_in_rt_contact, contact);
    EXPECT_EQ(kSuccess, result);
  }

  std::vector<Contact> bootstrap_contacts;
  (*env_->node_containers_.rbegin())->node()->GetBootstrapContacts(
      &bootstrap_contacts);

  // make one of the environment containers offline
  auto offline_container = *(env_->node_containers_.begin());
  offline_container->node()->Leave(&bootstrap_contacts);
  EXPECT_FALSE(offline_container->node()->joined());
  EXPECT_FALSE(bootstrap_contacts.empty());

  result = kPendingResult;
  // Test that getting an offline contact returns no contact
  {
    Contact contact;
    boost::mutex::scoped_lock lock(env_->mutex_);
    test_container_->GetContact(offline_container->node()->contact().node_id());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                              test_container_->wait_for_get_contact_functor()));
    test_container_->GetAndResetGetContactResult(&result, &contact);
    EXPECT_EQ(Contact(), contact);
    EXPECT_EQ(kFailedToGetContact, result);
  }
  result = kPendingResult;
  {
    // bring the offline environment container back online
    boost::mutex::scoped_lock lock(env_->mutex_);
    offline_container->Join(
        offline_container->node()->contact().node_id(),
        offline_container->bootstrap_contacts());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                offline_container->wait_for_join_functor())) << debug_msg_;
    offline_container->GetAndResetJoinResult(&result);
    EXPECT_EQ(kSuccess, result) << debug_msg_;
    EXPECT_TRUE(offline_container->node()->joined()) << debug_msg_;
  }
  {
    // ping the other environment containers to make sure contact info
    // is up to date
    boost::mutex::scoped_lock lock(env_->mutex_);
    for (auto it = env_->node_containers_.begin();
         it != env_->node_containers_.end(); ++it) {
      if (offline_container->node()->contact()
        != ((*it)->node()->contact())) {
        offline_container->Ping((*it)->node()->contact());
        EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                    offline_container->wait_for_ping_functor()))
                    << debug_msg_;
        result = kPendingResult;
        offline_container->GetAndResetPingResult(&result);
      }
    }
  }
}

INSTANTIATE_TEST_CASE_P(FullOrClient, NodeImplTest, testing::Bool());

}  // namespace test
}  // namespace kademlia
}  // namespace dht
}  // namespace maidsafe
