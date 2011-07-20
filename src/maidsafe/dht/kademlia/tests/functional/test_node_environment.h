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

#ifndef MAIDSAFE_DHT_KADEMLIA_TESTS_FUNCTIONAL_TEST_NODE_ENVIRONMENT_H_
#define MAIDSAFE_DHT_KADEMLIA_TESTS_FUNCTIONAL_TEST_NODE_ENVIRONMENT_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/thread/condition_variable.hpp"
#include "maidsafe/common/test.h"
#include "maidsafe/common/alternative_store.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/dht/log.h"
#include "maidsafe/dht/kademlia/config.h"
#include "maidsafe/dht/kademlia/contact.h"
#include "maidsafe/dht/kademlia/return_codes.h"
#include "maidsafe/dht/kademlia/node_id.h"
#include "maidsafe/dht/kademlia/node_container.h"

namespace bptime = boost::posix_time;


namespace maidsafe {
namespace dht {
namespace kademlia {
namespace test {


class TestNodeAlternativeStore : public AlternativeStore {
 public:
  ~TestNodeAlternativeStore() {}
  bool Has(const std::string&) const { return false; }
};


template <typename NodeType>
class NodesEnvironment : public testing::Environment {
 public:
  NodesEnvironment(size_t num_full_nodes,
                   size_t num_client_nodes,
                   uint8_t threads_per_node,
                   uint16_t k,
                   uint16_t alpha,
                   uint16_t beta,
                   const bptime::time_duration &mean_refresh_interval);
  virtual void SetUp();
  virtual void TearDown();

  maidsafe::test::TestPath test_root_;
  size_t num_full_nodes_, num_client_nodes_;
  uint8_t threads_per_node_;
  uint16_t k_, alpha_, beta_;
  bptime::time_duration mean_refresh_interval_;
  std::vector<std::shared_ptr<maidsafe::dht::kademlia::NodeContainer<NodeType>>>  // NOLINT (Fraser)
      node_containers_;
  std::vector<NodeId> node_ids_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  static NodesEnvironment* g_environment() { return g_env_; }

 private:
  static NodesEnvironment* g_env_;
};


template <typename NodeType>
NodesEnvironment<NodeType>* NodesEnvironment<NodeType>::g_env_ = NULL;

template <typename NodeType>
NodesEnvironment<NodeType>::NodesEnvironment(
    size_t num_full_nodes,
    size_t num_client_nodes,
    uint8_t threads_per_node,
    uint16_t k,
    uint16_t alpha,
    uint16_t beta,
    const bptime::time_duration &mean_refresh_interval)
        : test_root_(maidsafe::test::CreateTestPath(
                     "MaidSafe_Test_Nodes_Environment")),
          num_full_nodes_(num_full_nodes),
          num_client_nodes_(num_client_nodes),
          threads_per_node_(threads_per_node),
          k_(k),
          alpha_(alpha),
          beta_(beta),
          mean_refresh_interval_(mean_refresh_interval),
          node_containers_(),
          node_ids_(),
          mutex_(),
          cond_var_() {
  g_env_ = this;
}

template <typename NodeType>
void NodesEnvironment<NodeType>::SetUp() {
  std::vector<Contact> bootstrap_contacts;
  for (size_t i = 0; i != num_client_nodes_ + num_full_nodes_; ++i) {
    std::shared_ptr<maidsafe::dht::kademlia::NodeContainer<NodeType>>
        node_container(new maidsafe::dht::kademlia::NodeContainer<NodeType>());
    node_container->Init(threads_per_node_, SecurifierPtr(),
        AlternativeStorePtr(new TestNodeAlternativeStore), false, k_,
        alpha_, beta_, mean_refresh_interval_);
    node_container->MakeAllCallbackFunctors(&mutex_, &cond_var_);

    int attempts(0), max_attempts(5), result(kPendingResult);
    Port port(static_cast<Port>((RandomUint32() % 55535) + 10000));
    while ((result = node_container->Start(bootstrap_contacts, port)) !=
           kSuccess && (attempts != max_attempts)) {
      port = static_cast<Port>((RandomUint32() % 55535) + 10000);
      ++attempts;
    }
    ASSERT_EQ(kSuccess, result);
    ASSERT_TRUE(node_container->node()->joined());
    DLOG(INFO) << "Node " << i << " joined: " << DebugId(*node_container);
    if (i < num_full_nodes_)
      bootstrap_contacts.push_back(node_container->node()->contact());
    node_containers_.push_back(node_container);
    node_ids_.push_back(node_container->node()->contact().node_id());
  }
}

template <typename NodeType>
void NodesEnvironment<NodeType>::TearDown() {
  for (auto it(node_containers_.begin()); it != node_containers_.end(); ++it)
    (*it)->Stop(NULL);
}


}   //  namespace test
}   //  namespace kademlia
}   //  namespace dht
}   //   namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_TESTS_FUNCTIONAL_TEST_NODE_ENVIRONMENT_H_
