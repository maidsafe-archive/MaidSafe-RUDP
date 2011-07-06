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

#include <bitset>
#include <array>

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

namespace arg = std::placeholders;
namespace bptime = boost::posix_time;

namespace maidsafe {
namespace dht {
namespace kademlia {
namespace test {

namespace {
const boost::uint16_t kTest = 4;
const boost::uint16_t kAlpha = 3;
const boost::uint16_t kBeta = 2;
const size_t kNumberOfNodes = 10;
const boost::uint16_t kThreadGroupSize = 3;
const int kPending(9999999);
}  // unnamed namespace


class TestNodeAlternativeStore : public AlternativeStore {
 public:
  ~TestNodeAlternativeStore() {}
  bool Has(const std::string&) const { return false; }
};

class NodeImplTest : public testing::Test {
 public:
  void JoinFunction(int result_in, int *result_out) {
    boost::mutex::scoped_lock lock(mutex_);
    *result_out = result_in;
    cond_var_.notify_one();
  }

  void FindNodesFunction(int /*result*/,
                         std::vector<Contact> contacts,
                         std::vector<Contact>& k_closest) {
    k_closest = contacts;
    found_nodes_ = true;
  }

  void StoreValueFunction(int result) {
    std::cout << "StoreValueFunction " << result << std::endl;
    store_count_ = result;
    stored_value_ = true;
  }

  void FindValueFunction(int /*result*/,
                         std::vector<std::string> /*values*/,
                         std::vector<Contact> /*k_closest*/,
                         Contact /*store_contact*/,
                         Contact /*cache_contact*/) {
    found_value_ = true;
  }

  void DeleteFunction(int result) {
    std::cout << "DeleteFunction " << result << std::endl;
    delete_count_ = result;
    deleted_value_ = true;
  }

  void GetContactFunction(int /*result*/, Contact /*contact*/) {
    found_contact_ = true;
  }

  bool ResultReady(int *result) { return *result != kPending; }

 protected:
  typedef std::shared_ptr<boost::asio::io_service::work> WorkPtr;
  typedef std::shared_ptr<boost::thread_group> ThreadGroupPtr;
  NodeImplTest() : asio_services_(),
                   works_(),
                   thread_groups_(),
                   node_ids_(),
                   public_keys_(),
                   other_infos_(),
                   transports_(),
                   message_handlers_(),
                   nodes_(),
                   found_nodes_(false),
                   stored_value_(false),
                   found_value_(false),
                   deleted_value_(false),
                   found_contact_(false),
                   store_count_(0),
                   delete_count_(0),
                   mutex_(),
                   cond_var_(),
                   kTimeout_(bptime::seconds(10)) {}


  void SetUp() {
    maidsafe::crypto::RsaKeyPair rsa_key_pair;
    for (size_t i = 0; i != kNumberOfNodes; ++i) {
      ThreadGroupPtr local_thread_group(new boost::thread_group());
      asio_services_.push_back(std::shared_ptr<boost::asio::io_service>(
                               new boost::asio::io_service));
      works_.push_back(WorkPtr(new boost::asio::io_service::work(
          *asio_services_[i])));

      for (int j = 0; j != kThreadGroupSize; ++j) {
        local_thread_group->create_thread(
            std::bind(static_cast<size_t(boost::asio::io_service::*)()>(
                &boost::asio::io_service::run), asio_services_[i]));
      }

      thread_groups_.push_back(local_thread_group);
      node_ids_.push_back(NodeId(NodeId::kRandomId));
      rsa_key_pair.GenerateKeys(4096);
      public_keys_.push_back(rsa_key_pair.public_key());
      other_infos_.push_back(crypto::AsymSign(rsa_key_pair.public_key(),
                                              rsa_key_pair.private_key()));
      std::shared_ptr<Securifier> securifier(new Securifier(
          node_ids_[i].String(), rsa_key_pair.public_key(),
          rsa_key_pair.private_key()));
      transports_.push_back(TransportPtr(
          new transport::TcpTransport(*asio_services_[i])));
      message_handlers_.push_back(MessageHandlerPtr(
          new MessageHandler(securifier)));
      nodes_.push_back(std::shared_ptr<Node::Impl>(new Node::Impl(
          *asio_services_[i], transports_[i], message_handlers_[i], securifier,
          AlternativeStorePtr(new TestNodeAlternativeStore), false, kTest,
          kAlpha, kBeta, bptime::seconds(30))));

      int attempts(0), max_attempts(5);
      transport::Endpoint endpoint("127.0.0.1",
                                   Port((RandomUint32() % 55535) + 10000));
      while (transport::kSuccess != transports_[i]->StartListening(endpoint) &&
             (attempts != max_attempts)) {
        endpoint.port = static_cast<Port>((RandomUint32() % 55535) + 10000);
        ++attempts;
      }
      ASSERT_NE(0, transports_[i]->listening_port());
      transports_[i]->on_message_received()->connect(
        transport::OnMessageReceived::element_type::slot_type(
            &MessageHandler::OnMessageReceived, message_handlers_[i].get(),
            _1, _2, _3, _4).track_foreign(message_handlers_[i]));
      std::cout << "Node #" << i << " " << node_ids_[i].ToStringEncoded(NodeId::kHex).substr(0, 8) << " created." << std::endl;
    }

    std::vector<Contact> contacts;
    Contact contact(node_ids_[0],
                    transports_[0]->transport_details().endpoint,
                    std::vector<transport::Endpoint>(1,
                        transports_[0]->transport_details().endpoint),
                    transports_[0]->transport_details().rendezvous_endpoint,
                    false, false, node_ids_[0].String(), public_keys_[0],
                    other_infos_[0]);
    contacts.push_back(contact);
    int result(kPending);
    JoinFunctor join_functor =
        std::bind(&NodeImplTest::JoinFunction, this, arg::_1, &result);
    boost::function<bool()> wait_functor =
        boost::bind(&NodeImplTest::ResultReady, this, &result);
    {
      boost::mutex::scoped_lock lock(mutex_);
      nodes_[0]->Join(node_ids_[0], contacts, join_functor);
      ASSERT_TRUE(cond_var_.timed_wait(lock, kTimeout_, wait_functor));
    }
                                                                    ASSERT_EQ(1, result);
    ASSERT_TRUE(nodes_[0]->joined());
    std::cout << "Node #0 joined." << std::endl;

    for (size_t i = 1; i != kNumberOfNodes; ++i) {
      {
        result = kPending;
        boost::mutex::scoped_lock lock(mutex_);
        nodes_[i]->Join(node_ids_[i], contacts, join_functor);
        ASSERT_TRUE(cond_var_.timed_wait(lock, kTimeout_, wait_functor));
      }
      ASSERT_EQ(transport::kSuccess, result);
      ASSERT_TRUE(nodes_[i]->joined());
      std::cout << "Node #" << i << " joined." << std::endl;
    }
    std::cout << "----------------------------------------------" << std::endl << std::endl;
  }

  void TearDown() {
    for (std::size_t i = kNumberOfNodes - 1; i != -1; --i)
      nodes_[i]->Leave(NULL);
  }


  std::vector<std::shared_ptr<boost::asio::io_service>> asio_services_;
  std::vector<WorkPtr> works_;
  std::vector<ThreadGroupPtr> thread_groups_;
  std::vector<NodeId> node_ids_;
  std::vector<std::string> public_keys_;
  std::vector<std::string> other_infos_;
  std::vector<TransportPtr> transports_;
  std::vector<MessageHandlerPtr> message_handlers_;
  std::vector<std::shared_ptr<Node::Impl>> nodes_;
  bool found_nodes_, stored_value_, found_value_, deleted_value_,
       found_contact_;
  int store_count_, delete_count_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  const bptime::time_duration kTimeout_;
};  // NodeImplTest

TEST_F(NodeImplTest, BEH_KAD_FindNodes) {
  std::vector<Contact> k_closest;
  std::function<void(int,std::vector<Contact>)> find_nodes = std::bind(
      &NodeImplTest::FindNodesFunction, this,
      arg::_1, arg::_2, std::ref(k_closest));
  for (std::size_t i = 0; i != kNumberOfNodes; ++i) { 
    NodeId node_id(nodes_[i]->contact().node_id());
    nodes_[i]->FindNodes(node_id, find_nodes);
    while (!found_nodes_)
      Sleep(boost::posix_time::milliseconds(100));
    SortContacts(node_id, &k_closest);
    for (std::size_t j = 1; j != kTest; ++j)
      ASSERT_TRUE(CloserToTarget(k_closest[j-1].node_id(),
          k_closest[j], node_id));
    found_nodes_ = false;
  }
  k_closest.clear();
  NodeId node_id(NodeId::kRandomId);
  for (std::size_t i = 0; i != kNumberOfNodes; ++i) { 
    nodes_[i]->FindNodes(node_id, find_nodes);
    while (!found_nodes_)
      Sleep(boost::posix_time::milliseconds(100));
    SortContacts(node_id, &k_closest);
    for (std::size_t j = 1; j != kTest; ++j)
      ASSERT_TRUE(CloserToTarget(k_closest[j-1].node_id(),
          k_closest[j], node_id));
    found_nodes_ = false;
  }
}

TEST_F(NodeImplTest, BEH_KAD_Store) {
  std::function<void(int)> store_value = std::bind(
      &NodeImplTest::StoreValueFunction, this, arg::_1);
  maidsafe::crypto::RsaKeyPair rsa_key_pair;
  // boost::posix_time::seconds duration(3600);
  boost::posix_time::time_duration duration(0, 1, 0);

  std::size_t size = RandomUint32() % 1024;
  std::string value = RandomString(size);
  rsa_key_pair.GenerateKeys(4096);
  std::shared_ptr<Securifier> securifier;
  NodeId node_id(NodeId::kRandomId);
  std::vector<NodeId> nodeids(node_ids_);
  SortIds(node_id, &nodeids);
  std::size_t i = 0;
  for (; i != kNumberOfNodes; ++i)
    if (nodes_[i]->contact().node_id() == nodeids.back())
      break;

  nodes_[i]->Store(node_id, value, "", duration, securifier, store_value);
  while (!stored_value_)
    Sleep(boost::posix_time::milliseconds(100));
  stored_value_ = false;

  for (size_t i = 0; i != kTest; ++i) {
    for (size_t j = 0; j != kNumberOfNodes; ++j) {
      if (nodes_[j]->contact().node_id() == nodeids[i]) {
        ASSERT_TRUE(nodes_[j]->data_store_->HasKey(node_id.String()))
          << nodes_[j]->
             contact().node_id().ToStringEncoded(NodeId::kHex).substr(0, 8);
        break;
      }
    }
  }
  // Sleep for a while then test again...
  Sleep(boost::posix_time::seconds(120));
  for (size_t i = 0; i != kTest; ++i) {
    for (size_t j = 0; j != kNumberOfNodes; ++j) {
      if (nodes_[j]->contact().node_id() == nodeids[i]) {
        ASSERT_FALSE(nodes_[j]->data_store_->HasKey(node_id.String()))
          << nodes_[j]->
             contact().node_id().ToStringEncoded(NodeId::kHex).substr(0, 8);
        break;
      }
    }
  }
}

TEST_F(NodeImplTest, BEH_KAD_FindValue) {
  std::function<void(int)> store_value = std::bind(
      &NodeImplTest::StoreValueFunction, this, arg::_1);
  std::function<void(int, std::vector<std::string>, std::vector<Contact>,
      Contact, Contact)> find_value = std::bind(
      &NodeImplTest::FindValueFunction, this, arg::_1,
      arg::_2, arg::_3, arg::_4,
      arg::_5);
  maidsafe::crypto::RsaKeyPair rsa_key_pair;
  boost::posix_time::seconds duration(10);
  // boost::posix_time::time_duration duration(24, 0, 0);
  for (std::size_t i = 1; i != kNumberOfNodes; ++i) {
    std::size_t size = RandomUint32() % 1024;
    std::string value = RandomString(size);
    rsa_key_pair.GenerateKeys(4096);
    std::shared_ptr<Securifier> securifier(new Securifier(
      nodes_[i]->contact().node_id().String(), rsa_key_pair.public_key(),
      rsa_key_pair.private_key()));
    nodes_[i]->Store(nodes_[i-1]->contact().node_id(), value,
        securifier->Sign(value), duration, securifier, store_value);
    while (!stored_value_)
      Sleep(boost::posix_time::milliseconds(100));
    stored_value_ = false;
    nodes_[i]->FindValue(nodes_[i-1]->contact().node_id(), securifier,
        find_value);
    while (!found_value_)
      Sleep(boost::posix_time::milliseconds(100));
    found_value_ = false;
  }
}

TEST_F(NodeImplTest, BEH_KAD_Ping) {
  
}

TEST_F(NodeImplTest, BEH_KAD_Delete) {
  std::function<void(int)> store_value = std::bind(
      &NodeImplTest::StoreValueFunction, this, arg::_1);
  std::function<void(int)> delete_value = std::bind(
      &NodeImplTest::DeleteFunction, this, arg::_1);
  maidsafe::crypto::RsaKeyPair rsa_key_pair;
  // boost::posix_time::seconds duration(10);
  boost::posix_time::time_duration duration(0, 0, 30);
 
  std::size_t size = RandomUint32() % 1024;
  std::string value = RandomString(size);
  rsa_key_pair.GenerateKeys(4096);
  std::shared_ptr<Securifier> securifier;
  NodeId node_id(NodeId::kRandomId);
  std::vector<NodeId> nodeids(node_ids_);
  SortIds(node_id, &nodeids);
  std::size_t i = 0;
  for (; i != kNumberOfNodes; ++i)
    if (nodes_[i]->contact().node_id() == nodeids.back())
      break;
  nodes_[i]->Store(node_id, value, "", duration, securifier, store_value);
  while (!stored_value_)
    Sleep(boost::posix_time::milliseconds(100));
  stored_value_ = false;
  nodes_[i]->Delete(node_id, value, "", securifier, delete_value);
  while (!deleted_value_)
    Sleep(boost::posix_time::milliseconds(100));
  deleted_value_ = false;
  ASSERT_EQ(store_count_, delete_count_);
}

TEST_F(NodeImplTest, BEH_KAD_StoreRefresh) {
  std::function<void(int)> store_value = std::bind(
      &NodeImplTest::StoreValueFunction, this, arg::_1);
  maidsafe::crypto::RsaKeyPair rsa_key_pair;
  boost::posix_time::seconds duration(-1);
  std::size_t size = RandomUint32() % 1024;
  std::string value = RandomString(size);
  rsa_key_pair.GenerateKeys(4096);
  std::shared_ptr<Securifier> securifier;
  NodeId node_id(NodeId::kRandomId);
  std::vector<NodeId> nodeids(node_ids_);
  SortIds(node_id, &nodeids);
  std::size_t i = 0;
  for (; i != kNumberOfNodes; ++i)
    if (nodes_[i]->contact().node_id() == nodeids.back())
      break;
  // Store the value via nodes_[i]...
  nodes_[i]->Store(node_id, value, "", duration, securifier, store_value);
  while (!stored_value_)
    Sleep(boost::posix_time::milliseconds(100));
  stored_value_ = false;
  
  size = RandomUint32() % (kTest - 1);
  std::size_t count = kNumberOfNodes + 1;
  std::array<std::size_t, kTest+1> nodevals1, nodevals2; 
  // Ensure k closest hold the value and tag the one to leave...
  for (size_t i = 0; i != kTest; ++i) {
    for (size_t j = 0; j != kNumberOfNodes; ++j) {
      if (nodes_[j]->contact().node_id() == nodeids[i]) {
        if (i == size)
          count = j;
        ASSERT_TRUE(nodes_[j]->data_store_->HasKey(node_id.String()));
        nodevals1[i] = j;
        break;
      }
    }
  }
  // Let tagged node leave...
  ASSERT_NE(count, kNumberOfNodes + 1); 
  std::vector<Contact> bootstrap_contacts;
  nodes_[count]->Leave(&bootstrap_contacts);
  // Having set refresh time to 30 seconds, wait for 60 seconds...
  Sleep(boost::posix_time::seconds(60)); 
  // The kTest element of nodeids should now hold the value if a refresh
  // has occurred...
  /*for (size_t j = 0; j != kNumberOfNodes; ++j) {
    if (nodes_[j]->contact().node_id() == nodeids[kTest]) {
      ASSERT_TRUE(nodes_[j]->data_store_->HasKey(node_id.String()));
      break;
    }
  }*/
  for (size_t i = 0, j = 0; j != kNumberOfNodes; ++j) {
    if (nodes_[j]->data_store_->HasKey(node_id.String())) {
      nodevals2[i] = j;
      ++i;
    }
  }
  //for (size_t i = 0; i != kTest; ++i) {
  //  for (size_t j = 0; j != kNumberOfNodes; ++j) {
  //    //if (j == count)
  //    //  continue;
  //    if (nodes_[j]->contact().node_id() == nodeids[i]) {
  //      ASSERT_TRUE(nodes_[j]->data_store_->HasKey(node_id.String()));
  //      nodevals2[i] = j;
  //      break;
  //    }
  //  }
  //}
  ASSERT_NE(nodevals1, nodevals2);
}

TEST_F(NodeImplTest, BEH_KAD_DeleteRefresh) {
  std::function<void(int)> store_value = std::bind(
      &NodeImplTest::StoreValueFunction, this, arg::_1);
  std::function<void(int)> delete_value = std::bind(
      &NodeImplTest::DeleteFunction, this, arg::_1);
  maidsafe::crypto::RsaKeyPair rsa_key_pair;
  boost::posix_time::seconds duration(-1);
  std::size_t size = RandomUint32() % 1024;
  std::string value = RandomString(size);
  rsa_key_pair.GenerateKeys(4096);
  std::shared_ptr<Securifier> securifier;
  NodeId node_id(NodeId::kRandomId);
  std::vector<NodeId> nodeids(node_ids_);
  SortIds(node_id, &nodeids);
  std::size_t i = 0, storing_node;
  for (; i != kNumberOfNodes; ++i)
    if (nodes_[i]->contact().node_id() == nodeids.back())
      break;
  // Store the value via nodes_[i]...
  storing_node = i;
  nodes_[storing_node]->Store(node_id, value, "", duration, securifier, store_value);
  while (!stored_value_)
    Sleep(boost::posix_time::milliseconds(100));
  stored_value_ = false;
  
  size = RandomUint32() % (kTest - 1);
  std::size_t leave_node = kNumberOfNodes + 1;
  std::array<std::size_t, kTest+1> nodevals1;
  // Ensure k closest hold the value and tag the one to leave...
  for (size_t i = 0; i != kTest; ++i) {
    for (size_t j = 0; j != kNumberOfNodes; ++j) {
      if (nodes_[j]->contact().node_id() == nodeids[i]) {
        if (i == size)
          leave_node = j;
        ASSERT_TRUE(nodes_[j]->data_store_->HasKey(node_id.String()))
          << nodes_[j]->
             contact().node_id().ToStringEncoded(NodeId::kHex).substr(0, 8);
        nodevals1[i] = j;
        break;
      }
    }
  }
  // Let tagged node leave...
  ASSERT_NE(leave_node, kNumberOfNodes + 1); 
  std::vector<Contact> bootstrap_contacts;
  nodes_[leave_node]->Leave(&bootstrap_contacts);
  // Delete the value...
  nodes_[storing_node]->Delete(node_id, value, "", securifier, delete_value);
  // Ensure no currently joined node claims to have the value...
  std::vector<std::pair<std::string, std::string>> values;
  for (size_t i = 0; i != kNumberOfNodes; ++i) {
    if (i != leave_node) {
      ASSERT_FALSE(nodes_[i]->data_store_->GetValues(node_id.String(), &values));
    }
  }
  // Ensure no currently joined node has the value...
//  for (size_t j = 0; j != kNumberOfNodes; ++j)
//    if (j != leave_node)
//      ASSERT_FALSE(nodes_[j]->data_store_->HasKey(node_id.String()));
  // Allow node to rejoin the network...
  int join_result(kPending);
  JoinFunctor join_functor =
      std::bind(&NodeImplTest::JoinFunction, this, arg::_1, &join_result);
  std::function<bool()> wait_functor =
      std::bind(&NodeImplTest::ResultReady, this, &join_result);
  std::vector<Contact> contacts;
  for (size_t j = 0; j != kNumberOfNodes; ++j) {
    if (nodes_[leave_node]->contact().node_id() == nodeids[i]) {
      nodes_[leave_node]->GetBootstrapContacts(&contacts);
      {
        join_result = kPending;
        boost::mutex::scoped_lock lock(mutex_);
        nodes_[leave_node]->Join(node_ids_[i], contacts, join_functor);
        ASSERT_TRUE(cond_var_.timed_wait(lock, kTimeout_, wait_functor));
      }
      ASSERT_EQ(transport::kSuccess, join_result);
      ASSERT_TRUE(nodes_[leave_node]->joined());
      break;
    }
  }
  // Sleep for a while...
  Sleep(boost::posix_time::seconds(360));
  // Now make sure the value has been deleted from all nodes in network...
  for (size_t j = 0; j != kNumberOfNodes; ++j) {
    ASSERT_FALSE(nodes_[j]->data_store_->HasKey(node_id.String()));
  }
}

TEST_F(NodeImplTest, BEH_KAD_Downlist) {
}

}  // namespace test
}  // namespace kademlia
}  // namespace dht
}  // namespace maidsafe