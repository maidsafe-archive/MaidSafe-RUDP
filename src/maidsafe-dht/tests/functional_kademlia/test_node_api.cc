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

#include <exception>
#include <list>
#include <set>
#include <vector>

#include "gtest/gtest.h"
#include "boost/asio.hpp"
#include "boost/bind.hpp"
#include "boost/function.hpp"
#include "boost/cstdint.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/progress.hpp"
#include "boost/lexical_cast.hpp"

#include "maidsafe-dht/tests/functional_kademlia/test_node_environment.h"

namespace maidsafe {

namespace kademlia {

namespace node_api_test {
  const boost::uint16_t kThreadGroupSize = 3;
}   // namespace node_api_test

namespace test {

extern std::vector<std::shared_ptr<maidsafe::kademlia::Node> > nodes_;
extern std::vector<NodeId> node_ids_;
extern boost::uint16_t kNetworkSize;
extern std::vector<maidsafe::kademlia::Contact> bootstrap_contacts_;

class NodeApiTest: public testing::Test {
 protected:
  NodeApiTest()
      : asio_service_(),
        work_(),
        thread_group_(),
        securifier_(),
        transport_(),
        message_handler_(),
        alternative_store_() {}
  void SetUp() {
    rsa_key_pair.GenerateKeys(4096);
    asio_service_.reset(new boost::asio::io_service);
    work_.reset(new boost::asio::io_service::work(*asio_service_));
    thread_group_.reset(new boost::thread_group());
    for (size_t i = 0; i < node_api_test::kThreadGroupSize; ++i)
      thread_group_->create_thread(std::bind(static_cast<
          std::size_t(boost::asio::io_service::*)()>
              (&boost::asio::io_service::run), asio_service_));
    transport_.reset(new transport::TcpTransport(*asio_service_));
    EXPECT_EQ(transport::kSuccess, transport_->StartListening(
        transport::Endpoint("127.0.0.1", 8000)));
    securifier_.reset(new Securifier("", rsa_key_pair.public_key(),
                                     rsa_key_pair.private_key()));
    message_handler_.reset(new MessageHandler(securifier_));
  }
  void TearDown() {
    work_.reset();
    asio_service_->stop();
    thread_group_->join_all();
    thread_group_.reset();
  }
  ~NodeApiTest() {}

  crypto::RsaKeyPair rsa_key_pair;
  IoServicePtr asio_service_;
  WorkPtr work_;
  ThreadGroupPtr thread_group_;
  SecurifierPtr securifier_;
  TransportPtr transport_;
  MessageHandlerPtr message_handler_;
  AlternativeStorePtr alternative_store_;
 public:
  void JoinCallback(const int &result, bool *done) {
    *done = true;
  }
  void FindNodesCallback(const int &result,
                         std::vector<Contact> contacts, const int &node_id_pos,
                         bool *done) {
    *done = true;
    EXPECT_EQ(result, contacts.size());
    EXPECT_GE(nodes_[kNetworkSize - 1]->k(), contacts.size());
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
  }
};

TEST_F(NodeApiTest, BEH_KAD_Join_Client) {
  std::shared_ptr<Node> node;
  node.reset(new Node(asio_service_, transport_, message_handler_, securifier_,
                      alternative_store_, true, 2, 1, 1,
                      bptime::seconds(3600)));
  NodeId node_id(NodeId::kRandomId);
  nodes_.push_back(node);
  ++kNetworkSize;
  bool done(false);
  JoinFunctor jf = boost::bind(&NodeApiTest::JoinCallback, this, _1, &done);
  node->Join(node_id, bootstrap_contacts_, jf);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  EXPECT_EQ(size_t(kNetworkSize), nodes_.size());
  ASSERT_TRUE(nodes_[kNetworkSize -1]->client_only_node());
  ASSERT_TRUE(nodes_[kNetworkSize -1]->joined());
  nodes_[kNetworkSize - 1]->Leave(NULL);
  nodes_.pop_back();
  --kNetworkSize;
}

TEST_F(NodeApiTest, BEH_KAD_Join_Server) {
  std::shared_ptr<Node::Impl> node;
  node.reset(new Node::Impl(asio_service_, transport_, message_handler_,
                            securifier_, alternative_store_, false, 2, 1, 1,
                            bptime::seconds(3600)));
  NodeId node_id(NodeId::kRandomId);
  bool done(false);
  JoinFunctor jf = boost::bind(&NodeApiTest::JoinCallback, this, _1, &done);
  node->Join(node_id, bootstrap_contacts_, jf);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));

  EXPECT_EQ(size_t(kNetworkSize), nodes_.size());

  ASSERT_FALSE(node->client_only_node());
  ASSERT_TRUE(node->joined());
  ASSERT_TRUE(node->refresh_thread_running());
  ASSERT_TRUE(node->downlist_thread_running());
  node->Leave(NULL);
}

TEST_F(NodeApiTest, BEH_KAD_Find_Nodes) {
  std::shared_ptr<Node> node;
  node.reset(new Node(asio_service_, transport_, message_handler_, securifier_,
                      alternative_store_, true, 2, 1, 1,
                      bptime::seconds(3600)));
  NodeId node_id(NodeId::kRandomId);
  node_ids_.push_back(node_id);
  nodes_.push_back(node);
  ++kNetworkSize;
  bool done(false);
  JoinFunctor jf = boost::bind(&NodeApiTest::JoinCallback, this, _1, &done);
  node->Join(node_id, bootstrap_contacts_, jf);
  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  done = false;
  //  set node_id_pos for node to be searched and latter check for this node
  //  into list of output contacts
  int node_id_pos(0);
  FindNodesFunctor fnf = boost::bind(&NodeApiTest::FindNodesCallback, this, _1,
                                     _2, node_id_pos, &done);
  nodes_[kNetworkSize - 1]->FindNodes(nodes_[node_id_pos]->contact().node_id(),
                                      fnf);
  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  nodes_[kNetworkSize - 1]->Leave(NULL);
  nodes_.pop_back();
  node_ids_.pop_back();
  --kNetworkSize;
}


}  // namespace test

}  // namespace kademlia

}  // namespace maidsafe
