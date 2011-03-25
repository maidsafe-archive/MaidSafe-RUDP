/* Copyright (c) 2011 maidsafe.net limited
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
#include <bitset>
#include <memory>

#include "gtest/gtest.h"
#include "boost/lexical_cast.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/thread.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/enable_shared_from_this.hpp"

#include "maidsafe-dht/transport/tcp_transport.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-dht/kademlia/config.h"
#include "maidsafe-dht/kademlia/rpcs.pb.h"
#include "maidsafe-dht/kademlia/securifier.h"
#include "maidsafe-dht/kademlia/utils.h"
#include "maidsafe-dht/kademlia/service.h"
#include "maidsafe-dht/kademlia/rpcs.h"
#include "maidsafe-dht/kademlia/node_id.h"
#include "maidsafe-dht/kademlia/routing_table.h"
#include "maidsafe-dht/kademlia/message_handler.h"

namespace maidsafe {

namespace kademlia {

namespace test {

static const boost::uint16_t k = 16;

void TestPingCallback(RankInfoPtr,
                      int callback_code,
                      bool *done,
                      int *response_code) {
  *done = true;
  *response_code = callback_code;
}

void TestFindNodesCallback(RankInfoPtr,
                           int callback_code,
                           std::vector<Contact> contacts,
                           std::vector<Contact> *contact_list,
                           bool *done,
                           int *response_code) {
  *done = true;
  *response_code = callback_code;
  *contact_list = contacts;
}

class CreateContactAndNodeId {
 public:
  CreateContactAndNodeId() : contact_(), node_id_(NodeId::kRandomId),
                   routing_table_(new RoutingTable(node_id_, test::k)) {}

  NodeId GenerateUniqueRandomId(const NodeId& holder, const int& pos) {
    std::string holder_id = holder.ToStringEncoded(NodeId::kBinary);
    std::bitset<kKeySizeBits> holder_id_binary_bitset(holder_id);
    NodeId new_node;
    std::string new_node_string;
    bool repeat(true);
    boost::uint16_t times_of_try(0);
    // generate a random ID and make sure it has not been generated previously
    do {
      new_node = NodeId(NodeId::kRandomId);
      std::string new_id = new_node.ToStringEncoded(NodeId::kBinary);
      std::bitset<kKeySizeBits> binary_bitset(new_id);
      for (int i = kKeySizeBits - 1; i >= pos; --i)
        binary_bitset[i] = holder_id_binary_bitset[i];
      binary_bitset[pos].flip();
      new_node_string = binary_bitset.to_string();
      new_node = NodeId(new_node_string, NodeId::kBinary);
      // make sure the new contact not already existed in the routing table
      Contact result;
      routing_table_->GetContact(new_node, &result);
      if (result == Contact())
        repeat = false;
      ++times_of_try;
    } while (repeat && (times_of_try < 1000));
    // prevent deadlock, throw out an error message in case of deadlock
    if (times_of_try == 1000)
      EXPECT_LT(1000, times_of_try);
    return new_node;
  }

  Contact GenerateUniqueContact(const NodeId& holder, const int& pos,
                                RoutingTableContactsContainer& gnerated_nodes,
                                NodeId target) {
    std::string holder_id = holder.ToStringEncoded(NodeId::kBinary);
    std::bitset<kKeySizeBits> holder_id_binary_bitset(holder_id);
    NodeId new_node;
    std::string new_node_string;
    bool repeat(true);
    boost::uint16_t times_of_try(0);
    Contact new_contact;
    // generate a random contact and make sure it has not been generated
    // within the previously record
    do {
      new_node = NodeId(NodeId::kRandomId);
      std::string new_id = new_node.ToStringEncoded(NodeId::kBinary);
      std::bitset<kKeySizeBits> binary_bitset(new_id);
      for (int i = kKeySizeBits - 1; i >= pos; --i)
        binary_bitset[i] = holder_id_binary_bitset[i];
      binary_bitset[pos].flip();
      new_node_string = binary_bitset.to_string();
      new_node = NodeId(new_node_string, NodeId::kBinary);

      // make sure the new one hasn't been set as down previously
      ContactsById key_indx = gnerated_nodes.get<NodeIdTag>();
      auto it = key_indx.find(new_node);
      if (it == key_indx.end()) {
        new_contact = ComposeContact(new_node, 5000);
        RoutingTableContact new_routing_table_contact(new_contact,
                                                      target,
                                                      0);
        gnerated_nodes.insert(new_routing_table_contact);
        repeat = false;
      }
      ++times_of_try;
    } while (repeat && (times_of_try < 1000));
    // prevent deadlock, throw out an error message in case of deadlock
    if (times_of_try == 1000)
      EXPECT_LT(1000, times_of_try);
    return new_contact;
  }

  NodeId GenerateRandomId(const NodeId& holder, const int& pos) {
    std::string holder_id = holder.ToStringEncoded(NodeId::kBinary);
    std::bitset<kKeySizeBits> holder_id_binary_bitset(holder_id);
    NodeId new_node;
    std::string new_node_string;

    new_node = NodeId(NodeId::kRandomId);
    std::string new_id = new_node.ToStringEncoded(NodeId::kBinary);
    std::bitset<kKeySizeBits> binary_bitset(new_id);
    for (int i = kKeySizeBits - 1; i >= pos; --i)
      binary_bitset[i] = holder_id_binary_bitset[i];
    binary_bitset[pos].flip();
    new_node_string = binary_bitset.to_string();
    new_node = NodeId(new_node_string, NodeId::kBinary);

    return new_node;
  }

  Contact ComposeContact(const NodeId& node_id,
                         boost::uint16_t port) {
    std::string ip("127.0.0.1");
    std::vector<transport::Endpoint> local_endpoints;
    transport::Endpoint end_point(ip, port);
    local_endpoints.push_back(end_point);
    Contact contact(node_id, end_point, local_endpoints, end_point, false,
                    false, "", "", "");
    return contact;
  }

  Contact ComposeContactWithKey(const NodeId& node_id,
                                boost::uint16_t port,
                                const crypto::RsaKeyPair& crypto_key) {
    std::string ip("127.0.0.1");
    std::vector<transport::Endpoint> local_endpoints;
    transport::Endpoint end_point(ip, port);
    local_endpoints.push_back(end_point);
    Contact contact(node_id, end_point, local_endpoints, end_point, false,
                    false, "", crypto_key.public_key(), "");
    IP ipa = IP::from_string(ip);
    contact.SetPreferredEndpoint(ipa);
    return contact;
  }

  void PopulateContactsVector(int count,
                              const int& pos,
                              std::vector<Contact> *contacts) {
    for (int i = 0; i < count; ++i) {
      NodeId contact_id = GenerateRandomId(node_id_, pos);
      Contact contact = ComposeContact(contact_id, 5000);
      contacts->push_back(contact);
    }
  }

  Contact contact_;
  kademlia::NodeId node_id_;
  std::shared_ptr<RoutingTable> routing_table_;
};


class RpcsTest: public CreateContactAndNodeId, public testing::Test {
 public:
  RpcsTest() : node_id_(NodeId::kRandomId),
               routing_table_(new RoutingTable(node_id_, test::k)),
               data_store_(new kademlia::DataStore(bptime::seconds(3600))),
               alternative_store_(),
               asio_service_(new boost::asio::io_service()),
               local_asio_(new boost::asio::io_service()),
               rank_info_() { }

  static void SetUpTestCase() {
    sender_crypto_key_id_.GenerateKeys(4096);
    receiver_crypto_key_id_.GenerateKeys(4096);
  }

  virtual void SetUp() {
    // rpcs setup
    rpcs_securifier_ = std::shared_ptr<Securifier>(
        new Securifier("", sender_crypto_key_id_.public_key(),
                        sender_crypto_key_id_.private_key()));
    rpcs_= std::shared_ptr<Rpcs>(new Rpcs(asio_service_, rpcs_securifier_));
    NodeId rpcs_node_id = GenerateRandomId(node_id_, 502);
    rpcs_contact_ = ComposeContactWithKey(rpcs_node_id,
                                          5010,
                                          sender_crypto_key_id_);
    rpcs_->set_contact(rpcs_contact_);
    // service setup
    service_securifier_ = std::shared_ptr<Securifier>(
        new Securifier("", receiver_crypto_key_id_.public_key(),
                       receiver_crypto_key_id_.private_key()));
    service_securifier_ = std::shared_ptr<Securifier>(
        new Securifier("", receiver_crypto_key_id_.public_key(),
                       receiver_crypto_key_id_.private_key()));
    NodeId service_node_id = GenerateRandomId(node_id_, 503);
    service_contact_ = ComposeContactWithKey(service_node_id,
                                             5011,
                                             receiver_crypto_key_id_);
    service_ = std::shared_ptr<Service>(new Service(routing_table_,
                                                    data_store_,
                                                    alternative_store_,
                                                    service_securifier_,
                                                    k));
    service_->set_node_contact(service_contact_);
    service_->set_node_joined(true);
  }
  virtual void TearDown() { }

  void ListenPort() {
    local_asio_->run();
  }

  void PopulateRoutingTable(boost::uint16_t count) {
    for (int num_contact = 0; num_contact < count; ++num_contact) {
      NodeId contact_id(NodeId::kRandomId);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact, rank_info_);
    }
  }

  void AddContact(const Contact& contact, const RankInfoPtr rank_info) {
    routing_table_->AddContact(contact, rank_info);
    routing_table_->SetValidated(contact.node_id(), true);
  }

 protected:
  kademlia::NodeId  node_id_;
  std::shared_ptr<RoutingTable> routing_table_;
  std::shared_ptr<DataStore> data_store_;
  AlternativeStorePtr alternative_store_;
  SecurifierPtr service_securifier_;
  std::shared_ptr<Service> service_;
  SecurifierPtr rpcs_securifier_;
  IoServicePtr asio_service_;
  IoServicePtr local_asio_;
  std::shared_ptr<Rpcs> rpcs_;
  Contact rpcs_contact_;
  Contact service_contact_;
  static crypto::RsaKeyPair sender_crypto_key_id_;
  static crypto::RsaKeyPair receiver_crypto_key_id_;
  RankInfoPtr rank_info_;
};

crypto::RsaKeyPair RpcsTest::sender_crypto_key_id_;
crypto::RsaKeyPair RpcsTest::receiver_crypto_key_id_;

TEST_F(RpcsTest, BEH_KAD_PingNoTarget) {
  bool done(false);
  int response_code(0);

  rpcs_->Ping(rpcs_securifier_, rpcs_contact_,
              boost::bind(&TestPingCallback, _1, _2, &done, &response_code),
              kTcp);
  asio_service_->run();

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_GT(0, response_code);
  asio_service_->stop();
}

TEST_F(RpcsTest, BEH_KAD_PingTarget) {
  TransportPtr transport;
  transport.reset(new transport::TcpTransport(*local_asio_));
  MessageHandlerPtr handler(new MessageHandler(service_securifier_));
  service_->ConnectToSignals(transport, handler);
  transport->StartListening(service_contact_.endpoint());
  boost::thread th(boost::bind(&RpcsTest::ListenPort, this));
  bool done(false);
  int response_code(0);

  rpcs_->Ping(service_securifier_, service_contact_,
              boost::bind(&TestPingCallback, _1, _2, &done, &response_code),
              kTcp);
  asio_service_->run();

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(0, response_code);
  asio_service_->stop();
  local_asio_->stop();
  th.join();
}

TEST_F(RpcsTest, BEH_KAD_FindNodesEmptyRT) {
  // tests FindNodes using empty routing table
  TransportPtr transport;
  transport.reset(new transport::TcpTransport(*local_asio_));
  MessageHandlerPtr handler(new MessageHandler(service_securifier_));
  service_->ConnectToSignals(transport, handler);
  transport->StartListening(service_contact_.endpoint());
  boost::thread th(boost::bind(&RpcsTest::ListenPort, this));
  bool done(false);
  int response_code(0);
  std::vector<Contact> contact_list;
  Key key = service_contact_.node_id();

  rpcs_->FindNodes(key, service_securifier_, service_contact_,
                   boost::bind(&TestFindNodesCallback, _1, _2, _3,
                               &contact_list, &done, &response_code),
                   kTcp);
  asio_service_->run();

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(0, contact_list.size());
  ASSERT_EQ(0, response_code);
  asio_service_->stop();
  local_asio_->stop();
  th.join();
}

TEST_F(RpcsTest, BEH_KAD_FindNodesPopulatedRTnoNode) {
  // tests FindNodes with a populated routing table not containing the node
  // being sought
  TransportPtr transport;
  transport.reset(new transport::TcpTransport(*local_asio_));
  MessageHandlerPtr handler(new MessageHandler(service_securifier_));
  service_->ConnectToSignals(transport, handler);
  transport->StartListening(service_contact_.endpoint());
  boost::thread th(boost::bind(&RpcsTest::ListenPort, this));
  bool done(false);
  int response_code(0);
  std::vector<Contact> contact_list;
  PopulateRoutingTable(2*k);
  service_->set_node_contact(service_contact_);
  Key key = service_contact_.node_id();

  rpcs_->FindNodes(key, service_securifier_, service_contact_,
                   boost::bind(&TestFindNodesCallback, _1, _2, _3,
                               &contact_list, &done, &response_code),
                   kTcp);
  asio_service_->run();

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));

  bool found(false);
  auto it = contact_list.begin();
  while (it != contact_list.end()) {
    if ((*it).node_id() == service_contact_.node_id())
      found = true;
    ++it;
  }
  ASSERT_FALSE(found);
  ASSERT_EQ(k, contact_list.size());
  ASSERT_EQ(0, response_code);

  asio_service_->stop();
  local_asio_->stop();
  th.join();
}

TEST_F(RpcsTest, BEH_KAD_FindNodesPopulatedRTwithNode) {
  // tests FindNodes with a populated routing table which contains the node
  // being sought
  TransportPtr transport;
  transport.reset(new transport::TcpTransport(*local_asio_));
  MessageHandlerPtr handler(new MessageHandler(service_securifier_));
  service_->ConnectToSignals(transport, handler);
  transport->StartListening(service_contact_.endpoint());
  boost::thread th(boost::bind(&RpcsTest::ListenPort, this));
  bool done(false);
  int response_code(0);
  std::vector<Contact> contact_list;
  PopulateRoutingTable(2*k);
  service_->set_node_contact(service_contact_);
  AddContact(service_contact_, rank_info_);
  Key key = service_contact_.node_id();

  rpcs_->FindNodes(key, service_securifier_, service_contact_,
                   boost::bind(&TestFindNodesCallback, _1, _2, _3,
                               &contact_list, &done, &response_code),
                   kTcp);
  asio_service_->run();

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));

  bool found(false);
  auto it = contact_list.begin();
  while (it != contact_list.end()) {
    if ((*it).node_id() == service_contact_.node_id())
      found = true;
    ++it;
  }
  ASSERT_TRUE(found);
  ASSERT_EQ(k, contact_list.size());
  ASSERT_EQ(0, response_code);

  asio_service_->stop();
  local_asio_->stop();
  th.join();
}

}  // namespace test

}  // namespace kademlia

}  // namespace maidsafe
