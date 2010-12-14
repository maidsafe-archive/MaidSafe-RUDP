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

#include <gtest/gtest.h>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>

#include "maidsafe/base/log.h"
#include "maidsafe/base/routingtable.h"
#include "maidsafe/kademlia/contact.h"
#include "maidsafe/kademlia/node-api.h"
#include "maidsafe/kademlia/nodeimpl.h"
#include "maidsafe/rpcprotocol/channelmanager-api.h"
#include "maidsafe/transport/udttransport.h"
#include "maidsafe/tests/kademlia/fake_callbacks.h"


namespace kademlia {

namespace test_add_node {

static const boost::uint16_t K = 16;

class MessageHandler {
 public:
  MessageHandler(): msgs(), ids(), dead_server_(true), server_ip_(),
                    server_port_(0), id_(0), msgs_sent_(0) {}
  void OnMessage(const rpcprotocol::RpcMessage &msg,
                 const boost::uint32_t connection_id) {
    std::string message;
    msg.SerializeToString(&message);
    msgs.push_back(message);
    ids.push_back(connection_id);
  }
  void OnDeadRendezvousServer(const bool &dead_server, const std::string &ip,
                              const boost::uint16_t &port) {
    dead_server_ = dead_server;
    server_ip_ = ip;
    server_port_ = port;
  }
  void OnSend(const boost::uint32_t &, const bool &success) {
    if (success)
      msgs_sent_++;
  }
  std::list<std::string> msgs;
  std::list<boost::uint32_t> ids;
  bool dead_server_;
  std::string server_ip_;
  boost::uint16_t server_port_;
  boost::int16_t id_;
  int msgs_sent_;
 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);
};

class TestNodes : public testing::Test {
 public:
  TestNodes() : nodes_(), ch_managers_(), transports_(), transport_ports_(),
                 msg_handlers_(), datastore_dir_(2), test_dir_() {}
  virtual ~TestNodes() {}
 protected:
  void SetUp() {
    transports_.clear();
    test_dir_ = std::string("temp/TestNodes") +
                boost::lexical_cast<std::string>(base::RandomUint32());
    try {
      if (boost::filesystem::exists(test_dir_))
        boost::filesystem::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "filesystem exception: " << e.what() << std::endl;
    }

    ch_managers_.resize(2);
    transports_.resize(2);
    transport_ports_.resize(2);
    datastore_dir_.resize(2);
    NodeConstructionParameters kcp;
    kcp.type = VAULT;
    kcp.alpha = kademlia::kAlpha;
    kcp.beta = kademlia::kBeta;
    kcp.k = test_add_node::K;
    kcp.port_forwarded = false;
    kcp.private_key = "";
    kcp.public_key = "";
    kcp.refresh_time = kademlia::kRefreshTime;
    kcp.use_upnp = false;
    for (int i = 0; i < 2; ++i) {
      msg_handlers_.push_back(new MessageHandler);
      transports_[i].reset(new transport::UdtTransport);
      transport::TransportCondition tc;
      transport_ports_[i] = transports_[i]->StartListening("", 0, &tc);
      ASSERT_EQ(transport::kSuccess, tc);
      ASSERT_LT(0, transport_ports_[i]);
      kcp.port = transport_ports_[i];
      ch_managers_[i].reset(new rpcprotocol::ChannelManager(transports_[i]));
      ASSERT_EQ(0, ch_managers_[i]->Start());
      datastore_dir_[i] = test_dir_ + "/Datastore" +
                          boost::lexical_cast<std::string>(transport_ports_[i]);
      boost::filesystem::create_directories(
          boost::filesystem::path(datastore_dir_[i]));
      nodes_.push_back(KNode(ch_managers_[i], transports_[i], kcp));
      std::string s(nodes_[i].node_id().ToStringEncoded(kademlia::NodeId::kHex));
      DLOG(INFO) << "Listening port for node " <<  s.substr(0, 16) << ": "
                 << transport_ports_[i] << std::endl;
    }
  }
  void TearDown() {
    for (int i = 0; i < 2; ++i) {
      transports_[i]->StopListening(transport_ports_[i]);
      ch_managers_[i]->Stop();
      delete msg_handlers_[i];
      nodes_[i].Leave();
    }
    transports_.clear();
    try {
      if (boost::filesystem::exists(test_dir_))
        boost::filesystem::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "filesystem exception: " << e.what() << std::endl;
    }
  }
  std::vector<KNode> nodes_;
  std::vector<boost::shared_ptr<rpcprotocol::ChannelManager> > ch_managers_;
  std::vector<boost::shared_ptr<transport::UdtTransport> > transports_;
  std::vector<rpcprotocol::Port> transport_ports_;
  std::vector<MessageHandler*> msg_handlers_;
  std::vector<std::string> datastore_dir_;
  std::string test_dir_;
};

TEST_F(TestNodes, BEH_KAD_TestLastSeenNotReply) {
  if (test_add_node::K <= 2) {
    SUCCEED();
    return;
  }

  std::string kconfig_file = datastore_dir_[0] + "/.kadconfig";
  std::string id("7");
  for (int i = 1; i < kKeySizeBytes*2; ++i)
    id += "1";
  GeneralKadCallback callback;
  boost::asio::ip::address local_ip;
  ASSERT_TRUE(base::GetLocalAddress(&local_ip));
  kademlia::NodeId node_id(id, kademlia::NodeId::kHex);
  nodes_[0].JoinFirstNode(node_id, kconfig_file, local_ip.to_string(),
                          transport_ports_[0],
                          boost::bind(&GeneralKadCallback::CallbackFunc,
                                      &callback, _1));
  wait_result(&callback);
  ASSERT_TRUE(callback.result());
  callback.Reset();
  ASSERT_TRUE(nodes_[0].is_joined());

  // Adding Contacts until kbucket splits and filling kbuckets
  std::vector<std::string> bucket2ids(test_add_node::K + 1), bucket1ids(3);
  for (int i = 0; i < test_add_node::K + 1; i++) {
    for (int j = 0; j < kKeySizeBytes * 2; ++j)
      bucket2ids[i] += "f";
    std::string rep;
    int k;
    for (k = 0; k < i; ++k)
      rep += "0";
    bucket2ids[i].replace(1, k, rep);
  }
  for (int i = 0; i < 3; ++i) {
    for (int j = 0; j < kKeySizeBytes*2; j++)
      bucket1ids[i] += "7";
    std::string rep;
    int k;
    for (k = 0; k < i; ++k)
      rep += "2";
    bucket1ids[i].replace(1, k, rep);
  }
  int port = 7000;
  Contact last_seen;
  std::string ip = "127.0.0.1";
  for (int i = 1 ; i < test_add_node::K - 2; ++i) {
    kademlia::NodeId id(bucket2ids[i], kademlia::NodeId::kHex);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes_[0].AddContact(contact, 0.0, false));
    if (i == 1)
      last_seen = contact;
    ++port;
  }
  for (int i = 0; i < 3; ++i) {
    kademlia::NodeId id(bucket1ids[i], kademlia::NodeId::kHex);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes_[0].AddContact(contact, 0.0, false));
    ++port;
  }
  for (int i = test_add_node::K - 2; i < test_add_node::K + 1; ++i) {
    std::string id = base::DecodeFromHex(bucket2ids[i]);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes_[0].AddContact(contact, 0.0, false));
    ++port;
  }
  ++port;
  id = base::DecodeFromHex(bucket2ids[0]);
  Contact contact(id, ip, port, ip, port);
  ASSERT_EQ(2, nodes_[0].AddContact(contact, 0.0, false));

  Contact rec_contact;
  ASSERT_FALSE(nodes_[0].GetContact(contact.node_id(), &rec_contact));

  // waiting for the ping to the last seen contact to timeout
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(nodes_[0].GetContact(contact.node_id(), &rec_contact));
  ASSERT_TRUE(contact.Equals(rec_contact));
  ASSERT_FALSE(nodes_[0].GetContact(last_seen.node_id(), &rec_contact));

  nodes_[0].Leave();
  base::KadConfig kad_config;
  std::ifstream inputfile(kconfig_file.c_str(),
                          std::ios::in | std::ios::binary);
  ASSERT_TRUE(kad_config.ParseFromIstream(&inputfile));
  inputfile.close();
  ASSERT_EQ(test_add_node::K + 3, kad_config.contact_size());

  ASSERT_FALSE(nodes_[0].is_joined());
}

TEST_F(TestNodes, FUNC_KAD_TestLastSeenReplies) {
  if (test_add_node::K <= 2) {
    SUCCEED();
    return;
  }

  std::string kconfig_file = datastore_dir_[0] + "/.kadconfig";
  std::string kconfig_file1 = datastore_dir_[1] + "/.kadconfig";
  std::string id("7"), id2("9");
  for (int i = 1; i < kKeySizeBytes*2; ++i) {
    id += "1";
    id2 += "2";
  }
  GeneralKadCallback callback;
  boost::asio::ip::address local_ip;
  ASSERT_TRUE(base::GetLocalAddress(&local_ip));
  kademlia::NodeId kid(id, kademlia::NodeId::kHex), kid2(id2, kademlia::NodeId::kHex);
  nodes_[0].JoinFirstNode(kid, kconfig_file, local_ip.to_string(),
                          transport_ports_[0],
                          boost::bind(&GeneralKadCallback::CallbackFunc,
                                      &callback, _1));
  wait_result(&callback);
  ASSERT_TRUE(callback.result());
  callback.Reset();
  ASSERT_TRUE(nodes_[0].is_joined());
  // Joining node 2 bootstrapped to node 1 so that node 1 adds him to its
  // routing table
  base::KadConfig kad_config1;
  base::KadConfig::Contact *kad_contact = kad_config1.add_contact();
  kad_contact->set_node_id(nodes_[0].node_id().ToStringEncoded(NodeId::kHex));
  kad_contact->set_ip(nodes_[0].ip());
  kad_contact->set_port(nodes_[0].port());
  kad_contact->set_local_ip(nodes_[0].local_ip());
  kad_contact->set_local_port(nodes_[0].local_port());
  std::fstream output1(kconfig_file1.c_str(),
                       std::ios::out | std::ios::trunc | std::ios::binary);
  EXPECT_TRUE(kad_config1.SerializeToOstream(&output1));
  output1.close();

  nodes_[1].Join(kid2, kconfig_file1,
                 boost::bind(&GeneralKadCallback::CallbackFunc, &callback, _1));
  wait_result(&callback);
  ASSERT_TRUE(callback.result());
  callback.Reset();
  ASSERT_TRUE(nodes_[1].is_joined());
  Contact last_seen;
  ASSERT_TRUE(nodes_[0].GetContact(nodes_[1].node_id(), &last_seen));

  // Adding Contacts until kbucket splits and filling kbuckets
  std::vector<std::string> bucket2ids(test_add_node::K), bucket1ids(3);
  for (int i = 0; i < test_add_node::K; ++i) {
    for (int j = 0; j < kKeySizeBytes * 2; ++j)
      bucket2ids[i] += "f";
    std::string rep;
    int k;
    for (k = 0; k < i; ++k)
      rep += "0";
    bucket2ids[i].replace(1, k, rep);
  }
  for (int i = 0; i < 3; i++) {
    for (int j = 0; j < kKeySizeBytes*2; ++j)
      bucket1ids[i] += "7";
    std::string rep;
    int k;
    for (k = 0; k < i; ++k)
      rep += "2";
    bucket1ids[i].replace(1, k, rep);
  }
  int port = 7000;

  std::string ip = "127.0.0.1";
  for (int i = 1 ; i < test_add_node::K - 3; ++i) {
    kademlia::NodeId id(bucket2ids[i], kademlia::NodeId::kHex);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes_[0].AddContact(contact, 0.0, false));
    ++port;
  }
  for (int i = 0; i < 3; ++i) {
    kademlia::NodeId id(bucket1ids[i], kademlia::NodeId::kHex);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes_[0].AddContact(contact, 0.0, false));
    ++port;
  }
  for (int i = test_add_node::K - 3; i < test_add_node::K; ++i) {
    kademlia::NodeId id(bucket2ids[i], kademlia::NodeId::kHex);
    Contact contact(id, ip, port, ip, port);
    ASSERT_EQ(0, nodes_[0].AddContact(contact, 0.0, false));
    ++port;
  }
  ++port;
  Contact contact(kademlia::NodeId(bucket2ids[0], kademlia::NodeId::kHex), ip, port, ip,
                  port);
  ASSERT_EQ(2, nodes_[0].AddContact(contact, 0.0, false));

  Contact rec_contact;
  ASSERT_FALSE(nodes_[0].GetContact(contact.node_id(), &rec_contact));

  // wait for last seen contact to reply to ping
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_FALSE(nodes_[0].GetContact(contact.node_id(), &rec_contact));
  ASSERT_TRUE(nodes_[0].GetContact(last_seen.node_id(), &rec_contact));

  ASSERT_EQ(2, nodes_[0].AddContact(contact, 0.0, false));

  // wait for ping to last seen contact to timeout
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(nodes_[0].GetContact(contact.node_id(), &rec_contact));
  ASSERT_TRUE(nodes_[0].GetContact(last_seen.node_id(), &rec_contact));

  // Getting info from base routing table to check rtt
  base::PublicRoutingTableTuple tuple;
  ASSERT_EQ(0, (*base::PublicRoutingTable::GetInstance())[base::IntToString(
                nodes_[0].port())]->GetTupleInfo(
                nodes_[1].node_id().String(), &tuple));
  ASSERT_EQ(nodes_[1].node_id().String(), tuple.kademlia_id);
  ASSERT_EQ(nodes_[1].ip(), tuple.ip);
  ASSERT_EQ(nodes_[1].port(), tuple.port);
  ASSERT_EQ(nodes_[1].rendezvous_ip(), tuple.rendezvous_ip);
  ASSERT_EQ(nodes_[1].rendezvous_port(), tuple.rendezvous_port);
  EXPECT_LT(0.0, tuple.rtt);

  nodes_[1].Leave();
  nodes_[0].Leave();
  base::KadConfig kad_config;
  std::ifstream inputfile(kconfig_file.c_str(),
                          std::ios::in | std::ios::binary);
  ASSERT_TRUE(kad_config.ParseFromIstream(&inputfile));
  inputfile.close();
  ASSERT_EQ(test_add_node::K + 3, kad_config.contact_size());

  ASSERT_FALSE(nodes_[0].is_joined());
  ASSERT_FALSE(nodes_[1].is_joined());
}

}  // namespace test_add_node

}  // namespace kademlia
