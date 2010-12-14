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

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/cstdint.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/progress.hpp>
#include <boost/lexical_cast.hpp>

#include <exception>
#include <list>
#include <set>
#include <vector>

#include "maidsafe/base/crypto.h"
#include "maidsafe/base/log.h"
#include "maidsafe/base/routingtable.h"
#include "maidsafe/kademlia/node-api.h"
#include "maidsafe/kademlia/nodeimpl.h"
#include "maidsafe/rpcprotocol/channelmanager-api.h"
#include "maidsafe/transport/udttransport.h"
#include "maidsafe/tests/validationimpl.h"
#include "maidsafe/tests/kademlia/fake_callbacks.h"

namespace fs = boost::filesystem;

namespace kademlia {

namespace test_node {

static const boost::uint16_t K = 8;
const boost::int16_t kNetworkSize = test_node::K + 1;
const boost::int16_t kTestK = test_node::K;

inline void create_rsakeys(std::string *pub_key, std::string *priv_key) {
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  *pub_key =  kp.public_key();
  *priv_key = kp.private_key();
}

inline void create_req(const std::string &pub_key, const std::string &priv_key,
                       const std::string &key, std::string *sig_pub_key,
                       std::string *sig_req) {
  crypto::Crypto cobj;
  cobj.set_symm_algorithm(crypto::AES_256);
  cobj.set_hash_algorithm(crypto::SHA_512);
  *sig_pub_key = cobj.AsymSign(pub_key, "", priv_key, crypto::STRING_STRING);
  *sig_req = cobj.AsymSign(cobj.Hash(pub_key + *sig_pub_key + key, "",
                                     crypto::STRING_STRING, true),
                           "", priv_key, crypto::STRING_STRING);
}

std::string get_app_directory() {
  boost::filesystem::path app_path;
#if defined(MAIDSAFE_POSIX)
  app_path = boost::filesystem::path("/var/cache/maidsafe/");
#elif defined(MAIDSAFE_WIN32)
  TCHAR szpth[MAX_PATH];
  if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, 0, szpth))) {
    std::ostringstream stm;
    const std::ctype<char> &ctfacet =
        std::use_facet< std::ctype<char> >(stm.getloc());
    for (size_t i = 0; i < wcslen(szpth); ++i)
      stm << ctfacet.narrow(szpth[i], 0);
    app_path = boost::filesystem::path(stm.str());
    app_path /= "maidsafe";
  }
#elif defined(MAIDSAFE_APPLE)
  app_path = boost::filesystem::path("/Library/maidsafe/");
#endif
  return app_path.string();
}

void ConstructKcp(NodeConstructionParameters *kcp) {
  kcp->type = VAULT;
  kcp->alpha = kAlpha;
  kcp->beta = kBeta;
  kcp->k = test_node::K;
  kcp->port_forwarded = false;
  kcp->private_key = "";
  kcp->public_key = "";
  kcp->refresh_time = kRefreshTime;
  kcp->use_upnp = false;
}

class NodeTest: public testing::Test {
 protected:
  NodeTest() {}
  ~NodeTest() {}
};

std::string kad_config_file_;
std::vector<rpcprotocol::Port> transport_ports_;
std::vector<boost::shared_ptr<transport::UdtTransport> > transports_;
std::vector<boost::shared_ptr<rpcprotocol::ChannelManager> > channel_managers_;
std::vector<boost::shared_ptr<Node> > nodes_;
std::vector<std::string> dbs_;
crypto::Crypto cry_obj_;
GeneralKadCallback cb_;
std::vector<NodeId> node_ids_;
std::set<boost::uint16_t> ports_;
std::string test_dir_;
base::TestValidator validator;

class Env : public testing::Environment {
 public:
  Env() {
    cry_obj_.set_symm_algorithm(crypto::AES_256);
    cry_obj_.set_hash_algorithm(crypto::SHA_512);
  }

  virtual ~Env() {}

  virtual void SetUp() {
    test_dir_ = std::string("temp/NodeTest") +
                boost::lexical_cast<std::string>(base::RandomUint32());
    kad_config_file_ = test_dir_ + std::string("/.kadconfig");
    try {
      if (fs::exists(test_dir_))
        fs::remove_all(test_dir_);
      fs::create_directories(test_dir_);
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "filesystem error: " << e.what() << std::endl;
    }

    // setup the nodes without starting them
    std::string priv_key, pub_key;
    nodes_.resize(kNetworkSize);
    channel_managers_.resize(kNetworkSize);
    transports_.resize(kNetworkSize);
    transport_ports_.resize(kNetworkSize);
    NodeConstructionParameters kcp;
    ConstructKcp(&kcp);
    for (boost::int16_t  i = 0; i < kNetworkSize; ++i) {
      transports_[i].reset(new transport::UdtTransport);
      transport::TransportCondition tc;
      transport_ports_[i] = transports_[i]->StartListening("", 0, &tc);
      ASSERT_EQ(transport::kSuccess, tc);
      ASSERT_LT(0, transport_ports_[i]);
      kcp.port = transport_ports_[i];
      channel_managers_[i].reset(
          new rpcprotocol::ChannelManager(transports_[i]));
      ASSERT_EQ(0, channel_managers_[i]->Start());

      std::string db_local(test_dir_ + std::string("/datastore") +
                           boost::lexical_cast<std::string>(i));
      boost::filesystem::create_directories(db_local);
      dbs_.push_back(db_local);

      create_rsakeys(&pub_key, &priv_key);
      kcp.public_key = pub_key;
      kcp.private_key = priv_key;
      nodes_[i].reset(new Node(channel_managers_[i], transports_[i], kcp));
    }

    kad_config_file_ = dbs_[0] + "/.kadconfig";
    cb_.Reset();
    boost::asio::ip::address local_ip;
    ASSERT_TRUE(base::GetLocalAddress(&local_ip));
    nodes_[0]->JoinFirstNode(kad_config_file_, local_ip.to_string(),
                              transport_ports_[0],
                              boost::bind(&GeneralKadCallback::CallbackFunc,
                                          &cb_, _1));
    wait_result(&cb_);
    ASSERT_TRUE(cb_.result());
    ASSERT_TRUE(nodes_[0]->is_joined());
    nodes_[0]->set_signature_validator(&validator);
    DLOG(INFO) << "Node 0 joined "
              << nodes_[0]->node_id().ToStringEncoded(NodeId::kHex)
                 .substr(0, 12)
              << std::endl;
    node_ids_.push_back(nodes_[0]->node_id());
    base::KadConfig kad_config;
    base::KadConfig::Contact *kad_contact = kad_config.add_contact();
    kad_contact->set_node_id(
        nodes_[0]->node_id().ToStringEncoded(NodeId::kHex));
    kad_contact->set_ip(nodes_[0]->ip());
    kad_contact->set_port(nodes_[0]->port());
    kad_contact->set_local_ip(nodes_[0]->local_ip());
    kad_contact->set_local_port(nodes_[0]->local_port());

    for (boost::int16_t i = 1; i < kNetworkSize; i++) {
      kad_config_file_ = dbs_[i] + "/.kadconfig";
      std::fstream output2(kad_config_file_.c_str(),
                           std::ios::out | std::ios::trunc | std::ios::binary);
      ASSERT_TRUE(kad_config.SerializeToOstream(&output2));
      output2.close();
    }

    // start the rest of the nodes (including node 1 again)
    for (boost::int16_t  i = 1; i < kNetworkSize; ++i) {
      cb_.Reset();
      kad_config_file_ = dbs_[i] + "/.kadconfig";
      nodes_[i]->Join(kad_config_file_,
                       boost::bind(&GeneralKadCallback::CallbackFunc,
                                   &cb_, _1));
      wait_result(&cb_);
      ASSERT_TRUE(cb_.result());
      ASSERT_TRUE(nodes_[i]->is_joined());
      nodes_[i]->set_signature_validator(&validator);
      DLOG(INFO) << "Node " << i << " joined "
                << nodes_[i]->node_id().ToStringEncoded(NodeId::kHex)
                   .substr(0, 12)
                << std::endl;
      node_ids_.push_back(nodes_[i]->node_id());
    }
    cb_.Reset();
#ifdef WIN32
    HANDLE hconsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hconsole, 10 | 0 << 4);
#endif
    DLOG(INFO) << kNetworkSize << " local Kademlia nodes running" << std::endl;
#ifdef WIN32
    SetConsoleTextAttribute(hconsole, 11 | 0 << 4);
#endif
  }

  virtual void TearDown() {
    DLOG(INFO) << "TestNode, TearDown Starting..." << std::endl;
    boost::this_thread::sleep(boost::posix_time::seconds(5));

#ifdef WIN32
    HANDLE hconsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hconsole, 7 | 0 << 4);
#endif
    for (boost::int16_t i = kNetworkSize-1; i >= 0; i--) {
      DLOG(INFO) << "stopping node " << i << std::endl;
      cb_.Reset();
      nodes_[i]->Leave();
      EXPECT_FALSE(nodes_[i]->is_joined());
      transports_[i]->StopListening(transport_ports_[i]);
      channel_managers_[i]->Stop();
    }
    std::set<boost::uint16_t>::iterator it;
    for (it = ports_.begin(); it != ports_.end(); it++) {
      // Deleting the DBs in the app dir
      fs::path db_dir(get_app_directory());
      db_dir /= boost::lexical_cast<std::string>(*it);
      try {
        if (fs::exists(db_dir))
          fs::remove_all(db_dir);
      }
      catch(const std::exception &e) {
        DLOG(ERROR) << "filesystem error: " << e.what() << std::endl;
      }
    }
    try {
      if (fs::exists(test_dir_))
        fs::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "filesystem error: " << e.what() << std::endl;
    }
    nodes_.clear();
    channel_managers_.clear();
    transports_.clear();
    transport_ports_.clear();
    dbs_.clear();
    node_ids_.clear();
    ports_.clear();
    DLOG(INFO) << "TestNode, TearDown Finished." << std::endl;
    transport::UdtTransport::CleanUp();
  }
};

TEST_F(NodeTest, FUNC_KAD_ClientNodeConnect) {
  NodeConstructionParameters kcp;
  ConstructKcp(&kcp);

  boost::shared_ptr<transport::UdtTransport> t1(new transport::UdtTransport);
  transport::TransportCondition tc;
  transport::Port p1 = t1->StartListening("", 0, &tc);
  ASSERT_EQ(transport::kSuccess, tc);
  ASSERT_LT(0, p1);
  kcp.port = p1;
  boost::shared_ptr<rpcprotocol::ChannelManager> cm1(
      new rpcprotocol::ChannelManager(t1));
  ASSERT_EQ(0, cm1->Start());

  std::string db_local(test_dir_ + std::string("/datastore") +
                       boost::lexical_cast<std::string>(kNetworkSize + 1));
  boost::filesystem::create_directories(db_local);

  std::string privkey, pubkey;
  create_rsakeys(&pubkey, &privkey);
  kcp.type = CLIENT;
  kcp.public_key = pubkey;
  kcp.private_key = privkey;
  Node node_local_1(cm1, t1, kcp);

  std::string config_file = db_local + "/.kadconfig";
  base::KadConfig conf;
  base::KadConfig::Contact *ctc1 = conf.add_contact();
  ctc1->set_node_id(nodes_[0]->node_id().ToStringEncoded(NodeId::kHex));
  ctc1->set_ip(nodes_[0]->ip());
  ctc1->set_port(nodes_[0]->port());
  ctc1->set_local_ip(nodes_[0]->local_ip());
  ctc1->set_local_port(nodes_[0]->local_port());
  std::fstream output2(config_file.c_str(),
                       std::ios::out | std::ios::trunc | std::ios::binary);
  ASSERT_TRUE(conf.SerializeToOstream(&output2));
  output2.close();
  ASSERT_EQ(NONE, node_local_1.nat_type());
  node_local_1.Join(config_file,
                     boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1));
  wait_result(&cb_);
  ASSERT_TRUE(cb_.result());
  ASSERT_EQ(kClientId, node_local_1.node_id().String());
  ASSERT_EQ(DIRECT_CONNECTED, node_local_1.nat_type());

  boost::shared_ptr<transport::UdtTransport> t2(new transport::UdtTransport);
  transport::Port p2 = t2->StartListening("", 0, &tc);
  ASSERT_EQ(transport::kSuccess, tc);
  ASSERT_LT(0, p2);
  kcp.port = p2;
  boost::shared_ptr<rpcprotocol::ChannelManager> cm2(
      new rpcprotocol::ChannelManager(t2));
  ASSERT_EQ(0, cm2->Start());

//  std::string privkey, pubkey;
  create_rsakeys(&pubkey, &privkey);
  kcp.type = CLIENT;
  kcp.public_key = pubkey;
  kcp.private_key = privkey;
  Node node_local_2(cm2, t2, kcp);
  db_local = test_dir_ + std::string("/datastore") +
             boost::lexical_cast<std::string>(kNetworkSize + 2);
  boost::filesystem::create_directories(db_local);
  config_file = db_local + "/.kadconfig";
  conf.Clear();
  base::KadConfig::Contact *ctc2 = conf.add_contact();
  ctc2->set_node_id(nodes_[0]->node_id().ToStringEncoded(NodeId::kHex));
  ctc2->set_ip(nodes_[0]->ip());
  ctc2->set_port(nodes_[0]->port());
  ctc2->set_local_ip(nodes_[0]->local_ip());
  ctc2->set_local_port(nodes_[0]->local_port());
  std::fstream output3(config_file.c_str(),
                       std::ios::out | std::ios::trunc | std::ios::binary);
  ASSERT_TRUE(conf.SerializeToOstream(&output3));
  output3.close();
  ports_.insert(node_local_2.port());
  ASSERT_EQ(NONE, node_local_2.nat_type());
  cb_.Reset();
  node_local_2.Join(config_file,
                     boost::bind(&GeneralKadCallback::CallbackFunc, &cb_, _1));
  wait_result(&cb_);
  ASSERT_TRUE(cb_.result());
  ASSERT_EQ(kClientId, node_local_2.node_id().String());
  ASSERT_EQ(DIRECT_CONNECTED, node_local_2.nat_type());

  // Doing a storevalue
  NodeId key(cry_obj_.Hash("dccxxvdeee432cc", "", crypto::STRING_STRING, false));
  std::string value = base::RandomString(1024 * 10);  // 10KB
  SignedValue sig_value;
  StoreValueCallback cb_1;
  std::string sig_pub_key, sig_req;
  create_rsakeys(&pubkey, &privkey);
  create_req(pubkey, privkey, key.String(), &sig_pub_key, &sig_req);
  sig_value.set_value(value);
  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", privkey,
                                                  crypto::STRING_STRING));
  std::string ser_sig_value = sig_value.SerializeAsString();
  SignedRequest req;
  req.set_signer_id(node_local_1.node_id().String());
  req.set_public_key(pubkey);
  req.set_signed_public_key(sig_pub_key);
  req.set_signed_request(sig_req);
  node_local_1.StoreValue(key, sig_value, req, 24 * 3600,
                           boost::bind(&StoreValueCallback::CallbackFunc,
                                       &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());

  // loading the value with another existing node
  FindCallback cb_2;
  nodes_[kTestK / 2]->FindValue(key, false,
                                 boost::bind(&FindCallback::CallbackFunc,
                                             &cb_2, _1));
  wait_result(&cb_2);
  ASSERT_TRUE(cb_2.result());
  ASSERT_LE(1U, cb_2.signed_values().size());
  bool got_value = false;
  for (size_t i = 0; i < cb_2.signed_values().size(); i++) {
    if (value == cb_2.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value)
    FAIL();
  cb_2.Reset();

  // loading the value with the client
  node_local_1.FindValue(key, false,
                          boost::bind(&FindCallback::CallbackFunc, &cb_2, _1));
  wait_result(&cb_2);
  ASSERT_TRUE(cb_2.result());
  ASSERT_LE(1U, cb_2.signed_values().size());
  got_value = false;
  for (size_t i = 0; i < cb_2.signed_values().size(); i++) {
    if (value == cb_2.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value)
    FAIL();
  cb_2.Reset();

  // loading the value with the client2
  node_local_2.FindValue(key, false,
                          boost::bind(&FindCallback::CallbackFunc, &cb_2, _1));
  wait_result(&cb_2);
  ASSERT_TRUE(cb_2.result());
  ASSERT_LE(1U, cb_2.signed_values().size());
  got_value = false;
  for (size_t i = 0; i < cb_2.signed_values().size(); i++) {
    if (value == cb_2.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value)
    FAIL();
  cb_2.Reset();

  // Doing a find closest nodes with the client
  NodeId key1(cry_obj_.Hash("2evvnf3xssas21", "", crypto::STRING_STRING, false));
  FindCallback cb_3;
  node_local_1.FindKClosestNodes(key1,
                                  boost::bind(&FindCallback::CallbackFunc,
                                              &cb_3, _1));
  wait_result(&cb_3);
  // make sure the nodes returned are what we expect.
  ASSERT_TRUE(cb_3.result());
  ASSERT_FALSE(cb_3.closest_nodes().empty());
  std::list<std::string> closest_nodes_str;  // = cb_3.closest_nodes();
  for (size_t i = 0; i < cb_3.closest_nodes().size(); i++)
    closest_nodes_str.push_back(cb_3.closest_nodes()[i]);
  std::list<std::string>::iterator it;
  std::list<Contact> closest_nodes;
  for (it = closest_nodes_str.begin(); it != closest_nodes_str.end();
      it++) {
    Contact node;
    node.ParseFromString(*it);
    closest_nodes.push_back(node);
  }
  ASSERT_EQ(kTestK, closest_nodes.size());
  std::list<Contact> all_nodes;
  for (boost::int16_t i = 0; i < kNetworkSize; i++) {
    Contact node(nodes_[i]->node_id(), nodes_[i]->ip(),
        nodes_[i]->port());
    all_nodes.push_back(node);
  }
  SortContactList(key1, &all_nodes);
  std::list<Contact>::iterator it1, it2;
  it2= closest_nodes.begin();
  for (it1 = closest_nodes.begin(); it1 != closest_nodes.end();
      it1++, it2++) {
    ASSERT_TRUE(it1->Equals(*it2));
  }

  // Checking no node has stored the clients node in its routing table
  for (boost::int16_t i = 0; i < kNetworkSize; i++) {
    Contact client_node;
    ASSERT_FALSE(nodes_[i]->GetContact(node_local_1.node_id(), &client_node));
  }
  cb_.Reset();
  node_local_1.Leave();
  ASSERT_FALSE(node_local_1.is_joined());
  t1->StopListening(p1);
  cm1->Stop();

  node_local_2.Leave();
  ASSERT_FALSE(node_local_2.is_joined());
  t2->StopListening(p2);
  cm2->Stop();
}

TEST_F(NodeTest, FUNC_KAD_FindClosestNodes) {
  NodeId key(cry_obj_.Hash("2evvnf3xssas21", "", crypto::STRING_STRING, false));
  FindCallback cb_1;
  nodes_[kTestK/2]->FindKClosestNodes(key,
                                       boost::bind(&FindCallback::CallbackFunc,
                                                   &cb_1, _1));
  wait_result(&cb_1);
  // make sure the nodes returned are what we expect.
  ASSERT_TRUE(cb_1.result());
  ASSERT_FALSE(cb_1.closest_nodes().empty());
  std::list<std::string> closest_nodes_str;  // = cb_1.closest_nodes();
  for (size_t i = 0; i < cb_1.closest_nodes().size(); i++)
    closest_nodes_str.push_back(cb_1.closest_nodes()[i]);
  std::list<std::string>::iterator it;
  std::list<Contact> closest_nodes;
  for (it = closest_nodes_str.begin(); it != closest_nodes_str.end();
      it++) {
    Contact node;
    node.ParseFromString(*it);
    closest_nodes.push_back(node);
  }
  ASSERT_EQ(kTestK, closest_nodes.size());
  std::list<Contact> all_nodes;
  for (boost::int16_t i = 0; i < kNetworkSize; i++) {
    Contact node(nodes_[i]->node_id(), nodes_[i]->ip(),
        nodes_[i]->port(), nodes_[i]->local_ip(),
        nodes_[i]->local_port(), nodes_[i]->rendezvous_ip(),
        nodes_[i]->rendezvous_port());
    all_nodes.push_back(node);
  }
  SortContactList(key, &all_nodes);
  std::list<Contact>::iterator it1, it2;
  it2= closest_nodes.begin();
  for (it1 = closest_nodes.begin(); it1 != closest_nodes.end(); it1++, it2++) {
    ASSERT_TRUE(it1->Equals(*it2));
  }
}

TEST_F(NodeTest, FUNC_KAD_StoreAndLoadSmallValue) {
  // prepare small size of values
  NodeId key(cry_obj_.Hash("dccxxvdeee432cc", "", crypto::STRING_STRING, false));
  std::string value = base::RandomString(1024 * 5);  // 5KB
  SignedValue sig_value;
  sig_value.set_value(value);
  // save key/value pair from a node
  StoreValueCallback cb_;
  std::string pub_key, priv_key, sig_pub_key, sig_req;
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key.String(), &sig_pub_key, &sig_req);
  SignedRequest req;
  req.set_signer_id(nodes_[kTestK / 2]->node_id().String());
  req.set_public_key(pub_key);
  req.set_signed_public_key(sig_pub_key);
  req.set_signed_request(sig_req);

  nodes_[kTestK / 2]->StoreValue(key, sig_value, req, 24 * 3600,
                                  boost::bind(&StoreValueCallback::CallbackFunc,
                                              &cb_, _1));
  wait_result(&cb_);
  ASSERT_FALSE(cb_.result());
  cb_.Reset();

  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", priv_key,
      crypto::STRING_STRING));
  nodes_[kTestK / 2]->StoreValue(key, sig_value, req, 24 * 3600,
                                  boost::bind(&StoreValueCallback::CallbackFunc,
                                              &cb_, _1));
  wait_result(&cb_);
  ASSERT_TRUE(cb_.result());
  // calculate number of nodes which hold this key/value pair
  boost::int16_t number(0);
  for (boost::int16_t i = 0; i < kNetworkSize; i++) {
    std::vector<std::string> values;
    bool b = false;
    nodes_[i]->FindValueLocal(key, &values);
    if (!values.empty()) {
      for (boost::uint32_t n = 0; n < values.size() && !b; ++n) {
        SignedValue sig_value;
        ASSERT_TRUE(sig_value.ParseFromString(values[n]));
        if (value == sig_value.value()) {
          number++;
          b = true;
        }
      }
    }
  }
  boost::int16_t d = static_cast<boost::int16_t>
    (kTestK * kMinSuccessfulPecentageStore);
  ASSERT_LE(d, number);
  // load the value from no.kNetworkSize-1 node
  cb_.Reset();
  FindCallback cb_1;
  nodes_[kNetworkSize - 2]->FindValue(key, false, boost::bind(
    &FindCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  ASSERT_LE(1U, cb_1.signed_values().size());
  bool got_value = false;
  for (size_t i = 0; i < cb_1.signed_values().size(); i++) {
    if (value == cb_1.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value) {
    FAIL() << "FAIL node " << kNetworkSize - 2;
  }
  // load the value from no.1 node
  cb_1.Reset();
  ASSERT_TRUE(nodes_[0]->is_joined());
  nodes_[0]->FindValue(key, false, boost::bind(&FakeCallback::CallbackFunc,
                                                &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  ASSERT_LE(1U, cb_1.signed_values().size());
  got_value = false;
  for (size_t i = 0; i < cb_1.signed_values().size(); i++) {
    if (value == cb_1.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value) {
    FAIL() << "FAIL node 0";
  }
  cb_1.Reset();
}

TEST_F(NodeTest, FUNC_KAD_StoreAndLoadBigValue) {
  // prepare big size of values
  NodeId key(cry_obj_.Hash("vcdrer43dccdwwt", "", crypto::STRING_STRING, false));
  std::string value = base::RandomString(1024 * 1024);  // 1MB
  SignedValue sig_value;
  sig_value.set_value(value);
  // save key/value pair from a node
  StoreValueCallback cb_;
  std::string pub_key, priv_key, sig_pub_key, sig_req;
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key.String(), &sig_pub_key, &sig_req);
  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", priv_key,
                                                  crypto::STRING_STRING));
  SignedRequest req;
  req.set_signer_id(nodes_[kTestK / 3]->node_id().String());
  req.set_public_key(pub_key);
  req.set_signed_public_key(sig_pub_key);
  req.set_signed_request(sig_req);
  nodes_[kTestK / 3]->StoreValue(key, sig_value, req, 24*3600,
                                  boost::bind(&StoreValueCallback::CallbackFunc,
                                              &cb_, _1));
  wait_result(&cb_);
  ASSERT_TRUE(cb_.result());
  // calculate number of nodes which hold this key/value pair
  boost::int16_t number = 0;
  for (boost::int16_t i = 0; i < kNetworkSize; i++) {
    bool b = false;
    std::vector<std::string> values;
    nodes_[i]->FindValueLocal(key, &values);
    if (!values.empty()) {
      for (boost::uint32_t n = 0; n < values.size(); ++n) {
        SignedValue sig_value;
        ASSERT_TRUE(sig_value.ParseFromString(values[n]));
        if (value == sig_value.value()) {
          number++;
          b = true;
        }
      }
    }
  }
  boost::int16_t d(static_cast<boost::int16_t>
    (kTestK * kMinSuccessfulPecentageStore));
  ASSERT_LE(d, number);
  // load the value from the node
  FindCallback cb_1;
  nodes_[kTestK / 3]->FindValue(key, false,
                                 boost::bind(&FindCallback::CallbackFunc,
                                             &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  ASSERT_LE(1U, cb_1.signed_values().size());
  bool got_value = false;
  for (size_t i = 0; i < cb_1.signed_values().size(); i++) {
    if (value == cb_1.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value)
    FAIL();
  // load the value from another node
  FindCallback cb_2;
  nodes_[kTestK * 2 / 3]->FindValue(key, false,
                                     boost::bind(&FindCallback::CallbackFunc,
                                                 &cb_2, _1));
  wait_result(&cb_2);
  ASSERT_TRUE(cb_2.result());
  ASSERT_LE(1U, cb_2.signed_values().size());
  got_value = false;
  for (size_t i = 0; i < cb_1.signed_values().size(); i++) {
    if (value == cb_1.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value)
    FAIL();
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_StoreAndLoad100Values) {
  boost::int16_t count(100);
  std::vector<NodeId> keys(count);
  std::vector<SignedValue> values(count);
  std::vector<StoreValueCallback> cbs(count);
  std::string pub_key, priv_key, sig_pub_key, sig_req;
  create_rsakeys(&pub_key, &priv_key);
  DLOG(INFO) << "Store..." << std::endl;
  for (boost::int16_t n = 0; n < count; ++n) {
    keys[n] = NodeId(cry_obj_.Hash("key" + base::IntToString(n), "",
                  crypto::STRING_STRING, false));
    values[n].set_value(base::RandomString(1024));
    create_req(pub_key, priv_key, keys[n].String(), &sig_pub_key, &sig_req);
    values[n].set_value_signature(cry_obj_.AsymSign(values[n].value(), "",
                                  priv_key, crypto::STRING_STRING));
    SignedRequest req;
    int a(n % (kNetworkSize - 1));
    req.set_signer_id(nodes_[a]->node_id().String());
    req.set_public_key(pub_key);
    req.set_signed_public_key(sig_pub_key);
    req.set_signed_request(sig_req);
    nodes_[a]->StoreValue(keys[n], values[n], req, 24 * 3600,
                           boost::bind(&StoreValueCallback::CallbackFunc,
                                       &cbs[n], _1));
  }
  DLOG(INFO) << "Load..." << std::endl;
  for (boost::int16_t p = 0; p < count; ++p) {
    wait_result(&cbs[p]);
    EXPECT_TRUE(cbs[p].result())
              << "Failed to store " << kMinSuccessfulPecentageStore
              << "% of K copies of the " << p << "th value";
  }
  for (boost::int16_t p = 0; p < count; ++p) {
    FindCallback cb_1;
    nodes_[kTestK / 2]->FindValue(keys[p], false,
                                   boost::bind(&FindCallback::CallbackFunc,
                                               &cb_1, _1));
    wait_result(&cb_1);
    ASSERT_TRUE(cb_1.result())
              << "No copies of the " << p <<"th value where stored.";
    ASSERT_EQ(1U, cb_1.signed_values().size());
    ASSERT_EQ(values[p].value(), cb_1.signed_values()[0].value());
  }
  DLOG(INFO) << "Done." << std::endl;
}

TEST_F(NodeTest, FUNC_KAD_LoadNonExistingValue) {
  NodeId key(cry_obj_.Hash("bbffddnnooo8822", "", crypto::STRING_STRING, false));
  // load the value from last node
  FindCallback cb_1;
  nodes_[kNetworkSize - 1]->FindValue(key, false,
                                       boost::bind(&FindCallback::CallbackFunc,
                                                   &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  ASSERT_FALSE(cb_1.closest_nodes().empty());
  ASSERT_TRUE(cb_1.values().empty());
  ASSERT_TRUE(cb_1.signed_values().empty());
}

TEST_F(NodeTest, FUNC_KAD_GetNodeContactDetails) {
  // find an existing node
  NodeId node_id1(nodes_[kTestK / 3]->node_id());
  GetNodeContactDetailsCallback cb_1;
  nodes_[kNetworkSize-1]->GetNodeContactDetails(
      node_id1,
      boost::bind(&GetNodeContactDetailsCallback::CallbackFunc, &cb_1, _1),
      false);
  wait_result(&cb_1);
  ASSERT_FALSE(cb_1.result());
  Contact expect_node1;
  Contact target_node1(nodes_[kTestK / 3]->node_id(),
                            nodes_[kTestK / 3]->ip(),
                            nodes_[kTestK / 3]->port());
  expect_node1.ParseFromString(cb_1.contact());
  ASSERT_TRUE(target_node1.Equals(expect_node1));
  // find a non-existing node
  GetNodeContactDetailsCallback cb_2;
  NodeId node_id2(cry_obj_.Hash("bcdde34333", "", crypto::STRING_STRING, false));
  nodes_[kNetworkSize-1]->GetNodeContactDetails(
      node_id2,
      boost::bind(&GetNodeContactDetailsCallback::CallbackFunc, &cb_2, _1),
      false);
  wait_result(&cb_2);
  ASSERT_FALSE(cb_2.result());
}

TEST_F(NodeTest, FUNC_KAD_Ping) {
  // ping by contact
  Contact remote(nodes_[kTestK * 3 / 4]->node_id(),
                      nodes_[kTestK * 3 / 4]->ip(),
                      nodes_[kTestK * 3 / 4]->port(),
                      nodes_[kTestK * 3 / 4]->local_ip(),
                      nodes_[kTestK * 3 / 4]->local_port());
  PingCallback cb_1;
  nodes_[kNetworkSize-1]->Ping(remote, boost::bind(&PingCallback::CallbackFunc,
                                                    &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  // ping by node id
  NodeId remote_id(nodes_[kTestK / 4]->node_id());
  PingCallback cb_2;
  nodes_[kNetworkSize-2]->Ping(remote_id,
                                boost::bind(&PingCallback::CallbackFunc,
                                            &cb_2, _1));
  wait_result(&cb_2);
  // ASSERT_EQ(kRpcResultSuccess, cb_2.result());
  if (!cb_2.result()) {
    for (boost::int16_t i = 0; i < kNetworkSize; ++i) {
      Contact ctc;
      if (nodes_[i]->GetContact(remote_id, &ctc))
          DLOG(INFO) << "node " << i << " port " << nodes_[i]->port()
                     << "has node " << kTestK / 4 << std::endl;
    }
    NodeId zero_id;
    if (remote_id == zero_id)
      DLOG(INFO) << "remote id is a kClientId." << std::endl;
    if (remote_id == nodes_[kNetworkSize-2]->node_id())
      DLOG(INFO) << "remote_id == node_id of sender." << std::endl;
    FAIL();
  }
  // ping a dead node
  NodeId dead_id(cry_obj_.Hash("bb446dx", "", crypto::STRING_STRING, false));

  boost::uint16_t port(4242);
  std::set<boost::uint16_t>::iterator it;
  it = ports_.find(port);

  while (it != ports_.end()) {
    ++port;
    it = ports_.find(port);
  }

  Contact dead_remote(dead_id, "127.0.0.1", port);
  PingCallback cb_3;
  nodes_[kNetworkSize-1]->Ping(dead_remote,
                                boost::bind(&PingCallback::CallbackFunc,
                                            &cb_3, _1));
  wait_result(&cb_3);
  ASSERT_FALSE(cb_3.result());
  PingCallback cb_4;
  nodes_[kNetworkSize-1]->Ping(dead_id,
                                boost::bind(&PingCallback::CallbackFunc,
                                            &cb_4, _1));
  wait_result(&cb_4);
  ASSERT_FALSE(cb_4.result());
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_FindValueWithDeadNodes) {
  // Store a small value
  // prepair small size of values
  NodeId key(cry_obj_.Hash("rrvvdcccdd", "", crypto::STRING_STRING, false));
  std::string value = base::RandomString(3 * 1024);  // 3KB
  SignedValue sig_value;
  sig_value.set_value(value);
  // save key/value pair from no.8 node
  StoreValueCallback cb_1;
  std::string pub_key, priv_key, sig_pub_key, sig_req;
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key.String(), &sig_pub_key, &sig_req);
  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", priv_key,
                                                  crypto::STRING_STRING));
  SignedRequest req;
  req.set_signer_id(nodes_[kTestK * 3 / 4]->node_id().String());
  req.set_public_key(pub_key);
  req.set_signed_public_key(sig_pub_key);
  req.set_signed_request(sig_req);
  nodes_[kTestK * 3 / 4]->StoreValue(key, sig_value, req, 24 * 3600,
                                      boost::bind(&FakeCallback::CallbackFunc,
                                                  &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  // kill k-1 nodes, there should be at least one node left which holds this
  // value
  for (boost::int16_t i = 0; i < kTestK - 2 && i < kNetworkSize - 2; ++i) {
    nodes_[2 + i]->Leave();
    transports_[2 + i]->StopListening(transport_ports_[2 + i]);
    channel_managers_[2 + i]->Stop();
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  // try to find value
  // load the value from no.20 node
  FindCallback cb_2;
  nodes_[kNetworkSize - 1]->FindValue(key, false,
                                       boost::bind(&FakeCallback::CallbackFunc,
                                                   &cb_2, _1));
  wait_result(&cb_2);
  ASSERT_TRUE(cb_2.result());
  ASSERT_LE(1U, cb_2.signed_values().size());
  bool got_value = false;
  for (size_t i = 0; i < cb_2.signed_values().size(); ++i) {
    if (value == cb_2.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value) {
    FAIL();
  }
  for (boost::int16_t i = 0; i < kTestK - 2 && i < kNetworkSize - 2; ++i) {
    Contact ctc(nodes_[2 + i]->node_id(),
                     nodes_[2 + i]->ip(),
                     nodes_[2 + i]->port(),
                     nodes_[2 + i]->local_ip(),
                     nodes_[2 + i]->local_port());
    PingCallback ping_cb;
    nodes_[0]->Ping(ctc, boost::bind(&PingCallback::CallbackFunc,
                                      &ping_cb, _1));
    wait_result(&ping_cb);
    ASSERT_FALSE(ping_cb.result());
    ping_cb.Reset();
    nodes_[1]->Ping(ctc, boost::bind(&PingCallback::CallbackFunc,
                                      &ping_cb, _1));
    wait_result(&ping_cb);
    ASSERT_FALSE(ping_cb.result());
     ping_cb.Reset();
    nodes_[kNetworkSize - 1]->Ping(ctc,
                                    boost::bind(&PingCallback::CallbackFunc,
                                                &ping_cb, _1));
    wait_result(&ping_cb);
    ASSERT_FALSE(ping_cb.result());
  }
  // Restart dead nodes
  base::KadConfig kad_config;
  base::KadConfig::Contact *kad_contact = kad_config.add_contact();
  kad_contact->set_node_id(
      nodes_[0]->node_id().ToStringEncoded(NodeId::kHex));
  kad_contact->set_ip(nodes_[0]->ip());
  kad_contact->set_port(nodes_[0]->port());
  kad_contact->set_local_ip(nodes_[0]->local_ip());
  kad_contact->set_local_port(nodes_[0]->local_port());

  for (boost::int16_t i = 0; i < kTestK - 2 && i < kNetworkSize - 2; ++i) {
    cb_.Reset();
    std::string conf_file = dbs_[2 + i] + "/.kadconfig";

    std::fstream output(conf_file.c_str(),
                        std::ios::out | std::ios::trunc | std::ios::binary);
    ASSERT_TRUE(kad_config.SerializeToOstream(&output));
    output.close();

    transport::TransportCondition tc;
    transports_[i]->StartListening("", transport_ports_[2 + i], &tc);
    EXPECT_EQ(transport::kSuccess, tc);
    EXPECT_EQ(0, channel_managers_[2 + i]->Start());

    nodes_[2 + i]->Join(node_ids_[2 + i], conf_file,
                         boost::bind(&GeneralKadCallback::CallbackFunc,
                                     &cb_, _1));
    wait_result(&cb_);
    ASSERT_TRUE(cb_.result());
    ASSERT_TRUE(nodes_[2 + i]->is_joined());
    nodes_[2 + i]->set_signature_validator(&validator);
    ASSERT_TRUE(node_ids_[2 + i] == nodes_[2 + i]->node_id());
  }
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_Downlist) {
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  // select a random node from node 1 to node kNetworkSize
  int r_node = 1 + base::RandomInt32() % (kNetworkSize - 1);
  NodeId r_node_id(nodes_[r_node]->node_id());
  // Compute the sum of the nodes whose routing table contain r_node
  int sum_0 = 0;
  std::vector<boost::int16_t> holders;
  for (boost::int16_t i = 1; i < kNetworkSize; ++i) {
    if (i != r_node) {
      Contact test_contact;
      if (nodes_[i]->GetContact(r_node_id, &test_contact)) {
        if (test_contact.failed_rpc() == kFailedRpc) {
          ++sum_0;
          holders.push_back(i);
        }
      }
    }
  }
  cb_.Reset();
  // finding the closest node to the dead node
  boost::int16_t closest_node(0);
  NodeId holder_id(nodes_[holders[0]]->node_id());
  NodeId smallest_distance = r_node_id ^ holder_id;
  for (size_t i = 0; i < holders.size(); i++) {
    NodeId distance = r_node_id ^ nodes_[holders[i]]->node_id();
    if (smallest_distance > distance) {
      smallest_distance = distance;
      closest_node = i;
    }
  }

  Contact holder(nodes_[holders[closest_node]]->node_id(),
                 nodes_[holders[closest_node]]->ip(),
                 nodes_[holders[closest_node]]->port(),
                 nodes_[holders[closest_node]]->local_ip(),
                 nodes_[holders[closest_node]]->local_port());
  PingCallback cb_3;
  nodes_[0]->Ping(holder, boost::bind(&PingCallback::CallbackFunc, &cb_3, _1));
  wait_result(&cb_3);
  ASSERT_TRUE(cb_3.result());

  GetNodeContactDetailsCallback cb_1;
  Contact dead_node(r_node_id, nodes_[r_node]->ip(),
                    nodes_[r_node]->port(),
                    nodes_[r_node]->local_ip(),
                    nodes_[r_node]->local_port());
  PingCallback cb_2;
  nodes_[0]->Ping(dead_node, boost::bind(&PingCallback::CallbackFunc,
                                          &cb_2, _1));
  wait_result(&cb_2);
  ASSERT_TRUE(cb_2.result());
  // Kill r_node
  GeneralKadCallback cb_;
  nodes_[r_node]->Leave();
  ASSERT_FALSE(nodes_[r_node]->is_joined());
  transports_[r_node]->StopListening(transport_ports_[r_node]);
  channel_managers_[r_node]->Stop();

  // Do a find node
  nodes_[0]->FindKClosestNodes(
      r_node_id, boost::bind(&GetNodeContactDetailsCallback::CallbackFunc,
                             &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  // Wait for a RPC timeout interval until the downlist are handled in the
  // network
  boost::this_thread::sleep(boost::posix_time::seconds(11));
  // Compute the sum of the nodes whose routing table contain r_node again
  boost::int16_t sum_1(0);
  for (boost::int16_t i = 1; i < kNetworkSize; i++) {
    if (i != r_node) {
      Contact test_contact;
      if (nodes_[i]->GetContact(r_node_id, &test_contact)) {
        ++sum_1;
      } else {
        if (test_contact.failed_rpc() > kFailedRpc)
          ++sum_1;
      }
    }
  }
  // r_node should be removed from the routing tables of some nodes
  ASSERT_LT(sum_1, sum_0);

  // Restart dead node
  transport::TransportCondition tc;
  transports_[r_node]->StartListening("", transport_ports_[r_node], &tc);
  ASSERT_EQ(transport::kSuccess, tc);
  ASSERT_EQ(0, channel_managers_[r_node]->Start());
  cb_.Reset();
  std::string conf_file = dbs_[r_node] + "/.kadconfig";
  nodes_[r_node]->Join(node_ids_[r_node], conf_file,
                        boost::bind(&GeneralKadCallback::CallbackFunc,
                                    &cb_, _1));
  wait_result(&cb_);
  ASSERT_TRUE(cb_.result());
  ASSERT_TRUE(nodes_[r_node]->is_joined());
  nodes_[r_node]->set_signature_validator(&validator);
}

TEST_F(NodeTest, FUNC_KAD_StoreWithInvalidRequest) {
  NodeId key(cry_obj_.Hash("dccxxvdeee432cc", "", crypto::STRING_STRING, false));
  std::string value(base::RandomString(1024));  // 1KB
  SignedValue sig_value;
  sig_value.set_value(value);
  // save key/value pair from no.8 node
  StoreValueCallback cb_;
  std::string pub_key, priv_key, sig_pub_key, sig_req;
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key.String(), &sig_pub_key, &sig_req);
  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", priv_key,
                                                  crypto::STRING_STRING));
  std::string ser_sig_value = sig_value.SerializeAsString();
  SignedRequest req;
  req.set_signer_id(nodes_[kTestK / 2]->node_id().String());
  req.set_public_key(pub_key);
  req.set_signed_public_key(sig_pub_key);
  req.set_signed_request("bad request");

  nodes_[kTestK / 2]->StoreValue(key, sig_value, req, 24 * 3600,
                                  boost::bind(&StoreValueCallback::CallbackFunc,
                                              &cb_, _1));
  wait_result(&cb_);
  ASSERT_FALSE(cb_.result());
  std::string new_pub_key, new_priv_key;
  create_rsakeys(&new_pub_key, &new_priv_key);
  ASSERT_NE(pub_key, new_pub_key);
  cb_.Reset();
  req.set_signed_request(sig_req);
  req.set_public_key(new_pub_key);
  nodes_[kTestK / 2]->StoreValue(key, sig_value, req, 24 * 3600,
                                  boost::bind(&StoreValueCallback::CallbackFunc,
                                              &cb_, _1));
  wait_result(&cb_);
  ASSERT_FALSE(cb_.result());
}

TEST_F(NodeTest, FUNC_KAD_AllDirectlyConnected) {
  for (boost::int16_t i = 0; i < kNetworkSize; i++) {
    ASSERT_EQ(DIRECT_CONNECTED, nodes_[i]->nat_type());
    std::vector<Contact> exclude_contacts;
    std::vector<Contact> contacts;
    nodes_[i]->GetRandomContacts(static_cast<size_t>(kNetworkSize),
                                  exclude_contacts, &contacts);
    ASSERT_FALSE(contacts.empty());
    for (size_t j = 0; j < contacts.size(); j++) {
      ASSERT_EQ(std::string(""), contacts[j].rendezvous_ip());
      ASSERT_EQ(0, contacts[j].rendezvous_port());
    }
  }
}

TEST_F(NodeTest, FUNC_KAD_IncorrectNodeLocalAddrPing) {
  Contact remote(nodes_[kTestK * 3 / 4]->node_id(),
                      nodes_[kTestK * 3 / 4]->ip(),
                      nodes_[kTestK * 3 / 4]->port(),
                      nodes_[kTestK * 3 / 4]->local_ip(),
                      nodes_[kTestK * 3 / 4]->local_port());
  PingCallback cb_1;
  nodes_[kTestK / 4]->Ping(remote,
                            boost::bind(&PingCallback::CallbackFunc,
                                        &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());

  // now ping the node that has changed its local address
  Contact remote1(nodes_[kTestK / 4]->node_id(),
                       nodes_[kTestK / 4]->ip(),
                       nodes_[kTestK / 4]->port(),
                       nodes_[kTestK / 2]->local_ip(),
                       nodes_[kTestK / 2]->local_port());
  cb_1.Reset();
  nodes_[kTestK * 3 / 4]->Ping(remote1,
                                boost::bind(&PingCallback::CallbackFunc,
                                            &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_FindDeadNode) {
  // find an existing node that has gone down
  // select a random node from node 1 to node kNetworkSize
  boost::uint16_t r_node = 1 + rand() % (kNetworkSize - 2);  // NOLINT (Fraser)
  DLOG(INFO) << "+++++++++++++++++ r_node = " << r_node << std::endl;
  NodeId r_node_id = nodes_[r_node]->node_id();
  boost::uint16_t r_port = nodes_[r_node]->port();
  nodes_[r_node]->Leave();
  ASSERT_FALSE(nodes_[r_node]->is_joined());
  transports_[r_node]->StopListening(transport_ports_[r_node]);
  channel_managers_[r_node]->Stop();
  ports_.erase(r_port);
  // Do a find node
  DLOG(INFO) << "+++++++++++++++++ Node " << r_node << " stopped" << std::endl;
  GetNodeContactDetailsCallback cb_1;
  nodes_[kNetworkSize - 1]->GetNodeContactDetails(
      r_node_id, boost::bind(&GetNodeContactDetailsCallback::CallbackFunc,
                             &cb_1, _1),
      false);
  wait_result(&cb_1);
  ASSERT_FALSE(cb_1.result());
  boost::this_thread::sleep(boost::posix_time::seconds(33));
  // Restart dead node
  DLOG(INFO) << "+++++++++++++++++ Restarting " << r_node << std::endl;
  transport::TransportCondition tc;
  transports_[r_node]->StartListening("", transport_ports_[r_node], &tc);
  ASSERT_EQ(transport::kSuccess, tc);
  ASSERT_EQ(0, channel_managers_[r_node]->Start());
  cb_.Reset();
  std::string conf_file = dbs_[r_node] + "/.kadconfig";
  nodes_[r_node]->Join(node_ids_[r_node], conf_file,
                        boost::bind(&GeneralKadCallback::CallbackFunc,
                                    &cb_, _1));
  wait_result(&cb_);
  ASSERT_TRUE(cb_.result());
  ASSERT_TRUE(nodes_[r_node]->is_joined());
  nodes_[r_node]->set_signature_validator(&validator);
}

TEST_F(NodeTest, FUNC_KAD_StartStopNode) {
  boost::uint16_t r_node = 1 + rand() % (kNetworkSize - 1);  // NOLINT (Fraser)
  std::string kadconfig_path(dbs_[r_node] + "/.kadconfig");
  nodes_[r_node]->Leave();
  EXPECT_FALSE(nodes_[r_node]->is_joined());
  // Checking kadconfig file
  base::KadConfig kconf;
  ASSERT_TRUE(boost::filesystem::exists(
      boost::filesystem::path(kadconfig_path)));
  std::ifstream kadconf_file(kadconfig_path.c_str(),
                             std::ios::in | std::ios::binary);
  ASSERT_TRUE(kconf.ParseFromIstream(&kadconf_file));
  kadconf_file.close();
  ASSERT_LT(0, kconf.contact_size());
  cb_.Reset();
  std::string conf_file = dbs_[r_node] + "/.kadconfig";
  ASSERT_EQ(NONE, nodes_[r_node]->nat_type());
  nodes_[r_node]->Join(nodes_[r_node]->node_id(), conf_file,
                        boost::bind(&GeneralKadCallback::CallbackFunc,
                                    &cb_, _1));
  wait_result(&cb_);
  ASSERT_TRUE(cb_.result());
  ASSERT_TRUE(nodes_[r_node]->is_joined());
  ASSERT_EQ(DIRECT_CONNECTED, nodes_[r_node]->nat_type());
  nodes_[r_node]->set_signature_validator(&validator);
  cb_.Reset();
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_DeleteValue) {
  // prepare small size of values
  NodeId key(cry_obj_.Hash(base::RandomString(5), "", crypto::STRING_STRING,
                          false));
  std::string value(base::RandomString(1024 * 5));  // 5KB
  SignedValue sig_value;
  sig_value.set_value(value);
  // save key/value pair from no.8 node
  StoreValueCallback cb_;
  std::string pub_key, priv_key, sig_pub_key, sig_req;
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key.String(), &sig_pub_key, &sig_req);
  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", priv_key,
                                                  crypto::STRING_STRING));
  SignedRequest req;
  req.set_signer_id(nodes_[kTestK / 2]->node_id().String());
  req.set_public_key(pub_key);
  req.set_signed_public_key(sig_pub_key);
  req.set_signed_request(sig_req);

  nodes_[kTestK / 2]->StoreValue(key, sig_value, req, 24 * 3600,
                                  boost::bind(&StoreValueCallback::CallbackFunc,
                                              &cb_, _1));
  wait_result(&cb_);
  ASSERT_TRUE(cb_.result());
  // calculate number of nodes which hold this key/value pair
  boost::uint16_t number = 0;
  for (boost::uint16_t i = 0; i < kNetworkSize; i++) {
    std::vector<std::string> values;
    bool b = false;
    nodes_[i]->FindValueLocal(key, &values);
    if (!values.empty()) {
      for (size_t n = 0; n < values.size() && !b; ++n) {
        SignedValue sig_value;
        ASSERT_TRUE(sig_value.ParseFromString(values[n]));
        if (value == sig_value.value()) {
          number++;
          b = true;
        }
      }
    }
  }
  boost::uint16_t d(static_cast<boost::uint16_t>
    (kTestK * kMinSuccessfulPecentageStore));
  ASSERT_LE(d, number);
  // load the value from no.kNetworkSize-1 node
  cb_.Reset();
  FindCallback cb_1;
  nodes_[kNetworkSize - 2]->FindValue(key, false,
                                       boost::bind(&FindCallback::CallbackFunc,
                                                   &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  ASSERT_LE(1U, cb_1.signed_values().size());
  bool got_value = false;
  for (size_t i = 0; i < cb_1.signed_values().size(); i++) {
    if (value == cb_1.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value) {
    FAIL() << "FAIL node " << kNetworkSize - 2;
  }

  // Deleting Value
  DeleteValueCallback del_cb;
  nodes_[kTestK / 2]->DeleteValue(
      key, sig_value, req, boost::bind(&DeleteValueCallback::CallbackFunc,
                                       &del_cb, _1));
  wait_result(&del_cb);
  ASSERT_TRUE(del_cb.result());
  // Checking no node returns the value
  for (boost::uint16_t i = 0; i < kNetworkSize; i++) {
    std::vector<std::string> values;
    ASSERT_FALSE(nodes_[i]->FindValueLocal(key, &values));
    ASSERT_TRUE(values.empty());
  }


  // trying to load the value from no.1 node
  cb_1.Reset();
  nodes_[0]->FindValue(key, false,
                        boost::bind(&FakeCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_FALSE(cb_1.result());
  ASSERT_TRUE(cb_1.values().empty());
  ASSERT_TRUE(cb_1.signed_values().empty());
  cb_1.Reset();
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_InvalidRequestDeleteValue) {
  // prepare small size of values
  NodeId key(cry_obj_.Hash(base::RandomString(5), "", crypto::STRING_STRING,
                          false));
  std::string value = base::RandomString(1024 * 5);  // 5KB
  SignedValue sig_value;
  sig_value.set_value(value);
  // save key/value pair from no.8 node
  StoreValueCallback cb_;
  std::string pub_key, priv_key, sig_pub_key, sig_req;
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key.String(), &sig_pub_key, &sig_req);
  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", priv_key,
                                                  crypto::STRING_STRING));
  SignedRequest req;
  req.set_signer_id(nodes_[kTestK / 3]->node_id().String());
  req.set_public_key(pub_key);
  req.set_signed_public_key(sig_pub_key);
  req.set_signed_request(sig_req);

  nodes_[kTestK / 3]->StoreValue(key, sig_value, req, 24 * 3600,
                                  boost::bind(&StoreValueCallback::CallbackFunc,
                                              &cb_, _1));
  wait_result(&cb_);
  ASSERT_TRUE(cb_.result());

  // load the value from no.kNetworkSize-1 node
  cb_.Reset();
  FindCallback cb_1;
  nodes_[kNetworkSize - 2]->FindValue(key, false,
                                       boost::bind(&FindCallback::CallbackFunc,
                                                   &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  ASSERT_LE(1U, cb_1.signed_values().size());
  bool got_value = false;
  for (size_t i = 0; i < cb_1.signed_values().size(); i++) {
    if (value == cb_1.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value) {
    FAIL() << "FAIL node " << kNetworkSize - 2;
  }

  // Deleting Value
  std::string pub_key1, priv_key1, sig_pub_key1, sig_req1;
  create_rsakeys(&pub_key1, &priv_key1);
  create_req(pub_key1, priv_key1, key.String(), &sig_pub_key1, &sig_req1);
  req.Clear();
  req.set_signer_id(nodes_[kTestK / 2]->node_id().String());
  req.set_public_key(pub_key1);
  req.set_signed_public_key(sig_pub_key1);
  req.set_signed_request(sig_req1);
  DeleteValueCallback del_cb;
  nodes_[kNetworkSize - 1]->DeleteValue(
      key, sig_value, req, boost::bind(&DeleteValueCallback::CallbackFunc,
                                       &del_cb, _1));
  wait_result(&del_cb);
  ASSERT_FALSE(del_cb.result());

  del_cb.Reset();
  req.Clear();
  req.set_signer_id(nodes_[kTestK / 2]->node_id().String());
  req.set_public_key(pub_key1);
  req.set_signed_public_key(sig_pub_key);
  req.set_signed_request(sig_req);
  nodes_[kTestK / 3]->DeleteValue(
      key, sig_value, req, boost::bind(&DeleteValueCallback::CallbackFunc,
                                       &del_cb, _1));
  wait_result(&del_cb);
  ASSERT_FALSE(del_cb.result());

  del_cb.Reset();
  req.set_public_key(pub_key);
  sig_value.set_value("other value");
  nodes_[kTestK * 2 / 3]->DeleteValue(
      key, sig_value, req, boost::bind(&FakeCallback::CallbackFunc,
                                       &del_cb, _1));
  wait_result(&del_cb);
  ASSERT_FALSE(del_cb.result());

  // trying to load the value from no.1 node
  cb_1.Reset();
  nodes_[kNetworkSize - 2]->FindValue(key, false,
                                       boost::bind(&FakeCallback::CallbackFunc,
                                                   &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  ASSERT_LE(1U, cb_1.signed_values().size());
  got_value = false;
  for (size_t i = 0; i < cb_1.signed_values().size(); i++) {
    if (value == cb_1.signed_values()[i].value()) {
      got_value = true;
      break;
    }
  }
  if (!got_value) {
    FAIL() << "FAIL node " << kNetworkSize - 2;
  }
}

TEST_F(NodeTest, DISABLED_FUNC_KAD_UpdateValue) {
  // prepare small size of values
  NodeId key(cry_obj_.Hash(base::RandomString(5), "", crypto::STRING_STRING,
                          false));
  std::string value(base::RandomString(1024 * 5));  // 5KB
  std::string pub_key, priv_key, sig_pub_key, sig_req;
  create_rsakeys(&pub_key, &priv_key);
  create_req(pub_key, priv_key, key.String(), &sig_pub_key, &sig_req);

  SignedValue sig_value;
  sig_value.set_value(value);
  StoreValueCallback svcb;
  sig_value.set_value_signature(cry_obj_.AsymSign(value, "", priv_key,
                                                  crypto::STRING_STRING));
  SignedRequest req;
  req.set_signer_id(nodes_[kTestK / 2]->node_id().String());
  req.set_public_key(pub_key);
  req.set_signed_public_key(sig_pub_key);
  req.set_signed_request(sig_req);

  nodes_[kTestK / 2]->StoreValue(key, sig_value, req, 24 * 3600,
                                  boost::bind(&StoreValueCallback::CallbackFunc,
                                              &svcb, _1));
  wait_result(&svcb);
  ASSERT_TRUE(svcb.result());

  // calculate number of nodes which hold this key/value pair
  boost::uint16_t number(0);
  boost::int16_t no_value_node(-1);
  for (boost::uint16_t i = 0; i < kNetworkSize; i++) {
    std::vector<std::string> values;
    bool b(false);
    nodes_[i]->FindValueLocal(key, &values);
    if (!values.empty()) {
      for (size_t n = 0; n < values.size() && !b; ++n) {
        SignedValue sig_value;
        ASSERT_TRUE(sig_value.ParseFromString(values[n]));
        if (value == sig_value.value()) {
          ++number;
          b = true;
        }
      }
    } else {
      no_value_node = i;
    }
  }
  ASSERT_NE(-1, no_value_node);
  boost::uint16_t d(static_cast<boost::uint16_t>
                    (kTestK * kMinSuccessfulPecentageStore));
  ASSERT_LE(d, number);

  // load the value from no.kNetworkSize-1 node
  FindCallback cb_1;
  nodes_[no_value_node]->FindValue(key, false,
                                    boost::bind(&FindCallback::CallbackFunc,
                                                &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  ASSERT_LE(1U, cb_1.signed_values().size());
  bool got_value = false;
  for (size_t i = 0; i < cb_1.signed_values().size() && !got_value; i++)
    if (value == cb_1.signed_values()[i].value())
      got_value = true;

  if (!got_value) {
    FAIL() << "FAIL node " << kNetworkSize - 2;
  }

  // Deleting Value
  UpdateValueCallback update_cb;
  SignedValue new_sig_value;
  std::string new_value(base::RandomString(4 * 1024));  // 4KB
  new_sig_value.set_value(new_value);
  new_sig_value.set_value_signature(cry_obj_.AsymSign(new_value, "", priv_key,
                                                      crypto::STRING_STRING));
  nodes_[no_value_node]->UpdateValue(
      key, sig_value, new_sig_value, req, 86400,
      boost::bind(&UpdateValueCallback::CallbackFunc, &update_cb, _1));
  wait_result(&update_cb);
  ASSERT_TRUE(update_cb.result());
  number = 0;
  for (boost::uint16_t i = 0; i < kNetworkSize; ++i) {
    std::vector<std::string> values;
    bool b(false);
    nodes_[i]->FindValueLocal(key, &values);
    if (!values.empty()) {
      for (size_t n = 0; n < values.size() && !b; ++n) {
        SignedValue sig_value;
        ASSERT_TRUE(sig_value.ParseFromString(values[n]));
        if (new_value == sig_value.value()) {
          ++number;
          b = true;
        }
      }
    }
  }
  d = static_cast<boost::uint16_t>(kTestK * kMinSuccessfulPecentageStore);
  ASSERT_LE(d, number);

  // trying to load the value from no.1 node
  cb_1.Reset();
  nodes_[0]->FindValue(key, false,
                        boost::bind(&FindCallback::CallbackFunc, &cb_1, _1));
  wait_result(&cb_1);
  ASSERT_TRUE(cb_1.result());
  ASSERT_TRUE(cb_1.values().empty());
  ASSERT_EQ(1U, cb_1.signed_values().size());
  SignedValue el_valiu = cb_1.signed_values()[0];
  ASSERT_EQ(new_sig_value.SerializeAsString(), el_valiu.SerializeAsString());
}

}  // namespace test_node

}  // namespace kademlia
