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
#include "maidsafe/base/utils.h"
#include "maidsafe/kademlia/knode-api.h"
#include "maidsafe/kademlia/knodeimpl.h"
#include "maidsafe/rpcprotocol/channelmanager-api.h"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/udttransport.h"
#include "maidsafe/tests/validationimpl.h"
#include "maidsafe/tests/kademlia/fake_callbacks.h"

namespace kad {

namespace refresh_test {

class TestRefresh : public testing::Test {
 public:
  TestRefresh() : transports_(), ch_managers_(), nodes_(), datadirs_(),
                  test_dir_("temp/TestKnodes_"), testK_(4), testRefresh_(10),
                  testNetworkSize_(10), transport_ports_() {
    test_dir_ += boost::lexical_cast<std::string>(base::RandomUint32());
  }

  ~TestRefresh() { transport::UdtTransport::CleanUp(); }

  void SetUp() {
    try {
      if (boost::filesystem::exists(test_dir_))
        boost::filesystem::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "filesystem error: " << e.what() << std::endl;
    }

    // Creating the nodes
    transports_.resize(testNetworkSize_);
    ch_managers_.resize(testNetworkSize_);
    nodes_.resize(testNetworkSize_);
    datadirs_.resize(testNetworkSize_);
    transport_ports_.resize(testNetworkSize_);
    KnodeConstructionParameters kcp;
    kcp.type = VAULT;
    kcp.alpha = kad::kAlpha;
    kcp.beta = kad::kBeta;
    kcp.k = testK_;
    kcp.port_forwarded = false;
    kcp.private_key = "";
    kcp.public_key = "";
    kcp.refresh_time = testRefresh_;
    kcp.use_upnp = false;
    for (boost::int16_t i = 0; i < testNetworkSize_; ++i) {
      transports_[i].reset(new transport::UdtTransport);
      transport::TransportCondition tc;
      transport_ports_[i] = transports_[i]->StartListening("", 0, &tc);
      EXPECT_EQ(transport::kSuccess, tc);
      kcp.port = transport_ports_[i];
      ch_managers_[i].reset(new rpcprotocol::ChannelManager(transports_[i]));
      EXPECT_EQ(0, ch_managers_[i]->Start());
      std::string datadir = test_dir_ + std::string("/datastore") +
                            boost::lexical_cast<std::string>(i);
      boost::filesystem::create_directories(datadir);
      nodes_[i].reset(new KNode(ch_managers_[i], transports_[i], kcp));
      datadirs_[i] = datadir;
    }

    GeneralKadCallback callback;
    boost::asio::ip::address local_ip;
    ASSERT_TRUE(base::GetLocalAddress(&local_ip));
    DLOG(INFO) << "starting node 0" << std::endl;
    nodes_[0]->JoinFirstNode(datadirs_[0] + "/.kadconfig", local_ip.to_string(),
                             transport_ports_[0],
                             boost::bind(&GeneralKadCallback::CallbackFunc,
                                         &callback, _1));
    wait_result(&callback);
    ASSERT_TRUE(callback.result());
    callback.Reset();
    ASSERT_TRUE(nodes_[0]->is_joined());

    for (boost::int16_t i = 1; i < testNetworkSize_; ++i) {
      DLOG(INFO) << "starting node " <<  i << std::endl;
      std::string kconfig_file1 = datadirs_[i] + "/.kadconfig";
      base::KadConfig kad_config1;
      base::KadConfig::Contact *kad_contact = kad_config1.add_contact();
      kad_contact->set_node_id(
            nodes_[0]->node_id().ToStringEncoded(KadId::kHex));
      kad_contact->set_ip(nodes_[0]->ip());
      kad_contact->set_port(nodes_[0]->port());
      kad_contact->set_local_ip(nodes_[0]->local_ip());
      kad_contact->set_local_port(nodes_[0]->local_port());
      std::fstream output1(kconfig_file1.c_str(), std::ios::out |
                                                  std::ios::trunc |
                                                  std::ios::binary);
      EXPECT_TRUE(kad_config1.SerializeToOstream(&output1));
      output1.close();

      nodes_[i]->Join(kconfig_file1,
                      boost::bind(&GeneralKadCallback::CallbackFunc,
                                  &callback, _1));
      wait_result(&callback);
      ASSERT_TRUE(callback.result());
      callback.Reset();
      ASSERT_TRUE(nodes_[i]->is_joined());
    }
  }

  void TearDown() {
    for (boost::int16_t i = testNetworkSize_-1; i >= 0; --i) {
      DLOG(INFO) << "stopping node " << i << std::endl;
      nodes_[i]->Leave();
      EXPECT_FALSE(nodes_[i]->is_joined());
      transports_[i]->StopListening(transport_ports_[i]);
      ch_managers_[i]->Stop();
    }
    try {
      boost::filesystem::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "filesystem error: " << e.what() << std::endl;
    }
    nodes_.clear();
    ch_managers_.clear();
    transports_.clear();
    transport_ports_.clear();
    datadirs_.clear();
  }

  std::vector<boost::shared_ptr<transport::UdtTransport> > transports_;
  std::vector<boost::shared_ptr<rpcprotocol::ChannelManager> > ch_managers_;
  std::vector<boost::shared_ptr<KNode> > nodes_;
  std::vector<std::string> datadirs_;
  std::string test_dir_;
  boost::uint16_t testK_;
  boost::uint32_t testRefresh_;
  boost::int16_t testNetworkSize_;
  std::vector<rpcprotocol::Port> transport_ports_;
};

TEST_F(TestRefresh, FUNC_KAD_RefreshValue) {
/**/
  // Storing a Value
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  kad::KadId key(co.Hash("key", "", crypto::STRING_STRING, false));
  std::string value = base::RandomString(1024*5);
  StoreValueCallback store_cb;
  nodes_[4]->StoreValue(key, value, 24*3600,
                        boost::bind(&StoreValueCallback::CallbackFunc,
                                    &store_cb, _1));
  wait_result(&store_cb);
  ASSERT_TRUE(store_cb.result());
  std::vector<boost::int16_t> indxs;
  std::vector<boost::uint32_t> last_refresh_times;
  std::vector<boost::uint32_t> expire_times;
  for (boost::int16_t i = 0; i < testNetworkSize_; ++i) {
    std::vector<std::string> values;
    if (nodes_[i]->FindValueLocal(key, &values)) {
      ASSERT_EQ(value, values[0]);
      indxs.push_back(i);
      boost::uint32_t last_refresh = nodes_[i]->KeyLastRefreshTime(key, value);
      ASSERT_NE(0, last_refresh) << "key/value pair not found";
      last_refresh_times.push_back(last_refresh);
      boost::uint32_t expire_time = nodes_[i]->KeyExpireTime(key, value);
      ASSERT_NE(0, expire_time) << "key/value pair not found";
      expire_times.push_back(expire_time);
    }
  }
  ASSERT_EQ(testK_, indxs.size());
  boost::this_thread::sleep(boost::posix_time::seconds(testRefresh_+8));
  for (size_t i = 0; i < indxs.size(); i++) {
    std::vector<std::string> values;
    EXPECT_TRUE(nodes_[indxs[i]]->FindValueLocal(key, &values));
    EXPECT_EQ(value, values[0]);
    EXPECT_EQ(expire_times[i], nodes_[indxs[i]]->KeyExpireTime(key, value));
    EXPECT_LT(last_refresh_times[i],
              nodes_[indxs[i]]->KeyLastRefreshTime(key, value))
              << "FAILED  WITH NODE " << indxs[i];
  }
/**/
}

TEST_F(TestRefresh, FUNC_KAD_NewNodeinKClosest) {
  // Storing a Value
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  kad::KadId key(co.Hash("key", "", crypto::STRING_STRING, false));
  std::string value = base::RandomString(1024*5);
  StoreValueCallback store_cb;
  nodes_[4]->StoreValue(key, value, 24*3600,
                        boost::bind(&StoreValueCallback::CallbackFunc,
                                    &store_cb, _1));
  wait_result(&store_cb);
  ASSERT_TRUE(store_cb.result());
  std::vector<boost::int16_t> indxs;
  std::vector<boost::uint32_t> last_refresh_times;
  std::vector<boost::uint32_t> expire_times;
  for (boost::int16_t i = 0; i < testNetworkSize_; ++i) {
    std::vector<std::string> values;
    if (nodes_[i]->FindValueLocal(key, &values)) {
      ASSERT_EQ(value, values[0]);
      indxs.push_back(i);
      boost::uint32_t last_refresh = nodes_[i]->KeyLastRefreshTime(key, value);
      ASSERT_NE(0, last_refresh) << "key/value pair not found";
      last_refresh_times.push_back(last_refresh);
      boost::uint32_t expire_time = nodes_[i]->KeyExpireTime(key, value);
      ASSERT_NE(0, expire_time) << "key/value pair not found";
      expire_times.push_back(expire_time);
    }
  }
  ASSERT_EQ(testK_, indxs.size());

  boost::shared_ptr<transport::UdtTransport> trans(new transport::UdtTransport);
  boost::shared_ptr<rpcprotocol::ChannelManager> chm(
      new rpcprotocol::ChannelManager(trans));
  std::string local_dir(test_dir_ + std::string("/datastorenewnode"));
  boost::filesystem::create_directories(local_dir);
  transport::TransportCondition tc;
  transport::Port p = trans->StartListening("", 0, &tc);
  ASSERT_EQ(transport::kSuccess, tc);
  ASSERT_EQ(0, chm->Start());
  KnodeConstructionParameters kcp;
  kcp.type = VAULT;
  kcp.alpha = kad::kAlpha;
  kcp.beta = kad::kBeta;
  kcp.k = testK_;
  kcp.port_forwarded = false;
  kcp.private_key = "";
  kcp.public_key = "";
  kcp.refresh_time = testRefresh_;
  kcp.use_upnp = false;
  kcp.port = p;
  KNode node(chm, trans, kcp);

  std::string kconfig_file1(local_dir + "/.kadconfig");
  base::KadConfig kad_config1;
  base::KadConfig::Contact *kad_contact = kad_config1.add_contact();
  kad_contact->set_node_id(nodes_[0]->node_id().ToStringEncoded(KadId::kHex));
  kad_contact->set_ip(nodes_[0]->ip());
  kad_contact->set_port(nodes_[0]->port());
  kad_contact->set_local_ip(nodes_[0]->local_ip());
  kad_contact->set_local_port(nodes_[0]->local_port());
  std::fstream output1(kconfig_file1.c_str(), std::ios::out | std::ios::trunc |
                                              std::ios::binary);
  EXPECT_TRUE(kad_config1.SerializeToOstream(&output1));
  output1.close();
  GeneralKadCallback callback;
  // joining node with id == key of value stored
  node.Join(key, kconfig_file1,
            boost::bind(&GeneralKadCallback::CallbackFunc, &callback, _1));
  wait_result(&callback);
  ASSERT_TRUE(callback.result());
  callback.Reset();
  ASSERT_TRUE(node.is_joined());

  boost::this_thread::sleep(boost::posix_time::seconds(testRefresh_ + 8));
  std::vector<std::string> values;
  EXPECT_TRUE(node.FindValueLocal(key, &values));
  EXPECT_EQ(value, values[0]);
  EXPECT_NE(0, node.KeyExpireTime(key, value)) << "key/value pair not found";
  EXPECT_NE(0, node.KeyLastRefreshTime(key, value))
            << "key/value pair not found";

  node.Leave();
  EXPECT_FALSE(node.is_joined());
  trans->StopListening(p);
  chm->Stop();
}

class TestRefreshSignedValues : public testing::Test {
 protected:
  TestRefreshSignedValues()
      : transports_(), ch_managers_(), nodes_(), datadirs_(), keys_(),
        test_dir_("temp/TestKnodes_"), testK_(4), testRefresh_(10),
        testNetworkSize_(10), validators_(), transport_ports_() {
    test_dir_ += boost::lexical_cast<std::string>(base::RandomUint32());
  }

  ~TestRefreshSignedValues() {
    transport::UdtTransport::CleanUp();
  }

  void SetUp() {
    try {
      if (boost::filesystem::exists(test_dir_))
        boost::filesystem::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "filesystem error: " << e.what() << std::endl;
    }

    // Creating the nodes
    transports_.resize(testNetworkSize_);
    ch_managers_.resize(testNetworkSize_);
    nodes_.resize(testNetworkSize_);
    datadirs_.resize(testNetworkSize_);
    transport_ports_.resize(testNetworkSize_);
    keys_.resize(testNetworkSize_);
    validators_.resize(testNetworkSize_);

    crypto::RsaKeyPair keys;
    KnodeConstructionParameters kcp;
    kcp.type = VAULT;
    kcp.alpha = kad::kAlpha;
    kcp.beta = kad::kBeta;
    kcp.k = testK_;
    kcp.port_forwarded = false;
    kcp.refresh_time = testRefresh_;
    kcp.use_upnp = false;
    for (boost::int16_t i = 0; i < testNetworkSize_; i++) {
      keys.ClearKeys();
      keys.GenerateKeys(4096);
      kcp.private_key = keys.private_key();
      kcp.public_key = keys.public_key();
      keys_[i] = std::pair<std::string, std::string>(kcp.public_key,
                                                     kcp.private_key);
      transports_[i].reset(new transport::UdtTransport);
      transport::TransportCondition tc;
      transport_ports_[i] = transports_[i]->StartListening("", 0, &tc);
      EXPECT_EQ(transport::kSuccess, tc);
      kcp.port = transport_ports_[i];
      ch_managers_[i].reset(new rpcprotocol::ChannelManager(transports_[i]));
      EXPECT_EQ(0, ch_managers_[i]->Start());
      std::string datadir = test_dir_ + std::string("/datastore") +
                            boost::lexical_cast<std::string>(i);
      boost::filesystem::create_directories(datadir);
      nodes_[i].reset(new KNode(ch_managers_[i], transports_[i], kcp));
      datadirs_[i] = datadir;
      nodes_[i]->set_signature_validator(&validators_[i]);
    }

    GeneralKadCallback callback;
    DLOG(INFO) << "starting node 0 - port(" << transport_ports_[0] << ")"
              << std::endl;
    boost::asio::ip::address local_ip;
    ASSERT_TRUE(base::GetLocalAddress(&local_ip));
    nodes_[0]->JoinFirstNode(datadirs_[0] + "/.kadconfig", local_ip.to_string(),
                             transport_ports_[0],
                             boost::bind(&GeneralKadCallback::CallbackFunc,
                                         &callback, _1));
    wait_result(&callback);
    ASSERT_TRUE(callback.result());
    callback.Reset();
    ASSERT_TRUE(nodes_[0]->is_joined());
    for (boost::int16_t i = 1; i < testNetworkSize_; i++) {
      DLOG(INFO) << "starting node " << i << " - port(" << transport_ports_[i]
                << ")" << std::endl;
      std::string kconfig_file1 = datadirs_[i] + "/.kadconfig";
      base::KadConfig kad_config1;
      base::KadConfig::Contact *kad_contact = kad_config1.add_contact();
      kad_contact->set_node_id(
            nodes_[0]->node_id().ToStringEncoded(KadId::kHex));
      kad_contact->set_ip(nodes_[0]->ip());
      kad_contact->set_port(nodes_[0]->port());
      kad_contact->set_local_ip(nodes_[0]->local_ip());
      kad_contact->set_local_port(nodes_[0]->local_port());
      std::fstream output1(kconfig_file1.c_str(), std::ios::out |
                                                  std::ios::trunc |
                                                  std::ios::binary);
      EXPECT_TRUE(kad_config1.SerializeToOstream(&output1));
      output1.close();

      nodes_[i]->Join(kconfig_file1,
                      boost::bind(&GeneralKadCallback::CallbackFunc, &callback,
                                  _1));
      wait_result(&callback);
      ASSERT_TRUE(callback.result());
      callback.Reset();
      ASSERT_TRUE(nodes_[i]->is_joined());
    }
  }

  void TearDown() {
    for (boost::int16_t i = testNetworkSize_-1; i >= 0; --i) {
      DLOG(INFO) << "stopping node " << i << std::endl;
      nodes_[i]->Leave();
      EXPECT_FALSE(nodes_[i]->is_joined());
      transports_[i]->StopListening(transport_ports_[i]);
      ch_managers_[i]->Stop();
    }
    try {
      boost::filesystem::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "filesystem error: " << e.what() << std::endl;
    }
    nodes_.clear();
    ch_managers_.clear();
    transports_.clear();
    transport_ports_.clear();
    datadirs_.clear();
  }

  std::vector<boost::shared_ptr<transport::UdtTransport> > transports_;
  std::vector<boost::shared_ptr<rpcprotocol::ChannelManager> > ch_managers_;
  std::vector<boost::shared_ptr<KNode> > nodes_;
  std::vector<std::string> datadirs_;
  std::vector<std::pair<std::string, std::string> > keys_;
  std::string test_dir_;
  boost::uint16_t testK_;
  boost::uint32_t testRefresh_;
  boost::int16_t testNetworkSize_;
  std::vector<base::TestValidator> validators_;
  std::vector<transport::Port> transport_ports_;
};

TEST_F(TestRefreshSignedValues, FUNC_KAD_RefreshSignedValue) {
  // Storing a Value
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  kad::KadId key(co.Hash("key", "", crypto::STRING_STRING, false));
  std::string value = base::RandomString(1024*5);
  StoreValueCallback store_cb;
  std::string signed_public_key, signed_request;
  signed_public_key = co.AsymSign(keys_[4].first, "", keys_[4].second,
                                  crypto::STRING_STRING);
  signed_request = co.AsymSign(co.Hash(keys_[4].first + signed_public_key +
                                       key.String(), "",
                                       crypto::STRING_STRING, true),
                               "", keys_[4].second, crypto::STRING_STRING);
  kad::SignedValue sig_value;
  sig_value.set_value(value);
  sig_value.set_value_signature(co.AsymSign(value, "", keys_[4].second,
                                            crypto::STRING_STRING));
  std::string ser_sig_value = sig_value.SerializeAsString();
  kad::SignedRequest req;
  req.set_signer_id(nodes_[4]->node_id().String());
  req.set_public_key(keys_[4].first);
  req.set_signed_public_key(signed_public_key);
  req.set_signed_request(signed_request);
  nodes_[4]->StoreValue(key, sig_value, req, 24 * 3600,
                        boost::bind(&StoreValueCallback::CallbackFunc,
                                    &store_cb, _1));
  wait_result(&store_cb);
  ASSERT_TRUE(store_cb.result());
  std::vector<boost::int16_t> indxs;
  std::vector<boost::uint32_t> last_refresh_times;
  std::vector<boost::uint32_t> expire_times;
  for (boost::int16_t i = 0; i < testNetworkSize_; ++i) {
    std::vector<std::string> values;
    if (nodes_[i]->FindValueLocal(key, &values)) {
      ASSERT_EQ(ser_sig_value, values[0]);
      indxs.push_back(i);
      boost::uint32_t last_refresh =
          nodes_[i]->KeyLastRefreshTime(key, ser_sig_value);
      ASSERT_NE(0, last_refresh) << "key/value pair not found";
      last_refresh_times.push_back(last_refresh);
      boost::uint32_t expire_time = nodes_[i]->KeyExpireTime(key,
                                                             ser_sig_value);
      ASSERT_NE(0, expire_time) << "key/value pair not found";
      expire_times.push_back(expire_time);
    }
  }
  ASSERT_EQ(testK_, indxs.size());
  boost::this_thread::sleep(boost::posix_time::seconds(testRefresh_ + 8));
  for (size_t i = 0; i < indxs.size(); i++) {
    std::vector<std::string> values;
    EXPECT_TRUE(nodes_[indxs[i]]->FindValueLocal(key, &values));
    EXPECT_EQ(ser_sig_value, values[0]);
    EXPECT_EQ(expire_times[i],
              nodes_[indxs[i]]->KeyExpireTime(key, ser_sig_value));
    EXPECT_LT(last_refresh_times[i],
              nodes_[indxs[i]]->KeyLastRefreshTime(key, ser_sig_value))
              << "FAILED  WITH NODE " << indxs[i];
  }
}

TEST_F(TestRefreshSignedValues, FUNC_KAD_NewRSANodeinKClosest) {
  // Storing a Value
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  kad::KadId key(co.Hash("key", "", crypto::STRING_STRING, false));
  std::string value = base::RandomString(1024 * 5);
  StoreValueCallback store_cb;
  std::string pub_key = keys_[4].first;
  std::string priv_key = keys_[4].second;
  std::string signed_public_key, signed_request;
  signed_public_key = co.AsymSign(pub_key, "", priv_key, crypto::STRING_STRING);
  signed_request = co.AsymSign(co.Hash(pub_key+signed_public_key+key.String(),
                                       "", crypto::STRING_STRING, true),
                               "", priv_key, crypto::STRING_STRING);
  kad::SignedValue sig_value;
  sig_value.set_value(value);
  sig_value.set_value_signature(co.AsymSign(value, "", priv_key,
                                            crypto::STRING_STRING));
  std::string ser_sig_value = sig_value.SerializeAsString();
  kad::SignedRequest req;
  req.set_signer_id(nodes_[4]->node_id().String());
  req.set_public_key(pub_key);
  req.set_signed_public_key(signed_public_key);
  req.set_signed_request(signed_request);
  nodes_[4]->StoreValue(key, sig_value, req, 24 * 3600,
                        boost::bind(&StoreValueCallback::CallbackFunc,
                                    &store_cb, _1));
  wait_result(&store_cb);
  ASSERT_TRUE(store_cb.result());
  std::vector<boost::int16_t> indxs;
  std::vector<boost::uint32_t> last_refresh_times;
  std::vector<boost::uint32_t> expire_times;
  for (boost::int16_t i = 0; i < testNetworkSize_; i++) {
    std::vector<std::string> values;
    if (nodes_[i]->FindValueLocal(key, &values)) {
      ASSERT_EQ(ser_sig_value, values[0]);
      indxs.push_back(i);
      boost::uint32_t last_refresh =
          nodes_[i]->KeyLastRefreshTime(key, ser_sig_value);
      ASSERT_NE(0, last_refresh) << "key/value pair not found";
      last_refresh_times.push_back(last_refresh);
      boost::uint32_t expire_time = nodes_[i]->KeyExpireTime(key,
                                                             ser_sig_value);
      ASSERT_NE(0, expire_time) << "key/value pair not found";
      expire_times.push_back(expire_time);
    }
  }
  ASSERT_EQ(testK_, indxs.size());

  boost::shared_ptr<transport::UdtTransport> trans(new transport::UdtTransport);
  boost::shared_ptr<rpcprotocol::ChannelManager> chm(
      new rpcprotocol::ChannelManager(trans));
  std::string local_dir(test_dir_ + std::string("/datastorenewnode"));
  boost::filesystem::create_directories(local_dir);
  transport::TransportCondition tc;
  transport::Port p = trans->StartListening("", 0, &tc);
  ASSERT_EQ(transport::kSuccess, tc);
  ASSERT_EQ(0, chm->Start());

  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);
  KnodeConstructionParameters kcp;
  kcp.type = VAULT;
  kcp.alpha = kad::kAlpha;
  kcp.beta = kad::kBeta;
  kcp.k = testK_;
  kcp.port_forwarded = false;
  kcp.private_key = keys.private_key();
  kcp.public_key = keys.public_key();
  kcp.refresh_time = testRefresh_;
  kcp.use_upnp = false;
  kcp.port = p;
  KNode node(chm, trans, kcp);

  std::string kconfig_file1 = local_dir + "/.kadconfig";
  base::KadConfig kad_config1;
  base::KadConfig::Contact *kad_contact = kad_config1.add_contact();
  kad_contact->set_node_id(nodes_[0]->node_id().ToStringEncoded(KadId::kHex));
  kad_contact->set_ip(nodes_[0]->ip());
  kad_contact->set_port(nodes_[0]->port());
  kad_contact->set_local_ip(nodes_[0]->local_ip());
  kad_contact->set_local_port(nodes_[0]->local_port());
  std::fstream output1(kconfig_file1.c_str(), std::ios::out | std::ios::trunc |
                                              std::ios::binary);
  EXPECT_TRUE(kad_config1.SerializeToOstream(&output1));
  output1.close();
  GeneralKadCallback callback;
  // joining node with id == key of value stored
  base::TestValidator validator;
  node.set_signature_validator(&validator);
  node.Join(key, kconfig_file1,
            boost::bind(&GeneralKadCallback::CallbackFunc, &callback, _1));
  wait_result(&callback);
  ASSERT_TRUE(callback.result());
  callback.Reset();
  ASSERT_TRUE(node.is_joined());
  DLOG(INFO) << "Joined extra node - port (" << p << ")." << std::endl;

  boost::this_thread::sleep(boost::posix_time::seconds(testRefresh_ + 8));
  std::vector<std::string> values;
  if (!node.FindValueLocal(key, &values)) {
    node.Leave();
    EXPECT_FALSE(node.is_joined());
    trans->StopListening(p);
    chm->Stop();
    FAIL() << "New node doesn't have the value";
  }
  EXPECT_EQ(ser_sig_value, values[0]);
  EXPECT_NE(0, node.KeyExpireTime(key, ser_sig_value));
  EXPECT_NE(0, node.KeyLastRefreshTime(key, ser_sig_value));

  node.Leave();
  EXPECT_FALSE(node.is_joined());
  trans->StopListening(p);
  chm->Stop();
}

TEST_F(TestRefreshSignedValues, FUNC_KAD_InformOfDeletedValue) {
  // Storing a Value
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  kad::KadId key(co.Hash("key", "", crypto::STRING_STRING, false));
  std::string value = base::RandomString(1024 * 5);
  StoreValueCallback store_cb;
  std::string pub_key = keys_[4].first;
  std::string priv_key = keys_[4].second;
  std::string signed_public_key, signed_request;
  signed_public_key = co.AsymSign(pub_key, "", priv_key, crypto::STRING_STRING);
  signed_request = co.AsymSign(co.Hash(pub_key+signed_public_key+key.String(),
                                       "", crypto::STRING_STRING, true),
                               "", priv_key, crypto::STRING_STRING);
  kad::SignedValue sig_value;
  sig_value.set_value(value);
  sig_value.set_value_signature(co.AsymSign(value, "", priv_key,
                                            crypto::STRING_STRING));
  std::string ser_sig_value = sig_value.SerializeAsString();
  kad::SignedRequest req;
  req.set_signer_id(nodes_[4]->node_id().String());
  req.set_public_key(pub_key);
  req.set_signed_public_key(signed_public_key);
  req.set_signed_request(signed_request);
  nodes_[4]->StoreValue(key, sig_value, req, 24 * 3600,
                        boost::bind(&StoreValueCallback::CallbackFunc,
                                    &store_cb, _1));
  wait_result(&store_cb);
  ASSERT_TRUE(store_cb.result());

  boost::shared_ptr<transport::UdtTransport> trans(new transport::UdtTransport);
  boost::shared_ptr<rpcprotocol::ChannelManager> chm(
      new rpcprotocol::ChannelManager(trans));
  std::string local_dir(test_dir_ + std::string("/datastorenewnode"));
  boost::filesystem::create_directories(local_dir);
  transport::TransportCondition tc;
  transport::Port p = trans->StartListening("", 0, &tc);
  ASSERT_EQ(transport::kSuccess, tc);
  ASSERT_EQ(0, chm->Start());

  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);
  KnodeConstructionParameters kcp;
  kcp.type = VAULT;
  kcp.alpha = kad::kAlpha;
  kcp.beta = kad::kBeta;
  kcp.k = testK_;
  kcp.port_forwarded = false;
  kcp.private_key = keys.private_key();
  kcp.public_key = keys.public_key();
  kcp.refresh_time = testRefresh_;
  kcp.use_upnp = false;
  kcp.port = p;
  KNode node(chm, trans, kcp);

  std::string kconfig_file1 = local_dir + "/.kadconfig";
  base::KadConfig kad_config1;
  base::KadConfig::Contact *kad_contact = kad_config1.add_contact();
  kad_contact->set_node_id(nodes_[0]->node_id().ToStringEncoded(KadId::kHex));
  kad_contact->set_ip(nodes_[0]->ip());
  kad_contact->set_port(nodes_[0]->port());
  kad_contact->set_local_ip(nodes_[0]->local_ip());
  kad_contact->set_local_port(nodes_[0]->local_port());
  std::fstream output1(kconfig_file1.c_str(), std::ios::out | std::ios::trunc |
                                              std::ios::binary);
  EXPECT_TRUE(kad_config1.SerializeToOstream(&output1));
  output1.close();
  GeneralKadCallback callback;
  // joining node with id == key of value stored
  base::TestValidator validator;
  node.set_signature_validator(&validator);
  node.Join(key, kconfig_file1,
            boost::bind(&GeneralKadCallback::CallbackFunc, &callback, _1));
  wait_result(&callback);
  ASSERT_TRUE(callback.result());
  callback.Reset();
  ASSERT_TRUE(node.is_joined());

  boost::this_thread::sleep(boost::posix_time::seconds(testRefresh_ + 8));
  std::vector<std::string> values;
  if (!node.FindValueLocal(key, &values)) {
    node.Leave();
    EXPECT_FALSE(node.is_joined());
    trans->StopListening(p);
    chm->Stop();
    FAIL();
  }
  EXPECT_EQ(ser_sig_value, values[0]);
  EXPECT_NE(0, node.KeyExpireTime(key, ser_sig_value));
  EXPECT_NE(0, node.KeyLastRefreshTime(key, ser_sig_value));

  // Find a Node that doesn't have the value
  boost::int16_t counter = 0;
  for (counter = 0; counter < testNetworkSize_; ++counter) {
    values.clear();
    if (!nodes_[counter]->FindValueLocal(key, &values))
      break;
  }
  // Deleating the value
  DeleteValueCallback del_cb;
  nodes_[counter]->DeleteValue(key, sig_value, req,
                               boost::bind(&DeleteValueCallback::CallbackFunc,
                                           &del_cb, _1));
  wait_result(&del_cb);
  EXPECT_TRUE(del_cb.result());

  // at least one node should have the value
  counter = 0;
  for (counter = 0; counter < testNetworkSize_; ++counter) {
    values.clear();
    if (nodes_[counter]->FindValueLocal(key, &values))
      break;
  }
  if (counter == testNetworkSize_) {
    node.Leave();
    EXPECT_FALSE(node.is_joined());
    trans->StopListening(p);
    chm->Stop();
    FAIL() << "All values have been deleted, it will not be refreshed";
  }
  boost::this_thread::sleep(boost::posix_time::seconds(testRefresh_ * 2));
  for (counter = 0; counter < testNetworkSize_; ++counter) {
    values.clear();
    if (nodes_[counter]->FindValueLocal(key, &values))
      break;
  }
  values.clear();
  if (counter < testNetworkSize_ || node.FindValueLocal(key, &values)) {
    node.Leave();
    EXPECT_FALSE(node.is_joined());
    trans->StopListening(p);
    chm->Stop();
    FAIL() << "Key/pair was not deleted";
  }
  FindCallback find_cb;
  node.FindValue(key, false, boost::bind(&FindCallback::CallbackFunc,
                                         &find_cb, _1));
  wait_result(&find_cb);
  EXPECT_FALSE(find_cb.result());

  node.Leave();
  EXPECT_FALSE(node.is_joined());
  trans->StopListening(p);
  chm->Stop();
}

}  // namespace refresh_test

}  // namespace kad
