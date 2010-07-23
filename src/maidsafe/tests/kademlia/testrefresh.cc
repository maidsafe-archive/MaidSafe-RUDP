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
#include "maidsafe/tests/kademlia/fake_callbacks.h"
#include "maidsafe/base/log.h"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/transportudt.h"
#include "maidsafe/tests/validationimpl.h"

namespace kad {

class TestRefresh : public testing::Test {
 public:
  TestRefresh() : trans_handlers_(), ch_managers_(), nodes_(), datadirs_(),
    test_dir_("TestKnodes_"), testK_(4), testRefresh_(10),
    testNetworkSize_(10), transports_ids_() {
    test_dir_ += boost::lexical_cast<std::string>(
      base::RandomUint32());
  }
  ~TestRefresh() {
    transport::TransportUDT::CleanUp();
  }
 protected:
  void SetUp() {
    try {
      if (boost::filesystem::exists(test_dir_))
        boost::filesystem::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      LOG(ERROR) << "filesystem error: " << e.what() << std::endl;
    }
    // Creating the nodes_
    boost::int16_t transport_id;
    for (boost::int16_t i = 0; i < testNetworkSize_; ++i) {
      trans_handlers_.push_back(boost::shared_ptr<transport::TransportHandler>(
          new transport::TransportHandler));
      trans_handlers_.at(i)->Register(new transport::TransportUDT,
                                      &transport_id);
      transports_ids_.push_back(transport_id);
      ch_managers_.push_back(boost::shared_ptr<rpcprotocol::ChannelManager>(
          new rpcprotocol::ChannelManager(trans_handlers_[i].get())));
      std::string datadir = test_dir_ + std::string("/datastore") +
          boost::lexical_cast<std::string>(i);
      boost::filesystem::create_directories(datadir);
      nodes_.push_back(boost::shared_ptr<KNode>(new KNode(ch_managers_[i].get(),
          trans_handlers_[i].get(), VAULT, testK_, kAlpha, kBeta,
          testRefresh_, "", "", false, false)));
      nodes_[i]->set_transport_id(transport_id);
//       ASSERT_TRUE(ch_managers_[i]->RegisterNotifiersToTransport());
//       ASSERT_TRUE(trans_handlers_[i]->RegisterOnServerDown(boost::bind(
//         &kad::KNode::HandleDeadRendezvousServer, nodes_[i].get(), _1)));
//       EXPECT_EQ(0, trans_handlers_[i]->Start(0, transport_id));
      EXPECT_EQ(0, ch_managers_[i]->Start());
      datadirs_.push_back(datadir);
    }
    GeneralKadCallback callback;
    LOG(INFO) << "starting node 0" << std::endl;
    boost::asio::ip::address local_ip;
    ASSERT_TRUE(base::GetLocalAddress(&local_ip));
    nodes_[0]->Join(datadirs_[0] + "/.kadconfig",
      local_ip.to_string(), trans_handlers_[0]->listening_port(0),
      boost::bind(&GeneralKadCallback::CallbackFunc, &callback, _1));
    wait_result(&callback);
    ASSERT_EQ(kRpcResultSuccess, callback.result());
    callback.Reset();
    ASSERT_TRUE(nodes_[0]->is_joined());
    for (boost::int16_t i = 1; i < testNetworkSize_; ++i) {
      LOG(INFO) << "starting node " <<  i << std::endl;
      std::string kconfig_file1 = datadirs_[i] + "/.kadconfig";
      base::KadConfig kad_config1;
      base::KadConfig::Contact *kad_contact = kad_config1.add_contact();
      kad_contact->set_node_id(
            nodes_[0]->node_id().ToStringEncoded(KadId::kHex));
      kad_contact->set_ip(nodes_[0]->host_ip());
      kad_contact->set_port(nodes_[0]->host_port());
      kad_contact->set_local_ip(nodes_[0]->local_host_ip());
      kad_contact->set_local_port(nodes_[0]->local_host_port());
      std::fstream output1(kconfig_file1.c_str(),
        std::ios::out | std::ios::trunc | std::ios::binary);
      EXPECT_TRUE(kad_config1.SerializeToOstream(&output1));
      output1.close();

      nodes_[i]->Join(kconfig_file1,
          boost::bind(&GeneralKadCallback::CallbackFunc, &callback, _1));
      wait_result(&callback);
      ASSERT_EQ(kRpcResultSuccess, callback.result());
      callback.Reset();
      ASSERT_TRUE(nodes_[i]->is_joined());
    }
  }

  void TearDown() {
    // Stopping nodes_
    for (boost::int16_t i = 0; i < testNetworkSize_; ++i) {
      trans_handlers_[i]->StopPingRendezvous();
    }
    for (boost::int16_t i = testNetworkSize_-1; i >= 0; --i) {
      LOG(INFO) << "stopping node " << i << std::endl;
      nodes_[i]->Leave();
      EXPECT_FALSE(nodes_[i]->is_joined());
      trans_handlers_[i]->Stop(0);
      ch_managers_[i]->Stop();
      delete trans_handlers_[i]->Get(transports_ids_[i]);
      trans_handlers_[i]->Remove(transports_ids_[i]);
    }
    try {
      boost::filesystem::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      LOG(ERROR) << "filesystem error: " << e.what() << std::endl;
    }
    nodes_.clear();
    ch_managers_.clear();
    trans_handlers_.clear();
    transports_ids_.clear();
  }

  std::vector< boost::shared_ptr<transport::TransportHandler> > trans_handlers_;
  std::vector< boost::shared_ptr<rpcprotocol::ChannelManager> > ch_managers_;
  std::vector< boost::shared_ptr<KNode> > nodes_;
  std::vector<std::string> datadirs_;
  std::string test_dir_;
  boost::uint16_t testK_;
  boost::uint32_t testRefresh_;
  boost::int16_t testNetworkSize_;
  std::vector<boost::int16_t> transports_ids_;
};

TEST_F(TestRefresh, FUNC_KAD_RefreshValue) {
  // Storing a Value
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  kad::KadId key(co.Hash("key", "", crypto::STRING_STRING, false));
  std::string value = base::RandomString(1024*5);
  StoreValueCallback store_cb;
  nodes_[4]->StoreValue(key, value, 24*3600, boost::bind(
      &StoreValueCallback::CallbackFunc, &store_cb, _1));
  wait_result(&store_cb);
  ASSERT_EQ(kad::kRpcResultSuccess, store_cb.result());
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
        nodes_[indxs[i]]->KeyLastRefreshTime(key, value)) << "FAILED  WITH NODE"
        << indxs[i];
  }
}

TEST_F(TestRefresh, FUNC_KAD_NewNodeinKClosest) {
  // Storing a Value
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  kad::KadId key(co.Hash("key", "", crypto::STRING_STRING, false));
  std::string value = base::RandomString(1024*5);
  StoreValueCallback store_cb;
  nodes_[4]->StoreValue(key, value, 24*3600, boost::bind(
      &StoreValueCallback::CallbackFunc, &store_cb, _1));
  wait_result(&store_cb);
  ASSERT_EQ(kad::kRpcResultSuccess, store_cb.result());
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
  transport::TransportHandler trans_handler;
  boost::int16_t transport_id;
  trans_handler.Register(new transport::TransportUDT, &transport_id);
  rpcprotocol::ChannelManager ch_manager(&trans_handler);
  std::string local_dir = test_dir_ + std::string("/datastorenewnode");
  boost::filesystem::create_directories(local_dir);
  KNode node(&ch_manager, &trans_handler, VAULT, testK_, kAlpha, kBeta,
    testRefresh_, "", "", false, false);
  node.set_transport_id(transport_id);
//   ASSERT_TRUE(ch_manager.RegisterNotifiersToTransport());
//   ASSERT_TRUE(trans_handler.RegisterOnServerDown(boost::bind(
//       &kad::KNode::HandleDeadRendezvousServer, &node, _1)));
  ASSERT_EQ(0, trans_handler.Start(0, transport_id));
  ASSERT_EQ(0, ch_manager.Start());
  std::string kconfig_file1 = local_dir + "/.kadconfig";
  base::KadConfig kad_config1;
  base::KadConfig::Contact *kad_contact = kad_config1.add_contact();
  kad_contact->set_node_id(nodes_[0]->node_id().ToStringEncoded(KadId::kHex));
  kad_contact->set_ip(nodes_[0]->host_ip());
  kad_contact->set_port(nodes_[0]->host_port());
  kad_contact->set_local_ip(nodes_[0]->local_host_ip());
  kad_contact->set_local_port(nodes_[0]->local_host_port());
  std::fstream output1(kconfig_file1.c_str(),
    std::ios::out | std::ios::trunc | std::ios::binary);
  EXPECT_TRUE(kad_config1.SerializeToOstream(&output1));
  output1.close();
  GeneralKadCallback callback;
  // joining node with id == key of value stored
  node.Join(key, kconfig_file1,
    boost::bind(&GeneralKadCallback::CallbackFunc, &callback, _1));
  wait_result(&callback);
  ASSERT_EQ(kRpcResultSuccess, callback.result());
  callback.Reset();
  ASSERT_TRUE(node.is_joined());

  boost::this_thread::sleep(boost::posix_time::seconds(testRefresh_+8));
  std::vector<std::string> values;
  EXPECT_TRUE(node.FindValueLocal(key, &values));
  EXPECT_EQ(value, values[0]);
  EXPECT_NE(0, node.KeyExpireTime(key, value)) << "key/value pair not found";
  EXPECT_NE(0, node.KeyLastRefreshTime(key, value))
     << "key/value pair not found";

  node.Leave();
  EXPECT_FALSE(node.is_joined());
  trans_handler.Stop(transport_id);
  ch_manager.Stop();
  delete trans_handler.Get(transport_id);
  trans_handler.Remove(transport_id);
}

class TestRefreshSignedValues : public testing::Test {
 public:
  TestRefreshSignedValues() : trans_handlers_(), ch_managers_(), nodes_(),
    datadirs_(), test_dir_("TestKnodes_"), testK_(4), testRefresh_(10),
    testNetworkSize_(10), validator(), transport_ids_() {
      test_dir_ +=
        boost::lexical_cast<std::string>(base::RandomUint32());
  }
  ~TestRefreshSignedValues() {
    transport::TransportUDT::CleanUp();
  }
 protected:
  void SetUp() {
    try {
      if (boost::filesystem::exists(test_dir_))
        boost::filesystem::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      LOG(ERROR) << "filesystem error: " << e.what() << std::endl;
    }
    // Creating the nodes_
    crypto::RsaKeyPair keys;
    keys.GenerateKeys(4096);
    boost::int16_t transport_id;
    for (boost::int16_t i = 0; i < testNetworkSize_; i++) {
      trans_handlers_.push_back(boost::shared_ptr<transport::TransportHandler>(
          new transport::TransportHandler));
      trans_handlers_.at(i)->Register(new transport::TransportUDT,
                                      &transport_id);
      transport_ids_.push_back(transport_id);
      ch_managers_.push_back(boost::shared_ptr<rpcprotocol::ChannelManager>(
          new rpcprotocol::ChannelManager(trans_handlers_[i].get())));
      std::string datadir = test_dir_ + std::string("/datastore") +
          boost::lexical_cast<std::string>(i);
      boost::filesystem::create_directories(datadir);
      nodes_.push_back(boost::shared_ptr<KNode>(new KNode(ch_managers_[i].get(),
          trans_handlers_[i].get(), VAULT, testK_, kAlpha, kBeta, testRefresh_,
          keys.private_key(), keys.public_key(), false, false)));
      nodes_[i]->set_transport_id(transport_id);
//       ASSERT_TRUE(ch_managers_[i]->RegisterNotifiersToTransport());
//       ASSERT_TRUE(trans_handlers_[i]->RegisterOnServerDown(boost::bind(
//         &kad::KNode::HandleDeadRendezvousServer, nodes_[i].get(), _1)));
      EXPECT_EQ(0, trans_handlers_[i]->Start(0, transport_id));
      EXPECT_EQ(0, ch_managers_[i]->Start());
      datadirs_.push_back(datadir);
    }
    GeneralKadCallback callback;
    LOG(INFO) << "starting node 0" << std::endl;
    boost::asio::ip::address local_ip;
    ASSERT_TRUE(base::GetLocalAddress(&local_ip));
    nodes_[0]->Join(datadirs_[0] + "/.kadconfig",
      local_ip.to_string(), trans_handlers_[0]->listening_port(0),
      boost::bind(&GeneralKadCallback::CallbackFunc, &callback, _1));
    wait_result(&callback);
    ASSERT_EQ(kRpcResultSuccess, callback.result());
    nodes_[0]->set_signature_validator(&validator);
    callback.Reset();
    ASSERT_TRUE(nodes_[0]->is_joined());
    for (boost::int16_t i = 1; i < testNetworkSize_; i++) {
      LOG(INFO) << "starting node " << i << std::endl;
      std::string kconfig_file1 = datadirs_[i] + "/.kadconfig";
      base::KadConfig kad_config1;
      base::KadConfig::Contact *kad_contact = kad_config1.add_contact();
      kad_contact->set_node_id(
            nodes_[0]->node_id().ToStringEncoded(KadId::kHex));
      kad_contact->set_ip(nodes_[0]->host_ip());
      kad_contact->set_port(nodes_[0]->host_port());
      kad_contact->set_local_ip(nodes_[0]->local_host_ip());
      kad_contact->set_local_port(nodes_[0]->local_host_port());
      std::fstream output1(kconfig_file1.c_str(),
        std::ios::out | std::ios::trunc | std::ios::binary);
      EXPECT_TRUE(kad_config1.SerializeToOstream(&output1));
      output1.close();

      nodes_[i]->Join(kconfig_file1,
        boost::bind(&GeneralKadCallback::CallbackFunc, &callback, _1));
      wait_result(&callback);
      ASSERT_EQ(kRpcResultSuccess, callback.result());
      callback.Reset();
      ASSERT_TRUE(nodes_[i]->is_joined());
      nodes_[i]->set_signature_validator(&validator);
    }
  }

  void TearDown() {
    // Stopping nodes_
    for (boost::int16_t i = 0; i < testNetworkSize_; ++i) {
      trans_handlers_[i]->StopPingRendezvous();
    }
    for (boost::int16_t i = testNetworkSize_-1; i >= 0; --i) {
      LOG(INFO) << "stopping node " << i << std::endl;
      nodes_[i]->Leave();
      EXPECT_FALSE(nodes_[i]->is_joined());
      trans_handlers_[i]->Stop(0);
      ch_managers_[i]->Stop();
      delete trans_handlers_[i]->Get(transport_ids_[i]);
      trans_handlers_[i]->Remove(transport_ids_[i]);
    }
    try {
      boost::filesystem::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      LOG(ERROR) << "filesystem error: " << e.what() << std::endl;
    }

    nodes_.clear();
    ch_managers_.clear();
    trans_handlers_.clear();
    transport_ids_.clear();
  }

  std::vector< boost::shared_ptr<transport::TransportHandler> > trans_handlers_;
  std::vector< boost::shared_ptr<rpcprotocol::ChannelManager> > ch_managers_;
  std::vector< boost::shared_ptr<KNode> > nodes_;
  std::vector<std::string> datadirs_;
  std::string test_dir_;
  boost::uint16_t testK_;
  boost::uint32_t testRefresh_;
  boost::int16_t testNetworkSize_;
  base::TestValidator validator;
  std::vector<boost::int16_t> transport_ids_;
};

TEST_F(TestRefreshSignedValues, FUNC_KAD_RefreshSignedValue) {
  // Storing a Value
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  kad::KadId key(co.Hash("key", "", crypto::STRING_STRING, false));
  std::string value = base::RandomString(1024*5);
  StoreValueCallback store_cb;
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);
  std::string signed_public_key, signed_request;
  signed_public_key = co.AsymSign(keys.public_key(), "", keys.private_key(),
      crypto::STRING_STRING);
  signed_request = co.AsymSign(co.Hash(keys.public_key()+signed_public_key+
      key.String(), "", crypto::STRING_STRING, true), "",
      keys.private_key(), crypto::STRING_STRING);
  kad::SignedValue sig_value;
  sig_value.set_value(value);
  sig_value.set_value_signature(co.AsymSign(value, "", keys.private_key(),
      crypto::STRING_STRING));
  std::string ser_sig_value = sig_value.SerializeAsString();
  kad::SignedRequest req;
  req.set_signer_id(nodes_[4]->node_id().String());
  req.set_public_key(keys.public_key());
  req.set_signed_public_key(signed_public_key);
  req.set_signed_request(signed_request);
  nodes_[4]->StoreValue(key, sig_value, req, 24*3600,
    boost::bind(&StoreValueCallback::CallbackFunc, &store_cb, _1));
  wait_result(&store_cb);
  ASSERT_EQ(kad::kRpcResultSuccess, store_cb.result());
  std::vector<boost::int16_t> indxs;
  std::vector<boost::uint32_t> last_refresh_times;
  std::vector<boost::uint32_t> expire_times;
  for (boost::int16_t i = 0; i < testNetworkSize_; ++i) {
    std::vector<std::string> values;
    if (nodes_[i]->FindValueLocal(key, &values)) {
      ASSERT_EQ(ser_sig_value, values[0]);
      indxs.push_back(i);
      boost::uint32_t last_refresh = nodes_[i]->KeyLastRefreshTime(key,
          ser_sig_value);
      ASSERT_NE(0, last_refresh) << "key/value pair not found";
      last_refresh_times.push_back(last_refresh);
      boost::uint32_t expire_time = nodes_[i]->KeyExpireTime(key,
        ser_sig_value);
      ASSERT_NE(0, expire_time) << "key/value pair not found";
      expire_times.push_back(expire_time);
    }
  }
  ASSERT_EQ(testK_, indxs.size());
  boost::this_thread::sleep(boost::posix_time::seconds(testRefresh_+8));
  for (size_t i = 0; i < indxs.size(); i++) {
    std::vector<std::string> values;
    EXPECT_TRUE(nodes_[indxs[i]]->FindValueLocal(key, &values));
    EXPECT_EQ(ser_sig_value, values[0]);
    EXPECT_EQ(expire_times[i], nodes_[indxs[i]]->KeyExpireTime(key,
        ser_sig_value));
    EXPECT_LT(last_refresh_times[i],
        nodes_[indxs[i]]->KeyLastRefreshTime(key,
            ser_sig_value)) << "FAILED  WITH NODE" << indxs[i];
  }
}

TEST_F(TestRefreshSignedValues, FUNC_KAD_NewRSANodeinKClosest) {
  // Storing a Value
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  kad::KadId key(co.Hash("key", "", crypto::STRING_STRING, false));
  std::string value = base::RandomString(1024*5);
  StoreValueCallback store_cb;
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);
  std::string pub_key = keys.public_key();
  std::string priv_key = keys.private_key();
  std::string signed_public_key, signed_request;
  signed_public_key = co.AsymSign(pub_key, "", priv_key, crypto::STRING_STRING);
  signed_request = co.AsymSign(co.Hash(pub_key+signed_public_key+
      key.String(), "", crypto::STRING_STRING, true), "", priv_key,
      crypto::STRING_STRING);
  kad::SignedValue sig_value;
  sig_value.set_value(value);
  sig_value.set_value_signature(co.AsymSign(value, "", priv_key,
      crypto::STRING_STRING));
  std::string ser_sig_value = sig_value.SerializeAsString();
  keys.GenerateKeys(4096);
  kad::SignedRequest req;
  req.set_signer_id(nodes_[4]->node_id().String());
  req.set_public_key(pub_key);
  req.set_signed_public_key(signed_public_key);
  req.set_signed_request(signed_request);
  nodes_[4]->StoreValue(key, sig_value, req, 24*3600,
    boost::bind(&StoreValueCallback::CallbackFunc, &store_cb, _1));
  wait_result(&store_cb);
  ASSERT_EQ(kad::kRpcResultSuccess, store_cb.result());
  std::vector<boost::int16_t> indxs;
  std::vector<boost::uint32_t> last_refresh_times;
  std::vector<boost::uint32_t> expire_times;
  for (boost::int16_t i = 0; i < testNetworkSize_; i++) {
    std::vector<std::string> values;
    if (nodes_[i]->FindValueLocal(key, &values)) {
      ASSERT_EQ(ser_sig_value, values[0]);
      indxs.push_back(i);
      boost::uint32_t last_refresh = nodes_[i]->KeyLastRefreshTime(key,
          ser_sig_value);
      ASSERT_NE(0, last_refresh) << "key/value pair not found";
      last_refresh_times.push_back(last_refresh);
      boost::uint32_t expire_time = nodes_[i]->KeyExpireTime(key,
        ser_sig_value);
      ASSERT_NE(0, expire_time) << "key/value pair not found";
      expire_times.push_back(expire_time);
    }
  }
  ASSERT_EQ(testK_, indxs.size());
  transport::TransportHandler trans_handler;
  boost::int16_t transport_id;
  trans_handler.Register(new transport::TransportUDT, &transport_id);
  rpcprotocol::ChannelManager ch_manager(&trans_handler);
  std::string local_dir = test_dir_ + std::string("/datastorenewnode");
  boost::filesystem::create_directories(local_dir);
  KNode node(&ch_manager, &trans_handler, VAULT, testK_, kAlpha, kBeta,
      testRefresh_, keys.private_key(), keys.public_key(), false, false);
  node.set_transport_id(transport_id);
//   ASSERT_TRUE(ch_manager.RegisterNotifiersToTransport());
//   ASSERT_TRUE(trans_handler.RegisterOnServerDown(boost::bind(
//       &kad::KNode::HandleDeadRendezvousServer, &node, _1)));
  ASSERT_EQ(0, trans_handler.Start(0, transport_id));
  ASSERT_EQ(0, ch_manager.Start());
  std::string kconfig_file1 = local_dir + "/.kadconfig";
  base::KadConfig kad_config1;
  base::KadConfig::Contact *kad_contact = kad_config1.add_contact();
  kad_contact->set_node_id(nodes_[0]->node_id().ToStringEncoded(KadId::kHex));
  kad_contact->set_ip(nodes_[0]->host_ip());
  kad_contact->set_port(nodes_[0]->host_port());
  kad_contact->set_local_ip(nodes_[0]->local_host_ip());
  kad_contact->set_local_port(nodes_[0]->local_host_port());
  std::fstream output1(kconfig_file1.c_str(),
    std::ios::out | std::ios::trunc | std::ios::binary);
  EXPECT_TRUE(kad_config1.SerializeToOstream(&output1));
  output1.close();
  GeneralKadCallback callback;
  // joining node with id == key of value stored
  node.Join(key, kconfig_file1,
    boost::bind(&GeneralKadCallback::CallbackFunc, &callback, _1));
  wait_result(&callback);
  ASSERT_EQ(kRpcResultSuccess, callback.result());
  node.set_signature_validator(&validator);
  callback.Reset();
  ASSERT_TRUE(node.is_joined());

  boost::this_thread::sleep(boost::posix_time::seconds(testRefresh_+8));
  std::vector<std::string> values;
  if (!node.FindValueLocal(key, &values)) {
    node.Leave();
    trans_handler.Stop(transport_id);
    ch_manager.Stop();
    FAIL();
  }
  EXPECT_EQ(ser_sig_value, values[0]);
  EXPECT_NE(0, node.KeyExpireTime(key, ser_sig_value));
  EXPECT_NE(0, node.KeyLastRefreshTime(key, ser_sig_value));

  node.Leave();
  EXPECT_FALSE(node.is_joined());
  trans_handler.Stop(transport_id);
  ch_manager.Stop();
  delete trans_handler.Get(transport_id);
  trans_handler.Remove(transport_id);
}

TEST_F(TestRefreshSignedValues, FUNC_KAD_InformOfDeletedValue) {
  // Storing a Value
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  kad::KadId key(co.Hash("key", "", crypto::STRING_STRING, false));
  std::string value = base::RandomString(1024*5);
  StoreValueCallback store_cb;
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);
  std::string pub_key = keys.public_key();
  std::string priv_key = keys.private_key();
  std::string signed_public_key, signed_request;
  signed_public_key = co.AsymSign(pub_key, "", priv_key, crypto::STRING_STRING);
  signed_request = co.AsymSign(co.Hash(pub_key+signed_public_key+
      key.String(), "", crypto::STRING_STRING, true), "", priv_key,
      crypto::STRING_STRING);
  kad::SignedValue sig_value;
  sig_value.set_value(value);
  sig_value.set_value_signature(co.AsymSign(value, "", priv_key,
      crypto::STRING_STRING));
  std::string ser_sig_value = sig_value.SerializeAsString();
  keys.GenerateKeys(4096);
  kad::SignedRequest req;
  req.set_signer_id(nodes_[4]->node_id().String());
  req.set_public_key(pub_key);
  req.set_signed_public_key(signed_public_key);
  req.set_signed_request(signed_request);
  nodes_[4]->StoreValue(key, sig_value, req, 24*3600,
    boost::bind(&StoreValueCallback::CallbackFunc, &store_cb, _1));
  wait_result(&store_cb);
  ASSERT_EQ(kad::kRpcResultSuccess, store_cb.result());

  transport::TransportHandler trans_handler;
  transport::TransportUDT *temp_trans = new transport::TransportUDT;
  boost::int16_t transport_id;
  trans_handler.Register(temp_trans, &transport_id);
  rpcprotocol::ChannelManager ch_manager(&trans_handler);
  std::string local_dir = test_dir_ + std::string("/datastorenewnode");
  boost::filesystem::create_directories(local_dir);
  KNode node(&ch_manager, &trans_handler, VAULT, testK_, kAlpha,
    kBeta, testRefresh_, keys.private_key(), keys.public_key(), false, false);
  node.set_transport_id(transport_id);
//   ASSERT_TRUE(ch_manager.RegisterNotifiersToTransport());
//   ASSERT_TRUE(trans_handler.RegisterOnServerDown(boost::bind(
//       &kad::KNode::HandleDeadRendezvousServer, &node, _1)));
  ASSERT_EQ(0, trans_handler.Start(0, transport_id));
  ASSERT_EQ(0, ch_manager.Start());
  std::string kconfig_file1 = local_dir + "/.kadconfig";
  base::KadConfig kad_config1;
  base::KadConfig::Contact *kad_contact = kad_config1.add_contact();
  kad_contact->set_node_id(nodes_[0]->node_id().ToStringEncoded(KadId::kHex));
  kad_contact->set_ip(nodes_[0]->host_ip());
  kad_contact->set_port(nodes_[0]->host_port());
  kad_contact->set_local_ip(nodes_[0]->local_host_ip());
  kad_contact->set_local_port(nodes_[0]->local_host_port());
  std::fstream output1(kconfig_file1.c_str(),
    std::ios::out | std::ios::trunc | std::ios::binary);
  EXPECT_TRUE(kad_config1.SerializeToOstream(&output1));
  output1.close();
  GeneralKadCallback callback;
  // joining node with id == key of value stored
  node.Join(key, kconfig_file1,
    boost::bind(&GeneralKadCallback::CallbackFunc, &callback, _1));
  wait_result(&callback);
  ASSERT_EQ(kRpcResultSuccess, callback.result());
  node.set_signature_validator(&validator);
  callback.Reset();
  ASSERT_TRUE(node.is_joined());

  boost::this_thread::sleep(boost::posix_time::seconds(testRefresh_+8));
  std::vector<std::string> values;
  if (!node.FindValueLocal(key, &values)) {
    node.Leave();
    trans_handler.Stop(transport_id);
    ch_manager.Stop();
    FAIL();
  }
  EXPECT_EQ(ser_sig_value, values[0]);
  EXPECT_NE(0, node.KeyExpireTime(key, ser_sig_value));
  EXPECT_NE(0, node.KeyLastRefreshTime(key, ser_sig_value));

  // Find a Node that doesn't have the value
  boost::int16_t counter = 0;
  for (counter = 0; counter < testNetworkSize_; counter++) {
    values.clear();
    if (!nodes_[counter]->FindValueLocal(key, &values))
      break;
  }
  // Deleating the value
  DeleteValueCallback del_cb;
  nodes_[counter]->DeleteValue(key, sig_value, req,
    boost::bind(&DeleteValueCallback::CallbackFunc, &del_cb, _1));
  wait_result(&del_cb);
  EXPECT_EQ(kad::kRpcResultSuccess, del_cb.result());

  // at least one node should have the value
  counter = 0;
  for (counter = 0; counter < testNetworkSize_; counter++) {
    values.clear();
    if (nodes_[counter]->FindValueLocal(key, &values))
      break;
  }
  if (counter == testNetworkSize_) {
    node.Leave();
    trans_handler.Stop(transport_id);
    ch_manager.Stop();
    FAIL() << "All values have been deleted, it will not be refreshed";
  }
  boost::this_thread::sleep(boost::posix_time::seconds(testRefresh_*2));
  for (counter = 0; counter < testNetworkSize_; counter++) {
    values.clear();
    if (nodes_[counter]->FindValueLocal(key, &values))
      break;
  }
  values.clear();
  if (counter < testNetworkSize_ ||
      node.FindValueLocal(key, &values)) {
    node.Leave();
    trans_handler.Stop(transport_id);
    ch_manager.Stop();
    FAIL() << "Key Value pair was not deleted.";
  }
  FindCallback find_cb;
  node.FindValue(key, false, boost::bind(&FindCallback::CallbackFunc,
    &find_cb, _1));
  wait_result(&find_cb);
  EXPECT_EQ(kad::kRpcResultFailure, find_cb.result());

  node.Leave();
  EXPECT_FALSE(node.is_joined());
  trans_handler.Stop(transport_id);
  ch_manager.Stop();
}
}
