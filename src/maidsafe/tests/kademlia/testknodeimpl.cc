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
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <boost/lexical_cast.hpp>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "maidsafe/base/alternativestore.h"
#include "maidsafe/base/crypto.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/base/validationinterface.h"
#include "maidsafe/kademlia/contact.h"
#include "maidsafe/kademlia/kadid.h"
#include "maidsafe/kademlia/knodeimpl.h"
#include "maidsafe/rpcprotocol/channelmanager-api.h"
#include "maidsafe/transport/udttransport.h"
#include "maidsafe/tests/kademlia/fake_callbacks.h"

namespace kad {

namespace test_knodeimpl {

class TestAlternativeStore : public base::AlternativeStore {
 public:
  ~TestAlternativeStore() {}
  bool Has(const std::string&) { return false; }
};

class TestValidator : public base::SignatureValidator {
 public:
  ~TestValidator() {}
  bool ValidateSignerId(const std::string&, const std::string&,
                        const std::string&) { return true; }
  bool ValidateRequest(const std::string&, const std::string&,
                       const std::string&, const std::string&) { return true; }
};

void BootstrapCallbackTestCallback(const std::string &ser_result,
                                   bool *result, bool *done) {
  BootstrapResponse br;
  *result = true;
  if (!br.ParseFromString(ser_result)) {
    *done = true;
    return;
  }

  if (!br.IsInitialized()) {
    *done = true;
    return;
  }

  if (br.result() == kRpcResultFailure) {
    *result = false;
  }
  *done = true;
}

static const boost::uint16_t K = 16;

class TestKNodeImpl : public testing::Test {
 protected:
  static void SetUpTestCase() {
    test_dir_ = std::string("temp/TestKNodeImpl") +
                boost::lexical_cast<std::string>(base::RandomUint32());

    udt_.reset(new transport::UdtTransport);
    transport::TransportCondition tc;
    Port p = udt_->StartListening("", 0, &tc);
    EXPECT_EQ(transport::kSuccess, tc)
              << "Node failed to start transport." << std::endl;
    manager_.reset(new rpcprotocol::ChannelManager(udt_));
    EXPECT_EQ(transport::kSuccess, manager_->Start())
              << "Node failed to start ChannelManager." << std::endl;

    crypto::RsaKeyPair rkp;
    rkp.GenerateKeys(4096);
    kad::KnodeConstructionParameters kcp;
    kcp.alpha = kad::kAlpha;
    kcp.beta = kad::kBeta;
    kcp.type = kad::VAULT;
    kcp.public_key = rkp.public_key();
    kcp.private_key = rkp.private_key();
    kcp.k = K;
    kcp.refresh_time = kad::kRefreshTime;
    node_.reset(new KNodeImpl(manager_, udt_, kcp));

    boost::asio::ip::address local_ip;
    ASSERT_TRUE(base::GetLocalAddress(&local_ip));
    node_->JoinFirstNode(test_dir_ + std::string(".kadconfig"),
                         local_ip.to_string(), p,
                         boost::bind(&GeneralKadCallback::CallbackFunc,
                                     &cb_, _1));
    wait_result(&cb_);
    ASSERT_EQ(kad::kRpcResultSuccess, cb_.result());
    ASSERT_TRUE(node_->is_joined());
  }
  static void TearDownTestCase() {
    node_->Leave();
  }

  static std::string test_dir_;
  static boost::int16_t transport_id_;
  static boost::shared_ptr<transport::UdtTransport> udt_;
  static boost::shared_ptr<rpcprotocol::ChannelManager> manager_;
  static boost::shared_ptr<KNodeImpl> node_;
  static GeneralKadCallback cb_;
};

std::string TestKNodeImpl::test_dir_;
boost::int16_t TestKNodeImpl::transport_id_ = 0;
boost::shared_ptr<transport::UdtTransport> TestKNodeImpl::udt_;
boost::shared_ptr<rpcprotocol::ChannelManager> TestKNodeImpl::manager_;
boost::shared_ptr<KNodeImpl> TestKNodeImpl::node_;
GeneralKadCallback TestKNodeImpl::cb_;

TEST_F(TestKNodeImpl, BEH_KNodeImpl_ContactFunctions) {
  boost::asio::ip::address local_ip;
  ASSERT_TRUE(base::GetLocalAddress(&local_ip));
  KadId key1a, key2a, key1b(KadId::kRandomId), key2b(KadId::kRandomId),
        target_key(KadId::kRandomId);
  ContactAndTargetKey catk1, catk2;
  catk1.contact = Contact(key1a, local_ip.to_string(), 5001,
                          local_ip.to_string(), 5001);
  catk2.contact = Contact(key2a, local_ip.to_string(), 5002,
                          local_ip.to_string(), 5002);
  catk1.target_key = catk2.target_key = target_key;
  ASSERT_TRUE(CompareContact(catk1, catk2));
  catk1.contact = Contact(key1b, local_ip.to_string(), 5001,
                          local_ip.to_string(), 5001);
  ASSERT_FALSE(CompareContact(catk1, catk2));

  std::list<LookupContact> contact_list;
  SortLookupContact(target_key, &contact_list);
}

TEST_F(TestKNodeImpl, BEH_KNodeImpl_Uninitialised_Values) {
  DeleteValueCallback dvc;
  SignedValue signed_value, new_value;
  SignedRequest signed_request;
  node_->DeleteValue(KadId(KadId::kRandomId), signed_value, signed_request,
                     boost::bind(&DeleteValueCallback::CallbackFunc, &dvc, _1));
  while (dvc.result() == "")
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(kRpcResultFailure, dvc.result());

  UpdateValueCallback uvc;
  node_->UpdateValue(KadId(KadId::kRandomId), signed_value, new_value,
                     signed_request, 60 * 60 * 24,
                     boost::bind(&UpdateValueCallback::CallbackFunc, &uvc, _1));
  while (uvc.result() == "")
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(kRpcResultFailure, uvc.result());
}

TEST_F(TestKNodeImpl, BEH_KNodeImpl_ExecuteRPCs) {
  node_->is_joined_ = false;
  SignedValue old_value, new_value;
  SignedRequest sig_req;
  UpdateValueCallback uvc;
  node_->ExecuteUpdateRPCs("summat that doesn't parse", KadId(KadId::kRandomId),
                           old_value, new_value, sig_req, 3600 * 24,
                           boost::bind(&UpdateValueCallback::CallbackFunc,
                                       &uvc, _1));
  ASSERT_EQ("", uvc.result());

  DeleteValueCallback dvc;
  node_->DelValue_ExecuteDeleteRPCs("summat that doesn't parse",
                                    KadId(KadId::kRandomId),
                                    old_value,
                                    sig_req,
                                    boost::bind(
                                        &DeleteValueCallback::CallbackFunc,
                                        &dvc, _1));
  ASSERT_EQ("", dvc.result());

  dvc.Reset();
  std::vector<Contact> close_nodes;
  KadId key(KadId::kRandomId);
  SignedValue svalue;
  SignedRequest sreq;
  boost::shared_ptr<IterativeDelValueData> data(
      new struct IterativeDelValueData(close_nodes, key, svalue, sreq,
                                       boost::bind(
                                          &DeleteValueCallback::CallbackFunc,
                                          &dvc, _1)));
  data->is_callbacked = true;
  DeleteCallbackArgs callback_data(data);
  node_->DelValue_IterativeDeleteValue(NULL, callback_data);
  ASSERT_EQ("", dvc.result());

  node_->is_joined_ = true;
  uvc.Reset();
  FindResponse fr;
  fr.set_result(kRpcResultSuccess);
  std::string ser_fr, ser_c;
  Contact c(KadId(KadId::kRandomId), "127.0.0.1", 1234, "127.0.0.2", 1235,
            "127.0.0.3", 1236);
  c.SerialiseToString(&ser_c);
  int count = kMinSuccessfulPecentageStore * K - 1;
  for (int n = 0; n < count; ++n)
    fr.add_closest_nodes(ser_c);

  node_->ExecuteUpdateRPCs(fr.SerializeAsString(), KadId(KadId::kRandomId),
                           old_value, new_value, sig_req, 3600 * 24,
                           boost::bind(&UpdateValueCallback::CallbackFunc,
                                       &uvc, _1));
  while (uvc.result() == "")
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(kRpcResultFailure, uvc.result());

  fr.set_result(kRpcResultFailure);
  uvc.Reset();
  node_->ExecuteUpdateRPCs(fr.SerializeAsString(), KadId(KadId::kRandomId),
                           old_value, new_value, sig_req, 3600 * 24,
                           boost::bind(&UpdateValueCallback::CallbackFunc,
                                       &uvc, _1));
  while (uvc.result() == "")
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(kRpcResultFailure, uvc.result());

  dvc.Reset();
  node_->DelValue_IterativeDeleteValue(NULL, callback_data);
  ASSERT_EQ("", dvc.result());

  dvc.Reset();
  node_->DelValue_ExecuteDeleteRPCs("summat that doesn't parse",
                                    KadId(KadId::kRandomId),
                                    old_value,
                                    sig_req,
                                    boost::bind(
                                        &DeleteValueCallback::CallbackFunc,
                                        &dvc, _1));
  while (dvc.result() == "")
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(kRpcResultFailure, dvc.result());

  dvc.Reset();
  fr.Clear();
  fr.set_result(kRpcResultSuccess);
  node_->DelValue_ExecuteDeleteRPCs(fr.SerializeAsString(),
                                    KadId(KadId::kRandomId),
                                    old_value,
                                    sig_req,
                                    boost::bind(
                                        &DeleteValueCallback::CallbackFunc,
                                        &dvc, _1));
  while (dvc.result() == "")
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(kRpcResultFailure, dvc.result());
}

TEST_F(TestKNodeImpl, BEH_KNodeImpl_NotJoined) {
  node_->is_joined_ = false;
  node_->RefreshRoutine();

  StoreValueCallback svc;
  boost::shared_ptr<IterativeStoreValueData> isvd(
      new IterativeStoreValueData(std::vector<Contact>(), KadId(), "",
                                  boost::bind(&StoreValueCallback::CallbackFunc,
                                              &svc, _1),
                                  true, 3600 * 24, SignedValue(),
                                  SignedRequest()));

  ASSERT_EQ("", svc.result());
  node_->is_joined_ = true;
}

}  // namespace test_knodeimpl

}  // namespace kad
