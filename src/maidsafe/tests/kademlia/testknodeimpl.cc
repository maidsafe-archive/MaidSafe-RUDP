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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "maidsafe/base/alternativestore.h"
#include "maidsafe/base/crypto.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/base/validationinterface.h"
#include "maidsafe/kademlia/contact.h"
#include "maidsafe/kademlia/kadid.h"
#include "maidsafe/kademlia/knodeimpl.h"
#include "maidsafe/kademlia/kadroutingtable.h"
#include "maidsafe/rpcprotocol/channelmanager-api.h"
#include "maidsafe/transport/udttransport.h"
#include "maidsafe/tests/kademlia/fake_callbacks.h"

namespace kad {

namespace test_knodeimpl {

static const boost::uint16_t K = 16;

void GenericCallback(const std::string&, bool *done) { *done = true; }
void IterativeSearchCallback(const std::string &result, bool *done,
                             std::list<Contact> *cs) {
//  printf("AAAAAAA\n");
  cs->clear();
  FindResponse fr;
  if (fr.ParseFromString(result) && fr.result()) {
    for (int n = 0; n < fr.closest_nodes_size(); ++n) {
      Contact c;
      if (c.ParseFromString(fr.closest_nodes(n)))
        cs->push_back(c);
    }
  } else {
    printf("Protobufs! Figures...\n");
  }
  *done = true;
}

void CreateParameters(KnodeConstructionParameters *kcp) {
  crypto::RsaKeyPair rkp;
  rkp.GenerateKeys(4096);
  kcp->alpha = kAlpha;
  kcp->beta = kBeta;
  kcp->type = VAULT;
  kcp->public_key = rkp.public_key();
  kcp->private_key = rkp.private_key();
  kcp->k = K;
  kcp->refresh_time = kRefreshTime;
}

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
    KnodeConstructionParameters kcp;
    kcp.alpha = kAlpha;
    kcp.beta = kBeta;
    kcp.type = VAULT;
    kcp.public_key = rkp.public_key();
    kcp.private_key = rkp.private_key();
    kcp.k = K;
    kcp.refresh_time = kRefreshTime;
    node_.reset(new KNodeImpl(manager_, udt_, kcp));

    boost::asio::ip::address local_ip;
    ASSERT_TRUE(base::GetLocalAddress(&local_ip));
    node_->JoinFirstNode(test_dir_ + std::string(".kadconfig"),
                         local_ip.to_string(), p,
                         boost::bind(&GeneralKadCallback::CallbackFunc,
                                     &cb_, _1));
    wait_result(&cb_);
    ASSERT_TRUE(cb_.result());
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
  while (!dvc.result())
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_FALSE(dvc.result());

  UpdateValueCallback uvc;
  node_->UpdateValue(KadId(KadId::kRandomId), signed_value, new_value,
                     signed_request, 60 * 60 * 24,
                     boost::bind(&UpdateValueCallback::CallbackFunc, &uvc, _1));
  while (!uvc.result())
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_FALSE(uvc.result());
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
  ASSERT_FALSE(uvc.result());

  DeleteValueCallback dvc;
  node_->DelValue_ExecuteDeleteRPCs("summat that doesn't parse",
                                    KadId(KadId::kRandomId),
                                    old_value,
                                    sig_req,
                                    boost::bind(
                                        &DeleteValueCallback::CallbackFunc,
                                        &dvc, _1));
  ASSERT_FALSE(dvc.result());

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
  ASSERT_FALSE(dvc.result());

  node_->is_joined_ = true;
  uvc.Reset();
  FindResponse fr;
  fr.set_result(true);
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
  while (!uvc.result())
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_FALSE(uvc.result());

  fr.set_result(false);
  uvc.Reset();
  node_->ExecuteUpdateRPCs(fr.SerializeAsString(), KadId(KadId::kRandomId),
                           old_value, new_value, sig_req, 3600 * 24,
                           boost::bind(&UpdateValueCallback::CallbackFunc,
                                       &uvc, _1));
  while (!uvc.result())
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_FALSE(uvc.result());

  dvc.Reset();
  node_->DelValue_IterativeDeleteValue(NULL, callback_data);
  ASSERT_FALSE(dvc.result());

  dvc.Reset();
  node_->DelValue_ExecuteDeleteRPCs("summat that doesn't parse",
                                    KadId(KadId::kRandomId),
                                    old_value,
                                    sig_req,
                                    boost::bind(
                                        &DeleteValueCallback::CallbackFunc,
                                        &dvc, _1));
  while (!dvc.result())
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_FALSE(dvc.result());

  dvc.Reset();
  fr.Clear();
  fr.set_result(true);
  node_->DelValue_ExecuteDeleteRPCs(fr.SerializeAsString(),
                                    KadId(KadId::kRandomId),
                                    old_value,
                                    sig_req,
                                    boost::bind(
                                        &DeleteValueCallback::CallbackFunc,
                                        &dvc, _1));
  while (!dvc.result())
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_FALSE(dvc.result());
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

  ASSERT_FALSE(svc.result());
  node_->is_joined_ = true;
}

TEST_F(TestKNodeImpl, BEH_KNodeImpl_AddContactsToContainer) {
  bool done(false);
  std::vector<Contact> contacts;
  boost::shared_ptr<FindNodesArgs> fna(
      new FindNodesArgs(KadId(KadId::kRandomId),
                       boost::bind(&GenericCallback, _1, &done)));
  ASSERT_TRUE(fna->nc.empty());
  node_->AddContactsToContainer(contacts, fna);
  ASSERT_TRUE(fna->nc.empty());

  int k(K);
  std::string ip("123.234.231.134");
  for (int n = 0; n < k; ++n) {
    Contact c(KadId(KadId::kRandomId), ip, n);
    contacts.push_back(c);
  }
  node_->AddContactsToContainer(contacts, fna);
  ASSERT_EQ(K, fna->nc.size());
  node_->AddContactsToContainer(contacts, fna);
  ASSERT_EQ(K, fna->nc.size());
}

/*
TEST_F(TestKNodeImpl, BEH_KNodeImpl_GetAlphas) {
  bool done(false), calledback(false);
  std::list<Contact> lcontacts;
  KadId key(KadId::kRandomId);
  boost::shared_ptr<FindNodesArgs> fna(
      new FindNodesArgs(key, boost::bind(&GenericCallback, _1, &done)));
  ASSERT_TRUE(fna->nc.empty());
  boost::uint16_t a(3);
  ASSERT_TRUE(node_->GetAlphas(a, fna, &lcontacts, &calledback));
  ASSERT_TRUE(fna->nc.empty());
  ASSERT_EQ(boost::uint16_t(0), fna->round);
  ASSERT_TRUE(lcontacts.empty());

  int k(K);
  std::string ip("123.234.231.134");
  std::vector<Contact> vcontacts;
  for (int n = 0; n < k; ++n) {
    Contact c(KadId(KadId::kRandomId), ip, n);
    vcontacts.push_back(c);
  }
  node_->AddContactsToContainer(vcontacts, fna);
  ASSERT_EQ(K, fna->nc.size());

  std::list<Contact> inputs(vcontacts.begin(), vcontacts.end());
  SortContactList(key, &inputs);
  std::list<Contact>::iterator it(inputs.begin()), it2;
  int quotient(K/a), remainder(K%a), b(a);
  for (int n = 0; n <= quotient; ++n) {
    if (n == quotient)
      b = remainder;
    ASSERT_FALSE(node_->GetAlphas(a, fna, &lcontacts, &calledback));
    ASSERT_EQ(boost::uint16_t(n + 1), fna->round);
    ASSERT_EQ(size_t(b), lcontacts.size());
    for (it2 = lcontacts.begin(); it2 != lcontacts.end();  ++it2, ++it) {
      ASSERT_TRUE(*it == *it2);
    }
    lcontacts.clear();
  }
  ASSERT_TRUE(node_->GetAlphas(a, fna, &lcontacts, &calledback));
  ASSERT_EQ(boost::uint16_t(quotient + 1), fna->round);
}

TEST_F(TestKNodeImpl, BEH_KNodeImpl_MarkNode) {
  bool done(false), calledback(false);
  std::list<Contact> lcontacts;
  KadId key(KadId::kRandomId);
  boost::shared_ptr<FindNodesArgs> fna(
      new FindNodesArgs(key, boost::bind(&GenericCallback, _1, &done)));
  ASSERT_TRUE(fna->nc.empty());
  boost::uint16_t a(3);
  ASSERT_TRUE(node_->GetAlphas(a, fna, &lcontacts, &calledback));
  ASSERT_TRUE(fna->nc.empty());
  ASSERT_EQ(boost::uint16_t(0), fna->round);
  ASSERT_TRUE(lcontacts.empty());

  int k(K);
  std::string ip("123.234.231.134");
  std::vector<Contact> vcontacts;
  for (int n = 0; n < k; ++n) {
    Contact c(KadId(KadId::kRandomId), ip, n);
    vcontacts.push_back(c);
  }
  node_->AddContactsToContainer(vcontacts, fna);
  ASSERT_EQ(K, fna->nc.size());

  std::list<Contact> inputs(vcontacts.begin(), vcontacts.end());
  SortContactList(key, &inputs);
  std::list<Contact>::iterator it(inputs.begin()), it2;
  ASSERT_TRUE(node_->MarkNode(*it, fna, SEARCH_CONTACTED));
  ASSERT_FALSE(node_->GetAlphas(a, fna, &lcontacts, &calledback));
  ASSERT_EQ(boost::uint16_t(1), fna->round);
  ASSERT_EQ(size_t(a), lcontacts.size());
  for (it2 = lcontacts.begin(); it2 != lcontacts.end();  ++it2, ++it) {
    ASSERT_FALSE(*it == *it2);
  }

  ++it;
  ASSERT_TRUE(node_->MarkNode(*it, fna, SEARCH_DOWN));
  ASSERT_FALSE(node_->GetAlphas(a, fna, &lcontacts, &calledback));
  ASSERT_EQ(boost::uint16_t(2), fna->round);
  ASSERT_EQ(size_t(a), lcontacts.size());
  for (it2 = lcontacts.begin(); it2 != lcontacts.end();  ++it2, ++it) {
    ASSERT_FALSE(*it == *it2);
  }

  Contact not_in_list(KadId(KadId::kRandomId), ip, 8000);
  ASSERT_FALSE(node_->MarkNode(not_in_list, fna, SEARCH_CONTACTED));
}

TEST_F(TestKNodeImpl, BEH_KNodeImpl_BetaDone) {
  bool done(false), calledback(false);
  std::list<Contact> lcontacts;
  KadId key(KadId::kRandomId);
  boost::shared_ptr<FindNodesArgs> fna(
      new FindNodesArgs(key, boost::bind(&GenericCallback, _1, &done)));
  ASSERT_TRUE(fna->nc.empty());
  boost::uint16_t a(3);
  ASSERT_TRUE(node_->GetAlphas(a, fna, &lcontacts, &calledback));
  ASSERT_TRUE(fna->nc.empty());
  ASSERT_EQ(boost::uint16_t(0), fna->round);
  ASSERT_TRUE(lcontacts.empty());

  int k(K);
  std::string ip("123.234.231.134");
  std::vector<Contact> vcontacts;
  for (int n = 0; n < k; ++n) {
    Contact c(KadId(KadId::kRandomId), ip, n);
    vcontacts.push_back(c);
  }
  node_->AddContactsToContainer(vcontacts, fna);
  ASSERT_EQ(K, fna->nc.size());

  std::list<Contact> inputs(vcontacts.begin(), vcontacts.end());
  std::vector<std::list<Contact> > valphas;
  SortContactList(key, &inputs);
  std::list<Contact>::iterator it(inputs.begin()), it2;
  int quotient(K/a), remainder(K%a), b(a);
  for (int n = 0; n <= quotient; ++n) {
    if (n == quotient)
      b = remainder;
    ASSERT_FALSE(node_->GetAlphas(a, fna, &lcontacts, &calledback));
    ASSERT_EQ(boost::uint16_t(n + 1), fna->round);
    ASSERT_EQ(size_t(b), lcontacts.size());
    for (it2 = lcontacts.begin(); it2 != lcontacts.end();  ++it2, ++it) {
      ASSERT_TRUE(*it == *it2);
    }
    valphas.push_back(lcontacts);
    lcontacts.clear();
  }
  ASSERT_TRUE(node_->GetAlphas(a, fna, &lcontacts, &calledback));
  ASSERT_EQ(boost::uint16_t(quotient + 1), fna->round);

  for (size_t a = 0; a < valphas.size(); ++a) {
    ASSERT_TRUE(node_->MarkNode(valphas[a].front(), fna, SEARCH_CONTACTED));
    if (a == valphas.size() - 1)
      ASSERT_TRUE(node_->BetaDone(fna, a + 1));
    else
      ASSERT_FALSE(node_->BetaDone(fna, a + 1)) << a;
    valphas[a].pop_front();
  }

  for (size_t a = 0; a < valphas.size() - 1; ++a) {
    ASSERT_TRUE(node_->MarkNode(valphas[a].front(), fna, SEARCH_CONTACTED));
    ASSERT_TRUE(node_->BetaDone(fna, a));
  }
}

class MockIterativeSearchResponse : public KNodeImpl {
 public:
  MockIterativeSearchResponse(
      boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager,
      boost::shared_ptr<transport::UdtTransport> udt_transport,
      const KnodeConstructionParameters &knode_parameters)
          : KNodeImpl(channel_manager, udt_transport, knode_parameters) {}
  MOCK_METHOD2(IterativeSearch, void(const boost::uint16_t &count,
                                     boost::shared_ptr<FindNodesArgs> fna));
  void IterativeSearchDummy(boost::shared_ptr<FindNodesArgs> fna) {
    FindResponse fr;
    fr.set_result(kRpcResultSuccess);
    boost::thread th(fna->callback, fr.SerializeAsString());
  }
};

TEST_F(TestKNodeImpl, BEH_KNodeImpl_IterativeSearchResponse) {
  bool done(false), calledback(false);
  KadId key(KadId::kRandomId);
  boost::shared_ptr<FindNodesArgs> fna(
      new FindNodesArgs(key, boost::bind(&GenericCallback, _1, &done)));
  boost::shared_ptr<transport::UdtTransport> udt(new transport::UdtTransport);
  boost::shared_ptr<rpcprotocol::ChannelManager> cm(
      new rpcprotocol::ChannelManager(udt));
  KnodeConstructionParameters kcp;
  CreateParameters(&kcp);
  MockIterativeSearchResponse misr(cm, udt, kcp);

  EXPECT_CALL(misr, IterativeSearch(kAlpha, fna))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&MockIterativeSearchResponse::IterativeSearchDummy,
                      &misr, _1))));

  int k(K);
  std::string ip("123.234.231.134");
  std::vector<Contact> vcontacts, popped;
  for (int n = 0; n < k; ++n) {
    Contact c(KadId(KadId::kRandomId), ip, n);
    vcontacts.push_back(c);
  }
  misr.AddContactsToContainer(vcontacts, fna);
  ASSERT_EQ(K, fna->nc.size());
  std::list<Contact> lcontacts;
  ASSERT_FALSE(misr.GetAlphas(kcp.alpha, fna, &lcontacts, &calledback));

  boost::shared_ptr<FindNodesRpc> rpc(new FindNodesRpc(lcontacts.front(), fna));
  rpc->response->set_result(kRpcResultSuccess);
  misr.IterativeSearchResponse(rpc);

  popped.push_back(lcontacts.front());
  lcontacts.pop_front();
  popped.push_back(lcontacts.front());
  boost::shared_ptr<FindNodesRpc> rpc1(new FindNodesRpc(lcontacts.front(),
                                                        fna));
  rpc1->response->set_result(kRpcResultSuccess);
  misr.IterativeSearchResponse(rpc1);
  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));

  // Check fna to see if the two contacts changed state correctly
  for (size_t n = 0; n < popped.size(); ++n) {
    NodeContainerByContact &index_contact = fna->nc.get<nc_contact>();
    NodeContainerByContact::iterator it = index_contact.find(popped[n]);
    ASSERT_FALSE(it == index_contact.end());
    ASSERT_TRUE((*it).alpha && (*it).contacted && !(*it).down);
    ASSERT_EQ(rpc1->round, (*it).round);
  }
}
*/

class MockKadRpcs : public KadRpcs {
 public:
  explicit MockKadRpcs(
      boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager)
          : KadRpcs(channel_manager), node_list_mutex_(), node_list_(),
            backup_node_list_() {}
  MOCK_METHOD8(FindNode, void(const KadId &key, const IP &ip,
                              const Port &port, const IP &rendezvous_ip,
                              const Port &rendezvous_port, FindResponse *resp,
                              rpcprotocol::Controller *ctler,
                              google::protobuf::Closure *callback));
  void FindNodeDummy(FindResponse *resp, google::protobuf::Closure *callback) {
    resp->set_result(true);
    {
      boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
      if (!node_list_.empty()) {
        int summat(K/4 + 1);
        int size = node_list_.size();
        int elements = base::RandomUint32() % summat % size;
        for (int n = 0; n < elements; ++n) {
          resp->add_closest_nodes(node_list_.front().SerialiseAsString());
          node_list_.pop_front();
        }
      }
    }
    boost::thread th(boost::bind(&MockKadRpcs::FunctionForThread, this,
                                 callback));
  }
  void FunctionForThread(google::protobuf::Closure *callback) {
    boost::this_thread::sleep(
        boost::posix_time::milliseconds(100 * (base::RandomUint32() % 5 + 1)));
    callback->Run();
  }
  bool AllAlphasBack(boost::shared_ptr<FindNodesArgs> fna) {
    boost::mutex::scoped_lock loch_surlaplage(fna->mutex);
    NodeContainerByState &index_state = fna->nc.get<nc_state>();
    std::pair<NCBSit, NCBSit> pa = index_state.equal_range(kSelectedAlpha);
    return pa.first == pa.second;
  }
  bool GenerateContacts(const boost::uint16_t &total) {
    if (total > 100 || total < 1)
      return false;
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    std::string ip("123.234.134.1");
    for (boost::uint16_t n = 0; n < total; ++n) {
      Contact c(KadId(KadId::kRandomId),
                ip + boost::lexical_cast<std::string>(n), 52000 + n);
      node_list_.push_back(c);
    }
    backup_node_list_ = node_list_;
    return true;
  }
  std::list<Contact> node_list() {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    return node_list_;
  }
  std::list<Contact> backup_node_list() { return backup_node_list_; }

 private:
  boost::mutex node_list_mutex_;
  std::list<Contact> node_list_, backup_node_list_;
};

TEST_F(TestKNodeImpl, BEH_KNodeImpl_IterativeSearchHappy) {
  bool done(false);
  KadId key(KadId::kRandomId);
  std::list<Contact> lcontacts;
  boost::shared_ptr<FindNodesArgs> fna(
      new FindNodesArgs(key, boost::bind(&IterativeSearchCallback, _1, &done,
                                         &lcontacts)));
  int k(K);
  std::string ip("123.234.231.134");
  std::vector<Contact> vcontacts, popped;
  for (int n = 0; n < k; ++n) {
    Contact c(KadId(KadId::kRandomId), ip, n);
    vcontacts.push_back(c);
  }
  node_->AddContactsToContainer(vcontacts, fna);
  ASSERT_EQ(K, fna->nc.size());

  boost::shared_ptr<KadRpcs> old_rpcs = node_->kadrpcs_;
  boost::shared_ptr<MockKadRpcs> new_rpcs(
      new MockKadRpcs(node_->pchannel_manager_));
  node_->kadrpcs_ = new_rpcs;

  EXPECT_CALL(*new_rpcs, FindNode(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_,
                                  testing::_, testing::_))
      .Times(K)
      .WillRepeatedly(testing::WithArgs<5, 7>(testing::Invoke(
          boost::bind(&MockKadRpcs::FindNodeDummy, new_rpcs.get(), _1, _2))));

  NodeContainer::iterator node_it = fna->nc.begin();
  std::list<Contact> alphas;
  boost::uint16_t a(0);
  for (; node_it != fna->nc.end() && a < kAlpha; ++node_it, ++a) {
    alphas.push_back((*node_it).contact);
  }
  SortContactList(fna->key, &alphas);
  node_->IterativeSearch(fna, false, false, &alphas);
  while (!done || !new_rpcs->AllAlphasBack(fna))
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));

  std::set<Contact> lset(lcontacts.begin(), lcontacts.end()),
                    vset(vcontacts.begin(), vcontacts.end());
  ASSERT_TRUE(lset == vset);
  node_->kadrpcs_ = old_rpcs;
}

TEST_F(TestKNodeImpl, BEH_KNodeImpl_FindNodesHappy) {
  bool done(false);
  std::list<Contact> lcontacts;
  node_->prouting_table_->Clear();
  std::string ip("156.148.126.159");
  std::vector<Contact> vcontacts;
  for (boost::uint16_t n = 0; n < K; ++n) {
    Contact c(KadId(KadId::kRandomId), ip, 50000 + n);
    EXPECT_EQ(0, node_->AddContact(c, 1, false));
    vcontacts.push_back(c);
  }

  boost::shared_ptr<KadRpcs> old_rpcs = node_->kadrpcs_;
  boost::shared_ptr<MockKadRpcs> new_rpcs(
      new MockKadRpcs(node_->pchannel_manager_));
  node_->kadrpcs_ = new_rpcs;

  EXPECT_CALL(*new_rpcs, FindNode(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_,
                                  testing::_, testing::_))
      .WillRepeatedly(testing::WithArgs<5, 7>(testing::Invoke(
          boost::bind(&MockKadRpcs::FindNodeDummy, new_rpcs.get(), _1, _2))));

  FindNodesParams fnp1;
  fnp1.key = KadId(KadId::kRandomId);
  fnp1.callback = boost::bind(&IterativeSearchCallback, _1, &done, &lcontacts);
  node_->FindNodes(fnp1);
  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));

  std::set<Contact> lset(lcontacts.begin(), lcontacts.end()),
                    vset(vcontacts.begin(), vcontacts.end());
  ASSERT_TRUE(lset == vset);

  lcontacts.clear();
  done = false;
  FindNodesParams fnp2;
  fnp2.key = KadId(KadId::kRandomId);
  fnp2.callback = boost::bind(&IterativeSearchCallback, _1, &done, &lcontacts);
  std::list<Contact> winners, backup;
  ip = std::string("156.148.126.160");
  for (int a = 0; a < K; ++a) {
    Contact c(KadId(KadId::kRandomId), ip, 51000 + a);
    fnp2.start_nodes.push_back(c);
    winners.push_back(c);
    winners.push_back(vcontacts[a]);
  }

  node_->FindNodes(fnp2);
  SortContactList(fnp2.key, &winners);
  backup = winners;
  winners.resize(K);
  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));

  vset = std::set<Contact>(winners.begin(), winners.end());
  lset = std::set<Contact>(lcontacts.begin(), lcontacts.end());
  ASSERT_EQ(vset.size(), lset.size());
  ASSERT_TRUE(lset == vset);

  lcontacts.clear();
  done = false;
  FindNodesParams fnp3;
  fnp3.key = KadId(KadId::kRandomId);
  fnp3.callback = boost::bind(&IterativeSearchCallback, _1, &done, &lcontacts);
  fnp3.start_nodes = fnp2.start_nodes;
  int top(K/4 + 1);
  for (int y = 0; y < top; ++y)
    fnp3.exclude_nodes.push_back(vcontacts[y]);

  node_->FindNodes(fnp3);
  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));

  lset = std::set<Contact>(lcontacts.begin(), lcontacts.end());
  std::set<Contact> back(backup.begin(), backup.end());
  std::set<Contact>::iterator it;
  for (size_t e = 0; e < fnp3.exclude_nodes.size(); ++e) {
    it = lset.find(fnp3.exclude_nodes[e]);
    ASSERT_TRUE(it == lset.end());
    it = back.find(fnp3.exclude_nodes[e]);
    ASSERT_TRUE(it != back.end());
    back.erase(it);
  }

  backup = std::list<Contact>(back.begin(), back.end());
  SortContactList(fnp3.key, &backup);
  backup.resize(K);
  back = std::set<Contact>(backup.begin(), backup.end());
  ASSERT_EQ(lset.size(), back.size());
  ASSERT_TRUE(lset == back);

  node_->kadrpcs_ = old_rpcs;
}

TEST_F(TestKNodeImpl, BEH_KNodeImpl_FindNodesContactsInReponse) {
  bool done(false);
  std::list<Contact> lcontacts;
  node_->prouting_table_->Clear();
  std::string ip("156.148.126.159");
  std::vector<Contact> vcontacts;
  for (boost::uint16_t n = 0; n < K; ++n) {
    Contact c(KadId(KadId::kRandomId), ip, 50000 + n);
    EXPECT_EQ(0, node_->AddContact(c, 1, false));
    vcontacts.push_back(c);
  }

  boost::shared_ptr<KadRpcs> old_rpcs = node_->kadrpcs_;
  boost::shared_ptr<MockKadRpcs> new_rpcs(
      new MockKadRpcs(node_->pchannel_manager_));
  node_->kadrpcs_ = new_rpcs;
  ASSERT_TRUE(new_rpcs->GenerateContacts(100));

  EXPECT_CALL(*new_rpcs, FindNode(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_,
                                  testing::_, testing::_))
      .WillRepeatedly(testing::WithArgs<5, 7>(testing::Invoke(
          boost::bind(&MockKadRpcs::FindNodeDummy, new_rpcs.get(), _1, _2))));

  FindNodesParams fnp1;
  fnp1.key = KadId(KadId::kRandomId);
  fnp1.callback = boost::bind(&IterativeSearchCallback, _1, &done, &lcontacts);
  node_->FindNodes(fnp1);
  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));

  std::list<Contact> bcontacts = new_rpcs->backup_node_list();
  bcontacts.insert(bcontacts.end(), vcontacts.begin(), vcontacts.end());
  std::set<Contact> sss(bcontacts.begin(), bcontacts.end());
  std::list<Contact> ncontacts = new_rpcs->node_list();
  std::set<Contact>::iterator it;
  while (!ncontacts.empty()) {
    it = sss.find(ncontacts.front());
    if (it != sss.end())
      sss.erase(it);
    ncontacts.pop_front();
  }
  bcontacts = std::list<Contact>(sss.begin(), sss.end());
  SortContactList(fnp1.key, &bcontacts);
  bcontacts.resize(K);
  sss = std::set<Contact>(bcontacts.begin(), bcontacts.end());

  std::set<Contact> lset(lcontacts.begin(), lcontacts.end());
  ASSERT_EQ(lset.size(), sss.size());
  ASSERT_TRUE(lset == sss);

  node_->kadrpcs_ = old_rpcs;
}

}  // namespace test_knodeimpl

}  // namespace kad
