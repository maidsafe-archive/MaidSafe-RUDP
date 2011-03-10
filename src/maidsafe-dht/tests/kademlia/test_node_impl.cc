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
#include <bitset>

#include "boost/lexical_cast.hpp"
#include "boost/thread.hpp"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "maidsafe-dht/transport/utils.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe-dht/kademlia/alternative_store.h"
#include "maidsafe-dht/kademlia/securifier.h"
#include "maidsafe-dht/kademlia/rpcs.h"
#include "maidsafe-dht/kademlia/contact.h"
#include "maidsafe-dht/kademlia/node_id.h"
#include "maidsafe-dht/kademlia/node_impl.h"
#include "maidsafe-dht/kademlia/routing_table.h"
#include "maidsafe-dht/kademlia/datastore.h"

namespace maidsafe {

namespace kademlia {

namespace test {

static const boost::uint16_t k = 8;
static const boost::uint16_t alpha = 3;
static const boost::uint16_t beta = 2;
static const boost::uint16_t randomnoresponserate = 20; // in percentage

void FindNodeCallback(RankInfoPtr rank_info,
                      int result_size,
                      const std::vector<Contact> &cs,
                      bool *done,
                      std::vector<Contact> *contacts) {
  contacts->clear();
  *contacts = cs;
  *done = true;
}

void StoreCallback(RankInfoPtr rank_info,
                   int error_code,
                   bool *done,
                   int *response_code) {
  *done = true;
  *response_code = error_code;
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

  Contact ComposeContact(const NodeId& node_id, boost::uint16_t port) {
    std::string ip("127.0.0.1");
    std::vector<transport::Endpoint> local_endpoints;
    transport::Endpoint end_point(ip, port);
    local_endpoints.push_back(end_point);
    Contact contact(node_id, end_point, local_endpoints, end_point, false,
                    false, "", "", "");
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

class TestAlternativeStore : public AlternativeStore {
 public:
  ~TestAlternativeStore() {}
  bool Has(const std::string&) { return false; }
};

class NodeImplTest : public CreateContactAndNodeId, public testing::Test {
 protected:
  NodeImplTest() : CreateContactAndNodeId(),
                   data_store_(),
                   alternative_store_(),
                   securifier_(new Securifier("", "", "")),
                   info_(), rank_info_(), asio_service_(),
                   node_(new Node::Impl(asio_service_, info_,
                         securifier_, alternative_store_, true, test::k,
                         test::alpha, test::beta, bptime::seconds(3600))) {
    data_store_ = node_->data_store_;
    node_->routing_table_ = routing_table_;
  }

  static void SetUpTestCase() {
//     test_dir_ = std::string("temp/NodeImplTest") +
//                 boost::lexical_cast<std::string>(RandomUint32());
//    asio_service_.reset(new boost::asio::io_service);
//    udt_.reset(new transport::UdtTransport(asio_service_));
//     std::vector<IP> ips = transport::GetLocalAddresses();
//     transport::Endpoint ep(ips.at(0), 50000);
//    EXPECT_EQ(transport::kSuccess, udt_->StartListening(ep));
//
//     crypto::RsaKeyPair rkp;
//     rkp.GenerateKeys(4096);
//     NodeConstructionParameters kcp;
//     kcp.alpha = kAlpha;
//     kcp.beta = kBeta;
//     kcp.type = VAULT;
//     kcp.public_key = rkp.public_key();
//     kcp.private_key = rkp.private_key();
//     kcp.k = K;
//     kcp.refresh_time = kRefreshTime;
//     kcp.port = ep.port;
//     node_.reset(new NodeImpl(udt_, kcp));
//
//     node_->JoinFirstNode(test_dir_ + std::string(".kadconfig"),
//                          ep.ip, ep.port,
//                          boost::bind(&GeneralKadCallback::CallbackFunc,
//                                      &cb_, _1));
//     wait_result(&cb_);
//     ASSERT_TRUE(cb_.result());
//     ASSERT_TRUE(node_->is_joined());
  }
  static void TearDownTestCase() {
//    udt_->StopListening();
//    printf("udt_->StopListening();\n");
//     node_->Leave();
//    transport::UdtTransport::CleanUp();
  }

  void PopulateRoutingTable(boost::uint16_t count, boost::uint16_t pos) {
    for (int num_contact = 0; num_contact < count; ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(node_id_, pos);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact, rank_info_);
    }
  }

  void AddContact(const Contact& contact, const RankInfoPtr rank_info) {
    routing_table_->AddContact(contact, rank_info);
    routing_table_->SetValidated(contact.node_id(), true);
  }

  void GenericCallback(const std::string&, bool *done) { *done = true; }

  std::shared_ptr<Rpcs> GetRpc() {
    return node_->rpcs_;
  }

  void SetRpc(std::shared_ptr<Rpcs> rpc) {
    node_->rpcs_ = rpc;
  }

  KeyValueSignature MakeKVS(const crypto::RsaKeyPair &rsa_key_pair,
                            const size_t &value_size,
                            std::string key,
                            std::string value) {
    if (key.empty())
      key = crypto::Hash<crypto::SHA512>(RandomString(1024));
    if (value.empty()) {
      value.reserve(value_size);
      std::string temp = RandomString((value_size > 1024) ? 1024 : value_size);
      while (value.size() < value_size)
        value += temp;
      value = value.substr(0, value_size);
    }
    std::string signature = crypto::AsymSign(value, rsa_key_pair.private_key());
    return KeyValueSignature(key, value, signature);
  }

  std::shared_ptr<DataStore> data_store_;
  AlternativeStorePtr alternative_store_;
  SecurifierPtr securifier_;
  TransportPtr info_;
  RankInfoPtr rank_info_;
  std::shared_ptr<boost::asio::io_service> asio_service_;
  std::shared_ptr<Node::Impl> node_;
//   static std::string test_dir_;
//   static boost::int16_t transport_id_;
//   static boost::shared_ptr<transport::UdtTransport> udt_;
//   static GeneralKadCallback cb_;
};

class MockRpcs : public Rpcs, public CreateContactAndNodeId {
 public:
  explicit MockRpcs(std::shared_ptr<boost::asio::io_service> asio_service,
                    SecurifierPtr securifier)
      : Rpcs(asio_service, securifier),
        CreateContactAndNodeId(),
        node_list_mutex_(),
        node_list_(),
        rank_info_(),
        num_of_acquired_(0),
        num_of_deleted_(0),
        respond_contacts_(),
        target_id_(),
        threshold_(0) {}
  MOCK_METHOD8(Store, void(const Key &key,
                           const std::string &value,
                           const std::string &signature,
                           const boost::posix_time::seconds &ttl,
                           SecurifierPtr securifier,
                           const Contact &peer,
                           StoreFunctor callback,
                           TransportType type));
  MOCK_METHOD7(Delete, void(const Key &key,
                            const std::string &value,
                            const std::string &signature,
                            SecurifierPtr securifier,
                            const Contact &peer,
                            DeleteFunctor callback,
                            TransportType type));
  
  MOCK_METHOD5(FindNodes, void(const NodeId &key,
                               const SecurifierPtr securifier,
                               const Contact &contact,
                               FindNodesFunctor callback,
                               TransportType type));

  void FindNodeRandomResponseClose(const Contact &c,
                     FindNodesFunctor callback) {
    int response_factor = RandomUint32() % 100;
    bool response(true);
    if (response_factor < test::randomnoresponserate)
      response = false;
    std::vector<Contact> response_list;
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    if (response) {
      int elements = RandomUint32() % test::k;
      for (int n = 0; n < elements; ++n) {
        int element = RandomUint32() % node_list_.size();
        // make sure the new one hasn't been set as down previously
        ContactsById key_indx = down_contacts_->get<NodeIdTag>();
        auto it = key_indx.find(node_list_[element].node_id());
        if (it == key_indx.end()) {
          response_list.push_back(node_list_[element]);
          RoutingTableContact new_routing_table_contact(node_list_[element],
                                                        target_id_,
                                                        0);
          respond_contacts_->insert(new_routing_table_contact);
        }
      }
      boost::thread th(boost::bind(&MockRpcs::ResponseThread, this, callback,
                                   response_list));
    } else {
      ContactsById key_indx = respond_contacts_->get<NodeIdTag>();
      auto it = key_indx.find(c.node_id());
      if (it != key_indx.end()) {
        down_contacts_->insert((*it));
        respond_contacts_->erase(it);
      }
      boost::thread th(boost::bind(&MockRpcs::NoResponseThread, this, callback,
                                   response_list));
    }
  }

  void FindNodeResponseClose(const Contact &c,
                     FindNodesFunctor callback) {
    std::vector<Contact> response_list;
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    int elements = RandomUint32() % test::k;
    for (int n = 0; n < elements; ++n) {
      int element = RandomUint32() % node_list_.size();
      response_list.push_back(node_list_[element]);
      RoutingTableContact new_routing_table_contact(node_list_[element],
                                                    target_id_,
                                                    0);
      respond_contacts_->insert(new_routing_table_contact);
    }
    boost::thread th(boost::bind(&MockRpcs::ResponseThread, this, callback,
                                 response_list));
  }

  void FindNodeResponseNoClose(const Contact &c,
                     FindNodesFunctor callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    std::vector<Contact> response_list;
    boost::thread th(boost::bind(&MockRpcs::ResponseThread, this, callback,
                                 response_list));
  }

  void FindNodeFirstNoResponse(const Contact &c,
                     FindNodesFunctor callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    std::vector<Contact> response_list;
    if (num_of_acquired_ == 0) {
      boost::thread th(boost::bind(&MockRpcs::NoResponseThread, this, callback,
                                   response_list));
    } else {
      boost::thread th(boost::bind(&MockRpcs::ResponseThread, this, callback,
                                   response_list));
    }
    ++num_of_acquired_;
  }

  void FindNodeFirstAndLastNoResponse(const Contact &c,
                     FindNodesFunctor callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    std::vector<Contact> response_list;
    if ((num_of_acquired_ == (test::k - 1)) || (num_of_acquired_ == 0)) {
      boost::thread th(boost::bind(&MockRpcs::NoResponseThread, this, callback,
                                   response_list));
    } else {
      boost::thread th(boost::bind(&MockRpcs::ResponseThread, this, callback,
                                   response_list));
    }
    ++num_of_acquired_;
  }

  void FindNodeNoResponse(const Contact &c,
                     FindNodesFunctor callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    std::vector<Contact> response_list;
    boost::thread th(boost::bind(&MockRpcs::NoResponseThread, this, callback,
                                 response_list));
  }

  void ResponseThread(FindNodesFunctor callback,
                         std::vector<Contact> response_list) {
    boost::uint16_t interval(10 * (RandomUint32() % 5) + 1);
    boost::this_thread::sleep(boost::posix_time::milliseconds(interval));
    callback(rank_info_, response_list.size(), response_list);
  }

  void NoResponseThread(FindNodesFunctor callback,
                         std::vector<Contact> response_list) {
    boost::uint16_t interval(100 * (RandomUint32() % 5) + 1);
    boost::this_thread::sleep(boost::posix_time::milliseconds(interval));
    callback(rank_info_, -1, response_list);
  }

  void StoreResponse(const Contact &c,
                     StoreFunctor callback) {
    boost::thread th(boost::bind(&MockRpcs::StoreResponseThread, this,
                                 callback));
  }

  void StoreLastSeveralNoResponse(const Contact &c,
                                  StoreFunctor callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    if (num_of_acquired_ < (threshold_ - 1)) {
      boost::thread th(boost::bind(&MockRpcs::StoreResponseThread,
                                    this, callback));
    } else {
      boost::thread th(boost::bind(&MockRpcs::StoreNoResponseThread,
                                    this, callback));
    }
    ++num_of_acquired_;
  }

  void StoreFirstSeveralNoResponse(const Contact &c,
                                   StoreFunctor callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    if (num_of_acquired_ > (test::k - threshold_)) {
      boost::thread th(boost::bind(&MockRpcs::StoreResponseThread,
                                    this, callback));
    } else {
      boost::thread th(boost::bind(&MockRpcs::StoreNoResponseThread,
                                    this, callback));
    }
    ++num_of_acquired_;
  }

  void StoreLastLessNoResponse(const Contact &c,
                               StoreFunctor callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    if (num_of_acquired_ < threshold_) {
      boost::thread th(boost::bind(&MockRpcs::StoreResponseThread,
                                    this, callback));
    } else {
      boost::thread th(boost::bind(&MockRpcs::StoreNoResponseThread,
                                    this, callback));
    }
    ++num_of_acquired_;
  }

  void StoreResponseThread(StoreFunctor callback) {
    boost::uint16_t interval(10 * (RandomUint32() % 5) + 1);
    boost::this_thread::sleep(boost::posix_time::milliseconds(interval));
    callback(rank_info_, RandomUint32() % test::k);
  }

  void StoreNoResponseThread(StoreFunctor callback) {
    boost::uint16_t interval(100 * (RandomUint32() % 5) + 1);
    boost::this_thread::sleep(boost::posix_time::milliseconds(interval));
    callback(rank_info_, -1);
  }

  void DeleteResponse(const Contact &c,
                      DeleteFunctor callback) {
    boost::thread th(boost::bind(&MockRpcs::DeleteResponseThread, this,
                                 callback));
  }

  void DeleteResponseThread(DeleteFunctor callback) {
    boost::uint16_t interval(10 * (RandomUint32() % 5) + 1);
    boost::this_thread::sleep(boost::posix_time::milliseconds(interval));
    ++num_of_deleted_;
    callback(rank_info_, RandomUint32() % test::k);
  }

  void PopulateResponseCandidates(int count, const int& pos) {
    PopulateContactsVector(count, pos, &node_list_);
  }

  std::vector<Contact> node_list() {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    return node_list_;
  }
//   std::list<Contact> backup_node_list() { return backup_node_list_; }

// private:
  boost::mutex node_list_mutex_;
  std::vector<Contact> node_list_;
  RankInfoPtr rank_info_;
  
  boost::uint16_t num_of_acquired_;
  boost::uint16_t num_of_deleted_;
  
  std::shared_ptr<RoutingTableContactsContainer> respond_contacts_;
  std::shared_ptr<RoutingTableContactsContainer> down_contacts_;
  NodeId target_id_;

  int threshold_;
};

TEST_F(NodeImplTest, BEH_KAD_FindNodes) {
  PopulateRoutingTable(test::k, 500);

  std::shared_ptr<Rpcs> old_rpcs = GetRpc();
  std::shared_ptr<MockRpcs> new_rpcs(new MockRpcs(asio_service_, securifier_ ));
  new_rpcs->node_id_ = node_id_;
  SetRpc(new_rpcs);

  NodeId key = NodeId(NodeId::kRandomId);
  {
    // All k populated contacts giving no response
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeNoResponse,
                        new_rpcs.get(), _1, _2))));
    std::vector<Contact> lcontacts;
    bool done(false);
    node_->FindNodes(key,
                     boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done,
                                 &lcontacts));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(0, lcontacts.size());
  }
  new_rpcs->num_of_acquired_ = 0;
  {
    // The first of the k populated contacts giving no response
    // all the others give response with an empty closest list
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeFirstNoResponse,
                        new_rpcs.get(), _1, _2))));
    std::vector<Contact> lcontacts;
    bool done(false);
    node_->FindNodes(key,
                     boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done,
                                 &lcontacts));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(test::k - 1, lcontacts.size());
  }
  new_rpcs->num_of_acquired_ = 0;
  {
    // The first and the last of the k populated contacts giving no response
    // all the others give response with an empty closest list
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeFirstAndLastNoResponse,
                        new_rpcs.get(), _1, _2))));
    std::vector<Contact> lcontacts;
    bool done(false);
    node_->FindNodes(key,
                     boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done,
                                 &lcontacts));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(test::k - 2, lcontacts.size());
  }
  {
    // All k populated contacts response with an empty closest list
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeResponseNoClose,
                        new_rpcs.get(), _1, _2))));
    std::vector<Contact> lcontacts;
    bool done(false);
    node_->FindNodes(key,
                     boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done,
                                 &lcontacts));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(test::k, lcontacts.size());
  }
  int count = 10 * test::k;
  new_rpcs->PopulateResponseCandidates(count, 499);
  NodeId target = GenerateRandomId(node_id_, 498);
  new_rpcs->target_id_ = target;
  std::shared_ptr<RoutingTableContactsContainer> temp
      (new RoutingTableContactsContainer());
  new_rpcs->respond_contacts_ = temp;
  {
    // All k populated contacts response with random closest list (not greater
    // than k)
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeResponseClose,
                        new_rpcs.get(), _1, _2))));
    std::vector<Contact> lcontacts;
    bool done(false);
    node_->FindNodes(target,
                     boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done,
                                 &lcontacts));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(test::k, lcontacts.size());
    EXPECT_NE(lcontacts[0], lcontacts[test::k / 2]);
    EXPECT_NE(lcontacts[0], lcontacts[test::k - 1]);

    ContactsByDistanceToThisId key_dist_indx
      = new_rpcs->respond_contacts_->get<DistanceToThisIdTag>();
    auto it = key_dist_indx.begin();
    int step(0);
    while ((it != key_dist_indx.end()) && (step < test::k)) {
      EXPECT_NE(lcontacts.end(),
                std::find(lcontacts.begin(), lcontacts.end(), (*it).contact));
      ++it;
      ++step;
    }
  }
  new_rpcs->respond_contacts_->clear();
  std::shared_ptr<RoutingTableContactsContainer> down_list
      (new RoutingTableContactsContainer());
  new_rpcs->down_contacts_ = down_list;
  {
    // All k populated contacts randomly response with random closest list
    // (not greater than k)
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeRandomResponseClose,
                        new_rpcs.get(), _1, _2))));
    std::vector<Contact> lcontacts;
    bool done(false);
    node_->FindNodes(target,
                     boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done,
                                 &lcontacts));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));

    if (new_rpcs->respond_contacts_->size() >= test::k) {
      EXPECT_EQ(test::k, lcontacts.size());
      EXPECT_NE(lcontacts[0], lcontacts[test::k / 2]);
      EXPECT_NE(lcontacts[0], lcontacts[test::k - 1]);

      ContactsByDistanceToThisId key_dist_indx
        = new_rpcs->respond_contacts_->get<DistanceToThisIdTag>();
      auto it = key_dist_indx.begin();
      int step(0);
      while ((it != key_dist_indx.end()) && (step < test::k)) {
        EXPECT_NE(lcontacts.end(),
                  std::find(lcontacts.begin(), lcontacts.end(), (*it).contact));
        ++it;
        ++step;
      }
    } else {
      // if really unlucky, some of the original seeds might be pushed into the
      // result (the chance is very small).
      EXPECT_LE(new_rpcs->respond_contacts_->size(), lcontacts.size());
    }
  }
  //  sleep for a while to prevent the situation that resources got destructed
  //  before all call back from rpc completed. Which will cause "Segmentation
  //  Fault" in execution.
  boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
  //SetRpc(old_rpcs);
}

TEST_F(NodeImplTest, FUNC_KAD_HandleIterationStructure) {
  NodeId target = GenerateRandomId(node_id_, 497);
  {
    // test::k - 1 contacted, the last one respond as contacted
    std::vector<Contact> lcontacts;
    bool done(false);
    std::shared_ptr<FindNodesArgs> fna(new FindNodesArgs(target,
        boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done, &lcontacts)));

    RoutingTableContactsContainer generated_nodes;
    for (int i=0; i < (test::k - 1); ++i) {
      Contact contact = GenerateUniqueContact(node_id_, 499, generated_nodes,
                                              target);
      NodeContainerTuple nct(contact, fna->key, i / alpha);
      nct.state = kContacted;
      fna->nc.insert(nct);
    }
    NodeId contact_id = GenerateRandomId(node_id_, 498);
    Contact contact = ComposeContact(contact_id, 5000);
    NodeContainerTuple nct(contact, fna->key, (test::k-1) / alpha);
    nct.state = kSelectedAlpha;
    fna->nc.insert(nct);

    fna->round = (test::k-1) / alpha;
    NodeSearchState mark(kContacted);
    bool curr_iteration_done(false), calledback(false);
    node_->HandleIterationStructure(contact, fna,
                                    mark, &curr_iteration_done, &calledback);
    EXPECT_EQ(true, curr_iteration_done);
    EXPECT_EQ(true, calledback);
    EXPECT_EQ(true, done);
    EXPECT_EQ(test::k, lcontacts.size());
  }
  {
    // test::k - 2 contacted, the test::k -1 one pending
    // the last one respond as contacted
    std::vector<Contact> lcontacts;
    bool done(false);
    std::shared_ptr<FindNodesArgs> fna(new FindNodesArgs(target,
        boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done, &lcontacts)));

    RoutingTableContactsContainer generated_nodes;
    for (int i=0; i < (test::k - 2); ++i) {
      Contact contact = GenerateUniqueContact(node_id_, 499, generated_nodes,
                                              target);
      NodeContainerTuple nct(contact, fna->key, i / alpha);
      nct.state = kContacted;
      fna->nc.insert(nct);
    }
    Contact pending_contact = GenerateUniqueContact(node_id_, 499,
                                                    generated_nodes, target);
    NodeContainerTuple pending_nct(pending_contact, fna->key, (test::k-2) / alpha);
    pending_nct.state = kSelectedAlpha;
    fna->nc.insert(pending_nct);
    NodeId contact_id = GenerateRandomId(node_id_, 498);
    Contact contact = ComposeContact(contact_id, 5000);
    NodeContainerTuple nct(contact, fna->key, (test::k-1) / alpha);
    nct.state = kSelectedAlpha;
    fna->nc.insert(nct);

    fna->round = (test::k-1) / alpha;
    NodeSearchState mark(kContacted);
    bool curr_iteration_done(false), calledback(false);
    node_->HandleIterationStructure(contact, fna,
                                    mark, &curr_iteration_done, &calledback);
    EXPECT_EQ(false, curr_iteration_done);
    EXPECT_EQ(false, calledback);
    EXPECT_EQ(false, done);
    EXPECT_EQ(0, lcontacts.size());
  }
  {
    // test::k / 2 contacted, the last one respond as no-response
    std::vector<Contact> lcontacts;
    bool done(false);
    std::shared_ptr<FindNodesArgs> fna(new FindNodesArgs(target,
        boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done, &lcontacts)));

    RoutingTableContactsContainer generated_nodes;
    for (int i=0; i < (test::k / 2); ++i) {
      Contact contact = GenerateUniqueContact(node_id_, 499, generated_nodes,
                                              target);
      NodeContainerTuple nct(contact, fna->key, i / alpha);
      nct.state = kContacted;
      fna->nc.insert(nct);
    }
    NodeId contact_id = GenerateRandomId(node_id_, 498);
    Contact contact = ComposeContact(contact_id, 5000);
    NodeContainerTuple nct(contact, fna->key, (test::k / 2) / alpha);
    nct.state = kSelectedAlpha;
    fna->nc.insert(nct);

    fna->round = (test::k / 2) / alpha;
    NodeSearchState mark(kDown);
    bool curr_iteration_done(false), calledback(false);
    node_->HandleIterationStructure(contact, fna,
                                    mark, &curr_iteration_done, &calledback);
    EXPECT_EQ(true, curr_iteration_done);
    EXPECT_EQ(true, calledback);
    EXPECT_EQ(true, done);
    EXPECT_EQ(test::k / 2, lcontacts.size());
  }
  {
    // test::k candidates, for each previous round (alpha - beta) pending
    // for the last round, all contacted
    std::vector<Contact> lcontacts;
    bool done(false);
    std::shared_ptr<FindNodesArgs> fna(new FindNodesArgs(target,
        boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done, &lcontacts)));

    RoutingTableContactsContainer generated_nodes;
    for (int i=0; i < (alpha * (test::k / alpha)); ++i) {
      Contact contact = GenerateUniqueContact(node_id_, 499, generated_nodes,
                                              target);
      NodeContainerTuple nct(contact, fna->key, i / alpha);
      if ((i % alpha) < beta ) {
        nct.state = kContacted;
      } else {
        nct.state = kSelectedAlpha;
      }
      fna->nc.insert(nct);
    }
    for (int i=0; i < (test::k % alpha - 2); ++i) {
      Contact contact = GenerateUniqueContact(node_id_, 499, generated_nodes,
                                              target);
      NodeContainerTuple nct(contact, fna->key, test::k / alpha);
      nct.state = kContacted;
      fna->nc.insert(nct);
    }

    Contact contact = GenerateUniqueContact(node_id_, 499, generated_nodes,
                                            target);
    NodeContainerTuple nct(contact, fna->key, test::k / alpha);
    nct.state = kSelectedAlpha;
    fna->nc.insert(nct);
    Contact last_contact = GenerateUniqueContact(node_id_, 499, generated_nodes,
                                                 target);
    NodeContainerTuple last_nct(last_contact, fna->key, test::k / alpha);
    last_nct.state = kSelectedAlpha;
    fna->nc.insert(last_nct);

    fna->round = test::k / alpha;

    NodeSearchState mark(kContacted);
    bool curr_iteration_done(false), calledback(false);
    node_->HandleIterationStructure(contact, fna,
                                    mark, &curr_iteration_done, &calledback);
    EXPECT_EQ(false, curr_iteration_done);
    EXPECT_EQ(false, calledback);
    EXPECT_EQ(false, done);
    EXPECT_EQ(0, lcontacts.size());

    curr_iteration_done = false;
    calledback = false;
    node_->HandleIterationStructure(last_contact, fna,
                                    mark, &curr_iteration_done,
                                    &calledback);
    EXPECT_EQ(false, curr_iteration_done);
    EXPECT_EQ(false, calledback);
    EXPECT_EQ(false, done);
    EXPECT_EQ(0, lcontacts.size());
  }
  {
    // k candidates, with (beta - 1) contacted, the next one respond with
    // no response
    std::vector<Contact> lcontacts;
    bool done(false);
    std::shared_ptr<FindNodesArgs> fna(new FindNodesArgs(target,
        boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done, &lcontacts)));

    RoutingTableContactsContainer generated_nodes;
    Contact first_contact = GenerateUniqueContact(node_id_, 499,
                                                  generated_nodes,
                                                  target);
    NodeContainerTuple first_nct(first_contact, fna->key, 0);
    first_nct.state = kSelectedAlpha;
    fna->nc.insert(first_nct);
    Contact second_contact = GenerateUniqueContact(node_id_, 499,
                                                   generated_nodes,
                                                   target);
    NodeContainerTuple second_nct(second_contact, fna->key, 0);
    second_nct.state = kSelectedAlpha;
    fna->nc.insert(second_nct);

    for (int i=2; i < test::k; ++i) {
      Contact contact = GenerateUniqueContact(node_id_, 499, generated_nodes,
                                              target);
      NodeContainerTuple nct(contact, fna->key, i / alpha);
      nct.state = kNew;
      fna->nc.insert(nct);
    }

    fna->round = 0;
    NodeSearchState mark(kContacted);
    bool curr_iteration_done(false), calledback(false);
    node_->HandleIterationStructure(first_contact, fna,
                                    mark, &curr_iteration_done, &calledback);
    EXPECT_EQ(false, curr_iteration_done);
    EXPECT_EQ(false, calledback);
    EXPECT_EQ(false, done);
    EXPECT_EQ(0, lcontacts.size());

    mark = kDown;
    node_->HandleIterationStructure(second_contact, fna,
                                    mark, &curr_iteration_done,
                                    &calledback);
    EXPECT_EQ(true, curr_iteration_done);
    EXPECT_EQ(false, calledback);
    EXPECT_EQ(false, done);
    EXPECT_EQ(0, lcontacts.size());
  }
  // sleep for a while to prevent the situation that resources got destructed
  // before call back completed. Which will cause "Segmentation Fault" in
  // execution.
  boost::this_thread::sleep(boost::posix_time::milliseconds(100));
}

TEST_F(NodeImplTest, BEH_KAD_Store) {
  PopulateRoutingTable(test::k, 500);

  std::shared_ptr<Rpcs> old_rpcs = GetRpc();
  std::shared_ptr<MockRpcs> new_rpcs(new MockRpcs(asio_service_, securifier_ ));
  new_rpcs->node_id_ = node_id_;
  SetRpc(new_rpcs);

  NodeId key = NodeId(NodeId::kRandomId);

  new_rpcs->num_of_acquired_ = 0;

  int count = 10 * test::k;
  new_rpcs->PopulateResponseCandidates(count, 499);
  NodeId target = GenerateRandomId(node_id_, 498);
  new_rpcs->target_id_ = target;
  std::shared_ptr<RoutingTableContactsContainer> temp
      (new RoutingTableContactsContainer());
  new_rpcs->respond_contacts_ = temp;

  std::shared_ptr<RoutingTableContactsContainer> down_list
      (new RoutingTableContactsContainer());
  new_rpcs->down_contacts_ = down_list;
  EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                   testing::_, testing::_))
      .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
          boost::bind(&MockRpcs::FindNodeResponseClose,
                      new_rpcs.get(), _1, _2))));

  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(1024);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, key.String(), "");
  bptime::time_duration old_ttl(bptime::pos_infin);

  int threshold = (test::k * 3) / 4;
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // all k closest contacts respond with success
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            boost::bind(&MockRpcs::StoreResponse,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Store(key, kvs.value, kvs.signature, old_ttl, securifier_,
                 boost::bind(&StoreCallback, rank_info_, _1, &done,
                             &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));

    EXPECT_EQ(threshold, response_code);
  }
  new_rpcs->threshold_ = threshold;
  new_rpcs->num_of_acquired_ = 0;
  new_rpcs->num_of_deleted_ = 0;
  EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                testing::_, testing::_, testing::_,
                                testing::_))
      .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
          boost::bind(&MockRpcs::DeleteResponse,
                      new_rpcs.get(), _1, _2))));
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the last k - threshold closest contacts respond with DOWN, others respond
    // with success
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            boost::bind(&MockRpcs::StoreLastSeveralNoResponse,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Store(key, kvs.value, kvs.signature, old_ttl, securifier_,
                 boost::bind(&StoreCallback, rank_info_, _1, &done,
                             &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(-2, response_code);
    // wait for the delete processes to be completed
    // otherwise the counter might be incorrect
    boost::this_thread::sleep(boost::posix_time::milliseconds(300));
    EXPECT_EQ(test::k - threshold + 1, new_rpcs->num_of_deleted_);
  }
  new_rpcs->num_of_acquired_ = 0;
  new_rpcs->num_of_deleted_ = 0;
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the first k - threshold closest contacts respond with DOWN, others
    // respond with success
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            boost::bind(&MockRpcs::StoreFirstSeveralNoResponse,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Store(key, kvs.value, kvs.signature, old_ttl, securifier_,
                 boost::bind(&StoreCallback, rank_info_, _1, &done,
                             &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(-2, response_code);
    // wait for the delete processes to be completed
    // otherwise the counter might be incorrect
    // may not be necessary for this test
    boost::this_thread::sleep(boost::posix_time::milliseconds(300));
    EXPECT_EQ(test::k - threshold + 1, new_rpcs->num_of_deleted_);
  }
  new_rpcs->num_of_acquired_ = 0;
  new_rpcs->num_of_deleted_ = 0;
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the first k - threshold -1 closest contacts respond with DOWN, others
    // respond with success
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            boost::bind(&MockRpcs::StoreLastLessNoResponse,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Store(key, kvs.value, kvs.signature, old_ttl, securifier_,
                 boost::bind(&StoreCallback, rank_info_, _1, &done,
                             &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(threshold, response_code);
    // wait to ensure in case of wrong, the wrong deletion will be executed
    boost::this_thread::sleep(boost::posix_time::milliseconds(300));
    EXPECT_EQ(0, new_rpcs->num_of_deleted_);
  }
  // sleep for a while to prevent the situation that resources got destructed
  // before all call back from rpc completed. Which will cause "Segmentation
  // Fault" in execution.
  boost::this_thread::sleep(boost::posix_time::milliseconds(1000));

  //SetRpc(old_rpcs);
}

}  // namespace test_nodeimpl

}  // namespace kademlia

}  // namespace maidsafe