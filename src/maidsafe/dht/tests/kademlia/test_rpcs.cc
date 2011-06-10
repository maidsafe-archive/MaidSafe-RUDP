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

#include "maidsafe/dht/transport/tcp_transport.h"
#include "maidsafe/dht/transport/udp_transport.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/dht/kademlia/config.h"
#include "maidsafe/dht/kademlia/rpcs.pb.h"
#include "maidsafe/dht/kademlia/securifier.h"
#include "maidsafe/dht/kademlia/utils.h"
#include "maidsafe/dht/kademlia/service.h"
#include "maidsafe/dht/kademlia/rpcs.h"
#include "maidsafe/dht/kademlia/node_id.h"
#include "maidsafe/dht/kademlia/routing_table.h"
#include "maidsafe/dht/kademlia/message_handler.h"
#include "maidsafe/dht/tests/kademlia/utils.h"

namespace arg = std::placeholders;

namespace maidsafe {

namespace dht {

namespace kademlia {

namespace test {

const int kRpcClientNo = 10;
const int kMaxOps = 1;


void TestCallback(RankInfoPtr,
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

void TestFindValueCallback(RankInfoPtr,
                           int callback_code,
                           std::vector<std::string> values,
                           std::vector<Contact> contacts,
                           Contact alternative_value_holder,
                           std::vector<std::string> *return_values,
                           std::vector<Contact> *return_contacts,
                           bool *done,
                           int *response_code) {
  *done = true;
  *response_code = callback_code;
  *return_values = values;
  *return_contacts = contacts;
}

class RpcsTest: public CreateContactAndNodeId,
                public testing::TestWithParam<TransportType> {
 public:
  RpcsTest() : node_id_(NodeId::kRandomId),
               routing_table_(new RoutingTable(node_id_, test::k)),
               data_store_(new kademlia::DataStore(bptime::seconds(3600))),
               alternative_store_(),
               asio_service_(new boost::asio::io_service()),
               local_asio_(new boost::asio::io_service()),
               rank_info_(),
               contacts_(),
               transport_(),
               transport_type_(GetParam()),
               thread_group_(),
               work_(new boost::asio::io_service::work(*asio_service_)),
               work1_(new boost::asio::io_service::work(*local_asio_)) {
    thread_group_.create_thread(std::bind(static_cast<
        std::size_t(boost::asio::io_service::*)()>
            (&boost::asio::io_service::run), asio_service_));
    thread_group_.create_thread(std::bind(static_cast<
        std::size_t(boost::asio::io_service::*)()>
            (&boost::asio::io_service::run), local_asio_));
  }

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
        new SecurifierGetPublicKeyAndValidation("",
                receiver_crypto_key_id_.public_key(),
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
    switch (transport_type_) {
      case kTcp:
        transport_.reset(new transport::TcpTransport(*local_asio_));
        break;
      case kUdp:
        transport_.reset(new transport::UdpTransport(*local_asio_));
        break;
      default:
        break;
    }
    handler_.reset(new MessageHandler(service_securifier_));
    service_->ConnectToSignals(handler_);
    transport_->on_message_received()->connect(
        transport::OnMessageReceived::element_type::slot_type(
            &MessageHandler::OnMessageReceived, handler_.get(),
            _1, _2, _3, _4).track_foreign(handler_));
    ASSERT_EQ(transport::kSuccess,
              transport_->StartListening(service_contact_.endpoint()));
  }

  virtual void TearDown() { }

  ~RpcsTest() {
    work_.reset();
    work1_.reset();
    asio_service_->stop();
    local_asio_->stop();
  }

  void PopulateRoutingTable(boost::uint16_t count) {
    for (int num_contact = 0; num_contact < count; ++num_contact) {
      NodeId contact_id(NodeId::kRandomId);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(routing_table_, contact, rank_info_);
      contacts_.push_back(contact);
    }
  }

  void AddToReceiverDataStore(const KeyValueSignature& kvs,
                              const crypto::RsaKeyPair& crypto_key_data,
                              const Contact& contact,
                              RequestAndSignature& request_signature) {
    protobuf::StoreRequest store_request = MakeStoreRequest(contact, kvs);
    std::string store_message = store_request.SerializeAsString();
    std::string store_message_sig;
    while (store_message_sig.empty())
      store_message_sig = crypto::AsymSign(store_message,
                                           crypto_key_data.private_key());
    bptime::time_duration ttl(bptime::pos_infin);
    request_signature = std::make_pair(store_message, store_message_sig);
    EXPECT_TRUE(data_store_->StoreValue(kvs, ttl, request_signature,
                                        crypto_key_data.public_key(),
                                        false));
  }

  void DeleteFromReceiverDataStore(const KeyValueSignature& kvs,
                                   const crypto::RsaKeyPair& crypto_key_data,
                                   const Contact& contact,
                                   RequestAndSignature& request_signature) {
    protobuf::DeleteRequest delete_request = MakeDeleteRequest(contact, kvs);
    std::string delete_message = delete_request.SerializeAsString();
    std::string delete_message_sig;
    while (delete_message_sig.empty())
      delete_message_sig = crypto::AsymSign(delete_message,
                                            crypto_key_data.private_key());
    request_signature = std::make_pair(delete_message, delete_message_sig);
    EXPECT_TRUE(data_store_->DeleteValue(kvs, request_signature, false));
  }
  // Checks for not deleted value which are not marked as deleted
  bool IsKeyValueInDataStore(KeyValueSignature kvs,
                             std::shared_ptr<DataStore> data_store) {
    std::vector<std::pair<std::string, std::string>> values;
    data_store->GetValues(kvs.key, &values);
    for (size_t i = 0; i < values.size(); ++i) {
      if ((values[i].first == kvs.value) &&
          (values[i].second == kvs.signature)) {
        return true;
      }
    }
    return false;
  }

  bptime::ptime GetRefreshTime(KeyValueSignature kvs) {
    KeyValueIndex::index<TagKeyValue>::type& index_by_key_value =
        data_store_->key_value_index_->get<TagKeyValue>();
    auto it = index_by_key_value.find(boost::make_tuple(kvs.key, kvs.value));
    if (it == index_by_key_value.end())
      return bptime::neg_infin;
    return (*it).refresh_time;
  }

  boost::uint16_t KDistanceTo(const NodeId &lhs, const NodeId &rhs) {
    boost::uint16_t distance = 0;
    std::string this_id_binary = lhs.ToStringEncoded(NodeId::kBinary);
    std::string rhs_id_binary = rhs.ToStringEncoded(NodeId::kBinary);
    std::string::const_iterator this_it = this_id_binary.begin();
    std::string::const_iterator rhs_it = rhs_id_binary.begin();
    for (; ((this_it != this_id_binary.end()) && (*this_it == *rhs_it));
        ++this_it, ++rhs_it)
      ++distance;
    return distance;
  }

  int GetDistance(const std::vector<Contact> &list, int test) {
    int low(0), high(0);
    boost::uint16_t distance = KDistanceTo(service_contact_.node_id(),
                                           list[0].node_id());
    low = distance;
    auto it = list.begin();
    while (it != list.end()) {
      distance = KDistanceTo(service_contact_.node_id(), (*it).node_id());
      if (distance > high)
        high = distance;
      else if (distance < low)
        low = distance;
      ++it;
    }
    if (test > 0)
      return high;
    else
      return low;
  }

  void StopAndReset() {
    asio_service_->stop();
    local_asio_->stop();
    work_.reset();
    work1_.reset();
    thread_group_.join_all();
  }
 protected:
  typedef std::shared_ptr<boost::asio::io_service::work> WorkPtr;

  kademlia::NodeId node_id_;
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
  std::vector<Contact> contacts_;
  TransportPtr transport_;
  MessageHandlerPtr handler_;
  TransportType transport_type_;
  boost::thread_group thread_group_;
  WorkPtr work_;
  WorkPtr work1_;
};

class RpcsMultiNodesTest: public CreateContactAndNodeId,
                public testing::TestWithParam<TransportType> {
 public:
  RpcsMultiNodesTest() : node_id_(NodeId::kRandomId),
                routing_table_(new RoutingTable(node_id_, test::k)),
                data_store_(new kademlia::DataStore(bptime::seconds(3600))),
                alternative_store_(),
                local_asio_(new boost::asio::io_service()),
                rank_info_(),
                contacts_(),
                transport_(),
                transport_type_(GetParam()),
                thread_group_(),
                work1_(new boost::asio::io_service::work(*local_asio_)) {
    for (int index = 0; index < kRpcClientNo; ++index) {
      IoServicePtr ioservice(new boost::asio::io_service());
      asio_service_.push_back(ioservice);
      WorkPtr workptr(new
          boost::asio::io_service::work(*asio_service_[index]));
      work_.push_back(workptr);
      thread_group_.create_thread(std::bind(static_cast<
          std::size_t(boost::asio::io_service::*)()>
              (&boost::asio::io_service::run), asio_service_[index]));
    }
    thread_group_.create_thread(std::bind(static_cast<
        std::size_t(boost::asio::io_service::*)()>
            (&boost::asio::io_service::run), local_asio_));
  }

  static void SetUpTestCase() {
    for (int index = 0; index < kRpcClientNo; ++index) {
      crypto::RsaKeyPair temp_key_pair;
      temp_key_pair.GenerateKeys(4096);
      senders_crypto_key_id2_.push_back(temp_key_pair);
    }
    receiver_crypto_key_id2_.GenerateKeys(4096);
  }

  virtual void SetUp() {
    // rpcs setup
    for (int index = 0; index <kRpcClientNo; ++index) {
      rpcs_securifier_.push_back(std::shared_ptr<Securifier>(
          new Securifier("", senders_crypto_key_id2_[index].public_key(),
                         senders_crypto_key_id2_[index].private_key())));
      rpcs_.push_back(std::shared_ptr<Rpcs>(new Rpcs(asio_service_[index],
                                                     rpcs_securifier_[index])));

      NodeId rpcs_node_id = GenerateRandomId(node_id_, 503 + index);
      kademlia::Contact rpcs_contact;
      rpcs_contact = ComposeContactWithKey(rpcs_node_id,
                                            5011 + index,
                                            senders_crypto_key_id2_[index]);
      rpcs_contact_.push_back(rpcs_contact);
      rpcs_[index]->set_contact(rpcs_contact_[index]);
    }
    // service setup
    service_securifier_ = std::shared_ptr<Securifier>(
        new SecurifierGetPublicKeyAndValidation("",
                receiver_crypto_key_id2_.public_key(),
                    receiver_crypto_key_id2_.private_key()));
    NodeId service_node_id = GenerateRandomId(node_id_, 502);
    service_contact_ = ComposeContactWithKey(service_node_id,
                                             5010,
                                             receiver_crypto_key_id2_);
    service_ = std::shared_ptr<Service>(new Service(routing_table_,
                                                    data_store_,
                                                    alternative_store_,
                                                    service_securifier_,
                                                    k));
    service_->set_node_contact(service_contact_);
    service_->set_node_joined(true);
    switch (transport_type_) {
      case kTcp:
        transport_.reset(new transport::TcpTransport(*local_asio_));
        break;
      case kUdp:
        transport_.reset(new transport::UdpTransport(*local_asio_));
        break;
      default:
        break;
    }
    handler_.reset(new MessageHandler(service_securifier_));
    service_->ConnectToSignals(handler_);
    transport_->on_message_received()->connect(
        transport::OnMessageReceived::element_type::slot_type(
            &MessageHandler::OnMessageReceived, handler_.get(),
            _1, _2, _3, _4).track_foreign(handler_));
    ASSERT_EQ(transport::kSuccess,
              transport_->StartListening(service_contact_.endpoint()));
  }

  virtual void TearDown() { }

  ~RpcsMultiNodesTest() {
    for (int index = 0; index < kRpcClientNo; ++index) {
      asio_service_[index]->stop();
      work_[index].reset();
    }
    work1_.reset();
    local_asio_->stop();
  }

  void StopAndReset() {
    for (int index = 0; index < kRpcClientNo; ++index) {
      asio_service_[index]->stop();
      work_[index].reset();
    }
    local_asio_->stop();
    work1_.reset();
    thread_group_.join_all();
  }

  void RpcOperations(const int index, bool* done, int* response_code) {
    *done = false;
    *response_code = 0;
    Key key = rpcs_contact_[index].node_id();
    KeyValueSignature kvs = MakeKVS(senders_crypto_key_id2_[index], 1024,
                                    key.String(), "");
    boost::posix_time::seconds ttl(3600);

    // attempt to find value before any stored
    std::vector<std::string> return_values;
    std::vector<Contact> return_contacts;
    *done = false;
    *response_code = 0;
    rpcs_[index]->FindValue(key, rpcs_securifier_[index],
                                   service_contact_,
                                   std::bind(&TestFindValueCallback, arg::_1,
                                             arg::_2, arg::_3, arg::_4, arg::_5,
                                             &return_values, &return_contacts,
                                             done, response_code),
                                   transport_type_);
    while (!*done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    ASSERT_EQ(0, *response_code);
    ASSERT_EQ(0, return_values.size());

    *done = false;
    *response_code = 0;
    rpcs_[index]->Store(key, kvs.value, kvs.signature, ttl,
                               rpcs_securifier_[index],
                               service_contact_,
                               std::bind(&TestCallback, arg::_1, arg::_2, done,
                                         response_code),
                               transport_type_);
    while (!*done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    ASSERT_EQ(0, *response_code);
    JoinNetworkLookup(service_securifier_);

  // attempt to retrieve value stored
    return_values.clear();
    return_contacts.clear();
    *done = false;
    *response_code = 0;
    rpcs_[index]->FindValue(key, rpcs_securifier_[index],
                                   service_contact_,
                                   std::bind(&TestFindValueCallback, arg::_1,
                                             arg::_2, arg::_3, arg::_4, arg::_5,
                                             &return_values, &return_contacts,
                                             done, response_code),
                                   transport_type_);

    while (!*done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    ASSERT_EQ(0, *response_code);
    ASSERT_EQ(kvs.value, return_values[0]);
    ASSERT_EQ(0, return_contacts.size());

    *done = false;
    *response_code = 0;
    rpcs_[index]->Delete(key, kvs.value, kvs.signature,
                                rpcs_securifier_[index],
                                service_contact_,
                                std::bind(&TestCallback, arg::_1, arg::_2,
                                            done, response_code),
                                transport_type_);
    while (!*done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(transport::kSuccess, *response_code);
    JoinNetworkLookup(service_securifier_);

    return_values.clear();
    return_contacts.clear();
    *done = false;
    *response_code = 0;
    rpcs_[index]->FindValue(key, rpcs_securifier_[index],
                                   service_contact_,
                                   std::bind(&TestFindValueCallback, arg::_1,
                                             arg::_2, arg::_3, arg::_4, arg::_5,
                                             &return_values, &return_contacts,
                                             done, response_code),
                                   transport_type_);
    while (!*done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  // Value deleted
    EXPECT_EQ(transport::kSuccess, *response_code);
    EXPECT_EQ(0, return_values.size());
  }

 protected:
  typedef std::shared_ptr<boost::asio::io_service::work> WorkPtr;

  kademlia::NodeId node_id_;
  std::shared_ptr<RoutingTable> routing_table_;
  std::shared_ptr<DataStore> data_store_;
  AlternativeStorePtr alternative_store_;
  SecurifierPtr service_securifier_;
  std::shared_ptr<Service> service_;
  std::vector<SecurifierPtr> rpcs_securifier_;
  std::vector<IoServicePtr> asio_service_;
  IoServicePtr local_asio_;
  std::vector<std::shared_ptr<Rpcs> > rpcs_;
  std::vector<Contact> rpcs_contact_;
  Contact service_contact_;
  static std::vector<crypto::RsaKeyPair> senders_crypto_key_id2_;
  static crypto::RsaKeyPair receiver_crypto_key_id2_;
  RankInfoPtr rank_info_;
  std::vector<Contact> contacts_;
  TransportPtr transport_;
  MessageHandlerPtr handler_;
  TransportType transport_type_;
  boost::thread_group thread_group_;
  std::vector<WorkPtr> work_;
  WorkPtr work1_;
};

crypto::RsaKeyPair RpcsTest::sender_crypto_key_id_;
crypto::RsaKeyPair RpcsTest::receiver_crypto_key_id_;
std::vector<crypto::RsaKeyPair> RpcsMultiNodesTest::senders_crypto_key_id2_;
crypto::RsaKeyPair RpcsMultiNodesTest::receiver_crypto_key_id2_;

INSTANTIATE_TEST_CASE_P(TransportTypes, RpcsTest,
                        testing::Values(kTcp, kUdp));

INSTANTIATE_TEST_CASE_P(TransportTypes, RpcsMultiNodesTest,
                        testing::Values(kTcp, kUdp));


TEST_P(RpcsMultiNodesTest, BEH_KAD_MultipleClientOperations) {
  bool done[kRpcClientNo];
  int response_code[kRpcClientNo];
  int received_response(0);
  boost::thread_group thread_group;
  int random_op = 0;
  for (int index = 0; index < kRpcClientNo; ++index) {
    done[index] = false;
    response_code[index] = 0;
    random_op = random() % kMaxOps;
    random_op = 0;
    // This is to enable having more than one operation
    switch (random_op) {
      case 0: {
        thread_group.create_thread(
            std::bind(&RpcsMultiNodesTest::RpcOperations, this,
                      index, &done[index], &response_code[index]));
        break;
      }
/*      case 1: {
        thread_group.create_thread(std::bind(&RpcsTest::DeleteRpCOperation,
                                             this, index, done[index],
                                            response_code[index]));
        break;
      }
      case 2: {
        thread_group.create_thread(std::bind(&RpcsTest::FindNodeRpCOperation,
                                             this, index, done[index],
                                            response_code[index]));
        break;
      }*/
    }
  }
  thread_group.join_all();
  for (int index = 0; index < kRpcClientNo; ++index) {
    response_code[0] += response_code[index];
  }
  StopAndReset();
  ASSERT_EQ(0, response_code[0]);
}

TEST_P(RpcsTest, BEH_KAD_PingNoTarget) {
  bool done(false);
  int response_code(0);

  rpcs_->Ping(rpcs_securifier_, rpcs_contact_,
              std::bind(&TestCallback, arg::_1, arg::_2, &done, &response_code),
              transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  StopAndReset();

  ASSERT_GT(0, response_code);
}

TEST_P(RpcsTest, BEH_KAD_PingTarget) {
  bool done(false);
  int response_code(0);

  rpcs_->Ping(rpcs_securifier_, service_contact_,
              std::bind(&TestCallback, arg::_1, arg::_2, &done, &response_code),
              transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  StopAndReset();

  ASSERT_EQ(0, response_code);
}

TEST_P(RpcsTest, BEH_KAD_FindNodesEmptyRT) {
  // tests FindNodes using empty routing table
  bool done(false);
  int response_code(0);
  std::vector<Contact> contact_list;
  Key key = service_contact_.node_id();

  rpcs_->FindNodes(key, rpcs_securifier_, service_contact_,
                   std::bind(&TestFindNodesCallback, arg::_1, arg::_2, arg::_3,
                             &contact_list, &done, &response_code),
                   transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  StopAndReset();

  ASSERT_EQ(0, contact_list.size());
  ASSERT_EQ(0, response_code);
}

TEST_P(RpcsTest, BEH_KAD_FindNodesPopulatedRTnoNode) {
  // tests FindNodes with a populated routing table not containing the node
  // being sought
  bool done(false);
  int response_code(0);
  std::vector<Contact> contact_list;
  PopulateRoutingTable(2*k);
  Key key = service_contact_.node_id();


  rpcs_->FindNodes(key, rpcs_securifier_, service_contact_,
                   std::bind(&TestFindNodesCallback, arg::_1, arg::_2, arg::_3,
                             &contact_list, &done, &response_code),
                   transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  StopAndReset();

  bool found(false);
  std::sort(contact_list.begin(), contact_list.end());
  auto it = contact_list.begin();
  while (it != contact_list.end()) {
    if ((*it).node_id() == service_contact_.node_id())
      found = true;
    for (size_t i = 0; i < contacts_.size(); i++) {
      if ((*it).node_id() == contacts_[i].node_id())
        contacts_.erase(contacts_.begin()+i);
      }
    ++it;
  }
  ASSERT_FALSE(found);
  ASSERT_GE(GetDistance(contact_list, 0), GetDistance(contacts_, 1));
  ASSERT_EQ(k, contact_list.size());
  ASSERT_EQ(0, response_code);
}

TEST_P(RpcsTest, BEH_KAD_FindNodesPopulatedRTwithNode) {
  // tests FindNodes with a populated routing table which contains the node
  // being sought
  bool done(false);
  int response_code(0);
  PopulateRoutingTable(2*k-1);
  std::vector<Contact> contact_list;
  AddContact(routing_table_, service_contact_, rank_info_);
  Key key = service_contact_.node_id();

  rpcs_->FindNodes(key, rpcs_securifier_, service_contact_,
                   std::bind(&TestFindNodesCallback, arg::_1, arg::_2, arg::_3,
                             &contact_list, &done, &response_code),
                   transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  StopAndReset();

  bool found(false);
  auto it = contact_list.begin();
  while (it != contact_list.end()) {
    if ((*it).node_id() == service_contact_.node_id())
      found = true;
    for (size_t i = 0; i < contacts_.size(); i++) {
      if ((*it).node_id() == contacts_[i].node_id())
        contacts_.erase(contacts_.begin()+i);
      }
    ++it;
  }
  ASSERT_TRUE(found);
  ASSERT_GE(GetDistance(contact_list, 0), GetDistance(contacts_, 1));
  ASSERT_EQ(k, contact_list.size());
  ASSERT_EQ(0, response_code);
}

TEST_P(RpcsTest, BEH_KAD_StoreAndFindValue) {
  bool done(false);
  int response_code(0);
  PopulateRoutingTable(2*k);
  Key key = rpcs_contact_.node_id();
  KeyValueSignature kvs = MakeKVS(sender_crypto_key_id_, 1024,
                                  key.String(), "");
  boost::posix_time::seconds ttl(3600);

  // attempt to find value before any stored
  std::vector<std::string> return_values;
  std::vector<Contact> return_contacts;
  done = false;
  response_code = 0;
  rpcs_->FindValue(key, rpcs_securifier_, service_contact_,
                   std::bind(&TestFindValueCallback, arg::_1, arg::_2, arg::_3,
                             arg::_4, arg::_5, &return_values, &return_contacts,
                             &done, &response_code),
                   transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(0, response_code);
  ASSERT_EQ(0, return_values.size());
  ASSERT_EQ(k, return_contacts.size());

  done = false;
  response_code = 0;
  rpcs_->Store(key, kvs.value, kvs.signature, ttl, rpcs_securifier_,
               service_contact_,
               std::bind(&TestCallback, arg::_1, arg::_2, &done,
                         &response_code),
               transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(0, response_code);
  JoinNetworkLookup(service_securifier_);

  // attempt to retrieve value stored
  return_values.clear();
  return_contacts.clear();
  done = false;
  response_code = 0;
  rpcs_->FindValue(key, rpcs_securifier_, service_contact_,
                   std::bind(&TestFindValueCallback, arg::_1, arg::_2, arg::_3,
                             arg::_4, arg::_5, &return_values, &return_contacts,
                             &done, &response_code),
                   transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(0, response_code);
  ASSERT_EQ(kvs.value, return_values[0]);
  ASSERT_EQ(0, return_contacts.size());

  StopAndReset();
}

TEST_P(RpcsTest, BEH_KAD_StoreAndFindAndDeleteValueXXXToBeRemoved) {
  bool done(false);
  int response_code(0);
  PopulateRoutingTable(2*k);
  Key key = rpcs_contact_.node_id();
  KeyValueSignature kvs = MakeKVS(sender_crypto_key_id_, 1024,
                                  key.String(), "");
  boost::posix_time::seconds ttl(3600);

  // attempt to find value before any stored
  std::vector<std::string> return_values;
  std::vector<Contact> return_contacts;
  done = false;
  response_code = 0;
  rpcs_->FindValue(key, rpcs_securifier_, service_contact_,
                   std::bind(&TestFindValueCallback, arg::_1, arg::_2, arg::_3,
                             arg::_4, arg::_5, &return_values, &return_contacts,
                             &done, &response_code),
                   transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(0, response_code);
  ASSERT_EQ(0, return_values.size());
  ASSERT_EQ(k, return_contacts.size());

  done = false;
  response_code = 0;
  rpcs_->Store(key, kvs.value, kvs.signature, ttl, rpcs_securifier_,
               service_contact_,
               std::bind(&TestCallback, arg::_1, arg::_2, &done,
                         &response_code),
               transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(0, response_code);
  JoinNetworkLookup(service_securifier_);

  // attempt to retrieve value stored
  return_values.clear();
  return_contacts.clear();
  done = false;
  response_code = 0;
  rpcs_->FindValue(key, rpcs_securifier_, service_contact_,
                   std::bind(&TestFindValueCallback, arg::_1, arg::_2, arg::_3,
                             arg::_4, arg::_5, &return_values, &return_contacts,
                             &done, &response_code),
                   transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(0, response_code);
  ASSERT_EQ(kvs.value, return_values[0]);
  ASSERT_EQ(0, return_contacts.size());

  rpcs_->Delete(key, kvs.value, kvs.signature, rpcs_securifier_,
                service_contact_, std::bind(&TestCallback, arg::_1, arg::_2,
                                            &done, &response_code),
                transport_type_);

  done = false;
  response_code = 0;
  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  EXPECT_EQ(transport::kSuccess, response_code);
  JoinNetworkLookup(service_securifier_);

  return_values.clear();
  return_contacts.clear();
  done = false;
  response_code = 0;
  rpcs_->FindValue(key, rpcs_securifier_, service_contact_,
                   std::bind(&TestFindValueCallback, arg::_1, arg::_2, arg::_3,
                             arg::_4, arg::_5, &return_values, &return_contacts,
                             &done, &response_code),
                   transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  StopAndReset();
  // Value deleted
  EXPECT_EQ(transport::kSuccess, response_code);
  EXPECT_EQ(0, return_values.size());
  EXPECT_EQ(k, return_contacts.size());
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, data_store_));

  StopAndReset();
}


TEST_P(RpcsTest, BEH_KAD_StoreMalicious) {
  PopulateRoutingTable(2*k);
  bool done(false);
  int response_code(0);
  Key key = rpcs_contact_.node_id();
  boost::posix_time::seconds ttl(3600);
  KeyValueSignature kvs =
      MakeKVS(sender_crypto_key_id_, 1024, key.String(), "");
  AddTestValidation(service_securifier_, rpcs_contact_.node_id().String(),
                    "Different Public Key found on Network Lookup!!");
  // Malicious sender sends fake public_key
  rpcs_->Store(key, kvs.value, kvs.signature, ttl, rpcs_securifier_,
               service_contact_,
               std::bind(&TestCallback, arg::_1, arg::_2,
                         &done, &response_code),
               transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  // Sender receives kSuccess, but value not stored in receiver's datastore
  EXPECT_EQ(transport::kSuccess, response_code);
  JoinNetworkLookup(service_securifier_);

  std::vector<std::string> return_values;
  std::vector<Contact> return_contacts;
  done = false;
  response_code = 0;
  rpcs_->FindValue(key, rpcs_securifier_, service_contact_,
                   std::bind(&TestFindValueCallback, arg::_1, arg::_2, arg::_3,
                             arg::_4, arg::_5, &return_values, &return_contacts,
                             &done, &response_code),
                   transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  // Value not stored in data store
  ASSERT_EQ(0, response_code);
  ASSERT_EQ(0, return_values.size());
  ASSERT_EQ(k, return_contacts.size());
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, data_store_));
  StopAndReset();
}

TEST_P(RpcsTest, BEH_KAD_StoreMultipleRequest) {
  bool done(false);
  Key key = rpcs_contact_.node_id();
  std::vector<KeyValueSignature> kvs_vector;
  std::vector<std::pair<bool, int>> status_response;
  boost::posix_time::seconds ttl(3600);

  for (size_t i = 0; i< 10; ++i) {
    kvs_vector.push_back(MakeKVS(sender_crypto_key_id_, 1024, key.String(),
                                 ""));
    status_response.push_back(std::make_pair(false, -1));
  }
  AddTestValidation(service_securifier_, rpcs_contact_.node_id().String(),
                    sender_crypto_key_id_.public_key());
  std::string signature("");

  for (size_t i = 0; i< 10; ++i) {
    if (i%2)
      signature = "invalid signature";
    else
      signature = kvs_vector[i].signature;
    rpcs_->Store(key, kvs_vector[i].value, signature, ttl, rpcs_securifier_,
                 service_contact_, std::bind(&TestCallback, arg::_1, arg::_2,
                                             &status_response[i].first,
                                             &status_response[i].second),
                 transport_type_);
  }
  while (!done) {
    for (size_t i = 0; i< 10; ++i) {
      done = status_response[i].first;
      if (!done) {
        boost::this_thread::sleep(boost::posix_time::milliseconds(100));
        --i;
      }
    }
  }
  JoinNetworkLookup(service_securifier_);
  StopAndReset();

  // Checking results
  for (int i = 0; i< 10; ++i) {
    EXPECT_EQ(transport::kSuccess, status_response[i].second);
    if (i%2)
      EXPECT_FALSE(IsKeyValueInDataStore(kvs_vector[i], data_store_));
    else
      EXPECT_TRUE(IsKeyValueInDataStore(kvs_vector[i], data_store_));
  }
}

TEST_P(RpcsTest, BEH_KAD_StoreRefresh) {
  PopulateRoutingTable(2*k);
  bool done(false);
  int response_code(0);
  std::vector<std::string> return_values;
  std::vector<Contact> return_contacts;
  Key key = rpcs_contact_.node_id();
  boost::posix_time::seconds ttl(2);
  KeyValueSignature kvs = MakeKVS(sender_crypto_key_id_, 1024,
                                  key.String(), "");
  protobuf::StoreRequest store_request = MakeStoreRequest(rpcs_contact_, kvs);
  std::string message = store_request.SerializeAsString();
  std::string store_message_sig =
      crypto::AsymSign(message, sender_crypto_key_id_.private_key());
  AddTestValidation(service_securifier_, rpcs_contact_.node_id().String(),
                    sender_crypto_key_id_.public_key());

  // send original store request
  rpcs_->Store(key, kvs.value, kvs.signature, ttl, rpcs_securifier_,
               service_contact_, std::bind(&TestCallback, arg::_1, arg::_2,
                                           &done, &response_code),
               transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(0, response_code);
  JoinNetworkLookup(service_securifier_);
  bptime::ptime refresh_time_old = GetRefreshTime(kvs);
  boost::this_thread::sleep(boost::posix_time::seconds(1));

  // send store refresh request
  done = false;
  response_code = 0;
  rpcs_->StoreRefresh(message, store_message_sig, rpcs_securifier_,
                      service_contact_, std::bind(&TestCallback, arg::_1,
                                                  arg::_2, &done,
                                                  &response_code),
                      transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  JoinNetworkLookup(service_securifier_);
  ASSERT_EQ(0, response_code);

  // attempt to find original value
  done = false;
  response_code = 0;
  return_values.clear();
  return_contacts.clear();
  rpcs_->FindValue(key, rpcs_securifier_, service_contact_,
                   std::bind(&TestFindValueCallback, arg::_1, arg::_2, arg::_3,
                             arg::_4, arg::_5, &return_values, &return_contacts,
                             &done, &response_code),
                   transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(0, response_code);
  ASSERT_EQ(kvs.value, return_values[0]);
  ASSERT_EQ(0, return_contacts.size());
  ASSERT_GT(GetRefreshTime(kvs), refresh_time_old);

  // attempt store refresh then find - ttl has expired so refresh should be
  // unsuccessful and find should fail
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  done = false;
  response_code = 0;
  rpcs_->StoreRefresh(message, store_message_sig, rpcs_securifier_,
                      service_contact_,
                      std::bind(&TestCallback, arg::_1, arg::_2, &done,
                                &response_code),
                      transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  JoinNetworkLookup(service_securifier_);
  ASSERT_EQ(0, response_code);

  done = false;
  response_code = 0;
  return_values.clear();
  return_contacts.clear();
  rpcs_->FindValue(key, rpcs_securifier_, service_contact_,
                   std::bind(&TestFindValueCallback, arg::_1, arg::_2, arg::_3,
                             arg::_4, arg::_5, &return_values, &return_contacts,
                             &done, &response_code),
                   transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(0, response_code);
  ASSERT_EQ(0, return_values.size());
  ASSERT_EQ(k, return_contacts.size());
  ASSERT_EQ(0, IsKeyValueInDataStore(kvs, data_store_));

  StopAndReset();
}

TEST_P(RpcsTest, BEH_KAD_StoreRefreshMultipleRequests) {
  bool done(false);
  std::vector<KeyValueSignature> kvs_vector;
  std::vector<std::pair<bool, int>> status_response;
  std::vector<bptime::ptime> refresh_time_old_vector;
  std::vector<RequestAndSignature> req_sig_vector;
  for (size_t i = 0; i< 10; ++i) {
    // Adding key value from different contact in the receiver's datastore
    NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
    kvs_vector.push_back(MakeKVS(sender_crypto_key_id_, 4096, "", ""));
    RequestAndSignature request_signature("", "");
    Contact sender = ComposeContactWithKey(sender_id, 5001,
                                           sender_crypto_key_id_);
    AddToReceiverDataStore(kvs_vector[i], sender_crypto_key_id_, sender,
                           request_signature);
    req_sig_vector.push_back(request_signature);
    ASSERT_TRUE(IsKeyValueInDataStore(kvs_vector[i], data_store_));
    status_response.push_back(std::make_pair(false, -1));
    refresh_time_old_vector.push_back(GetRefreshTime(kvs_vector[i]));
    AddTestValidation(service_securifier_, sender_id.String(),
                      sender_crypto_key_id_.public_key());
  }
  // Store Refresh rpc
  std::string req_signature;
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  for (size_t i = 0; i< 10; ++i) {
    if (i%2)
      req_signature = "Invalid Request Signature";
    else
      req_signature = req_sig_vector[i].second;
    rpcs_->StoreRefresh(req_sig_vector[i].first, req_signature,
                        rpcs_securifier_, service_contact_,
                        std::bind(&TestCallback, arg::_1, arg::_2,
                                  &status_response[i].first,
                                  &status_response[i].second),
                        transport_type_);
  }
  while (!done) {
    for (size_t i = 0; i< 10; ++i) {
      done = status_response[i].first;
      if (!done) {
        boost::this_thread::sleep(boost::posix_time::milliseconds(100));
        --i;
      }
    }
  }
  JoinNetworkLookup(service_securifier_);
  StopAndReset();
  // Check results
  for (size_t i = 0; i< 10; ++i) {
    EXPECT_EQ(0, status_response[i].second);
    EXPECT_TRUE(IsKeyValueInDataStore(kvs_vector[i], data_store_));
    if (i%2)
      EXPECT_EQ(GetRefreshTime(kvs_vector[i]), refresh_time_old_vector[i]);
    else
      EXPECT_GT(GetRefreshTime(kvs_vector[i]), refresh_time_old_vector[i]);
  }
}

TEST_P(RpcsTest, BEH_KAD_StoreRefreshMalicious) {
  PopulateRoutingTable(2*k);
  bool done(false);
  int response_code(0);
  Key key = rpcs_contact_.node_id();
  boost::posix_time::seconds ttl(2);
  KeyValueSignature kvs =
      MakeKVS(sender_crypto_key_id_, 1024, key.String(), "");
  protobuf::StoreRequest store_request = MakeStoreRequest(rpcs_contact_, kvs);
  std::string message = store_request.SerializeAsString();
  std::string store_message_sig =
      crypto::AsymSign(message, sender_crypto_key_id_.private_key());
  AddTestValidation(service_securifier_, rpcs_contact_.node_id().String(),
                    sender_crypto_key_id_.public_key());

  rpcs_->Store(key, kvs.value, kvs.signature, ttl, rpcs_securifier_,
               service_contact_,
               std::bind(&TestCallback, arg::_1, arg::_2,
                         &done, &response_code),
               transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  EXPECT_EQ(0, response_code);
  JoinNetworkLookup(service_securifier_);

  // Attempt refresh with fake key
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  AddTestValidation(service_securifier_, rpcs_contact_.node_id().String(),
                    "Different Public Key found on Network Lookup!!");
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  done = false;
  response_code = 0;
  rpcs_->StoreRefresh(message, store_message_sig, rpcs_securifier_,
                      service_contact_, std::bind(&TestCallback, arg::_1,
                                                  arg::_2, &done,
                                                  &response_code),
                      transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  JoinNetworkLookup(service_securifier_);
  ASSERT_EQ(0, response_code);

  // attempt to find value - refresh should have failed and ttl expired from
  // original store, so no value returned
  std::vector<std::string> return_values;
  std::vector<Contact> return_contacts;
  done = false;
  response_code = 0;
  rpcs_->FindValue(key, rpcs_securifier_, service_contact_,
                   std::bind(&TestFindValueCallback, arg::_1, arg::_2, arg::_3,
                             arg::_4, arg::_5, &return_values, &return_contacts,
                             &done, &response_code),
                   transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(0, response_code);
  ASSERT_EQ(0, return_values.size());
  ASSERT_EQ(k, return_contacts.size());
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, data_store_));

  StopAndReset();
}

TEST_P(RpcsTest, BEH_KAD_Delete) {
  PopulateRoutingTable(2*k);
  bool done(false);
  int response_code(-1);
  Key key = rpcs_contact_.node_id();
  KeyValueSignature kvs =
      MakeKVS(sender_crypto_key_id_, 1024, key.String(), "");
  // Adding key value in the receiver's datastore
  RequestAndSignature request_signature("", "");
  AddToReceiverDataStore(kvs, sender_crypto_key_id_, rpcs_contact_,
                         request_signature);
  ASSERT_TRUE(IsKeyValueInDataStore(kvs, data_store_));
  AddTestValidation(service_securifier_, rpcs_contact_.node_id().String(),
                    sender_crypto_key_id_.public_key());

  rpcs_->Delete(key, kvs.value, kvs.signature, rpcs_securifier_,
                service_contact_, std::bind(&TestCallback, arg::_1, arg::_2,
                                            &done, &response_code),
                transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  EXPECT_EQ(transport::kSuccess, response_code);
  JoinNetworkLookup(service_securifier_);

  std::vector<std::string> return_values;
  std::vector<Contact> return_contacts;
  done = false;
  response_code = 0;
  rpcs_->FindValue(key, rpcs_securifier_, service_contact_,
                   std::bind(&TestFindValueCallback, arg::_1, arg::_2, arg::_3,
                             arg::_4, arg::_5, &return_values, &return_contacts,
                             &done, &response_code),
                   transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  StopAndReset();
  // Value deleted
  EXPECT_EQ(transport::kSuccess, response_code);
  EXPECT_EQ(0, return_values.size());
  EXPECT_EQ(k, return_contacts.size());
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, data_store_));
}

TEST_P(RpcsTest, BEH_KAD_DeleteMalicious) {
  bool done(false);
  int response_code(-1);
  Key key = rpcs_contact_.node_id();
  KeyValueSignature kvs =
      MakeKVS(sender_crypto_key_id_, 1024, key.String(), "");
  // Adding key value in the receiver's datastore
  RequestAndSignature request_signature("", "");
  AddToReceiverDataStore(kvs, sender_crypto_key_id_, rpcs_contact_,
                         request_signature);
  ASSERT_TRUE(IsKeyValueInDataStore(kvs, data_store_));
  AddTestValidation(service_securifier_, rpcs_contact_.node_id().String(),
                    "Different Public Key found on Network Lookup!!");

  // Malicious sender sends fake public_key
  rpcs_->Delete(key, kvs.value, kvs.signature, rpcs_securifier_,
                service_contact_, std::bind(&TestCallback, arg::_1, arg::_2,
                                            &done, &response_code),
                transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  // Sender receives kSuccess, but value not deleted from receiver's datastore
  EXPECT_EQ(transport::kSuccess, response_code);
  JoinNetworkLookup(service_securifier_);
  // attempt to retrieve value stored
  std::vector<std::string> return_values;
  std::vector<Contact> return_contacts;
  return_values.clear();
  return_contacts.clear();
  done = false;
  response_code = -1;
  rpcs_->FindValue(key, rpcs_securifier_, service_contact_,
                   std::bind(&TestFindValueCallback, arg::_1, arg::_2, arg::_3,
                             arg::_4, arg::_5, &return_values, &return_contacts,
                             &done, &response_code),
                   transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  StopAndReset();
  // Value not deleted from data store
  EXPECT_EQ(transport::kSuccess, response_code);
  EXPECT_EQ(kvs.value, return_values[0]);
  EXPECT_EQ(0, return_contacts.size());
  EXPECT_TRUE(IsKeyValueInDataStore(kvs, data_store_));
}

TEST_P(RpcsTest, BEH_KAD_DeleteNonExistingKey) {
  bool done(false);
  int response_code(-1);
  Key key = rpcs_contact_.node_id();
  KeyValueSignature kvs =
      MakeKVS(sender_crypto_key_id_, 1024, key.String(), "");

  ASSERT_FALSE(IsKeyValueInDataStore(kvs, data_store_));
  AddTestValidation(service_securifier_, rpcs_contact_.node_id().String(),
                    sender_crypto_key_id_.public_key());

  rpcs_->Delete(key, kvs.value, kvs.signature, rpcs_securifier_,
                service_contact_, std::bind(&TestCallback, arg::_1, arg::_2,
                                            &done, &response_code),
                transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  StopAndReset();
  EXPECT_NE(transport::kSuccess, response_code);

  JoinNetworkLookup(service_securifier_);
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, data_store_));
}

TEST_P(RpcsTest, BEH_KAD_DeleteMultipleRequest) {
  bool done(false);
  Key key = rpcs_contact_.node_id();
  std::vector<KeyValueSignature> kvs_vector;
  std::vector<std::pair<bool, int>> status_response;

  for (size_t i = 0; i< 10; ++i) {
    kvs_vector.push_back(MakeKVS(sender_crypto_key_id_, 1024, key.String(),
                                 ""));
    status_response.push_back(std::make_pair(false, -1));
    RequestAndSignature request_signature("", "");
    AddToReceiverDataStore(kvs_vector[i], sender_crypto_key_id_, rpcs_contact_,
                           request_signature);
    ASSERT_TRUE(IsKeyValueInDataStore(kvs_vector[i], data_store_));
  }
  AddTestValidation(service_securifier_, rpcs_contact_.node_id().String(),
                    sender_crypto_key_id_.public_key());
  std::string signature("");

  for (size_t i = 0; i< 10; ++i) {
    if (i%2)
      signature = "invalid signature";
    else
      signature = "";
    rpcs_->Delete(key, kvs_vector[i].value, signature, rpcs_securifier_,
                  service_contact_, std::bind(&TestCallback, arg::_1, arg::_2,
                                              &status_response[i].first,
                                              &status_response[i].second),
                  transport_type_);
  }
  while (!done) {
    for (size_t i = 0; i< 10; ++i) {
      done = status_response[i].first;
      if (!done) {
        boost::this_thread::sleep(boost::posix_time::milliseconds(100));
        --i;
      }
    }
  }
  StopAndReset();
  JoinNetworkLookup(service_securifier_);

  // Checking results
  for (int i = 0; i< 10; ++i) {
    EXPECT_EQ(transport::kSuccess, status_response[i].second);
    if (i%2)
      EXPECT_TRUE(IsKeyValueInDataStore(kvs_vector[i], data_store_));
    else
      EXPECT_FALSE(IsKeyValueInDataStore(kvs_vector[i], data_store_));
  }
}

TEST_P(RpcsTest, BEH_KAD_DeleteRefresh) {
  PopulateRoutingTable(2*k);
  bool done(false);
  int response_code(-1);
  // Adding key value from different contact in the receiver's datastore
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(1024);
  Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_data);
  Key key = sender.node_id();
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, key.String(), "");
  RequestAndSignature request_signature("", "");
  AddToReceiverDataStore(kvs, crypto_key_data, sender, request_signature);
  ASSERT_TRUE(IsKeyValueInDataStore(kvs, data_store_));

  AddTestValidation(service_securifier_, sender_id.String(),
                    crypto_key_data.public_key());
  // Deleting
  DeleteFromReceiverDataStore(kvs, crypto_key_data, sender, request_signature);
  ASSERT_FALSE(IsKeyValueInDataStore(kvs, data_store_));
  bptime::ptime refresh_time_old = GetRefreshTime(kvs);

  rpcs_->DeleteRefresh(request_signature.first, request_signature.second,
                       rpcs_securifier_, service_contact_,
                       std::bind(&TestCallback, arg::_1, arg::_2, &done,
                                 &response_code),
                       transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  EXPECT_EQ(transport::kSuccess, response_code);
  JoinNetworkLookup(service_securifier_);

  std::vector<std::string> return_values;
  std::vector<Contact> return_contacts;
  done = false;
  response_code = -1;
  rpcs_->FindValue(key, rpcs_securifier_, service_contact_,
                   std::bind(&TestFindValueCallback, arg::_1, arg::_2, arg::_3,
                             arg::_4, arg::_5, &return_values, &return_contacts,
                             &done, &response_code),
                   transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  StopAndReset();

  EXPECT_EQ(transport::kSuccess, response_code);
  EXPECT_EQ(0, return_values.size());
  EXPECT_EQ(k, return_contacts.size());
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, data_store_));
  // Refreshed
  EXPECT_GT(GetRefreshTime(kvs), refresh_time_old);
}

TEST_P(RpcsTest, BEH_KAD_DeleteRefreshStoredValue) {
  PopulateRoutingTable(2*k);
  bool done(false);
  int response_code(-1);
  // Adding key value from different contact in the receiver's datastore
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(1024);
  Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_data);
  Key key = sender.node_id();
  RequestAndSignature request_sig("", "");
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, key.String(), "");
  AddToReceiverDataStore(kvs, crypto_key_data, sender, request_sig);
  ASSERT_TRUE(IsKeyValueInDataStore(kvs, data_store_));

  AddTestValidation(service_securifier_, sender_id.String(),
                    crypto_key_data.public_key());
  // Value not deleted
  RequestAndSignature request_signature("", "");
  ASSERT_TRUE(IsKeyValueInDataStore(kvs, data_store_));
  bptime::ptime refresh_time_old = GetRefreshTime(kvs);

  // Delete refresh without deleting
  rpcs_->DeleteRefresh(request_signature.first, request_signature.second,
                       rpcs_securifier_, service_contact_,
                       std::bind(&TestCallback, arg::_1, arg::_2, &done,
                                 &response_code),
                       transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  EXPECT_NE(transport::kSuccess, response_code);
  JoinNetworkLookup(service_securifier_);

  std::vector<std::string> return_values;
  std::vector<Contact> return_contacts;
  done = false;
  response_code = -1;
  rpcs_->FindValue(key, rpcs_securifier_, service_contact_,
                   std::bind(&TestFindValueCallback, arg::_1, arg::_2, arg::_3,
                             arg::_4, arg::_5, &return_values, &return_contacts,
                             &done, &response_code),
                   transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  StopAndReset();
  // Value present in data store
  ASSERT_EQ(transport::kSuccess, response_code);
  ASSERT_EQ(kvs.value, return_values[0]);
  ASSERT_EQ(0, return_contacts.size());

  EXPECT_TRUE(IsKeyValueInDataStore(kvs, data_store_));
  // Not Refreshed
  EXPECT_EQ(GetRefreshTime(kvs), refresh_time_old);
}

TEST_P(RpcsTest, BEH_KAD_DeleteRefreshMalicious) {
  bool done(false);
  int response_code(-1);
  // Adding key value from different contact in the receiver's datastore
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(1024);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
  Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_data);
  RequestAndSignature request_signature("", "");
  AddToReceiverDataStore(kvs, crypto_key_data, sender, request_signature);
  ASSERT_TRUE(IsKeyValueInDataStore(kvs, data_store_));

  // Deleting
  DeleteFromReceiverDataStore(kvs, crypto_key_data, sender, request_signature);
  ASSERT_FALSE(IsKeyValueInDataStore(kvs, data_store_));
  bptime::ptime refresh_time_old = GetRefreshTime(kvs);

  AddTestValidation(service_securifier_, sender_id.String(),
                    "Different Public Key found on Network Lookup!!");
  // Malicious sender sends fake public_key
  rpcs_->DeleteRefresh(request_signature.first, request_signature.second,
                       rpcs_securifier_, service_contact_,
                       std::bind(&TestCallback, arg::_1, arg::_2, &done,
                                 &response_code),
                       transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  EXPECT_EQ(transport::kSuccess, response_code);

  StopAndReset();
  JoinNetworkLookup(service_securifier_);
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, data_store_));
  EXPECT_EQ(GetRefreshTime(kvs), refresh_time_old);
}

TEST_P(RpcsTest, BEH_KAD_DeleteRefreshNonExistingKey) {
  bool done(false);
  int response_code(-1);
  // Creating Delete request
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(1024);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
  Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_data);
  protobuf::DeleteRequest delete_request = MakeDeleteRequest(sender, kvs);
  AddTestValidation(service_securifier_, sender_id.String(),
                    crypto_key_data.public_key());
  std::string delete_message = delete_request.SerializeAsString();
  std::string delete_message_sig;
  while (delete_message_sig.empty())
    delete_message_sig = crypto::AsymSign(delete_message,
                                          crypto_key_data.private_key());
  RequestAndSignature request_signature(delete_message, delete_message_sig);
  // Sending delete refresh
  rpcs_->DeleteRefresh(request_signature.first, request_signature.second,
                       rpcs_securifier_, service_contact_,
                       std::bind(&TestCallback, arg::_1, arg::_2, &done,
                                 &response_code),
                       transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  EXPECT_NE(transport::kSuccess, response_code);

  StopAndReset();
  JoinNetworkLookup(service_securifier_);
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, data_store_));
}

TEST_P(RpcsTest, BEH_KAD_DeleteRefreshMultipleRequests) {
  bool done(false);
  std::vector<KeyValueSignature> kvs_vector;
  std::vector<std::pair<bool, int>> status_response;
  std::vector<bptime::ptime> refresh_time_old_vector;
  std::vector<RequestAndSignature> req_sig_vector;
  for (size_t i = 0; i< 10; ++i) {
    // Adding key value from different contact in the receiver's datastore
    NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
    crypto::RsaKeyPair crypto_key_data;
    crypto_key_data.GenerateKeys(1024);
    kvs_vector.push_back(MakeKVS(crypto_key_data, 1024, "", ""));
    Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_data);
    RequestAndSignature request_signature("", "");
    AddToReceiverDataStore(kvs_vector[i], crypto_key_data, sender,
                           request_signature);
    ASSERT_TRUE(IsKeyValueInDataStore(kvs_vector[i], data_store_));
    status_response.push_back(std::make_pair(false, -1));

    // Deleting
    DeleteFromReceiverDataStore(kvs_vector[i], crypto_key_data, sender,
                                request_signature);
    req_sig_vector.push_back(request_signature);
    ASSERT_FALSE(IsKeyValueInDataStore(kvs_vector[i], data_store_));
    refresh_time_old_vector.push_back(GetRefreshTime(kvs_vector[i]));
    AddTestValidation(service_securifier_, sender_id.String(),
                      crypto_key_data.public_key());
  }
  // Delete Refresh rpc
  std::string req_signature;
  for (size_t i = 0; i< 10; ++i) {
    if (i%2)
      req_signature = "Invalid Request Signature";
    else
      req_signature = req_sig_vector[i].second;
    rpcs_->DeleteRefresh(req_sig_vector[i].first, req_signature,
                         rpcs_securifier_, service_contact_,
                         std::bind(&TestCallback, arg::_1, arg::_2,
                                   &status_response[i].first,
                                   &status_response[i].second),
                         transport_type_);
  }
  while (!done) {
    for (size_t i = 0; i< 10; ++i) {
      done = status_response[i].first;
      if (!done) {
        boost::this_thread::sleep(boost::posix_time::milliseconds(100));
        --i;
      }
    }
  }
  StopAndReset();
  JoinNetworkLookup(service_securifier_);
  // Checking results
  for (size_t i = 0; i< 10; ++i) {
    EXPECT_EQ(transport::kSuccess, status_response[i].second);
    EXPECT_FALSE(IsKeyValueInDataStore(kvs_vector[i], data_store_));
    if (i%2)
      EXPECT_EQ(GetRefreshTime(kvs_vector[i]), refresh_time_old_vector[i]);
    else
      EXPECT_GT(GetRefreshTime(kvs_vector[i]), refresh_time_old_vector[i]);
  }
}

}  // namespace test

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe
