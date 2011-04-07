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
#include "maidsafe-dht/transport/udp_transport.h"
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

namespace arg = std::placeholders;

namespace maidsafe {

namespace kademlia {

namespace test {

static const boost::uint16_t k = 16;
const boost::posix_time::milliseconds kNetworkDelay(200);

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

class SecurifierGetPublicKeyAndValidationReceiver: public Securifier {
 public:
  SecurifierGetPublicKeyAndValidationReceiver(const std::string &public_key_id,
                                              const std::string &public_key,
                                              const std::string &private_key)
      : Securifier(public_key_id, public_key, private_key),
        public_key_id_map_(), thread_group_() {}
  // Immitating a non-blocking function
  void GetPublicKeyAndValidation(const std::string &public_key_id,
                                 GetPublicKeyAndValidationCallback callback) {
    thread_group_.add_thread(
        new boost::thread(
                &SecurifierGetPublicKeyAndValidationReceiver::DummyFind, this,
                    public_key_id, callback));
  }

  void Join() {
    thread_group_.join_all();
  }
  // This method will validate the network lookup for given public_key_id
  bool AddTestValidation(const std::string &public_key_id,
                         const std::string &public_key) {
    auto itr = public_key_id_map_.insert(std::make_pair(public_key_id,
                                                        public_key));
    return itr.second;
  }

  void ClearTestValidationMap() {
    public_key_id_map_.erase(public_key_id_map_.begin(),
                             public_key_id_map_.end());
  }

 private:
  void DummyFind(std::string public_key_id,
                 GetPublicKeyAndValidationCallback callback) {
    // Imitating delay in lookup for kNetworkDelay seconds
    boost::this_thread::sleep(boost::posix_time::milliseconds(kNetworkDelay));
    std::map<std::string, std::string>::iterator  itr;
    itr = public_key_id_map_.find(public_key_id);
    if (itr != public_key_id_map_.end())
      callback((*itr).second, "");
    else
      callback("", "");
  }
  std::map<std::string, std::string> public_key_id_map_;
  boost::thread_group thread_group_;
};

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
                    false, node_id.String(), crypto_key.public_key(), "");
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
        new SecurifierGetPublicKeyAndValidationReceiver("",
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
    handler_ = std::shared_ptr<MessageHandler>(
        new MessageHandler(service_securifier_));
    service_->ConnectToSignals(transport_, handler_);
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
      AddContact(contact, rank_info_);
      contacts_.push_back(contact);
    }
  }

  void AddContact(const Contact& contact, const RankInfoPtr rank_info) {
    routing_table_->AddContact(contact, rank_info);
    routing_table_->SetValidated(contact.node_id(), true);
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
    std::string signature;
    while (signature.empty())
      signature = crypto::AsymSign(value, rsa_key_pair.private_key());
    return KeyValueSignature(key, value, signature);
  }

  protobuf::StoreRequest MakeStoreRequest(const Contact& sender,
                                          const KeyValueSignature& kvs) {
    protobuf::StoreRequest store_request;
    store_request.mutable_sender()->CopyFrom(ToProtobuf(sender));
    store_request.set_key(kvs.key);
    store_request.mutable_signed_value()->set_signature(kvs.signature);
    store_request.mutable_signed_value()->set_value(kvs.value);
    store_request.set_ttl(3600*24);
    return store_request;
  }

  protobuf::DeleteRequest MakeDeleteRequest(const Contact& sender,
                                            const KeyValueSignature& kvs) {
    protobuf::DeleteRequest delete_request;
    delete_request.mutable_sender()->CopyFrom(ToProtobuf(sender));
    delete_request.set_key(kvs.key);
    delete_request.mutable_signed_value()->set_signature(kvs.signature);
    delete_request.mutable_signed_value()->set_value(kvs.value);
    return delete_request;
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

  bool AddTestValidation(std::string public_key_id, std::string public_key) {
    SecurifierGPKPtr securifier_gpkv = std::static_pointer_cast
        <SecurifierGetPublicKeyAndValidationReceiver>(service_securifier_);
    return securifier_gpkv->AddTestValidation(public_key_id, public_key);
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

  void JoinNetworkLookup() {
    SecurifierGPKPtr securifier_gpkv = std::static_pointer_cast
        <SecurifierGetPublicKeyAndValidationReceiver>(service_securifier_);
    securifier_gpkv->Join();
  }

  void StopAndReset() {
    asio_service_->stop();
    local_asio_->stop();
    work_.reset();
    work1_.reset();
    thread_group_.join_all();
  }

 protected:
  typedef std::shared_ptr<SecurifierGetPublicKeyAndValidationReceiver>
              SecurifierGPKPtr;
  typedef std::shared_ptr<boost::asio::io_service::work> WorkPtr;

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
  std::vector<Contact> contacts_;
  TransportPtr transport_;
  MessageHandlerPtr handler_;
  TransportType transport_type_;
  boost::thread_group thread_group_;
  WorkPtr work_;
  WorkPtr work1_;
};

crypto::RsaKeyPair RpcsTest::sender_crypto_key_id_;
crypto::RsaKeyPair RpcsTest::receiver_crypto_key_id_;

INSTANTIATE_TEST_CASE_P(TransportTypes, RpcsTest,
                        testing::Values(kTcp, kUdp));

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
  AddContact(service_contact_, rank_info_);
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
  JoinNetworkLookup();

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

TEST_P(RpcsTest, BEH_KAD_StoreMalicious) {
  PopulateRoutingTable(2*k);
  bool done(false);
  int response_code(0);
  Key key = rpcs_contact_.node_id();
  boost::posix_time::seconds ttl(3600);
  KeyValueSignature kvs =
      MakeKVS(sender_crypto_key_id_, 1024, key.String(), "");
  AddTestValidation(rpcs_contact_.node_id().String(),
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
  JoinNetworkLookup();

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
  AddTestValidation(rpcs_contact_.node_id().String(),
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
  JoinNetworkLookup();
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
  AddTestValidation(rpcs_contact_.node_id().String(),
                    sender_crypto_key_id_.public_key());

  // send original store request
  rpcs_->Store(key, kvs.value, kvs.signature, ttl, rpcs_securifier_,
               service_contact_, std::bind(&TestCallback, arg::_1, arg::_2,
                                           &done, &response_code),
               transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(0, response_code);
  JoinNetworkLookup();
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
  JoinNetworkLookup();
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
  JoinNetworkLookup();
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
    AddTestValidation(sender_id.String(), sender_crypto_key_id_.public_key());
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
  JoinNetworkLookup();
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
  AddTestValidation(rpcs_contact_.node_id().String(),
                    sender_crypto_key_id_.public_key());

  rpcs_->Store(key, kvs.value, kvs.signature, ttl, rpcs_securifier_,
               service_contact_,
               std::bind(&TestCallback, arg::_1, arg::_2,
                         &done, &response_code),
               transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  EXPECT_EQ(0, response_code);
  JoinNetworkLookup();

  // Attempt refresh with fake key
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  AddTestValidation(rpcs_contact_.node_id().String(),
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
  JoinNetworkLookup();
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
  AddTestValidation(rpcs_contact_.node_id().String(),
                    sender_crypto_key_id_.public_key());

  rpcs_->Delete(key, kvs.value, kvs.signature, rpcs_securifier_,
                service_contact_, std::bind(&TestCallback, arg::_1, arg::_2,
                                            &done, &response_code),
                transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  EXPECT_EQ(transport::kSuccess, response_code);
  JoinNetworkLookup();

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
  AddTestValidation(rpcs_contact_.node_id().String(),
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
  JoinNetworkLookup();
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
  AddTestValidation(rpcs_contact_.node_id().String(),
                    sender_crypto_key_id_.public_key());

  rpcs_->Delete(key, kvs.value, kvs.signature, rpcs_securifier_,
                service_contact_, std::bind(&TestCallback, arg::_1, arg::_2,
                                            &done, &response_code),
                transport_type_);

  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  StopAndReset();
  EXPECT_NE(transport::kSuccess, response_code);

  JoinNetworkLookup();
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
  AddTestValidation(rpcs_contact_.node_id().String(),
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
  JoinNetworkLookup();

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

  AddTestValidation(sender_id.String(), crypto_key_data.public_key());
  // Deleting
//   RequestAndSignature request_signature("", "");
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
  JoinNetworkLookup();

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

  AddTestValidation(sender_id.String(), crypto_key_data.public_key());
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
  JoinNetworkLookup();

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

  AddTestValidation(sender_id.String(),
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
  JoinNetworkLookup();
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
  AddTestValidation(sender_id.String(), crypto_key_data.public_key());
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
  JoinNetworkLookup();
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
    AddTestValidation(sender_id.String(), crypto_key_data.public_key());
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
  JoinNetworkLookup();
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

}  // namespace maidsafe
