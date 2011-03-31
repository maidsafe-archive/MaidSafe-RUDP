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
const boost::posix_time::milliseconds kNetworkDelay(200);

void TestPingCallback(RankInfoPtr,  // Todo: @Prakash rename after merging
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

class SecurifierGetPublicKeyAndValidationReciever: public Securifier {
 public:
  SecurifierGetPublicKeyAndValidationReciever(const std::string &public_key_id,
                                              const std::string &public_key,
                                              const std::string &private_key)
      : Securifier(public_key_id, public_key, private_key),
        public_key_id_map_(), thread_group_() {}
  // Immitating a non-blocking function
  void GetPublicKeyAndValidation(const std::string &public_key_id,
                                 GetPublicKeyAndValidationCallback callback) {
    thread_group_.add_thread(
        new boost::thread(
                &SecurifierGetPublicKeyAndValidationReciever::DummyFind, this,
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
        new SecurifierGetPublicKeyAndValidationReciever("",
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

  protobuf::StoreRequest MakeStoreRequest(const Contact& sender,
      const KeyValueSignature& kvs, const crypto::RsaKeyPair& crypto_key_data) {
    protobuf::StoreRequest store_request;
    store_request.mutable_sender()->CopyFrom(ToProtobuf(sender));
    store_request.set_key(kvs.key);
    store_request.mutable_signed_value()->set_signature(kvs.signature);
    store_request.mutable_signed_value()->set_value(kvs.value);
    store_request.set_ttl(3600*24);
    store_request.set_signing_public_key_id(
        crypto::Hash<crypto::SHA512>(crypto_key_data.public_key() +
            crypto::AsymSign(crypto_key_data.public_key(),
                             crypto_key_data.private_key())));
    return store_request;
  }

  protobuf::DeleteRequest MakeDeleteRequest(const Contact& sender,
                            const KeyValueSignature& kvs,
                            const crypto::RsaKeyPair& crypto_key_data) {
    protobuf::DeleteRequest delete_request;
    delete_request.mutable_sender()->CopyFrom(ToProtobuf(sender));
    delete_request.set_key(kvs.key);
    delete_request.mutable_signed_value()->set_signature(kvs.signature);
    delete_request.mutable_signed_value()->set_value(kvs.value);
    delete_request.set_signing_public_key_id(
        crypto::Hash<crypto::SHA512>(crypto_key_data.public_key() +
            crypto::AsymSign(crypto_key_data.public_key(),
                            crypto_key_data.private_key())));
    return delete_request;
  }

  void AddToRecieverDataStore(const KeyValueSignature& kvs,
                              const crypto::RsaKeyPair& crypto_key_data,
                              const Contact& contact) {
    protobuf::StoreRequest store_request = MakeStoreRequest(contact, kvs,
                                                            crypto_key_data);
    std::string store_message = store_request.SerializeAsString();
    std::string store_message_sig =
        crypto::AsymSign(store_message, crypto_key_data.private_key());
    RequestAndSignature request_signature(store_message, store_message_sig);
    bptime::time_duration ttl(bptime::pos_infin);
    EXPECT_TRUE(data_store_->StoreValue(kvs, ttl, request_signature,
                                        crypto_key_data.public_key(),
                                        false));
  }

  void DeleteFromRecieverDataStore(const KeyValueSignature& kvs,
                                   const crypto::RsaKeyPair& crypto_key_data,
                                   const Contact& contact,
                                   RequestAndSignature& request_signature) {
    protobuf::DeleteRequest delete_request = MakeDeleteRequest(contact, kvs,
                                                               crypto_key_data);
    std::string delete_message = delete_request.SerializeAsString();
    std::string delete_message_sig =
        crypto::AsymSign(delete_message, crypto_key_data.private_key());
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

  bool AddTestValidation(std::string public_key_id, std::string public_key) {
    SecurifierGPKPtr securifier_gpkv = std::static_pointer_cast
        <SecurifierGetPublicKeyAndValidationReciever>(service_securifier_);
    return securifier_gpkv->AddTestValidation(public_key_id, public_key);
  }

  void JoinNetworkLookup() {
    SecurifierGPKPtr securifier_gpkv = std::static_pointer_cast
        <SecurifierGetPublicKeyAndValidationReciever>(service_securifier_);
    securifier_gpkv->Join();
  }

 protected:
  typedef std::shared_ptr<SecurifierGetPublicKeyAndValidationReciever>
              SecurifierGPKPtr;

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

  rpcs_->Ping(rpcs_securifier_, service_contact_,
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

  rpcs_->FindNodes(key, rpcs_securifier_, service_contact_,
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
  TransportPtr transport(new transport::TcpTransport(*local_asio_));
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

  rpcs_->FindNodes(key, rpcs_securifier_, service_contact_,
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

  rpcs_->FindNodes(key, rpcs_securifier_, service_contact_,
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

TEST_F(RpcsTest, BEH_KAD_Delete) {
  TransportPtr transport(new transport::TcpTransport(*local_asio_));
  MessageHandlerPtr handler(new MessageHandler(service_securifier_));
  service_->ConnectToSignals(transport, handler);
  transport->StartListening(service_contact_.endpoint());
  boost::thread th(boost::bind(&RpcsTest::ListenPort, this));
  bool done(false);
  int response_code(-1);
  Key key = rpcs_contact_.node_id();
  KeyValueSignature kvs =
      MakeKVS(sender_crypto_key_id_, 1024, key.String(), "");
  // Adding key value in the reciever's datastore
  AddToRecieverDataStore(kvs, sender_crypto_key_id_, rpcs_contact_);
  ASSERT_TRUE(IsKeyValueInDataStore(kvs, data_store_));
  AddTestValidation(rpcs_contact_.node_id().String(),
                    sender_crypto_key_id_.public_key());
  rpcs_->Delete(key, kvs.value, kvs.signature, rpcs_securifier_,
                service_contact_, boost::bind(&TestPingCallback, _1, _2, &done,
                                              &response_code), kTcp);
  asio_service_->run();
  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  EXPECT_EQ(transport::kSuccess, response_code);
  asio_service_->stop();
  local_asio_->stop();
  th.join();
  JoinNetworkLookup();

  EXPECT_FALSE(IsKeyValueInDataStore(kvs, data_store_));
}

TEST_F(RpcsTest, BEH_KAD_DeleteMalicious) {
  TransportPtr transport(new transport::TcpTransport(*local_asio_));
  MessageHandlerPtr handler(new MessageHandler(service_securifier_));
  service_->ConnectToSignals(transport, handler);
  transport->StartListening(service_contact_.endpoint());
  boost::thread th(boost::bind(&RpcsTest::ListenPort, this));
  bool done(false);
  int response_code(-1);
  Key key = rpcs_contact_.node_id();
  KeyValueSignature kvs =
      MakeKVS(sender_crypto_key_id_, 1024, key.String(), "");
  // Adding key value in the reciever's datastore
  AddToRecieverDataStore(kvs, sender_crypto_key_id_, rpcs_contact_);
  ASSERT_TRUE(IsKeyValueInDataStore(kvs, data_store_));
  AddTestValidation(rpcs_contact_.node_id().String(),
                    "Different Public Key found on Network Lookup!!");
  // Malicious sender sends fake public_key
  rpcs_->Delete(key, kvs.value, kvs.signature, rpcs_securifier_,
                service_contact_, boost::bind(&TestPingCallback, _1, _2, &done,
                                              &response_code), kTcp);
  asio_service_->run();
  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  // Sender recieves kSuccess, but value not deleted from reciever's datastore
  EXPECT_EQ(transport::kSuccess, response_code);
  asio_service_->stop();
  local_asio_->stop();
  th.join();
  JoinNetworkLookup();
  // Value not deleted from data store
  EXPECT_TRUE(IsKeyValueInDataStore(kvs, data_store_));
}

TEST_F(RpcsTest, BEH_KAD_DeleteNonExistingKey) {
  TransportPtr transport(new transport::TcpTransport(*local_asio_));
  MessageHandlerPtr handler(new MessageHandler(service_securifier_));
  service_->ConnectToSignals(transport, handler);
  transport->StartListening(service_contact_.endpoint());
  boost::thread th(boost::bind(&RpcsTest::ListenPort, this));
  bool done(false);
  int response_code(-1);
  Key key = rpcs_contact_.node_id();
  KeyValueSignature kvs =
      MakeKVS(sender_crypto_key_id_, 1024, key.String(), "");

  ASSERT_FALSE(IsKeyValueInDataStore(kvs, data_store_));
  AddTestValidation(rpcs_contact_.node_id().String(),
                    sender_crypto_key_id_.public_key());

  rpcs_->Delete(key, kvs.value, kvs.signature, rpcs_securifier_,
                service_contact_, boost::bind(&TestPingCallback, _1, _2, &done,
                                              &response_code), kTcp);
  asio_service_->run();
  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  EXPECT_NE(transport::kSuccess, response_code);
  asio_service_->stop();
  local_asio_->stop();
  th.join();
  JoinNetworkLookup();

  EXPECT_FALSE(IsKeyValueInDataStore(kvs, data_store_));
}

TEST_F(RpcsTest, BEH_KAD_DeleteMultipleRequest) {
  TransportPtr transport(new transport::TcpTransport(*local_asio_));
  MessageHandlerPtr handler(new MessageHandler(service_securifier_));
  service_->ConnectToSignals(transport, handler);
  transport->StartListening(service_contact_.endpoint());
  boost::thread th(boost::bind(&RpcsTest::ListenPort, this));
  bool done(false);
  Key key = rpcs_contact_.node_id();
  std::vector<KeyValueSignature> kvs_vector;
  std::vector<std::pair<bool, int>> status_response;

  for (size_t i = 0; i< 10; ++i) {
    kvs_vector.push_back(MakeKVS(sender_crypto_key_id_, 1024, key.String(),
                                 ""));
    status_response.push_back(std::make_pair(false, -1));
    AddToRecieverDataStore(kvs_vector[i], sender_crypto_key_id_, rpcs_contact_);
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
    rpcs_->Delete(key, kvs_vector[i].value, signature,
        rpcs_securifier_, service_contact_, boost::bind(&TestPingCallback,
            _1, _2, &status_response[i].first, &status_response[i].second),
                kTcp);
  }
  asio_service_->run();
  while (!done) {
    for (size_t i = 0; i< 10; ++i) {
      done = status_response[i].first;
      if (!done) {
        boost::this_thread::sleep(boost::posix_time::milliseconds(100));
        --i;
      }
    }
  }
  asio_service_->stop();
  local_asio_->stop();
  th.join();
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

TEST_F(RpcsTest, BEH_KAD_DeleteRefresh) {
  TransportPtr transport(new transport::TcpTransport(*local_asio_));
  MessageHandlerPtr handler(new MessageHandler(service_securifier_));
  service_->ConnectToSignals(transport, handler);
  transport->StartListening(service_contact_.endpoint());
  boost::thread th(boost::bind(&RpcsTest::ListenPort, this));
  bool done(false);
  int response_code(-1);

  // Adding key value from different contact in the reciever's datastore
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(1024);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
  Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_data);
  AddToRecieverDataStore(kvs, crypto_key_data, sender);
  ASSERT_TRUE(IsKeyValueInDataStore(kvs, data_store_));

  AddTestValidation(sender_id.String(), crypto_key_data.public_key());
  // Deleting
  RequestAndSignature request_signature("", "");
  DeleteFromRecieverDataStore(kvs, crypto_key_data, sender, request_signature);
  ASSERT_FALSE(IsKeyValueInDataStore(kvs, data_store_));
  bptime::ptime refresh_time_old = GetRefreshTime(kvs);

  rpcs_->DeleteRefresh(request_signature.first, request_signature.second,
      rpcs_securifier_, service_contact_, boost::bind(&TestPingCallback, _1, _2,
          &done, &response_code), kTcp);
  asio_service_->run();
  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  EXPECT_EQ(transport::kSuccess, response_code);

  asio_service_->stop();
  local_asio_->stop();
  th.join();
  JoinNetworkLookup();

  EXPECT_FALSE(IsKeyValueInDataStore(kvs, data_store_));
  EXPECT_GT(GetRefreshTime(kvs), refresh_time_old);
}

TEST_F(RpcsTest, BEH_KAD_DeleteRefreshMalicious) {
  TransportPtr transport(new transport::TcpTransport(*local_asio_));
  MessageHandlerPtr handler(new MessageHandler(service_securifier_));
  service_->ConnectToSignals(transport, handler);
  transport->StartListening(service_contact_.endpoint());
  boost::thread th(boost::bind(&RpcsTest::ListenPort, this));
  bool done(false);
  int response_code(-1);

  // Adding key value from different contact in the reciever's datastore
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(1024);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
  Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_data);
  AddToRecieverDataStore(kvs, crypto_key_data, sender);
  ASSERT_TRUE(IsKeyValueInDataStore(kvs, data_store_));

  // Deleting
  RequestAndSignature request_signature("", "");
  DeleteFromRecieverDataStore(kvs, crypto_key_data, sender, request_signature);
  ASSERT_FALSE(IsKeyValueInDataStore(kvs, data_store_));
  bptime::ptime refresh_time_old = GetRefreshTime(kvs);

  AddTestValidation(sender_id.String(),
                    "Different Public Key found on Network Lookup!!");
  // Malicious sender sends fake public_key
  rpcs_->DeleteRefresh(request_signature.first, request_signature.second,
      rpcs_securifier_, service_contact_, boost::bind(&TestPingCallback, _1, _2,
          &done, &response_code), kTcp);
  asio_service_->run();
  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  EXPECT_EQ(transport::kSuccess, response_code);

  asio_service_->stop();
  local_asio_->stop();
  th.join();
  JoinNetworkLookup();
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, data_store_));
  EXPECT_EQ(GetRefreshTime(kvs), refresh_time_old);
}

TEST_F(RpcsTest, BEH_KAD_DeleteRefreshNonExistingKey) {
  TransportPtr transport(new transport::TcpTransport(*local_asio_));
  MessageHandlerPtr handler(new MessageHandler(service_securifier_));
  service_->ConnectToSignals(transport, handler);
  transport->StartListening(service_contact_.endpoint());
  boost::thread th(boost::bind(&RpcsTest::ListenPort, this));
  bool done(false);
  int response_code(-1);
  // Creating Delete request
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(1024);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
  Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_data);
  protobuf::DeleteRequest delete_request = MakeDeleteRequest(sender, kvs,
                                                             crypto_key_data);
  AddTestValidation(sender_id.String(), crypto_key_data.public_key());
  std::string delete_message = delete_request.SerializeAsString();
  std::string delete_message_sig =
        crypto::AsymSign(delete_message, crypto_key_data.private_key());
  RequestAndSignature request_signature(delete_message, delete_message_sig);
  // Sending delete refresh
  rpcs_->DeleteRefresh(request_signature.first, request_signature.second,
      rpcs_securifier_, service_contact_, boost::bind(&TestPingCallback, _1, _2,
          &done, &response_code), kTcp);
  asio_service_->run();
  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  EXPECT_NE(transport::kSuccess, response_code);

  asio_service_->stop();
  local_asio_->stop();
  th.join();
  JoinNetworkLookup();
  EXPECT_FALSE(IsKeyValueInDataStore(kvs, data_store_));
}

TEST_F(RpcsTest, BEH_KAD_DeleteRefreshMultipleRequests) {
  TransportPtr transport(new transport::TcpTransport(*local_asio_));
  MessageHandlerPtr handler(new MessageHandler(service_securifier_));
  service_->ConnectToSignals(transport, handler);
  transport->StartListening(service_contact_.endpoint());
  boost::thread th(boost::bind(&RpcsTest::ListenPort, this));
  bool done(false);
  int response_code(-1);
  std::vector<KeyValueSignature> kvs_vector;
  std::vector<std::pair<bool, int>> status_response;
  std::vector<bptime::ptime> refresh_time_old_vector;
  std::vector<RequestAndSignature> req_sig_vector;
  for (size_t i = 0; i< 10; ++i) {
    // Adding key value from different contact in the reciever's datastore
    NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
    crypto::RsaKeyPair crypto_key_data;
    crypto_key_data.GenerateKeys(1024);
    kvs_vector.push_back(MakeKVS(crypto_key_data, 1024, "", ""));
    Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_data);
    AddToRecieverDataStore(kvs_vector[i], crypto_key_data, sender);
    ASSERT_TRUE(IsKeyValueInDataStore(kvs_vector[i], data_store_));
    status_response.push_back(std::make_pair(false, -1));

    // Deleting
    RequestAndSignature request_signature("", "");
    DeleteFromRecieverDataStore(kvs_vector[i], crypto_key_data, sender,
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
                         boost::bind(&TestPingCallback, _1, _2, &done,
                                     &response_code),
                         kTcp);
  }
  asio_service_->run();
  while (!done) {
    for (size_t i = 0; i< 10; ++i) {
      done = status_response[i].first;
      if (!done) {
        boost::this_thread::sleep(boost::posix_time::milliseconds(100));
        --i;
      }
    }
  }
  asio_service_->stop();
  local_asio_->stop();
  th.join();
  JoinNetworkLookup();
  // Checking results
  for (size_t i = 0; i< 10; ++i) {
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
