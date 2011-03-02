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
#include <utility>
#include <bitset>

#include "gtest/gtest.h"
#include "boost/lexical_cast.hpp"

#include "maidsafe-dht/kademlia/alternative_store.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-dht/kademlia/securifier.h"
#include "maidsafe-dht/kademlia/datastore.h"
#include "maidsafe-dht/kademlia/service.h"
#include "maidsafe-dht/kademlia/routing_table.h"
#include "maidsafe-dht/kademlia/rpcs.pb.h"
#include "maidsafe-dht/kademlia/utils.h"
#include "maidsafe-dht/transport/transport.h"

// #include "maidsafe-dht/tests/kademlia/fake_callbacks.h"

namespace maidsafe {

namespace kademlia {

namespace test {

static const boost::uint16_t k = 16;

inline void CreateRSAKeys(std::string *pub_key, std::string *priv_key) {
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  *pub_key =  kp.public_key();
  *priv_key = kp.private_key();
}

class SecurifierValidateFalse: public Securifier {
 public:
  SecurifierValidateFalse(const std::string &public_key_id,
                          const std::string &public_key,
                          const std::string &private_key) :
      Securifier(public_key_id, public_key, private_key) {}

  bool Validate(const std::string &value,
                const std::string &value_signature,
                const std::string &public_key_id,
                const std::string &public_key,
                const std::string &public_key_validation,
                const std::string &kademlia_key) const {
    return false;
  }
};

class AlternativeStoreTrue: public AlternativeStore {
 public:
  virtual ~AlternativeStoreTrue() {}
  virtual bool Has(const std::string &key) {
    return true;
  }
};

class AlternativeStoreFalse: public AlternativeStore {
 public:
  virtual ~AlternativeStoreFalse() {}
  virtual bool Has(const std::string &key) {
    return false;
  }
};

typedef std::shared_ptr<AlternativeStoreTrue> AlternativeStoreTruePtr;
typedef std::shared_ptr<AlternativeStoreFalse> AlternativeStoreFalsePtr;

class ServicesTest: public testing::Test {
 public:
  ServicesTest() : contact_(), node_id_(NodeId::kRandomId),
                   data_store_(new kademlia::DataStore(bptime::seconds(3600))),
                   routing_table_(new RoutingTable(node_id_, test::k)),
                   alternative_store_(),
                   securifier_(new Securifier("", "", "")),
                   info_(), rank_info_(),
                   service_(new Service(routing_table_, data_store_,
                   alternative_store_, securifier_)),
                   num_of_pings_(0) {
    service_->set_node_joined(true);
  }

  virtual void SetUp() {
  }

  NodeId GenerateUniqueRandomId(const NodeId& holder, const int& pos) {
    std::string holder_id = holder.ToStringEncoded(NodeId::kBinary);
    std::bitset<kKeySizeBits> holder_id_binary_bitset(holder_id);
    NodeId new_node;
    std::string new_node_string;
    bool repeat(true);
    boost::uint16_t times_of_try(0);
    // generate a random ID and make sure it has not been geneated previously
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

  KeyValueTuple MakeKVT(const crypto::RsaKeyPair &rsa_key_pair,
                        const size_t &value_size,
                        const bptime::time_duration &ttl,
                        std::string key,
                        std::string value) {
    KeyValueSignature kvs = MakeKVS(rsa_key_pair, value_size, key, value);
    bptime::ptime now = bptime::microsec_clock::universal_time();
    bptime::ptime expire_time = now + ttl;
    bptime::ptime refresh_time = now + bptime::minutes(30);
    std::string request = RandomString(1024);
    std::string req_sig = crypto::AsymSign(request, rsa_key_pair.private_key());
    return KeyValueTuple(kvs, expire_time, refresh_time,
                         RequestAndSignature(request, req_sig), false);
  }

  protobuf::StoreRequest MakeStoreRequest(const Contact& sender,
                            const KeyValueSignature& kvs,
                            const crypto::RsaKeyPair& crypto_key_data) {
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

  void FakePingContact(Contact contact) {
    ++num_of_pings_;
  }

  void Clear() {
    routing_table_->Clear();
    data_store_->key_value_index_->clear();
    num_of_pings_ = 0;
  }

  virtual void TearDown() {}

 protected:
  Contact ComposeContact(const NodeId& node_id, boost::uint16_t port) {
    std::string ip("127.0.0.1");
    std::vector<transport::Endpoint> local_endpoints;
    transport::Endpoint end_point(ip, port);
    local_endpoints.push_back(end_point);
    Contact contact(node_id, end_point, local_endpoints, end_point, false,
                    false, "", "", "");
    return contact;
  }

  Contact ComposeContactWithKey(const NodeId& node_id, boost::uint16_t port,
                                const crypto::RsaKeyPair& crypto_key) {
    std::string ip("127.0.0.1");
    std::vector<transport::Endpoint> local_endpoints;
    transport::Endpoint end_point(ip, port);
    local_endpoints.push_back(end_point);
    Contact contact(node_id, end_point, local_endpoints, end_point, false,
                    false, node_id.String(), crypto_key.public_key(), "");
    return contact;
  }

  void PopulateDataStore(boost::uint16_t count) {
    bptime::time_duration old_ttl(bptime::pos_infin);
    crypto::RsaKeyPair crypto_key;
    crypto_key.GenerateKeys(1024);
    for (int i = 0; i < count; ++i) {
      KeyValueTuple cur_kvt = MakeKVT(crypto_key, 1024, old_ttl, "", "");
      EXPECT_TRUE(data_store_->StoreValue(cur_kvt.key_value_signature, old_ttl,
          cur_kvt.request_and_signature, crypto_key.public_key(), false));
    }
  }

  void PopulateRoutingTable(boost::uint16_t count) {
    for (int num_contact = 0; num_contact < count; ++num_contact) {
      NodeId contact_id(NodeId::kRandomId);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(contact, rank_info_);
    }
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

  size_t GetRoutingTableSize() const {
    return routing_table_->Size();
  }

  size_t CountUnValidatedContacts() const {
    return routing_table_->unvalidated_contacts_.size();
  }

  size_t GetDataStoreSize() const {
    return data_store_->key_value_index_->size();
  }

  Contact contact_;
  kademlia::NodeId node_id_;
  std::shared_ptr<DataStore> data_store_;
  std::shared_ptr<RoutingTable> routing_table_;
  AlternativeStorePtr alternative_store_;
  SecurifierPtr securifier_;
  transport::Info info_;
  RankInfoPtr rank_info_;
  std::shared_ptr<Service> service_;
  int num_of_pings_;
};

TEST_F(ServicesTest, BEH_KAD_Store) {
  crypto::RsaKeyPair crypto_key_id;
  crypto_key_id.GenerateKeys(1024);
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_id);

  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(1024);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");

  protobuf::StoreRequest store_request = MakeStoreRequest(sender, kvs,
                                                          crypto_key_data);

  std::string message = store_request.SerializeAsString();
  std::string message_sig = crypto::AsymSign(message,
                                             crypto_key_data.private_key());
  RequestAndSignature request_signature(message, message_sig);
  bptime::time_duration old_ttl(bptime::pos_infin);

  {
    // Try to store with empty message and mesaage_sig
    // into empty datastore and empty routingtable
    std::string message_empty;
    std::string message_sig_empty;

    protobuf::StoreResponse store_response;
    service_->Store(info_, store_request, message_empty,
                  message_sig_empty, &store_response);
    EXPECT_FALSE(store_response.result());
    ASSERT_EQ(0U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to store an in-valid tuple
    // into empty datastore and empty routingtable
    SecurifierPtr securifier_local(new SecurifierValidateFalse(
    sender.public_key_id(), sender.public_key(), sender.other_info()));
    Service service(routing_table_, data_store_,
                    alternative_store_, securifier_local);
    service.set_node_joined(true);

    protobuf::StoreResponse store_response;
    service.Store(info_, store_request, message, message_sig, &store_response);
    EXPECT_FALSE(store_response.result());
    ASSERT_EQ(0U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to store a validated tuple
    // into empty datastore, but the routingtable already contains the sender
    AddContact(sender, rank_info_);
    ASSERT_EQ(1U, GetRoutingTableSize());

    protobuf::StoreResponse store_response;
    service_->Store(info_, store_request, message, message_sig,
                    &store_response);
    EXPECT_TRUE(store_response.result());
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(1U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to store a validated tuple, into the datastore already containing it
    EXPECT_TRUE(data_store_->StoreValue(kvs, old_ttl, request_signature,
                                        crypto_key_data.public_key(), false));
    ASSERT_EQ(1U, GetDataStoreSize());

    protobuf::StoreResponse store_response;
    service_->Store(info_, store_request, message, message_sig,
                    &store_response);
    EXPECT_TRUE(store_response.result());
    ASSERT_EQ(1U, GetDataStoreSize());
    // the sender will be pushed into the unvalidated_contacts list
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
}

TEST_F(ServicesTest, BEH_KAD_Delete) {
  crypto::RsaKeyPair crypto_key_id;
  crypto_key_id.GenerateKeys(1024);
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_id);

  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(1024);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");

  protobuf::StoreRequest store_request = MakeStoreRequest(sender, kvs,
                                                          crypto_key_data);
  std::string store_message = store_request.SerializeAsString();
  std::string store_message_sig = crypto::AsymSign(store_message,
                                      crypto_key_data.private_key());

  protobuf::DeleteRequest delete_request = MakeDeleteRequest(sender, kvs,
                                                             crypto_key_data);
  std::string delete_message = delete_request.SerializeAsString();
  std::string delete_message_sig = crypto::AsymSign(delete_message,
                                       crypto_key_data.private_key());
  RequestAndSignature request_signature(delete_message, delete_message_sig);
  bptime::time_duration old_ttl(bptime::pos_infin);

  {
    // Try to delete with empty message and mesaage_sig
    // from empty datastore and empty routingtable
    std::string message_empty;
    std::string message_sig_empty;

    protobuf::DeleteResponse delete_response;
    service_->Delete(info_, delete_request, message_empty,
                     message_sig_empty, &delete_response);
    EXPECT_FALSE(delete_response.result());
    ASSERT_EQ(0U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to delete an in-valid tuple
    // from populated datastore and empty routingtable
    SecurifierPtr securifier_local(new SecurifierValidateFalse(
    sender.public_key_id(), sender.public_key(), sender.other_info()));
    Service service(routing_table_, data_store_,
                    alternative_store_, securifier_local);
    service.set_node_joined(true);

    EXPECT_TRUE(data_store_->StoreValue(kvs, old_ttl, request_signature,
                                        crypto_key_data.public_key(), false));
    ASSERT_EQ(1U, GetDataStoreSize());

    protobuf::DeleteResponse delete_response;
    service.Delete(info_, delete_request, delete_message,
                   delete_message_sig, &delete_response);
    EXPECT_FALSE(delete_response.result());
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to delete a validated tuple
    // from empty datastore, but the routingtable already contains the sender
    AddContact(sender, rank_info_);
    ASSERT_EQ(1U, GetRoutingTableSize());

    protobuf::DeleteResponse delete_response;
    service_->Delete(info_, delete_request, delete_message,
                     delete_message_sig, &delete_response);
    EXPECT_FALSE(delete_response.result());
    ASSERT_EQ(0U, GetDataStoreSize());
    ASSERT_EQ(1U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to delete a validated tuple, from the datastore already containing it
    // with an empty routing table
    protobuf::StoreResponse store_response;
    service_->Store(info_, store_request, store_message,
                    store_message_sig, &store_response);
    ASSERT_TRUE(store_response.result());
    ASSERT_EQ(1U, GetDataStoreSize());

    protobuf::DeleteResponse delete_response;
    service_->Delete(info_, delete_request, delete_message,
                     delete_message_sig, &delete_response);
    EXPECT_TRUE(delete_response.result());
    // data_store_ will only mark the entry as deleted, but still keep it
    ASSERT_EQ(1U, GetDataStoreSize());
    // the sender will be pushed into the unvalidated_contacts list
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
}

TEST_F(ServicesTest, BEH_KAD_StoreRefresh) {
  crypto::RsaKeyPair crypto_key_id;
  crypto_key_id.GenerateKeys(1024);
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_id);

  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(1024);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");

  protobuf::StoreRequest store_request = MakeStoreRequest(sender, kvs,
                                                          crypto_key_data);

  std::string message = store_request.SerializeAsString();
  std::string message_sig = crypto::AsymSign(message,
                                             crypto_key_data.private_key());
  RequestAndSignature request_signature(message, message_sig);
  bptime::time_duration old_ttl(bptime::pos_infin);

  crypto::RsaKeyPair new_crypto_key_id;
  new_crypto_key_id.GenerateKeys(1024);
  NodeId new_sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact new_sender = ComposeContactWithKey(new_sender_id, 5001,
                                             new_crypto_key_id);
  protobuf::StoreRefreshRequest store_refresh_request;
  store_refresh_request.mutable_sender()->CopyFrom(ToProtobuf(new_sender));

  {
    // Try to storerefresh with empty message and mesaage_sig
    // into empty datastore and empty routingtable
    std::string empty_string;
    store_refresh_request.set_serialised_store_request(empty_string);
    store_refresh_request.set_serialised_store_request_signature(empty_string);

    protobuf::StoreRefreshResponse store_refresh_response;
    service_->StoreRefresh(info_, store_refresh_request,
                           &store_refresh_response);
    EXPECT_FALSE(store_refresh_response.result());
    ASSERT_EQ(0U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  store_refresh_request.set_serialised_store_request(message);
  store_refresh_request.set_serialised_store_request_signature(message_sig);
  {
    // Try to storefresh an in-valid tuple
    // into empty datastore and empty routingtable
    SecurifierPtr securifier_local(new SecurifierValidateFalse(
    sender.public_key_id(), sender.public_key(), sender.other_info()));
    Service service(routing_table_, data_store_,
                    alternative_store_, securifier_local);
    service.set_node_joined(true);

    protobuf::StoreRefreshResponse store_fresh_response;
    service.StoreRefresh(info_, store_refresh_request, &store_fresh_response);
    EXPECT_FALSE(store_fresh_response.result());
    ASSERT_EQ(0U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to storerefresh a validated tuple into empty datastore,
    // but the routingtable already contains the sender
    AddContact(new_sender, rank_info_);
    ASSERT_EQ(1U, GetRoutingTableSize());

    protobuf::StoreRefreshResponse store_fresh_response;
    service_->StoreRefresh(info_, store_refresh_request, &store_fresh_response);
    EXPECT_TRUE(store_fresh_response.result());
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(1U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to storerefresh a validated tuple into the datastore already
    // containing it
    EXPECT_TRUE(data_store_->StoreValue(kvs, old_ttl, request_signature,
                                        crypto_key_data.public_key(), false));
    ASSERT_EQ(1U, GetDataStoreSize());

    protobuf::StoreRefreshResponse store_fresh_response;
    service_->StoreRefresh(info_, store_refresh_request, &store_fresh_response);
    EXPECT_TRUE(store_fresh_response.result());
    ASSERT_EQ(1U, GetDataStoreSize());
    // the sender will be pushed into the unvalidated_contacts list
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
}

TEST_F(ServicesTest, BEH_KAD_DeleteRefresh) {
  crypto::RsaKeyPair crypto_key_id;
  crypto_key_id.GenerateKeys(1024);
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_id);

  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(1024);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");

  protobuf::StoreRequest store_request = MakeStoreRequest(sender, kvs,
                                                          crypto_key_data);
  std::string store_message = store_request.SerializeAsString();
  std::string store_message_sig = crypto::AsymSign(store_message,
                                      crypto_key_data.private_key());

  protobuf::DeleteRequest delete_request = MakeDeleteRequest(sender, kvs,
                                                             crypto_key_data);
  std::string delete_message = delete_request.SerializeAsString();
  std::string delete_message_sig = crypto::AsymSign(delete_message,
                                       crypto_key_data.private_key());
  RequestAndSignature request_signature(delete_message, delete_message_sig);
  bptime::time_duration old_ttl(bptime::pos_infin);

  crypto::RsaKeyPair new_crypto_key_id;
  new_crypto_key_id.GenerateKeys(1024);
  NodeId new_sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact new_sender = ComposeContactWithKey(new_sender_id, 5001,
                                             new_crypto_key_id);
  protobuf::DeleteRefreshRequest delete_refresh_request;
  delete_refresh_request.mutable_sender()->CopyFrom(ToProtobuf(new_sender));

  {
    // Try to deleterefresh with empty message and mesaage_sig
    // from empty datastore and empty routingtable
    std::string empty_string;
    delete_refresh_request.set_serialised_delete_request(empty_string);
    delete_refresh_request.
        set_serialised_delete_request_signature(empty_string);

    protobuf::DeleteRefreshResponse delete_refresh_response;
    service_->DeleteRefresh(info_, delete_refresh_request,
                            &delete_refresh_response);
    EXPECT_FALSE(delete_refresh_response.result());
    ASSERT_EQ(0U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  delete_refresh_request.set_serialised_delete_request(delete_message);
  delete_refresh_request.
      set_serialised_delete_request_signature(delete_message_sig);
  {
    // Try to deleterefresh an in-valid tuple
    // from populated datastore and empty routingtable
    SecurifierPtr securifier_local(new SecurifierValidateFalse(
    sender.public_key_id(), sender.public_key(), sender.other_info()));
    Service service(routing_table_, data_store_,
                    alternative_store_, securifier_local);
    service.set_node_joined(true);

    EXPECT_TRUE(data_store_->StoreValue(kvs, old_ttl, request_signature,
                                        crypto_key_data.public_key(), false));
    ASSERT_EQ(1U, GetDataStoreSize());

    protobuf::DeleteRefreshResponse delete_refresh_response;
    service.DeleteRefresh(info_, delete_refresh_request,
                          &delete_refresh_response);
    EXPECT_FALSE(delete_refresh_response.result());
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to deleterefresh a validated tuple
    // from empty datastore, but the routingtable already contains the sender
    AddContact(sender, rank_info_);
    ASSERT_EQ(1U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());

    protobuf::DeleteRefreshResponse delete_refresh_response;
    service_->DeleteRefresh(info_, delete_refresh_request,
                            &delete_refresh_response);
    EXPECT_FALSE(delete_refresh_response.result());
    ASSERT_EQ(0U, GetDataStoreSize());
    ASSERT_EQ(1U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to deleterefresh a validated tuple, from the datastore already
    // containing it
    protobuf::StoreResponse store_response;
    service_->Store(info_, store_request, store_message,
                    store_message_sig, &store_response);
    ASSERT_TRUE(store_response.result());
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());

    protobuf::DeleteRefreshResponse delete_refresh_response;
    service_->DeleteRefresh(info_, delete_refresh_request,
                            &delete_refresh_response);
    // If the entry was not marked as deleted yet, trying to deleterefresh it
    // will fail, but the sender will be added into the routing table
    EXPECT_FALSE(delete_refresh_response.result());
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(2U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to deleterefresh a validated tuple, make a delete before doing the
    // deleterefresh, to mark the entry to be deleted
    protobuf::StoreResponse store_response;
    service_->Store(info_, store_request, store_message,
                    store_message_sig, &store_response);
    ASSERT_TRUE(store_response.result());
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());

    // delete the entry, mark it as "deleted"
    protobuf::DeleteResponse delete_response;
    service_->Delete(info_, delete_request, delete_message,
                     delete_message_sig, &delete_response);
    EXPECT_TRUE(delete_response.result());
    // data_store_ will only mark the entry as deleted, but still keep it
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());

    protobuf::DeleteRefreshResponse delete_refresh_response;
    service_->DeleteRefresh(info_, delete_refresh_request,
                            &delete_refresh_response);
    // If the entry was marked as deleted yet, trying to deleterefresh it
    // will refresh its ttl
    EXPECT_TRUE(delete_refresh_response.result());
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(2U, CountUnValidatedContacts());
  }
}

TEST_F(ServicesTest, BEH_KAD_FindNodes) {
  NodeId target_id = GenerateUniqueRandomId(node_id_, 503);
  Contact target = ComposeContact(target_id, 5001);
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact sender = ComposeContact(sender_id, 5001);

  protobuf::FindNodesRequest find_nodes_req;
  find_nodes_req.mutable_sender()->CopyFrom(ToProtobuf(sender));
  find_nodes_req.set_key(target_id.String());
  {
    // try to find a node from an empty routing table
    protobuf::FindNodesResponse find_nodes_rsp;
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(0U, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
  Clear();
  {
    // try to find the target from an k/2 filled routing table
    // (not containing the target)
    PopulateRoutingTable(test::k / 2);
    EXPECT_EQ(test::k / 2, GetRoutingTableSize());

    protobuf::FindNodesResponse find_nodes_rsp;
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(test::k / 2, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(test::k / 2, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
  Clear();
  {
    // try to find the target from a 2*k filled routing table
    // (not containing the target)
    PopulateRoutingTable(test::k, 500);
    PopulateRoutingTable(test::k, 501);
    EXPECT_EQ(2 * test::k, GetRoutingTableSize());

    protobuf::FindNodesResponse find_nodes_rsp;
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(test::k, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(2 * test::k, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
  Clear();
  {
    // try to find the target from a 2*k filled routing table
    // (containing the target)
    PopulateRoutingTable(test::k, 500);
    PopulateRoutingTable(test::k - 1, 501);
    AddContact(target, rank_info_);
    EXPECT_EQ(2 * test::k, GetRoutingTableSize());

    protobuf::FindNodesResponse find_nodes_rsp;
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(test::k, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(2 * test::k, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
    // the target must be contained in the response's closest_nodes
    bool target_exist(false);
    for (int i = 0; i < find_nodes_rsp.closest_nodes_size(); ++i) {
      Contact current(FromProtobuf(find_nodes_rsp.closest_nodes(i)));
      if (current.node_id() == target_id)
        target_exist = true;
    }
    ASSERT_EQ(true, target_exist);
  }
  Clear();
  {
    // try to find the target from a 2*k+1 filled routing table
    // (containing the sender, but not containing the target)
    PopulateRoutingTable(test::k, 500);
    PopulateRoutingTable(test::k, 501);
    AddContact(sender, rank_info_);
    EXPECT_EQ(2 * test::k + 1, GetRoutingTableSize());

    protobuf::FindNodesResponse find_nodes_rsp;
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(test::k, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(2 * test::k + 1, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
}

TEST_F(ServicesTest, BEH_KAD_FindValue) {
  NodeId target_id = GenerateUniqueRandomId(node_id_, 503);
  Contact target = ComposeContact(target_id, 5001);
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact sender = ComposeContact(sender_id, 5001);

  protobuf::FindValueRequest find_value_req;
  find_value_req.mutable_sender()->CopyFrom(ToProtobuf(sender));
  find_value_req.set_key(target_id.String());
  {
    // Search in empty routing table and datastore
    // no alternative_store_
    protobuf::FindValueResponse find_value_rsp;
    service_->FindValue(info_, find_value_req, &find_value_rsp);
    ASSERT_TRUE(find_value_rsp.result());
    ASSERT_EQ(0U, find_value_rsp.closest_nodes_size());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Search in empty datastore
    // but with 2*k+1 populated routing table (containing the key)
    // no alternative_store_
    PopulateRoutingTable(test::k, 500);
    PopulateRoutingTable(test::k, 501);
    AddContact(target, rank_info_);

    protobuf::FindValueResponse find_value_rsp;
    service_->FindValue(info_, find_value_req, &find_value_rsp);
    ASSERT_TRUE(find_value_rsp.result());
    ASSERT_EQ(test::k, find_value_rsp.closest_nodes_size());
    // the target must be contained in the response's closest_nodes
    bool target_exist(false);
    for (int i = 0; i < find_value_rsp.closest_nodes_size(); ++i) {
      Contact current(FromProtobuf(find_value_rsp.closest_nodes(i)));
      if (current.node_id() == target_id)
        target_exist = true;
    }
    ASSERT_TRUE(target_exist);
    ASSERT_EQ(2 * test::k + 1, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Search in k populated datastore (not containing the target)
    // but with an empty routing table
    // no alternative_store_
    PopulateDataStore(test::k);
    ASSERT_EQ(test::k, GetDataStoreSize());

    protobuf::FindValueResponse find_value_rsp;
    service_->FindValue(info_, find_value_req, &find_value_rsp);
    ASSERT_TRUE(find_value_rsp.result());
    ASSERT_EQ(0U, find_value_rsp.closest_nodes_size());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
  Clear();

  crypto::RsaKeyPair crypto_key;
  crypto_key.GenerateKeys(1024);
  bptime::time_duration old_ttl(bptime::pos_infin), new_ttl(bptime::hours(24));
  KeyValueTuple target_kvt = MakeKVT(crypto_key, 1024, old_ttl, "", "");
  std::string target_key = target_kvt.key_value_signature.key;
  std::string target_value = target_kvt.key_value_signature.value;

  {
    // Search in K+1 populated datastore (containing the target)
    // with empty routing table
    // no alternative_store_
    PopulateDataStore(test::k);
    EXPECT_TRUE(data_store_->StoreValue(target_kvt.key_value_signature, old_ttl,
        target_kvt.request_and_signature, crypto_key.public_key(), false));
    ASSERT_EQ(test::k + 1, GetDataStoreSize());

    find_value_req.set_key(target_key);
    protobuf::FindValueResponse find_value_rsp;
    service_->FindValue(info_, find_value_req, &find_value_rsp);
    ASSERT_TRUE(find_value_rsp.result());
    ASSERT_EQ(target_value, (*find_value_rsp.mutable_signed_values(0)).value());
    ASSERT_EQ(0U, find_value_rsp.closest_nodes_size());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Search in k populated datastore (not containing the target)
    // with empty routing table
    // with alternative_store_ (not containing the target)
    PopulateDataStore(test::k);
    ASSERT_EQ(test::k, GetDataStoreSize());

    AlternativeStoreFalsePtr
        alternative_store_false_ptr(new AlternativeStoreFalse());
    Service service(routing_table_, data_store_,
                    alternative_store_false_ptr, securifier_);
    service.set_node_joined(true);

    find_value_req.set_key(target_key);
    protobuf::FindValueResponse find_value_rsp;
    service.FindValue(info_, find_value_req, &find_value_rsp);
    ASSERT_TRUE(find_value_rsp.result());
    ASSERT_EQ(0U, find_value_rsp.mutable_signed_values()->size());
    ASSERT_EQ(Contact(),
        FromProtobuf((*find_value_rsp.mutable_alternative_value_holder())));
    ASSERT_EQ(0U, find_value_rsp.closest_nodes_size());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
  Clear();

  Contact node_contact = ComposeContact(node_id_, 5000);
  {
    // Search in k populated datastore (not containing the target)
    // with empty routing table
    // with alternative_store_ (containing the target)
    PopulateDataStore(test::k);
    ASSERT_EQ(test::k, GetDataStoreSize());

    AlternativeStoreTruePtr
        alternative_store_true_ptr(new AlternativeStoreTrue());
    Service service(routing_table_, data_store_,
                    alternative_store_true_ptr, securifier_);
    service.set_node_joined(true);
    service.set_node_contact(node_contact);

    find_value_req.set_key(target_key);
    protobuf::FindValueResponse find_value_rsp;
    service.FindValue(info_, find_value_req, &find_value_rsp);
    ASSERT_TRUE(find_value_rsp.result());
    ASSERT_EQ(0U, find_value_rsp.mutable_signed_values()->size());
    ASSERT_EQ(node_contact,
        FromProtobuf((*find_value_rsp.mutable_alternative_value_holder())));
    ASSERT_EQ(0U, find_value_rsp.closest_nodes_size());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
}

TEST_F(ServicesTest, BEH_KAD_Downlist) {
  service_->GetPingDownListSignalHandler()->connect(
      kademlia::PingDownListContactsPtr::element_type::slot_type(
          &ServicesTest::FakePingContact, this, _1));
  protobuf::DownlistNotification downlist_request;

  {
    // given an empty downlist
    service_->Downlist(info_, downlist_request);
    ASSERT_EQ(0U, num_of_pings_);
  }
  {
    // given a downlist contains k nodes in the routingtable
    for (int i = 0; i < test::k; ++i) {
      NodeId contact_id = GenerateUniqueRandomId(node_id_, 500);
      Contact contact = ComposeContact(contact_id, 5000);
      downlist_request.add_node_ids(contact_id.String());
      AddContact(contact, rank_info_);
    }
    service_->Downlist(info_, downlist_request);
    // boost::this_thread::sleep(boost::posix_time::milliseconds(100);
    ASSERT_EQ(test::k, num_of_pings_);
  }
  num_of_pings_ = 0;
  {
    // given a downlist contains k+1 nodes
    // with one node not in the routingtable
    NodeId contact_id = GenerateUniqueRandomId(node_id_, 501);
    downlist_request.add_node_ids(contact_id.String());
    service_->Downlist(info_, downlist_request);
    // boost::this_thread::sleep(boost::posix_time::milliseconds(100);
    ASSERT_EQ(test::k, num_of_pings_);
  }
}

TEST_F(ServicesTest, BEH_KAD_Ping) {
  protobuf::PingRequest ping_request;
  NodeId contact_id(NodeId::kRandomId);
  Contact contact = ComposeContact(contact_id, 5000);
  ping_request.mutable_sender()->CopyFrom(ToProtobuf(contact));

  {
    // Check failure with ping set incorrectly.
    ping_request.set_ping("doink");
    protobuf::PingResponse ping_response;
    service_->Ping(info_, ping_request, &ping_response);
  //   while (!ping_response.IsInitialized())
  //     boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_FALSE(ping_response.IsInitialized());
    EXPECT_FALSE(ping_response.has_echo());
    EXPECT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  {
    // Check success.
    ping_request.set_ping("ping");
    protobuf::PingResponse ping_response;
    service_->Ping(info_, ping_request, &ping_response);
  //   while (!ping_response.IsInitialized())
  //     boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_TRUE(ping_response.IsInitialized());
    EXPECT_EQ("pong", ping_response.echo());
    EXPECT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
}


}  // namespace test_service

}  // namespace kademlia

}  // namespace maidsafe
