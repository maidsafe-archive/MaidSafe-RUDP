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

#include <algorithm>
#include <functional>
#include <set>
#include <utility>
#include <bitset>

#include "boost/lexical_cast.hpp"
#include "boost/thread.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/common/alternative_store.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/dht/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/dht/kademlia/securifier.h"
#include "maidsafe/dht/kademlia/data_store.h"
#include "maidsafe/dht/kademlia/service.h"
#include "maidsafe/dht/kademlia/message_handler.h"
#include "maidsafe/dht/kademlia/routing_table.h"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/dht/kademlia/rpcs.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "maidsafe/dht/kademlia/utils.h"
#include "maidsafe/dht/kademlia/return_codes.h"
#include "maidsafe/dht/transport/transport.h"
#include "maidsafe/dht/kademlia/tests/test_utils.h"

namespace arg = std::placeholders;

namespace maidsafe {

namespace dht {

namespace kademlia {

namespace test {

namespace {

const uint16_t g_kKademliaK = 16;

boost::posix_time::time_duration time_out = transport::kDefaultInitialTimeout;

inline void CreateRSAKeys(std::string *pub_key, std::string *priv_key) {
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  *pub_key =  kp.public_key();
  *priv_key = kp.private_key();
}

}  // unnamed namespace

class MockTransportServiceTest : public transport::Transport {
 public:
  explicit MockTransportServiceTest(boost::asio::io_service &asio_service)  // NOLINT
      : transport::Transport(asio_service) {}
  virtual transport::TransportCondition StartListening(
      const transport::Endpoint &) { return transport::kSuccess; }
  virtual transport::TransportCondition Bootstrap(
      const std::vector<transport::Endpoint> &) {
    return transport::kSuccess;
  }
  virtual void StopListening() {}
  virtual void Send(const std::string &,
                    const transport::Endpoint &,
                    const transport::Timeout &) {}
};

class SecurifierValidateFalse: public SecurifierGetPublicKeyAndValidation {
 public:
  SecurifierValidateFalse(const std::string &public_key_id,
                          const std::string &public_key,
                          const std::string &private_key)
      : SecurifierGetPublicKeyAndValidation(public_key_id, public_key,
                                            private_key) {}

  bool Validate(const std::string&,
                const std::string&,
                const std::string&,
                const std::string&,
                const std::string&,
                const std::string&) const {
    return false;
  }
};

class AlternativeStoreTrue: public AlternativeStore {
 public:
  virtual ~AlternativeStoreTrue() {}
  virtual bool Has(const std::string&) const { return true; }
};

class AlternativeStoreFalse: public AlternativeStore {
 public:
  virtual ~AlternativeStoreFalse() {}
  virtual bool Has(const std::string&) const { return false; }
};

typedef std::shared_ptr<AlternativeStoreTrue> AlternativeStoreTruePtr;
typedef std::shared_ptr<AlternativeStoreFalse> AlternativeStoreFalsePtr;

class ServicesTest: public CreateContactAndNodeId, public testing::Test {
 public:
  ServicesTest()
      : CreateContactAndNodeId(g_kKademliaK),
        contact_(),
        node_id_(NodeId::kRandomId),
        data_store_(new kademlia::DataStore(bptime::seconds(3600))),
        routing_table_(new RoutingTable(node_id_, g_kKademliaK)),
        alternative_store_(),
        securifier_(new SecurifierGetPublicKeyAndValidation("", "", "")),
        info_(),
        rank_info_(),
        service_(new Service(routing_table_, data_store_, alternative_store_,
                             securifier_, g_kKademliaK)),
        num_of_pings_(0) {
    service_->set_node_joined(true);
  }

  virtual void SetUp() {}

  void FakePingContact(Contact /*contact*/) {
    ++num_of_pings_;
  }

  void Clear() {
    routing_table_->Clear();
    data_store_->key_value_index_->clear();
    num_of_pings_ = 0;
  }

  size_t GetSenderTaskSize() {
    return service_->sender_task_->task_index_->size();
  }

  size_t GetSenderTaskSize(const Service &service) {
    return service.sender_task_->task_index_->size();
  }

  void CheckServiceConstructAttributes(const Service& service, uint16_t k) {
    EXPECT_EQ(0U, service.routing_table_->Size());
    EXPECT_EQ(0U, service.datastore_->key_value_index_->size());
    EXPECT_FALSE(service.node_joined_);
    EXPECT_EQ(k, service.k_);
    EXPECT_EQ(0U, GetSenderTaskSize(service));
  }

  bool DoStore(NodeId sender_id,
               KeyValueSignature kvs,
               crypto::RsaKeyPair& crypto_key_data) {
    Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_data);
    protobuf::StoreRequest store_request = MakeStoreRequest(sender, kvs);
    std::string message = store_request.SerializeAsString();
    std::string message_sig =
        crypto::AsymSign(message, crypto_key_data.private_key());
    protobuf::StoreResponse store_response;
    service_->Store(info_, store_request, message, message_sig,
                    &store_response, &time_out);
    return store_response.result();
  }

  bool DoDelete(NodeId sender_id,
                KeyValueSignature kvs,
                crypto::RsaKeyPair& crypto_key_data) {
    Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_data);
    protobuf::DeleteRequest delete_request = MakeDeleteRequest(sender, kvs);
    std::string delete_message = delete_request.SerializeAsString();
    std::string delete_message_sig =
        crypto::AsymSign(delete_message, crypto_key_data.private_key());
    protobuf::DeleteResponse delete_response;
    service_->Delete(info_, delete_request, delete_message,
                     delete_message_sig, &delete_response, &time_out);
    return delete_response.result();
  }

  bool DoStoreRefresh(NodeId sender_id_new,
                      crypto::RsaKeyPair& crypto_key_data_new,
                      NodeId sender_id_orig_req,
                      KeyValueSignature& kvs,
                      crypto::RsaKeyPair& crypto_key_data) {
    Contact sender_orig = ComposeContactWithKey(sender_id_orig_req, 5001,
                                                crypto_key_data);
    protobuf::StoreRequest store_request = MakeStoreRequest(sender_orig, kvs);
    std::string message = store_request.SerializeAsString();
    std::string message_sig =
        crypto::AsymSign(message, crypto_key_data.private_key());
    Contact new_sender = ComposeContactWithKey(sender_id_new, 5001,
                                               crypto_key_data_new);
    protobuf::StoreRefreshRequest store_refresh_request;
    store_refresh_request.mutable_sender()->CopyFrom(ToProtobuf(new_sender));
    store_refresh_request.set_serialised_store_request(message);
    store_refresh_request.set_serialised_store_request_signature(message_sig);

    protobuf::StoreRefreshResponse store_refresh_response;
    service_->StoreRefresh(info_, store_refresh_request,
                           &store_refresh_response, &time_out);
    return store_refresh_response.result();
  }

  bool DoDeleteRefresh(NodeId sender_id_new,
                       crypto::RsaKeyPair& crypto_key_data_new,
                       NodeId sender_id_orig_req,
                       KeyValueSignature& kvs,
                       crypto::RsaKeyPair& crypto_key_data) {
    Contact sender_orig = ComposeContactWithKey(sender_id_orig_req, 5001,
                                                crypto_key_data);
    protobuf::DeleteRequest delete_request = MakeDeleteRequest(sender_orig,
                                                               kvs);
    std::string delete_message = delete_request.SerializeAsString();
    std::string delete_message_sig =
        crypto::AsymSign(delete_message, crypto_key_data.private_key());
    Contact new_sender = ComposeContactWithKey(sender_id_new, 5001,
                                               crypto_key_data_new);
    protobuf::DeleteRefreshRequest delete_refresh_request;
    delete_refresh_request.mutable_sender()->CopyFrom(ToProtobuf(new_sender));
    delete_refresh_request.set_serialised_delete_request(delete_message);
    delete_refresh_request.
        set_serialised_delete_request_signature(delete_message_sig);
    protobuf::DeleteRefreshResponse delete_refresh_response;
    service_->DeleteRefresh(info_, delete_refresh_request,
                            &delete_refresh_response, &time_out);
    return delete_refresh_response.result();
  }

  void DoOps(std::function<bool()> ops, bool expectation, std::string op) {
    EXPECT_EQ(expectation, ops()) <<"For: " << op;
  }

  void PingDownlistCallback(const Contact &contact,
                            std::set<NodeId> *ids,
                            boost::mutex *mutex,
                            boost::condition_variable *cond_var) {
    boost::thread(&ServicesTest::DoPingDownlistCallback, this, contact, ids,
                  mutex, cond_var);
  }

  virtual void TearDown() {}

 protected:

  void PopulateDataStore(uint16_t count) {
    bptime::time_duration old_ttl(bptime::pos_infin);
    crypto::RsaKeyPair crypto_key;
    crypto_key.GenerateKeys(4096);
    for (int i = 0; i < count; ++i) {
      KeyValueTuple cur_kvt = MakeKVT(crypto_key, 1024, old_ttl, "", "");
      EXPECT_EQ(kSuccess, data_store_->StoreValue(cur_kvt.key_value_signature,
                                                  old_ttl,
                                                  cur_kvt.request_and_signature,
                                                  false));
    }
  }

  void PopulateRoutingTable(uint16_t count) {
    for (int num_contact = 0; num_contact < count; ++num_contact) {
      NodeId contact_id(NodeId::kRandomId);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(routing_table_, contact, rank_info_);
    }
  }
  void PopulateRoutingTable(uint16_t count, uint16_t pos) {
    for (int num_contact = 0; num_contact < count; ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(node_id_, pos);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(routing_table_, contact, rank_info_);
    }
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

  size_t CountPendingOperations() const {
    return 0;
  }

  // Checks for not deleted value which are not marked as deleted
  bool IsKeyValueInDataStore(KeyValueSignature kvs) {
    std::vector<ValueAndSignature> values_and_signatures;
    data_store_->GetValues(kvs.key, &values_and_signatures);
    for (size_t i = 0; i < values_and_signatures.size(); ++i) {
      if ((values_and_signatures[i].first == kvs.value) &&
          (values_and_signatures[i].second == kvs.signature)) {
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

  void DoPingDownlistCallback(const Contact &contact,
                              std::set<NodeId> *ids,
                              boost::mutex *mutex,
                              boost::condition_variable *cond_var) {
    boost::mutex::scoped_lock lock(*mutex);
    ids->insert(contact.node_id());
    cond_var->notify_one();
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


TEST_F(ServicesTest, BEH_Constructor) {
  Service service(routing_table_, data_store_, alternative_store_, securifier_,
                  g_kKademliaK);
  CheckServiceConstructAttributes(service, 16U);

  Service service_k(routing_table_, data_store_, alternative_store_,
                    securifier_, 2U);
  CheckServiceConstructAttributes(service_k, 2U);
}

TEST_F(ServicesTest, BEH_Store) {
  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(4096);
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_data);

  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");

  protobuf::StoreRequest store_request = MakeStoreRequest(sender, kvs);

  std::string message = store_request.SerializeAsString();
  std::string message_sig =
      crypto::AsymSign(message, crypto_key_data.private_key());
  RequestAndSignature request_signature(message, message_sig);
  bptime::time_duration old_ttl(bptime::pos_infin);
  {
    protobuf::StoreResponse store_response;
    service_->set_node_joined(false);
    service_->Store(info_, store_request, message, message_sig,
                    &store_response, &time_out);
    EXPECT_FALSE(store_response.result());
    service_->set_node_joined(true);
  }
  Clear();
  {
    // Try to store with empty message and mesaage_sig
    // into empty datastore and empty routingtable
    std::string message_empty;
    std::string message_sig_empty;

    protobuf::StoreResponse store_response;
    service_->Store(info_, store_request, message_empty, message_sig_empty,
                    &store_response, &time_out);
    EXPECT_FALSE(store_response.result());
    EXPECT_EQ(0U, GetSenderTaskSize());
    JoinNetworkLookup(securifier_);
    ASSERT_EQ(0U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
    ASSERT_EQ(0U, CountPendingOperations());
  }
  Clear();
  {
    // Try to store an in-valid tuple
    // into empty datastore and empty routingtable
    SecurifierPtr securifier_local(new SecurifierValidateFalse(
        sender.public_key_id(), sender.public_key(), sender.other_info()));
    Service service(routing_table_, data_store_, alternative_store_,
                    securifier_local, g_kKademliaK);
    service.set_node_joined(true);

    protobuf::StoreResponse store_response;
    service.Store(info_, store_request, message, message_sig, &store_response,
                  &time_out);
    EXPECT_TRUE(store_response.result());
    EXPECT_EQ(1U, GetSenderTaskSize(service));
    JoinNetworkLookup(securifier_local);
    EXPECT_EQ(0U, GetSenderTaskSize(service));
    ASSERT_EQ(0U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to store a validated tuple with invalid ttl
    store_request.set_ttl(0);
    protobuf::StoreResponse store_response;
    service_->Store(info_, store_request, message, message_sig,
                    &store_response, &time_out);
    EXPECT_TRUE(store_response.result());
    EXPECT_EQ(1U, GetSenderTaskSize());
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(0U, GetSenderTaskSize());
    ASSERT_EQ(0U, GetDataStoreSize());
    store_request.set_ttl(3600*24);
  }
  Clear();
  {
    // Try to store a validated tuple
    // into empty datastore, but the routingtable already contains the sender
    AddContact(routing_table_, sender, rank_info_);
    ASSERT_EQ(1U, GetRoutingTableSize());

    protobuf::StoreResponse store_response;
    service_->Store(info_, store_request, message, message_sig,
                    &store_response, &time_out);
    EXPECT_TRUE(store_response.result());
    EXPECT_EQ(1U, GetSenderTaskSize());
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(0U, GetSenderTaskSize());
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(1U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to store a validated tuple, into the datastore already containing it
    AddTestValidation(securifier_, sender_id.String(),
                      crypto_key_data.public_key());
    EXPECT_EQ(kSuccess, data_store_->StoreValue(kvs, old_ttl, request_signature,
                                                false));
    ASSERT_EQ(1U, GetDataStoreSize());

    protobuf::StoreResponse store_response;
    service_->Store(info_, store_request, message, message_sig,
                    &store_response, &time_out);
    EXPECT_TRUE(store_response.result());
    EXPECT_EQ(1U, GetSenderTaskSize());
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(0U, GetSenderTaskSize());
    EXPECT_EQ(1U, GetDataStoreSize());
    // the sender will be pushed into the unvalidated_contacts list
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
}

TEST_F(ServicesTest, BEH_Delete) {
  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(4096);
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_data);

  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");

  protobuf::StoreRequest store_request = MakeStoreRequest(sender, kvs);
  std::string store_message = store_request.SerializeAsString();
  std::string store_message_sig =
      crypto::AsymSign(store_message, crypto_key_data.private_key());

  protobuf::DeleteRequest delete_request = MakeDeleteRequest(sender, kvs);
  std::string delete_message = delete_request.SerializeAsString();
  std::string delete_message_sig =
      crypto::AsymSign(delete_message, crypto_key_data.private_key());
  RequestAndSignature request_signature(delete_message, delete_message_sig);
  bptime::time_duration old_ttl(bptime::pos_infin);
  {
    service_->set_node_joined(false);
    protobuf::DeleteResponse delete_response;
    service_->Delete(info_, delete_request, delete_message,
                     delete_message_sig, &delete_response, &time_out);
    EXPECT_FALSE(delete_response.result());
    service_->set_node_joined(true);
  }
  Clear();
  {
    // Try to delete with empty message and mesaage_sig
    // from empty datastore and empty routingtable
    std::string message_empty;
    std::string message_sig_empty;

    protobuf::DeleteResponse delete_response;
    service_->Delete(info_, delete_request, message_empty,
                     message_sig_empty, &delete_response, &time_out);
    EXPECT_FALSE(delete_response.result());
    EXPECT_EQ(0U, GetSenderTaskSize());
    JoinNetworkLookup(securifier_);
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
    Service service(routing_table_, data_store_, alternative_store_,
                    securifier_local, g_kKademliaK);
    service.set_node_joined(true);

    EXPECT_EQ(kSuccess, data_store_->StoreValue(kvs, old_ttl, request_signature,
                                                false));
    ASSERT_EQ(1U, GetDataStoreSize());

    protobuf::DeleteResponse delete_response;
    service.Delete(info_, delete_request, delete_message,
                   delete_message_sig, &delete_response, &time_out);
    EXPECT_TRUE(delete_response.result());
    EXPECT_EQ(1U, GetSenderTaskSize(service));
    JoinNetworkLookup(securifier_local);
    EXPECT_EQ(0U, GetSenderTaskSize(service));
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to delete a validated tuple
    // from empty datastore, but the routingtable already contains the sender
    AddContact(routing_table_, sender, rank_info_);
    ASSERT_EQ(1U, GetRoutingTableSize());

    protobuf::DeleteResponse delete_response;
    service_->Delete(info_, delete_request, delete_message,
                     delete_message_sig, &delete_response, &time_out);
    EXPECT_TRUE(delete_response.result());
    EXPECT_EQ(0U, GetSenderTaskSize());
    JoinNetworkLookup(securifier_);
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
                    store_message_sig, &store_response, &time_out);
    ASSERT_TRUE(store_response.result());
    EXPECT_EQ(1U, GetSenderTaskSize());
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(0U, GetSenderTaskSize());
    ASSERT_EQ(1U, GetDataStoreSize());

    protobuf::DeleteResponse delete_response;
    service_->Delete(info_, delete_request, delete_message,
                     delete_message_sig, &delete_response, &time_out);
    EXPECT_TRUE(delete_response.result());
    EXPECT_EQ(1U, GetSenderTaskSize());
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(0U, GetSenderTaskSize());
    // data_store_ will only mark the entry as deleted, but still keep it
    ASSERT_EQ(1U, GetDataStoreSize());
    // the sender will be pushed into the unvalidated_contacts list
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
}

TEST_F(ServicesTest, FUNC_StoreRefresh) {
  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(4096);
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_data);

  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");

  protobuf::StoreRequest store_request = MakeStoreRequest(sender, kvs);

  std::string message = store_request.SerializeAsString();
  std::string message_sig =
      crypto::AsymSign(message, crypto_key_data.private_key());
  RequestAndSignature request_signature(message, message_sig);
  bptime::time_duration old_ttl(bptime::pos_infin);

  crypto::RsaKeyPair new_crypto_key_id;
  new_crypto_key_id.GenerateKeys(4096);
  NodeId new_sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact new_sender = ComposeContactWithKey(new_sender_id, 5001,
                                             new_crypto_key_id);
  protobuf::StoreRefreshRequest store_refresh_request;
  store_refresh_request.mutable_sender()->CopyFrom(ToProtobuf(new_sender));
  {
    service_->set_node_joined(false);
    protobuf::StoreRefreshResponse store_refresh_response;
    service_->StoreRefresh(info_, store_refresh_request,
                           &store_refresh_response, &time_out);
    EXPECT_FALSE(store_refresh_response.result());
    service_->set_node_joined(true);
  }
  Clear();
  {
    // Try to storerefresh with empty message and mesaage_sig
    // into empty datastore and empty routingtable
    std::string empty_string;
    store_refresh_request.set_serialised_store_request(empty_string);
    store_refresh_request.set_serialised_store_request_signature(empty_string);

    protobuf::StoreRefreshResponse store_refresh_response;
    service_->StoreRefresh(info_, store_refresh_request,
                           &store_refresh_response, &time_out);
    EXPECT_FALSE(store_refresh_response.result());
    EXPECT_EQ(0U, GetSenderTaskSize());
    JoinNetworkLookup(securifier_);
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
    Service service(routing_table_, data_store_, alternative_store_,
                    securifier_local, g_kKademliaK);
    service.set_node_joined(true);

    protobuf::StoreRefreshResponse store_refresh_response;
    service.StoreRefresh(info_, store_refresh_request, &store_refresh_response,
                         &time_out);
    EXPECT_TRUE(store_refresh_response.result());
    EXPECT_EQ(1U, GetSenderTaskSize(service));
    JoinNetworkLookup(securifier_local);
    EXPECT_EQ(0U, GetSenderTaskSize(service));
    ASSERT_EQ(0U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to storerefresh a validated tuple into empty datastore,
    // but the routingtable already contains the sender
    AddContact(routing_table_, new_sender, rank_info_);
    ASSERT_EQ(1U, GetRoutingTableSize());
    protobuf::StoreRefreshResponse store_refresh_response;
    service_->StoreRefresh(info_, store_refresh_request,
                           &store_refresh_response, &time_out);
    AddTestValidation(securifier_, sender_id.String(),
                      crypto_key_data.public_key());
    EXPECT_TRUE(store_refresh_response.result());
    EXPECT_EQ(1U, GetSenderTaskSize());
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(0U, GetSenderTaskSize());
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(1U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to storerefresh a validated tuple into the datastore already
    // containing it
    EXPECT_EQ(kSuccess, data_store_->StoreValue(kvs, old_ttl, request_signature,
                                                false));
    ASSERT_EQ(1U, GetDataStoreSize());
    bptime::ptime refresh_time_old = GetRefreshTime(kvs);
    protobuf::StoreRefreshResponse store_fresh_response;
    service_->StoreRefresh(info_, store_refresh_request, &store_fresh_response,
                           &time_out);
    AddTestValidation(securifier_, sender_id.String(),
                      crypto_key_data.public_key());
    EXPECT_TRUE(store_fresh_response.result());
    EXPECT_EQ(1U, GetSenderTaskSize());
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(0U, GetSenderTaskSize());
    ASSERT_EQ(1U, GetDataStoreSize());
    bptime::ptime refresh_time_new = GetRefreshTime(kvs);
    EXPECT_GT(refresh_time_new, refresh_time_old);
    // the sender will be pushed into the unvalidated_contacts list
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
}

TEST_F(ServicesTest, FUNC_DeleteRefresh) {
  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(4096);
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_data);

  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");

  protobuf::StoreRequest store_request = MakeStoreRequest(sender, kvs);
  std::string store_message = store_request.SerializeAsString();
  std::string store_message_sig =
      crypto::AsymSign(store_message, crypto_key_data.private_key());

  protobuf::DeleteRequest delete_request = MakeDeleteRequest(sender, kvs);
  std::string delete_message = delete_request.SerializeAsString();
  std::string delete_message_sig =
      crypto::AsymSign(delete_message, crypto_key_data.private_key());
  RequestAndSignature request_signature(delete_message, delete_message_sig);
  bptime::time_duration old_ttl(bptime::pos_infin);

  crypto::RsaKeyPair new_crypto_key_id;
  new_crypto_key_id.GenerateKeys(4096);
  NodeId new_sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact new_sender = ComposeContactWithKey(new_sender_id, 5001,
                                              new_crypto_key_id);
  protobuf::DeleteRefreshRequest delete_refresh_request;
  AddTestValidation(securifier_, sender_id.String(),
                    crypto_key_data.public_key());
  delete_refresh_request.mutable_sender()->CopyFrom(ToProtobuf(new_sender));
  {
    service_->set_node_joined(false);
    protobuf::DeleteRefreshResponse delete_refresh_response;
    service_->DeleteRefresh(info_, delete_refresh_request,
                            &delete_refresh_response, &time_out);
    EXPECT_FALSE(delete_refresh_response.result());
    service_->set_node_joined(true);
  }
  Clear();
  {
    // Try to deleterefresh with empty message and mesaage_sig
    // from empty datastore and empty routingtable
    std::string empty;
    delete_refresh_request.set_serialised_delete_request(empty);
    delete_refresh_request.set_serialised_delete_request_signature(empty);

    protobuf::DeleteRefreshResponse delete_refresh_response;
    service_->DeleteRefresh(info_, delete_refresh_request,
                            &delete_refresh_response, &time_out);
    EXPECT_FALSE(delete_refresh_response.result());
    EXPECT_EQ(0U, GetSenderTaskSize());
    JoinNetworkLookup(securifier_);
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
    Service service(routing_table_, data_store_, alternative_store_,
                    securifier_local, g_kKademliaK);
    service.set_node_joined(true);

    EXPECT_EQ(kSuccess, data_store_->StoreValue(kvs, old_ttl, request_signature,
                                                false));
    ASSERT_EQ(1U, GetDataStoreSize());

    protobuf::DeleteRefreshResponse delete_refresh_response;
    service.DeleteRefresh(info_, delete_refresh_request,
                          &delete_refresh_response, &time_out);
    EXPECT_TRUE(delete_refresh_response.result());
    EXPECT_EQ(1U, GetSenderTaskSize(service));
    JoinNetworkLookup(securifier_local);
    EXPECT_EQ(0U, GetSenderTaskSize(service));
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to deleterefresh a validated tuple from empty datastore, but the
    // routingtable already contains the sender - should add the deleted value
    AddContact(routing_table_, new_sender, rank_info_);
    ASSERT_EQ(1U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());

    protobuf::DeleteRefreshResponse delete_refresh_response;
    service_->DeleteRefresh(info_, delete_refresh_request,
                            &delete_refresh_response, &time_out);
    EXPECT_TRUE(delete_refresh_response.result());
    EXPECT_EQ(1U, GetSenderTaskSize());
    JoinNetworkLookup(securifier_);
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(1U, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to deleterefresh a validated tuple, from the datastore already
    // containing it
    protobuf::StoreResponse store_response;
    service_->Store(info_, store_request, store_message,
                    store_message_sig, &store_response, &time_out);
    ASSERT_TRUE(store_response.result());
    EXPECT_EQ(1U, GetSenderTaskSize());
    JoinNetworkLookup(securifier_);
    bptime::ptime refresh_time_old = GetRefreshTime(kvs);
    EXPECT_EQ(0U, GetSenderTaskSize());
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());

    protobuf::DeleteRefreshResponse delete_refresh_response;
    service_->DeleteRefresh(info_, delete_refresh_request,
                            &delete_refresh_response, &time_out);
    // If the entry was not marked as deleted yet, trying to deleterefresh it
    // will fail, but the sender will be added into the routing table
    EXPECT_TRUE(delete_refresh_response.result());
    EXPECT_EQ(1U, GetSenderTaskSize());
    JoinNetworkLookup(securifier_);
    bptime::ptime refresh_time_new = GetRefreshTime(kvs);
    EXPECT_EQ(refresh_time_new, refresh_time_old);
    EXPECT_EQ(0U, GetSenderTaskSize());
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
  //    ASSERT_EQ(2U, CountUnValidatedContacts());
  }
  Clear();
  {
    // Try to deleterefresh a validated tuple, make a delete before doing the
    // deleterefresh, to mark the entry to be deleted
    protobuf::StoreResponse store_response;
    service_->Store(info_, store_request, store_message,
                    store_message_sig, &store_response, &time_out);
    ASSERT_TRUE(store_response.result());
    EXPECT_EQ(1U, GetSenderTaskSize());
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(0U, GetSenderTaskSize());
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());

    // delete the entry, mark it as "deleted"
    protobuf::DeleteResponse delete_response;
    service_->Delete(info_, delete_request, delete_message,
                      delete_message_sig, &delete_response, &time_out);
    EXPECT_TRUE(delete_response.result());
    EXPECT_EQ(1U, GetSenderTaskSize());
    JoinNetworkLookup(securifier_);
    bptime::ptime refresh_time_old = GetRefreshTime(kvs);
    EXPECT_EQ(0U, GetSenderTaskSize());
    // data_store_ will only mark the entry as deleted, but still keep it
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());

    protobuf::DeleteRefreshResponse delete_refresh_response;
    service_->DeleteRefresh(info_, delete_refresh_request,
                            &delete_refresh_response, &time_out);
    // If the entry was marked as deleted yet, trying to deleterefresh it
    // will refresh its ttl
    EXPECT_TRUE(delete_refresh_response.result());
    EXPECT_EQ(1U, GetSenderTaskSize());
    JoinNetworkLookup(securifier_);
    bptime::ptime refresh_time_new = GetRefreshTime(kvs);
    EXPECT_GT(refresh_time_new, refresh_time_old);
    EXPECT_EQ(0U, GetSenderTaskSize());
    ASSERT_EQ(1U, GetDataStoreSize());
    ASSERT_EQ(0U, GetRoutingTableSize());
  //    ASSERT_EQ(2U, CountUnValidatedContacts());
  }
}

TEST_F(ServicesTest, BEH_FindNodes) {
  NodeId target_id = GenerateUniqueRandomId(node_id_, 503);
  Contact target = ComposeContact(target_id, 5001);
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact sender = ComposeContact(sender_id, 5001);

  protobuf::FindNodesRequest find_nodes_req;
  find_nodes_req.mutable_sender()->CopyFrom(ToProtobuf(sender));
  find_nodes_req.set_key(target_id.String());
  {
    service_->set_node_joined(false);
    protobuf::FindNodesResponse find_nodes_rsp;
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp, &time_out);
    EXPECT_FALSE(find_nodes_rsp.result());
    service_->set_node_joined(true);
  }
  {
    // try to find a node from an empty routing table
    protobuf::FindNodesResponse find_nodes_rsp;
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp, &time_out);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(0U, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
  Clear();
  {
    // try to find the target from an k/2 filled routing table
    // (not containing the target)
    PopulateRoutingTable(g_kKademliaK / 2);
    EXPECT_EQ(g_kKademliaK / 2, GetRoutingTableSize());

    protobuf::FindNodesResponse find_nodes_rsp;
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp, &time_out);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(g_kKademliaK / 2, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(g_kKademliaK / 2, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
  Clear();
  {
    // try to find the target from a 2*k filled routing table
    // (not containing the target)
    PopulateRoutingTable(g_kKademliaK, 500);
    PopulateRoutingTable(g_kKademliaK, 501);
    EXPECT_EQ(2 * g_kKademliaK, GetRoutingTableSize());

    protobuf::FindNodesResponse find_nodes_rsp;
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp, &time_out);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(g_kKademliaK, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(2 * g_kKademliaK, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
  Clear();
  {
    // try to find the target from a 2*k filled routing table
    // (containing the target)
    PopulateRoutingTable(g_kKademliaK, 500);
    PopulateRoutingTable(g_kKademliaK - 1, 501);
    AddContact(routing_table_, target, rank_info_);
    EXPECT_EQ(2 * g_kKademliaK, GetRoutingTableSize());

    protobuf::FindNodesResponse find_nodes_rsp;
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp, &time_out);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(g_kKademliaK, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(2 * g_kKademliaK, GetRoutingTableSize());
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
    PopulateRoutingTable(g_kKademliaK, 500);
    PopulateRoutingTable(g_kKademliaK, 501);
    AddContact(routing_table_, sender, rank_info_);
    EXPECT_EQ(2 * g_kKademliaK + 1, GetRoutingTableSize());

    protobuf::FindNodesResponse find_nodes_rsp;
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp, &time_out);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(g_kKademliaK, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(2 * g_kKademliaK + 1, GetRoutingTableSize());
    ASSERT_EQ(0U, CountUnValidatedContacts());
  }

  Clear();
  {
    // try to find the target from a 2*k filled routing table
    // where num_nodes_requested < g_kKademliaK, it should return
    // g_kKademliaK contacts
    PopulateRoutingTable(g_kKademliaK, 500);
    PopulateRoutingTable(g_kKademliaK, 501);
    EXPECT_EQ(2 * g_kKademliaK, GetRoutingTableSize());

    protobuf::FindNodesResponse find_nodes_rsp;
    find_nodes_req.set_num_nodes_requested(g_kKademliaK/2);
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp, &time_out);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(g_kKademliaK, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(2 * g_kKademliaK, GetRoutingTableSize());
  }
  Clear();
  {
    // try to find the target from a 2*k filled routing table
    // where num_nodes_requested > g_kKademliaK, it should return
    // num_nodes_requested contacts
    PopulateRoutingTable(g_kKademliaK, 500);
    PopulateRoutingTable(g_kKademliaK, 501);
    EXPECT_EQ(2 * g_kKademliaK, GetRoutingTableSize());

    protobuf::FindNodesResponse find_nodes_rsp;
    find_nodes_req.set_num_nodes_requested(g_kKademliaK*3/2);
    service_->FindNodes(info_, find_nodes_req, &find_nodes_rsp, &time_out);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(g_kKademliaK*3/2, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(2 * g_kKademliaK, GetRoutingTableSize());
  }
}

TEST_F(ServicesTest, FUNC_FindValue) {
  NodeId target_id = GenerateUniqueRandomId(node_id_, 503);
  Contact target = ComposeContact(target_id, 5001);
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact sender = ComposeContact(sender_id, 5001);

  protobuf::FindValueRequest find_value_req;
  find_value_req.mutable_sender()->CopyFrom(ToProtobuf(sender));
  find_value_req.set_key(target_id.String());
  {
    service_->set_node_joined(false);
    protobuf::FindValueResponse find_value_rsp;
    service_->FindValue(info_, find_value_req, &find_value_rsp, &time_out);
    ASSERT_FALSE(find_value_rsp.result());
    service_->set_node_joined(true);
  }
  Clear();
  {
    // Search in empty routing table and datastore
    // no alternative_store_
    protobuf::FindValueResponse find_value_rsp;
    service_->FindValue(info_, find_value_req, &find_value_rsp, &time_out);
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
    PopulateRoutingTable(g_kKademliaK, 500);
    PopulateRoutingTable(g_kKademliaK, 501);
    AddContact(routing_table_, target, rank_info_);

    protobuf::FindValueResponse find_value_rsp;
    service_->FindValue(info_, find_value_req, &find_value_rsp, &time_out);
    ASSERT_TRUE(find_value_rsp.result());
    ASSERT_EQ(g_kKademliaK, find_value_rsp.closest_nodes_size());
    // the target must be contained in the response's closest_nodes
    bool target_exist(false);
    for (int i = 0; i < find_value_rsp.closest_nodes_size(); ++i) {
      Contact current(FromProtobuf(find_value_rsp.closest_nodes(i)));
      if (current.node_id() == target_id)
        target_exist = true;
    }
    ASSERT_TRUE(target_exist);
    ASSERT_EQ(2 * g_kKademliaK + 1, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }

  Clear();
  {
    // Search in empty datastore with 2*k populated routing table
    // no alternative_store_,  where num_nodes_requested < g_kKademliaK.
    // The response should contain g_kKademliaK contacts.
    PopulateRoutingTable(g_kKademliaK, 500);
    PopulateRoutingTable(g_kKademliaK, 501);

    find_value_req.set_num_nodes_requested(g_kKademliaK/2);
    protobuf::FindValueResponse find_value_rsp;
    service_->FindValue(info_, find_value_req, &find_value_rsp, &time_out);
    ASSERT_TRUE(find_value_rsp.result());
    ASSERT_EQ(g_kKademliaK, find_value_rsp.closest_nodes_size());
    ASSERT_EQ(2 * g_kKademliaK, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
  Clear();

  {
    // Search in empty datastore with 2*k populated routing table no
    // alternative_store_, where num_nodes_requested > g_kKademliaK.
    // The response should contain num_nodes_requested contacts.
    PopulateRoutingTable(g_kKademliaK, 500);
    PopulateRoutingTable(g_kKademliaK, 501);

    find_value_req.set_num_nodes_requested(g_kKademliaK*3/2);
    protobuf::FindValueResponse find_value_rsp;
    service_->FindValue(info_, find_value_req, &find_value_rsp, &time_out);
    ASSERT_TRUE(find_value_rsp.result());
    ASSERT_EQ(g_kKademliaK*3/2, find_value_rsp.closest_nodes_size());
    ASSERT_EQ(2 * g_kKademliaK, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
  Clear();

  {
    // Search in k populated datastore (not containing the target)
    // but with an empty routing table
    // no alternative_store_
    PopulateDataStore(g_kKademliaK);
    ASSERT_EQ(g_kKademliaK, GetDataStoreSize());

    protobuf::FindValueResponse find_value_rsp;
    service_->FindValue(info_, find_value_req, &find_value_rsp, &time_out);
    ASSERT_TRUE(find_value_rsp.result());
    ASSERT_EQ(0U, find_value_rsp.closest_nodes_size());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
  Clear();

  crypto::RsaKeyPair crypto_key;
  crypto_key.GenerateKeys(4096);
  bptime::time_duration old_ttl(bptime::pos_infin), new_ttl(bptime::hours(24));
  KeyValueTuple target_kvt = MakeKVT(crypto_key, 1024, old_ttl, "", "");
  std::string target_key = target_kvt.key_value_signature.key;
  std::string target_value = target_kvt.key_value_signature.value;

  {
    // Search in K+1 populated datastore (containing the target)
    // with empty routing table
    // no alternative_store_
    PopulateDataStore(g_kKademliaK);
    EXPECT_EQ(kSuccess,
              data_store_->StoreValue(target_kvt.key_value_signature,
                                      old_ttl,
                                      target_kvt.request_and_signature,
                                      false));
    ASSERT_EQ(g_kKademliaK + 1, GetDataStoreSize());

    find_value_req.set_key(target_key);
    protobuf::FindValueResponse find_value_rsp;
    service_->FindValue(info_, find_value_req, &find_value_rsp, &time_out);
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
    PopulateDataStore(g_kKademliaK);
    ASSERT_EQ(g_kKademliaK, GetDataStoreSize());

    AlternativeStoreFalsePtr
        alternative_store_false_ptr(new AlternativeStoreFalse());
    Service service(routing_table_, data_store_, alternative_store_false_ptr,
                    securifier_, g_kKademliaK);
    service.set_node_joined(true);

    find_value_req.set_key(target_key);
    protobuf::FindValueResponse find_value_rsp;
    service.FindValue(info_, find_value_req, &find_value_rsp, &time_out);
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
    PopulateDataStore(g_kKademliaK);
    ASSERT_EQ(g_kKademliaK, GetDataStoreSize());

    AlternativeStoreTruePtr
        alternative_store_true_ptr(new AlternativeStoreTrue());
    Service service(routing_table_, data_store_, alternative_store_true_ptr,
                    securifier_, g_kKademliaK);
    service.set_node_joined(true);
    service.set_node_contact(node_contact);

    find_value_req.set_key(target_key);
    protobuf::FindValueResponse find_value_rsp;
    service.FindValue(info_, find_value_req, &find_value_rsp, &time_out);
    ASSERT_TRUE(find_value_rsp.result());
    ASSERT_EQ(0U, find_value_rsp.mutable_signed_values()->size());
    ASSERT_EQ(node_contact,
        FromProtobuf((*find_value_rsp.mutable_alternative_value_holder())));
    ASSERT_EQ(0U, find_value_rsp.closest_nodes_size());
    ASSERT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
}

TEST_F(ServicesTest, BEH_Downlist) {
  // Try with a downlist with 2 x k_ NodeIds with all in routing table
  PopulateRoutingTable(5 * g_kKademliaK);
  std::vector<Contact> contacts;
  routing_table_->GetAllContacts(&contacts);
  std::sort(contacts.begin(), contacts.end());

  protobuf::DownlistNotification downlist_notification;
  NodeId contact_id(NodeId::kRandomId);
  Contact contact = ComposeContact(contact_id, 5000);
  downlist_notification.mutable_sender()->CopyFrom(ToProtobuf(contact));
  std::set<NodeId> node_ids, pinged_node_ids;
  for (size_t i(0); i != 2 * g_kKademliaK; ++i) {
    downlist_notification.add_node_ids(contacts.at(i).node_id().String());
    node_ids.insert(contacts.at(i).node_id());
  }

  boost::mutex mutex;
  boost::condition_variable cond_var;
  routing_table_->ping_down_contact()->connect(
      std::bind(&ServicesTest::PingDownlistCallback, this, arg::_1,
                &pinged_node_ids, &mutex, &cond_var));
  {
    boost::mutex::scoped_lock lock(mutex);
    service_->Downlist(info_, downlist_notification, &time_out);
    while (node_ids.size() != pinged_node_ids.size())
      EXPECT_TRUE(cond_var.timed_wait(lock, bptime::milliseconds(10)));
  }
  ASSERT_EQ(node_ids.size(), pinged_node_ids.size());
  auto in_itr(node_ids.begin()), out_itr(pinged_node_ids.begin());
  while (in_itr != node_ids.end()) {
    EXPECT_EQ(*in_itr, *out_itr);
    ++in_itr;
    ++out_itr;
  }

  // Try with a downlist with (2 x k_) + 1 NodeIds
  pinged_node_ids.clear();
  protobuf::DownlistNotification original_downlist_notification =
      downlist_notification;
  downlist_notification.add_node_ids(contacts.back().node_id().String());
  node_ids.insert(contacts.back().node_id());
  {
    boost::mutex::scoped_lock lock(mutex);
    service_->Downlist(info_, downlist_notification, &time_out);
    while (node_ids.size() != pinged_node_ids.size()) {
      if (!cond_var.timed_wait(lock, bptime::milliseconds(10)))
        break;
    }
  }
  EXPECT_TRUE(pinged_node_ids.empty());

  // Try original downlist, but on an empty routing table
  Clear();
  {
    boost::mutex::scoped_lock lock(mutex);
    service_->Downlist(info_, original_downlist_notification, &time_out);
    while (node_ids.size() != pinged_node_ids.size()) {
      if (!cond_var.timed_wait(lock, bptime::milliseconds(10)))
        break;
    }
  }
  EXPECT_TRUE(pinged_node_ids.empty());
}

TEST_F(ServicesTest, BEH_Ping) {
  protobuf::PingRequest ping_request;
  NodeId contact_id(NodeId::kRandomId);
  Contact contact = ComposeContact(contact_id, 5000);
  ping_request.mutable_sender()->CopyFrom(ToProtobuf(contact));

  {
    // Check with ping set to empty string.
    ping_request.set_ping("");
    protobuf::PingResponse ping_response;
    service_->Ping(info_, ping_request, &ping_response, &time_out);
    EXPECT_TRUE(ping_response.IsInitialized());
    EXPECT_TRUE(ping_response.has_echo());
    EXPECT_TRUE(ping_response.echo().empty());
    EXPECT_EQ(0U, GetRoutingTableSize());
    EXPECT_EQ(0U, CountUnValidatedContacts());
  }
  {
    // Check success.
    ping_request.set_ping(RandomString(50 + (RandomUint32() % 50)));
    protobuf::PingResponse ping_response;
    service_->Ping(info_, ping_request, &ping_response, &time_out);
    EXPECT_TRUE(ping_response.IsInitialized());
    EXPECT_EQ(ping_request.ping(), ping_response.echo());
    EXPECT_EQ(0U, GetRoutingTableSize());
    ASSERT_EQ(1U, CountUnValidatedContacts());
  }
}

TEST_F(ServicesTest, FUNC_MultipleStoreRequests) {
  NodeId sender_id_1 = GenerateUniqueRandomId(node_id_, 502);
  NodeId sender_id_2 = GenerateUniqueRandomId(node_id_, 502);
  NodeId sender_id_3 = GenerateUniqueRandomId(node_id_, 502);

  crypto::RsaKeyPair crypto_key_data_1;
  crypto::RsaKeyPair crypto_key_data_2;
  crypto::RsaKeyPair crypto_key_data_3;

  crypto_key_data_1.GenerateKeys(4096);
  crypto_key_data_2.GenerateKeys(4096);
  crypto_key_data_3.GenerateKeys(4096);

  KeyValueSignature k1_v1 = MakeKVS(crypto_key_data_1, 1024, "", "");
  KeyValueSignature k1_v2 = MakeKVS(crypto_key_data_1, 1024, k1_v1.key, "");
  KeyValueSignature k1_v3 = MakeKVS(crypto_key_data_1, 1024, k1_v1.key, "");
  KeyValueSignature k2_v1 = MakeKVS(crypto_key_data_2, 1024, "", "");
  KeyValueSignature k3_v1 = MakeKVS(crypto_key_data_3, 1024, "", "");

  // This will validate network lookup.
  AddTestValidation(securifier_, sender_id_1.String(),
                    crypto_key_data_1.public_key());
  AddTestValidation(securifier_, sender_id_2.String(),
                    crypto_key_data_2.public_key());
  AddTestValidation(securifier_, sender_id_3.String(),
                    crypto_key_data_3.public_key());

  ASSERT_EQ(0U, GetDataStoreSize());
  // Multilple Store requests same key value
  EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
  EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
  EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
  JoinNetworkLookup(securifier_);
  EXPECT_EQ(1U, GetDataStoreSize());
  EXPECT_EQ(1U, CountUnValidatedContacts());
  EXPECT_TRUE(IsKeyValueInDataStore(k1_v1));

  // Store requests for same key different value from same sender
  EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
  EXPECT_TRUE(DoStore(sender_id_1, k1_v2, crypto_key_data_1));
  EXPECT_TRUE(DoStore(sender_id_1, k1_v3, crypto_key_data_1));
  JoinNetworkLookup(securifier_);
  EXPECT_EQ(3U, GetDataStoreSize());
  EXPECT_EQ(1U, CountUnValidatedContacts());
  EXPECT_TRUE(IsKeyValueInDataStore(k1_v1));
  EXPECT_TRUE(IsKeyValueInDataStore(k1_v2));
  EXPECT_TRUE(IsKeyValueInDataStore(k1_v3));
  Clear();

  // Store request for same key from different senders
  // Case 1 : key already present in datastore
  EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
  JoinNetworkLookup(securifier_);
  EXPECT_EQ(1U, GetDataStoreSize());
  EXPECT_FALSE(DoStore(sender_id_2, k1_v2, crypto_key_data_2));
  EXPECT_FALSE(DoStore(sender_id_3, k1_v3, crypto_key_data_3));
  EXPECT_TRUE(DoStore(sender_id_1, k1_v2, crypto_key_data_1));
  JoinNetworkLookup(securifier_);
  EXPECT_EQ(2U, GetDataStoreSize());
  EXPECT_TRUE(IsKeyValueInDataStore(k1_v1));
  EXPECT_TRUE(IsKeyValueInDataStore(k1_v2));
  Clear();

  // Store request for same key from different senders
  // Case 2: key not present in datastore, valid sender calls after invalid
  // Invalid request recieves true but value doesn't get stored
  EXPECT_TRUE(DoStore(sender_id_2, k1_v2, crypto_key_data_2));
  EXPECT_FALSE(DoStore(sender_id_3, k1_v3, crypto_key_data_3));
  // If the valid sender calls just after invalid sender it could fail
  int attempts(0);
  bool succeeded(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
  while (attempts != 100 && !succeeded) {
    Sleep(bptime::milliseconds(10));
    succeeded = DoStore(sender_id_1, k1_v1, crypto_key_data_1);
    ++attempts;
  }
  EXPECT_TRUE(succeeded);
  JoinNetworkLookup(securifier_);
  EXPECT_EQ(1U, GetDataStoreSize());
  Clear();

  // Store request for same key from different senders
  // Case 3: key not present in datastore, valid sender calls first
  // If the valid sender calls store first, other senders recieves false
  EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
  EXPECT_FALSE(DoStore(sender_id_2, k1_v2, crypto_key_data_2));
  EXPECT_FALSE(DoStore(sender_id_3, k1_v3, crypto_key_data_3));
  JoinNetworkLookup(securifier_);
  EXPECT_EQ(1U, GetDataStoreSize());
  EXPECT_TRUE(IsKeyValueInDataStore(k1_v1));
  Clear();

  // Store request from different senders (valid)
  EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
  EXPECT_EQ(1U, GetSenderTaskSize());
  // Sleep to allow task callback to execute and remove task.
  Sleep(kNetworkDelay + kNetworkDelay);
  EXPECT_TRUE(DoStore(sender_id_2, k2_v1, crypto_key_data_2));
  EXPECT_EQ(1U, GetSenderTaskSize());
  // Sleep to allow task callback to execute and remove task.
  Sleep(kNetworkDelay + kNetworkDelay);
  EXPECT_TRUE(DoStore(sender_id_3, k3_v1, crypto_key_data_3));
  EXPECT_EQ(1U, GetSenderTaskSize());
  JoinNetworkLookup(securifier_);
  EXPECT_EQ(3U, GetDataStoreSize());
  EXPECT_EQ(3U, CountUnValidatedContacts());
  EXPECT_TRUE(IsKeyValueInDataStore(k1_v1));
  EXPECT_TRUE(IsKeyValueInDataStore(k2_v1));
  EXPECT_TRUE(IsKeyValueInDataStore(k3_v1));
  Clear();
}

TEST_F(ServicesTest, FUNC_MultipleDeleteRequests) {
  NodeId sender_id_1 = GenerateUniqueRandomId(node_id_, 502);
  NodeId sender_id_2 = GenerateUniqueRandomId(node_id_, 502);
  NodeId sender_id_3 = GenerateUniqueRandomId(node_id_, 502);

  crypto::RsaKeyPair crypto_key_data_1;
  crypto::RsaKeyPair crypto_key_data_2;
  crypto::RsaKeyPair crypto_key_data_3;

  crypto_key_data_1.GenerateKeys(4096);
  crypto_key_data_2.GenerateKeys(4096);
  crypto_key_data_3.GenerateKeys(4096);

  KeyValueSignature k1_v1 = MakeKVS(crypto_key_data_1, 1024, "", "");
  KeyValueSignature k1_v2 = MakeKVS(crypto_key_data_1, 1024, k1_v1.key, "");
  KeyValueSignature k1_v3 = MakeKVS(crypto_key_data_1, 1024, k1_v1.key, "");
  KeyValueSignature k2_v1 = MakeKVS(crypto_key_data_2, 1024, "", "");
  KeyValueSignature k3_v1 = MakeKVS(crypto_key_data_3, 1024, "", "");

  // This will validate network lookup.
  AddTestValidation(securifier_, sender_id_1.String(),
                    crypto_key_data_1.public_key());
  AddTestValidation(securifier_, sender_id_2.String(),
                    crypto_key_data_2.public_key());
  AddTestValidation(securifier_, sender_id_3.String(),
                    crypto_key_data_3.public_key());

  ASSERT_EQ(0U, GetDataStoreSize());
  // Multilple Delete requests same key value
  EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
  JoinNetworkLookup(securifier_);
  EXPECT_TRUE(DoDelete(sender_id_1, k1_v1, crypto_key_data_1));
  EXPECT_TRUE(DoDelete(sender_id_1, k1_v1, crypto_key_data_1));
  EXPECT_TRUE(DoDelete(sender_id_1, k1_v1, crypto_key_data_1));
  JoinNetworkLookup(securifier_);
  EXPECT_EQ(1U, GetDataStoreSize());
  EXPECT_EQ(1U, CountUnValidatedContacts());
  EXPECT_FALSE(IsKeyValueInDataStore(k1_v1));

  // Delete requests for same key different value from same sender
  EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
  EXPECT_TRUE(DoStore(sender_id_1, k1_v2, crypto_key_data_1));
  EXPECT_TRUE(DoStore(sender_id_1, k1_v3, crypto_key_data_1));
  JoinNetworkLookup(securifier_);
  EXPECT_EQ(3U, GetDataStoreSize());
  EXPECT_TRUE(DoDelete(sender_id_1, k1_v1, crypto_key_data_1));
  EXPECT_TRUE(DoDelete(sender_id_1, k1_v2, crypto_key_data_1));
  EXPECT_TRUE(DoDelete(sender_id_1, k1_v3, crypto_key_data_1));
  JoinNetworkLookup(securifier_);
  EXPECT_EQ(3U, GetDataStoreSize());
  EXPECT_EQ(1U, CountUnValidatedContacts());
  EXPECT_FALSE(IsKeyValueInDataStore(k1_v1));
  EXPECT_FALSE(IsKeyValueInDataStore(k1_v2));
  EXPECT_FALSE(IsKeyValueInDataStore(k1_v3));
  Clear();

  // Delete request for same key from different senders
  EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
  JoinNetworkLookup(securifier_);
  EXPECT_EQ(1U, GetDataStoreSize());
  EXPECT_FALSE(DoDelete(sender_id_2, k1_v2, crypto_key_data_2));
  EXPECT_FALSE(DoDelete(sender_id_3, k1_v3, crypto_key_data_3));
  EXPECT_TRUE(DoDelete(sender_id_1, k1_v1, crypto_key_data_1));
  JoinNetworkLookup(securifier_);
  EXPECT_EQ(1U, GetDataStoreSize());
  EXPECT_FALSE(IsKeyValueInDataStore(k1_v1));
  Clear();

  // Delete request from different senders (valid)
  EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
  EXPECT_TRUE(DoStore(sender_id_2, k2_v1, crypto_key_data_2));
  EXPECT_TRUE(DoStore(sender_id_3, k3_v1, crypto_key_data_3));
  JoinNetworkLookup(securifier_);
  EXPECT_EQ(3U, GetDataStoreSize());
  EXPECT_TRUE(DoDelete(sender_id_1, k1_v1, crypto_key_data_1));
  EXPECT_TRUE(DoDelete(sender_id_2, k2_v1, crypto_key_data_2));
  EXPECT_TRUE(DoDelete(sender_id_3, k3_v1, crypto_key_data_3));
  JoinNetworkLookup(securifier_);
  EXPECT_FALSE(IsKeyValueInDataStore(k1_v1));
  EXPECT_FALSE(IsKeyValueInDataStore(k2_v1));
  EXPECT_FALSE(IsKeyValueInDataStore(k3_v1));
  EXPECT_EQ(3U, GetDataStoreSize());
  EXPECT_EQ(3U, CountUnValidatedContacts());
  Clear();
}

TEST_F(ServicesTest, FUNC_MultipleStoreRefreshRequests) {
  NodeId sender_id_1 = GenerateUniqueRandomId(node_id_, 502);
  NodeId sender_id_2 = GenerateUniqueRandomId(node_id_, 502);
  NodeId sender_id_3 = GenerateUniqueRandomId(node_id_, 502);

  crypto::RsaKeyPair crypto_key_data_1;
  crypto::RsaKeyPair crypto_key_data_2;
  crypto::RsaKeyPair crypto_key_data_3;

  crypto_key_data_1.GenerateKeys(4096);
  crypto_key_data_2.GenerateKeys(4096);
  crypto_key_data_3.GenerateKeys(4096);

  KeyValueSignature k1_v1 = MakeKVS(crypto_key_data_1, 1024, "", "");
  KeyValueSignature k1_v2 = MakeKVS(crypto_key_data_1, 1024, k1_v1.key, "");
  KeyValueSignature k1_v3 = MakeKVS(crypto_key_data_1, 1024, k1_v1.key, "");
  KeyValueSignature k2_v1 = MakeKVS(crypto_key_data_2, 1024, "", "");
  KeyValueSignature k3_v1 = MakeKVS(crypto_key_data_3, 1024, "", "");

  // This will validate network lookup.
  AddTestValidation(securifier_, sender_id_1.String(),
                    crypto_key_data_1.public_key());
  AddTestValidation(securifier_, sender_id_2.String(),
                    crypto_key_data_2.public_key());
  AddTestValidation(securifier_, sender_id_3.String(),
                    crypto_key_data_3.public_key());

  ASSERT_EQ(0U, GetDataStoreSize());
  // Multilple Store Refresh requests same key value
  {
    EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(1U, GetDataStoreSize());
    bptime::ptime refresh_time_old_k1_v1 = GetRefreshTime(k1_v1);
    EXPECT_TRUE(DoStoreRefresh(sender_id_2, crypto_key_data_2, sender_id_1,
                               k1_v1, crypto_key_data_1));
    EXPECT_TRUE(DoStoreRefresh(sender_id_2, crypto_key_data_2, sender_id_1,
                               k1_v1, crypto_key_data_1));
    EXPECT_TRUE(DoStoreRefresh(sender_id_2, crypto_key_data_2, sender_id_1,
                               k1_v1, crypto_key_data_1));
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(1U, GetDataStoreSize());
    EXPECT_EQ(2U, CountUnValidatedContacts());
    EXPECT_TRUE(IsKeyValueInDataStore(k1_v1));
    bptime::ptime refresh_time_new_k1_v1 = GetRefreshTime(k1_v1);
    EXPECT_GT(refresh_time_new_k1_v1, refresh_time_old_k1_v1);
  }
  Clear();
  // Store refresh requests for same key different value from same sender
  {
    EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
    EXPECT_TRUE(DoStore(sender_id_1, k1_v2, crypto_key_data_1));
    EXPECT_TRUE(DoStore(sender_id_1, k1_v3, crypto_key_data_1));
    bptime::ptime refresh_time_old_k1_v1 = GetRefreshTime(k1_v1);
    bptime::ptime refresh_time_old_k1_v2 = GetRefreshTime(k1_v2);
    bptime::ptime refresh_time_old_k1_v3 = GetRefreshTime(k1_v3);
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(3U, GetDataStoreSize());
    EXPECT_TRUE(DoStoreRefresh(sender_id_2, crypto_key_data_2, sender_id_1,
                               k1_v1, crypto_key_data_1));
    EXPECT_TRUE(DoStoreRefresh(sender_id_2, crypto_key_data_2, sender_id_1,
                               k1_v2, crypto_key_data_1));
    EXPECT_TRUE(DoStoreRefresh(sender_id_2, crypto_key_data_2, sender_id_1,
                               k1_v3, crypto_key_data_1));
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(3U, GetDataStoreSize());
    EXPECT_EQ(2U, CountUnValidatedContacts());
    EXPECT_TRUE(IsKeyValueInDataStore(k1_v1));
    EXPECT_TRUE(IsKeyValueInDataStore(k1_v2));
    EXPECT_TRUE(IsKeyValueInDataStore(k1_v3));

    bptime::ptime refresh_time_new_k1_v1 = GetRefreshTime(k1_v1);
    bptime::ptime refresh_time_new_k1_v2 = GetRefreshTime(k1_v2);
    bptime::ptime refresh_time_new_k1_v3 = GetRefreshTime(k1_v3);
    EXPECT_GT(refresh_time_new_k1_v1, refresh_time_old_k1_v1);
    EXPECT_GT(refresh_time_new_k1_v2, refresh_time_old_k1_v2);
    EXPECT_GT(refresh_time_new_k1_v3, refresh_time_old_k1_v3);
  }
  Clear();
  // Store refresh request for same key from different requester
  // Case 1 : key already present in datastore
  {
    EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(1U, GetDataStoreSize());
    bptime::ptime refresh_time_old_k1_v1 = GetRefreshTime(k1_v1);
    // Invalid request recieves true but value doesn't get stored
    EXPECT_TRUE(DoStoreRefresh(sender_id_3, crypto_key_data_3, sender_id_2,
                               k1_v1, crypto_key_data_2));
    // If the valid sender calls just after invalid sender it could fail
    int attempts(0);
    bool succeeded(false);
    while (attempts != 100 && !succeeded) {
      Sleep(bptime::milliseconds(10));
      succeeded = DoStoreRefresh(sender_id_2, crypto_key_data_2, sender_id_1,
                                 k1_v1, crypto_key_data_1);
      ++attempts;
    }
    EXPECT_TRUE(succeeded);
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(1U, GetDataStoreSize());
    EXPECT_TRUE(IsKeyValueInDataStore(k1_v1));
    EXPECT_FALSE(IsKeyValueInDataStore(k1_v2));
    bptime::ptime refresh_time_new_k1_v1 = GetRefreshTime(k1_v1);
    EXPECT_GT(refresh_time_new_k1_v1, refresh_time_old_k1_v1);
  }
  Clear();
  // Store refresh request for same key from different requester
  // Case 2: key not present in datastore, valid sender calls after invalid
  {
    // Invalid request recieves true but value doesn't get stored
    EXPECT_TRUE(DoStoreRefresh(sender_id_3, crypto_key_data_3, sender_id_2,
                               k1_v1, crypto_key_data_2));
    // If the valid sender calls just after invalid sender it could fail
    int attempts(0);
    bool succeeded(false);
    while (attempts != 100 && !succeeded) {
      Sleep(bptime::milliseconds(10));
      succeeded = DoStoreRefresh(sender_id_2, crypto_key_data_2, sender_id_1,
                                 k1_v1, crypto_key_data_1);
      ++attempts;
    }
    EXPECT_TRUE(succeeded);
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(1U, GetDataStoreSize());
  }
  Clear();
  // Store Refresh request for same key from different requester
  // Case 3: key not present in datastore, valid sender calls first
  {
    // If the valid sender calls store first, other senders recieves false
    EXPECT_TRUE(DoStoreRefresh(sender_id_2, crypto_key_data_2, sender_id_1,
                               k1_v1, crypto_key_data_1));
    EXPECT_FALSE(DoStoreRefresh(sender_id_3, crypto_key_data_3, sender_id_2,
                               k1_v1, crypto_key_data_2));
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(1U, GetDataStoreSize());
    EXPECT_TRUE(IsKeyValueInDataStore(k1_v1));
  }
    Clear();
  // Store Refresh request from different senders (valid)
  {
    EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
    EXPECT_TRUE(DoStore(sender_id_2, k2_v1, crypto_key_data_2));
    EXPECT_TRUE(DoStore(sender_id_3, k3_v1, crypto_key_data_3));
    bptime::ptime refresh_time_old_k1_v1 = GetRefreshTime(k1_v1);
    bptime::ptime refresh_time_old_k2_v1 = GetRefreshTime(k2_v1);
    bptime::ptime refresh_time_old_k3_v1 = GetRefreshTime(k3_v1);

    JoinNetworkLookup(securifier_);
    EXPECT_EQ(3U, GetDataStoreSize());
    EXPECT_EQ(3U, CountUnValidatedContacts());
    EXPECT_TRUE(DoStoreRefresh(sender_id_2, crypto_key_data_2, sender_id_1,
                               k1_v1, crypto_key_data_1));
    EXPECT_TRUE(DoStoreRefresh(sender_id_3, crypto_key_data_3, sender_id_2,
                               k2_v1, crypto_key_data_2));
    EXPECT_TRUE(DoStoreRefresh(sender_id_1, crypto_key_data_1, sender_id_3,
                               k3_v1, crypto_key_data_3));
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(3U, GetDataStoreSize());

    bptime::ptime refresh_time_new_k1_v1 = GetRefreshTime(k1_v1);
    bptime::ptime refresh_time_new_k2_v1 = GetRefreshTime(k2_v1);
    bptime::ptime refresh_time_new_k3_v1 = GetRefreshTime(k3_v1);
    EXPECT_GT(refresh_time_new_k1_v1, refresh_time_old_k1_v1);
    EXPECT_GT(refresh_time_new_k2_v1, refresh_time_old_k2_v1);
    EXPECT_GT(refresh_time_new_k3_v1, refresh_time_old_k3_v1);
  }
  Clear();
}

TEST_F(ServicesTest, FUNC_MultipleDeleteRefreshRequests) {
  NodeId sender_id_1 = GenerateUniqueRandomId(node_id_, 502);
  NodeId sender_id_2 = GenerateUniqueRandomId(node_id_, 502);
  NodeId sender_id_3 = GenerateUniqueRandomId(node_id_, 502);

  crypto::RsaKeyPair crypto_key_data_1;
  crypto::RsaKeyPair crypto_key_data_2;
  crypto::RsaKeyPair crypto_key_data_3;

  crypto_key_data_1.GenerateKeys(4096);
  crypto_key_data_2.GenerateKeys(4096);
  crypto_key_data_3.GenerateKeys(4096);

  KeyValueSignature k1_v1 = MakeKVS(crypto_key_data_1, 1024, "", "");
  KeyValueSignature k1_v2 = MakeKVS(crypto_key_data_1, 1024, k1_v1.key, "");
  KeyValueSignature k1_v3 = MakeKVS(crypto_key_data_1, 1024, k1_v1.key, "");
  KeyValueSignature k2_v1 = MakeKVS(crypto_key_data_2, 1024, "", "");
  KeyValueSignature k3_v1 = MakeKVS(crypto_key_data_3, 1024, "", "");

  // This will validate network lookup.
  AddTestValidation(securifier_, sender_id_1.String(),
                    crypto_key_data_1.public_key());
  AddTestValidation(securifier_, sender_id_2.String(),
                    crypto_key_data_2.public_key());
  AddTestValidation(securifier_, sender_id_3.String(),
                    crypto_key_data_3.public_key());

  ASSERT_EQ(0U, GetDataStoreSize());
  // Multilple Delete Refresh requests same key value
  {
    EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
    JoinNetworkLookup(securifier_);
    EXPECT_TRUE(DoDelete(sender_id_1, k1_v1, crypto_key_data_1));
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(1U, GetDataStoreSize());
    bptime::ptime refresh_time_old_k1_v1 = GetRefreshTime(k1_v1);
    EXPECT_TRUE(DoDeleteRefresh(sender_id_2, crypto_key_data_2,
                                sender_id_1, k1_v1, crypto_key_data_1));
    EXPECT_TRUE(DoDeleteRefresh(sender_id_3, crypto_key_data_3,
                                sender_id_1, k1_v1, crypto_key_data_1));
    EXPECT_TRUE(DoDeleteRefresh(sender_id_3, crypto_key_data_3,
                                sender_id_1, k1_v1, crypto_key_data_1));
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(1U, GetDataStoreSize());
    bptime::ptime refresh_time_new_k1_v1 = GetRefreshTime(k1_v1);
    EXPECT_GT(refresh_time_new_k1_v1, refresh_time_old_k1_v1);
    EXPECT_EQ(3U, CountUnValidatedContacts());
    EXPECT_FALSE(IsKeyValueInDataStore(k1_v1));
  }
  // Delete Refresh requests for same key different value from same sender
  {
    EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
    EXPECT_TRUE(DoStore(sender_id_1, k1_v2, crypto_key_data_1));
    EXPECT_TRUE(DoStore(sender_id_1, k1_v3, crypto_key_data_1));
    JoinNetworkLookup(securifier_);
    EXPECT_TRUE(DoDelete(sender_id_1, k1_v1, crypto_key_data_1));
    EXPECT_TRUE(DoDelete(sender_id_1, k1_v2, crypto_key_data_1));
    EXPECT_TRUE(DoDelete(sender_id_1, k1_v3, crypto_key_data_1));
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(3U, GetDataStoreSize());
    bptime::ptime refresh_time_old_k1_v1 = GetRefreshTime(k1_v1);
    bptime::ptime refresh_time_old_k1_v2 = GetRefreshTime(k1_v2);
    bptime::ptime refresh_time_old_k1_v3 = GetRefreshTime(k1_v3);

    EXPECT_TRUE(DoDeleteRefresh(sender_id_2, crypto_key_data_2,
                                sender_id_1, k1_v1, crypto_key_data_1));
    EXPECT_TRUE(DoDeleteRefresh(sender_id_2, crypto_key_data_2,
                                sender_id_1, k1_v2, crypto_key_data_1));
    EXPECT_TRUE(DoDeleteRefresh(sender_id_2, crypto_key_data_2,
                                sender_id_1, k1_v3, crypto_key_data_1));
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(3U, GetDataStoreSize());
    EXPECT_EQ(3U, CountUnValidatedContacts());
    EXPECT_FALSE(IsKeyValueInDataStore(k1_v1));
    EXPECT_FALSE(IsKeyValueInDataStore(k1_v2));
    EXPECT_FALSE(IsKeyValueInDataStore(k1_v3));

    bptime::ptime refresh_time_new_k1_v1 = GetRefreshTime(k1_v1);
    bptime::ptime refresh_time_new_k1_v2 = GetRefreshTime(k1_v2);
    bptime::ptime refresh_time_new_k1_v3 = GetRefreshTime(k1_v3);
    EXPECT_GT(refresh_time_new_k1_v1, refresh_time_old_k1_v1);
    EXPECT_GT(refresh_time_new_k1_v2, refresh_time_old_k1_v2);
    EXPECT_GT(refresh_time_new_k1_v3, refresh_time_old_k1_v3);
  }
  Clear();
  // Delete Refresh requests for existing key from different sender
  {
    EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
    JoinNetworkLookup(securifier_);
    EXPECT_FALSE(DoDeleteRefresh(sender_id_2, crypto_key_data_2,
                                 sender_id_3, k1_v2, crypto_key_data_3));
    EXPECT_FALSE(DoDeleteRefresh(sender_id_3, crypto_key_data_3,
                                 sender_id_3, k1_v3, crypto_key_data_3));
    EXPECT_EQ(3U, CountUnValidatedContacts());
    EXPECT_EQ(1U, GetDataStoreSize());
  }
  Clear();
  // Delete Refresh requests for different key value from different sender
  {
    EXPECT_TRUE(DoStore(sender_id_1, k1_v1, crypto_key_data_1));
    EXPECT_TRUE(DoStore(sender_id_2, k2_v1, crypto_key_data_2));
    EXPECT_TRUE(DoStore(sender_id_3, k3_v1, crypto_key_data_3));
    JoinNetworkLookup(securifier_);
    EXPECT_TRUE(DoDelete(sender_id_1, k1_v1, crypto_key_data_1));
    EXPECT_TRUE(DoDelete(sender_id_2, k2_v1, crypto_key_data_2));
    EXPECT_TRUE(DoDelete(sender_id_3, k3_v1, crypto_key_data_3));
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(3U, GetDataStoreSize());
    bptime::ptime refresh_time_old_k1_v1 = GetRefreshTime(k1_v1);
    bptime::ptime refresh_time_old_k2_v1 = GetRefreshTime(k2_v1);
    bptime::ptime refresh_time_old_k3_v1 = GetRefreshTime(k3_v1);

    EXPECT_TRUE(DoDeleteRefresh(sender_id_2, crypto_key_data_2,
                                sender_id_1, k1_v1, crypto_key_data_1));
    EXPECT_TRUE(DoDeleteRefresh(sender_id_3, crypto_key_data_3,
                                sender_id_2, k2_v1, crypto_key_data_2));
    EXPECT_TRUE(DoDeleteRefresh(sender_id_1, crypto_key_data_1,
                                sender_id_3, k3_v1, crypto_key_data_3));
    JoinNetworkLookup(securifier_);
    EXPECT_EQ(3U, GetDataStoreSize());
    EXPECT_EQ(3U, CountUnValidatedContacts());
    EXPECT_FALSE(IsKeyValueInDataStore(k1_v1));
    EXPECT_FALSE(IsKeyValueInDataStore(k1_v2));
    EXPECT_FALSE(IsKeyValueInDataStore(k1_v3));

    bptime::ptime refresh_time_new_k1_v1 = GetRefreshTime(k1_v1);
    bptime::ptime refresh_time_new_k2_v1 = GetRefreshTime(k2_v1);
    bptime::ptime refresh_time_new_k3_v1 = GetRefreshTime(k3_v1);
    EXPECT_GT(refresh_time_new_k1_v1, refresh_time_old_k1_v1);
    EXPECT_GT(refresh_time_new_k2_v1, refresh_time_old_k2_v1);
    EXPECT_GT(refresh_time_new_k3_v1, refresh_time_old_k3_v1);
  }
}

TEST_F(ServicesTest, FUNC_MultipleThreads) {
  const size_t kNumberOfThreads(8);
  // Preparing data
  NodeId sender_id_1 = GenerateUniqueRandomId(node_id_, 502);
  NodeId sender_id_2 = GenerateUniqueRandomId(node_id_, 502);
  NodeId sender_id_3 = GenerateUniqueRandomId(node_id_, 502);
  NodeId sender_id_4 = GenerateUniqueRandomId(node_id_, 502);

  crypto::RsaKeyPair crypto_key_data_1;
  crypto::RsaKeyPair crypto_key_data_2;
  crypto::RsaKeyPair crypto_key_data_3;
  crypto::RsaKeyPair crypto_key_data_4;

  crypto_key_data_1.GenerateKeys(4096);
  crypto_key_data_2.GenerateKeys(4096);
  crypto_key_data_3.GenerateKeys(4096);
  crypto_key_data_4.GenerateKeys(4096);

  KeyValueSignature k1_v1 = MakeKVS(crypto_key_data_1, 1024, "", "");
  KeyValueSignature k1_v2 = MakeKVS(crypto_key_data_1, 1024, k1_v1.key, "");
  KeyValueSignature k2_v1 = MakeKVS(crypto_key_data_2, 1024, "", "");
  KeyValueSignature k2_v2 = MakeKVS(crypto_key_data_2, 1024, k2_v1.key, "");
  KeyValueSignature k3_v1 = MakeKVS(crypto_key_data_3, 1024, "", "");
  KeyValueSignature k3_v2 = MakeKVS(crypto_key_data_3, 1024, k3_v1.key, "");
  KeyValueSignature k4_v1 = MakeKVS(crypto_key_data_4, 1024, "", "");
  KeyValueSignature k4_v2 = MakeKVS(crypto_key_data_4, 1024, k4_v1.key, "");
  Clear();
  // This will validate network lookup for given public_key_id.
  AddTestValidation(securifier_, sender_id_1.String(),
                    crypto_key_data_1.public_key());
  AddTestValidation(securifier_, sender_id_2.String(),
                    crypto_key_data_2.public_key());
  AddTestValidation(securifier_, sender_id_3.String(),
                    crypto_key_data_3.public_key());
  AddTestValidation(securifier_, sender_id_4.String(),
                    crypto_key_data_4.public_key());
  // Store initial data
  // Data for store Refresh
  EXPECT_TRUE(DoStore(sender_id_2, k2_v1, crypto_key_data_2));
  EXPECT_TRUE(DoStore(sender_id_2, k2_v2, crypto_key_data_2));
  JoinNetworkLookup(securifier_);
  bptime::ptime refresh_time_old_k2_v1 = GetRefreshTime(k2_v1);
  bptime::ptime refresh_time_old_k2_v2 = GetRefreshTime(k2_v2);
  // Data for Delete
  EXPECT_TRUE(DoStore(sender_id_3, k3_v1, crypto_key_data_3));
  EXPECT_TRUE(DoStore(sender_id_3, k3_v2, crypto_key_data_3));
  // Data for Delete refresh
  EXPECT_TRUE(DoStore(sender_id_4, k4_v1, crypto_key_data_4));
  EXPECT_TRUE(DoStore(sender_id_4, k4_v2, crypto_key_data_4));
  JoinNetworkLookup(securifier_);
  EXPECT_TRUE(DoDelete(sender_id_4, k4_v1, crypto_key_data_4));
  EXPECT_TRUE(DoDelete(sender_id_4, k4_v2, crypto_key_data_4));
  JoinNetworkLookup(securifier_);
  bptime::ptime refresh_time_old_k4_v1 = GetRefreshTime(k4_v1);
  bptime::ptime refresh_time_old_k4_v2 = GetRefreshTime(k4_v2);

  EXPECT_EQ(6U, GetDataStoreSize());
  EXPECT_EQ(3U, CountUnValidatedContacts());

  AsioService asio_service;
  boost::thread_group asio_thread_group;
  std::function<bool()> ops;
  // Posting jobs
  // Store
  ops = std::bind(&ServicesTest::DoStore, this, sender_id_1, k1_v1,
                  crypto_key_data_1);
  asio_service.post(std::bind(&ServicesTest::DoOps, this, ops, true,
                              "DoStore"));
  ops = std::bind(&ServicesTest::DoStore, this, sender_id_1, k1_v2,
                  crypto_key_data_1);
  asio_service.post(std::bind(&ServicesTest::DoOps, this, ops, true,
                             "DoStore"));
  // Store Refresh
  ops = std::bind(&ServicesTest::DoStoreRefresh, this, sender_id_4,
                  crypto_key_data_4, sender_id_2, k2_v1, crypto_key_data_2);
  asio_service.post(std::bind(&ServicesTest::DoOps, this, ops, true,
                              "DoStoreRefresh"));
  ops = std::bind(&ServicesTest::DoStoreRefresh, this, sender_id_4,
                  crypto_key_data_4, sender_id_2, k2_v2, crypto_key_data_2);
  asio_service.post(std::bind(&ServicesTest::DoOps, this, ops, true,
                              "DoStoreRefresh"));
  // Delete
  ops = std::bind(&ServicesTest::DoDelete, this, sender_id_3, k3_v1,
                  crypto_key_data_3);
  asio_service.post(std::bind(&ServicesTest::DoOps, this, ops, true,
                              "DoDelete"));
  ops = std::bind(&ServicesTest::DoDelete, this, sender_id_3, k3_v2,
                  crypto_key_data_3);
  asio_service.post(std::bind(&ServicesTest::DoOps, this, ops, true,
                              "DoDelete"));
  // Delete refresh
  ops = std::bind(&ServicesTest::DoDeleteRefresh, this, sender_id_2,
                  crypto_key_data_2, sender_id_4, k4_v1, crypto_key_data_4);
  asio_service.post(std::bind(&ServicesTest::DoOps, this, ops, true,
                              "DoDeleteRefresh"));
  ops = std::bind(&ServicesTest::DoDeleteRefresh, this, sender_id_2,
                  crypto_key_data_2, sender_id_4, k4_v2, crypto_key_data_4);
  asio_service.post(std::bind(&ServicesTest::DoOps, this, ops, true,
                              "DoDeleteRefresh"));
  // Running the threads
  for (size_t i = 0; i < kNumberOfThreads; ++i) {
    asio_thread_group.create_thread(
        std::bind(static_cast<size_t(boost::asio::io_service::*)()>(
            &boost::asio::io_service::run), &asio_service));
  }
  // Check results
  asio_thread_group.join_all();
  JoinNetworkLookup(securifier_);
  // Store
  EXPECT_TRUE(IsKeyValueInDataStore(k1_v1));
  EXPECT_TRUE(IsKeyValueInDataStore(k1_v2));
  // Store Refresh
  {
    EXPECT_TRUE(IsKeyValueInDataStore(k2_v1));
    EXPECT_TRUE(IsKeyValueInDataStore(k2_v2));
    bptime::ptime refresh_time_new_k2_v1 = GetRefreshTime(k2_v1);
    bptime::ptime refresh_time_new_k2_v2 = GetRefreshTime(k2_v2);
    EXPECT_GT(refresh_time_new_k2_v1, refresh_time_old_k2_v1);
    EXPECT_GT(refresh_time_new_k2_v2, refresh_time_old_k2_v2);
  }
  // Delete
  EXPECT_FALSE(IsKeyValueInDataStore(k3_v1));
  EXPECT_FALSE(IsKeyValueInDataStore(k3_v2));
  // Delete Refresh
  {
    EXPECT_FALSE(IsKeyValueInDataStore(k4_v1));
    EXPECT_FALSE(IsKeyValueInDataStore(k4_v2));
    bptime::ptime refresh_time_new_k4_v1 = GetRefreshTime(k4_v1);
    bptime::ptime refresh_time_new_k4_v2 = GetRefreshTime(k4_v2);
    EXPECT_GT(refresh_time_new_k4_v1, refresh_time_old_k4_v1);
    EXPECT_GT(refresh_time_new_k4_v2, refresh_time_old_k4_v2);
  }
  EXPECT_EQ(4U, CountUnValidatedContacts());
  EXPECT_EQ(8U, GetDataStoreSize());
}

TEST_F(ServicesTest, BEH_SignalConnection) {
  MessageHandlerPtr message_handler_ptr(new MessageHandler(securifier_));
  boost::asio::io_service ioservice;
  TransportPtr transport_ptr(new MockTransportServiceTest(ioservice));
  // Connecting to Signals
  service_->ConnectToSignals(message_handler_ptr);
  transport_ptr->on_message_received()->connect(
      transport::OnMessageReceived::element_type::slot_type(
          &MessageHandler::OnMessageReceived, message_handler_ptr.get(),
          _1, _2, _3, _4).track_foreign(message_handler_ptr));
  // Data
  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(4096);
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact sender = ComposeContactWithKey(sender_id, 5001, crypto_key_data);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");

  // Signal PingRequest
  protobuf::PingRequest ping_request;
  ping_request.mutable_sender()->CopyFrom(ToProtobuf(sender));
  ping_request.set_ping(RandomString(50 + (RandomUint32() % 50)));
  protobuf::PingResponse ping_response;
  (*message_handler_ptr->on_ping_request())(info_, ping_request, &ping_response,
                                            &time_out);
  EXPECT_TRUE(ping_response.IsInitialized());
  EXPECT_EQ(ping_request.ping(), ping_response.echo());

  // Signal FindValueRequest
  protobuf::FindValueRequest find_value_req;
  find_value_req.mutable_sender()->CopyFrom(ToProtobuf(sender));
  find_value_req.set_key(sender_id.String());
  protobuf::FindValueResponse find_value_rsp;
  (*message_handler_ptr->on_find_value_request())(info_, find_value_req,
                                                  &find_value_rsp, &time_out);
  ASSERT_TRUE(find_value_rsp.result());

  // Signal FindNodeRequest
  protobuf::FindNodesRequest find_nodes_req;
  find_nodes_req.mutable_sender()->CopyFrom(ToProtobuf(sender));
  find_nodes_req.set_key(sender_id.String());
  protobuf::FindNodesResponse find_nodes_rsp;
  (*message_handler_ptr->on_find_nodes_request())(info_, find_nodes_req,
                                                  &find_nodes_rsp, &time_out);
  ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
  ASSERT_EQ(0U, find_nodes_rsp.closest_nodes_size());

  // Signal StoreRequest
  protobuf::StoreRequest store_request = MakeStoreRequest(sender, kvs);
  std::string message = store_request.SerializeAsString();
  std::string message_sig =
      crypto::AsymSign(message, crypto_key_data.private_key());
  protobuf::StoreResponse store_response;
  (*message_handler_ptr->on_store_request())(info_, store_request, message,
      message_sig, &store_response, &time_out);
  EXPECT_TRUE(store_response.result());

  // Signal StoreRefresh
  protobuf::StoreRefreshRequest store_refresh_request;
  store_refresh_request.mutable_sender()->CopyFrom(ToProtobuf(sender));
  store_refresh_request.set_serialised_store_request(message);
  store_refresh_request.set_serialised_store_request_signature(message_sig);
  protobuf::StoreRefreshResponse store_refresh_response;
  (*message_handler_ptr->on_store_refresh_request())(info_,
                                                     store_refresh_request,
                                                     &store_refresh_response,
                                                     &time_out);
  EXPECT_TRUE(store_refresh_response.result());
  JoinNetworkLookup(securifier_);

  // Signal DeleteRequest
  protobuf::DeleteRequest delete_request = MakeDeleteRequest(sender, kvs);
  std::string delete_message = delete_request.SerializeAsString();
  std::string delete_message_sig =
      crypto::AsymSign(delete_message, crypto_key_data.private_key());
  protobuf::DeleteResponse delete_response;
  (*message_handler_ptr->on_delete_request())(info_, delete_request,
                                              delete_message,
                                              delete_message_sig,
                                              &delete_response,
                                              &time_out);
  EXPECT_TRUE(delete_response.result());

  // Signal DeleteRefreshRequest
  protobuf::DeleteRefreshRequest delete_refresh_request;
  delete_refresh_request.mutable_sender()->CopyFrom(ToProtobuf(sender));
  delete_refresh_request.set_serialised_delete_request(delete_message);
  delete_refresh_request.
      set_serialised_delete_request_signature(delete_message_sig);
  protobuf::DeleteRefreshResponse delete_refresh_response;
  (*message_handler_ptr->on_delete_refresh_request())(info_,
                                                      delete_refresh_request,
                                                      &delete_refresh_response,
                                                      &time_out);
  EXPECT_TRUE(delete_refresh_response.result());

  // Signal DownlistNotification
  protobuf::DownlistNotification downlist_request;
  service_->Downlist(info_, downlist_request, &time_out);
  (*message_handler_ptr->on_downlist_notification())(info_, downlist_request,
                                                     &time_out);
  EXPECT_EQ(0U, num_of_pings_);
  JoinNetworkLookup(securifier_);
}

}  // namespace test_service

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe
