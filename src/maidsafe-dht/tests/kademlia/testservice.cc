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

#include "maidsafe-dht/common/alternative_store.h"
#include "maidsafe-dht/common/crypto.h"
#include "maidsafe-dht/common/log.h"
#include "maidsafe-dht/common/utils.h"
#include "maidsafe-dht/kademlia/datastore.h"
#include "maidsafe-dht/kademlia/service.h"
#include "maidsafe-dht/kademlia/routing_table.h"
#include "maidsafe-dht/kademlia/rpcs.pb.h"
#include "maidsafe-dht/kademlia/utils.h"
#include "maidsafe-dht/transport/transport.h"
#include "maidsafe-dht/transport/udttransport.h"

// #include "maidsafe-dht/tests/validationimpl.h"
// #include "maidsafe-dht/tests/kademlia/fake_callbacks.h"

namespace maidsafe {

namespace kademlia {

namespace test {

static const boost::uint16_t k = 16;
/*
inline void CreateRSAKeys(std::string *pub_key, std::string *priv_key) {
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  *pub_key =  kp.public_key();
  *priv_key = kp.private_key();
}

inline void CreateSignedRequest(const std::string &pub_key,
                                const std::string &priv_key,
                                const std::string &key,
                                std::string *pub_key_val,
                                std::string *sig_req) {
}

inline void CreateDecodedKey(std::string *key) {
  crypto::Crypto cobj;
  cobj.set_hash_algorithm(crypto::SHA_512);
  *key = cobj.Hash(RandomString(64), "", crypto::STRING_STRING, false);
}

class DummyAltStore : public AlternativeStore {
 public:
  DummyAltStore() : keys_() {}
  bool Has(const std::string &key) { return keys_.find(key) != keys_.end();}
  void Store(const std::string &key) { keys_.insert(key); }

 private:
  std::set<std::string> keys_;
};

class Callback {
 public:
  void CallbackFunction() {}
};
*/

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
 protected:
  ServicesTest() : contact_(), node_id_(NodeId::kRandomId), service_(),
                   data_store_(new kademlia::DataStore(bptime::seconds(3600))),
                   routing_table_(new RoutingTable(node_id_, test::k)),
                   alternative_store_(), securifier_(),
                   info_(), rank_info_() {
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

  KeyValueTuple MakeKVT(const crypto::RsaKeyPair &rsa_key_pair,
                        const size_t &value_size,
                        const bptime::time_duration &ttl,
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
    bptime::ptime now = bptime::microsec_clock::universal_time();
    bptime::ptime expire_time = now + ttl;
    bptime::ptime refresh_time = now + bptime::minutes(30);
    std::string request = RandomString(1024);
    std::string req_sig = crypto::AsymSign(request, rsa_key_pair.private_key());
    return KeyValueTuple(KeyValueSignature(key, value, signature),
                         expire_time, refresh_time,
                         RequestAndSignature(request, req_sig), false);
  }

  void Clear () {
    routing_table_->Clear();
    data_store_->key_value_index_->clear();
  }

  virtual void TearDown() {}

 protected:
  Contact ComposeContact(const NodeId& node_id, boost::uint16_t port) {
    std::string ip("127.0.0.1");
    std::vector<transport::Endpoint> local_endpoints;
    transport::Endpoint end_point(ip, port);
    local_endpoints.push_back(end_point);
    Contact contact(node_id, end_point, local_endpoints, end_point, false,
                    false);
    return contact;
  }

  void PopulateDataStore (boost::uint16_t count) {
    bptime::time_duration old_ttl(bptime::pos_infin);
    for (int i=0; i < count; ++i) {
      crypto::RsaKeyPair crypto_key;
      crypto_key.GenerateKeys(1024);
      KeyValueTuple cur_kvt = MakeKVT(crypto_key, 1024, old_ttl, "", "");
      EXPECT_TRUE(data_store_->StoreValue(cur_kvt.key_value_signature, old_ttl,
          cur_kvt.request_and_signature, crypto_key.public_key(), false));
    }
  }   

  void PopulateRoutingTable (boost::uint16_t count) {
    for (int num_contact = 0; num_contact < count; ++num_contact) {
      NodeId contact_id(NodeId::kRandomId);
      Contact contact = ComposeContact(contact_id, 5000);
      routing_table_->AddContact(contact, rank_info_);
    }
  } 
  void PopulateRoutingTable (boost::uint16_t count, boost::uint16_t pos) {
    for (int num_contact = 0; num_contact < count; ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(node_id_, pos);
      Contact contact = ComposeContact(contact_id, 5000);
      routing_table_->AddContact(contact, rank_info_);
    }    
  }

  size_t GetRoutingTableSize() const {
    return routing_table_->Size();
  }

  size_t GetDataStoreSize() const {
    return data_store_->key_value_index_->size();
  }  

  Contact contact_;
  kademlia::NodeId node_id_;
  std::shared_ptr<Service> service_;
  std::shared_ptr<DataStore> data_store_;
  std::shared_ptr<RoutingTable> routing_table_;
  AlternativeStorePtr alternative_store_;
  SecurifierPtr securifier_;
  transport::Info info_;
  RankInfoPtr rank_info_;
/*  int AddCtc(Contact ctc, const float&, const bool &only_db) {
    if (!only_db)
      return routingtable_->AddContact(ctc);
    return -1;
  }
  bool GetCtc(const kademlia::NodeId &id, Contact *ctc) {
    return routingtable_->GetContact(id, ctc);
  }
  void GetRandCtcs(const size_t &count, const std::vector<Contact> &ex_ctcs,
                   std::vector<Contact> *ctcs) {
    ctcs->clear();
    std::vector<Contact> all_contacts;
    int kbuckets = routingtable_->KbucketSize();
    for (int i = 0; i < kbuckets; ++i) {
      std::vector<Contact> contacts_i;
      routingtable_->GetContacts(i, ex_ctcs, &contacts_i);
      for (int j = 0; j < static_cast<int>(contacts_i.size()); ++j)
        all_contacts.push_back(contacts_i[j]);
    }
    std::random_shuffle(all_contacts.begin(), all_contacts.end());
    all_contacts.resize(std::min(all_contacts.size(), count));
    *ctcs = all_contacts;
  }
  void GetKCtcs(const kademlia::NodeId &key, const std::vector<Contact> &ex_ctcs,
                std::vector<Contact> *ctcs) {
    routingtable_->FindCloseNodes(key, test_service::K, ex_ctcs, ctcs);
  }
  void Ping(const Contact &ctc, VoidFunctorOneString callback) {
    boost::thread thrd(boost::bind(&ServicesTest::ExePingCb, this,
                                   ctc.node_id(), callback));
  }
  void ExePingCb(const kademlia::NodeId &id, VoidFunctorOneString callback) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    routingtable_->RemoveContact(id, true);
    PingResponse resp;
    resp.set_result(false);
    callback(resp.SerializeAsString());
  }
  void RemoveContact(const NodeId&) {}
  */
};

TEST_F(ServicesTest, BEH_KAD_Find_Nodes) {
  NodeId target_id = GenerateUniqueRandomId(node_id_, 503);
  Contact target=ComposeContact(target_id, 5001);
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact sender=ComposeContact(sender_id, 5001);
  Clear();
  {
    // try to find a node from an empty routing table
    Service service(routing_table_, data_store_,
                    alternative_store_, securifier_);
    service.set_node_joined(true);
    
    protobuf::FindNodesRequest find_nodes_req;
    find_nodes_req.mutable_sender()->CopyFrom(ToProtobuf(sender));
    find_nodes_req.set_key(target_id.String());
    protobuf::FindNodesResponse find_nodes_rsp;
    service.FindNodes(info_, find_nodes_req, &find_nodes_rsp);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(0, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(1, GetRoutingTableSize());
    // the sender must be pushed into the routing table
    Contact pushed_in;
    routing_table_->GetContact(sender_id, &pushed_in);
    ASSERT_EQ(sender_id, pushed_in.node_id());
  }
  Clear();
  {
    // try to find the target from an k/2 filled routing table
    // (not containing the target)
    PopulateRoutingTable (test::k / 2);
    EXPECT_EQ(test::k / 2, GetRoutingTableSize());

    Service service(routing_table_, data_store_,
                    alternative_store_, securifier_);
    service.set_node_joined(true);
    protobuf::FindNodesRequest find_nodes_req;
    find_nodes_req.mutable_sender()->CopyFrom(ToProtobuf(sender));
    find_nodes_req.set_key(target_id.String());
    protobuf::FindNodesResponse find_nodes_rsp;
    service.FindNodes(info_, find_nodes_req, &find_nodes_rsp);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(test::k / 2, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(test::k / 2 + 1, GetRoutingTableSize());
    // the sender must be pushed into the routing table
    Contact pushed_in;
    routing_table_->GetContact(sender_id, &pushed_in);
    ASSERT_EQ(sender_id, pushed_in.node_id());
  }
  Clear();
  {
    // try to find the target from a 2*k filled routing table
    // (not containing the target)
    PopulateRoutingTable(test::k, 500);
    PopulateRoutingTable(test::k, 501);
    EXPECT_EQ(2 * test::k, GetRoutingTableSize());

    Service service(routing_table_, data_store_,
                    alternative_store_, securifier_);
    service.set_node_joined(true);
    protobuf::FindNodesRequest find_nodes_req;
    find_nodes_req.mutable_sender()->CopyFrom(ToProtobuf(sender));
    find_nodes_req.set_key(target_id.String());
    protobuf::FindNodesResponse find_nodes_rsp;
    service.FindNodes(info_, find_nodes_req, &find_nodes_rsp);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(test::k, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(2 * test::k + 1, GetRoutingTableSize());
    // the sender must be pushed into the routing table
    Contact pushed_in;
    routing_table_->GetContact(sender_id, &pushed_in);
    ASSERT_EQ(sender_id, pushed_in.node_id());
  }
  Clear();
  {
    // try to find the target from a 2*k filled routing table
    // (containing the target)
    PopulateRoutingTable(test::k, 500);
    PopulateRoutingTable(test::k - 1, 501);    
    routing_table_->AddContact(target, rank_info_);
    EXPECT_EQ(2 * test::k, GetRoutingTableSize());

    Service service(routing_table_, data_store_,
                    alternative_store_, securifier_);
    service.set_node_joined(true);
    protobuf::FindNodesRequest find_nodes_req;
    find_nodes_req.mutable_sender()->CopyFrom(ToProtobuf(sender));
    find_nodes_req.set_key(target_id.String());
    protobuf::FindNodesResponse find_nodes_rsp;
    service.FindNodes(info_, find_nodes_req, &find_nodes_rsp);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(test::k, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(2 * test::k + 1, GetRoutingTableSize());
    // the target must be contained in the response's closest_nodes
    bool target_exist(false);
    for (int i=0; i < find_nodes_rsp.closest_nodes_size(); ++i) {
      Contact current(FromProtobuf(find_nodes_rsp.closest_nodes(i)));
      if (current.node_id() == target_id)
        target_exist = true;
    }
    ASSERT_EQ(true, target_exist);
    // the sender must be pushed into the routing table
    Contact pushed_in;
    routing_table_->GetContact(sender_id, &pushed_in);
    ASSERT_EQ(sender_id, pushed_in.node_id());
  }
  Clear();
  {
    // try to find the target from a 2*k+1 filled routing table
    // (containing the sender, but not containing the target)
    PopulateRoutingTable(test::k, 500);
    PopulateRoutingTable(test::k, 501);
    routing_table_->AddContact(sender, rank_info_);
    EXPECT_EQ(2 * test::k + 1, GetRoutingTableSize());

    Service service(routing_table_, data_store_,
                    alternative_store_, securifier_);
    service.set_node_joined(true);
    protobuf::FindNodesRequest find_nodes_req;
    find_nodes_req.mutable_sender()->CopyFrom(ToProtobuf(sender));
    find_nodes_req.set_key(target_id.String());
    protobuf::FindNodesResponse find_nodes_rsp;
    service.FindNodes(info_, find_nodes_req, &find_nodes_rsp);
    ASSERT_EQ(true, find_nodes_rsp.IsInitialized());
    ASSERT_EQ(test::k, find_nodes_rsp.closest_nodes_size());
    ASSERT_EQ(2 * test::k + 1, GetRoutingTableSize());
  }
  Clear();
}

TEST_F(ServicesTest, BEH_KAD_ServicesFindValue) {
  NodeId target_id = GenerateUniqueRandomId(node_id_, 503);
  Contact target=ComposeContact(target_id, 5001);
  NodeId sender_id = GenerateUniqueRandomId(node_id_, 502);
  Contact sender=ComposeContact(sender_id, 5001);
  {
    // Search in empty routing table and datastore
    // no alternative_store_
    protobuf::FindValueRequest find_value_req;
    protobuf::FindValueResponse find_value_rsp;
    find_value_req.mutable_sender()->CopyFrom(ToProtobuf(sender));
    find_value_req.set_key(target_id.String());
    Service service(routing_table_, data_store_,
                alternative_store_, securifier_);
    service.set_node_joined(true);
    service.FindValue(info_, find_value_req, &find_value_rsp);
    ASSERT_TRUE(find_value_rsp.result());
    ASSERT_EQ(0U, find_value_rsp.closest_nodes_size());
    ASSERT_EQ(1U, GetRoutingTableSize());
    // the sender must be pushed into the routing table
    Contact pushed_in;
    routing_table_->GetContact(sender_id, &pushed_in);
    ASSERT_EQ(sender_id, pushed_in.node_id());
  }
  Clear();
  {
    // Search in empty datastore
    // but with 2*k+1 populated routing table (containing the key)
    // no alternative_store_
    PopulateRoutingTable(test::k, 500);
    PopulateRoutingTable(test::k, 501);
    routing_table_->AddContact(target, rank_info_);
    protobuf::FindValueRequest find_value_req;
    protobuf::FindValueResponse find_value_rsp;
    find_value_req.mutable_sender()->CopyFrom(ToProtobuf(sender));
    find_value_req.set_key(target_id.String());
    Service service(routing_table_, data_store_,
                alternative_store_, securifier_);
    service.set_node_joined(true);
    service.FindValue(info_, find_value_req, &find_value_rsp);
    ASSERT_TRUE(find_value_rsp.result());
    ASSERT_EQ(test::k, find_value_rsp.closest_nodes_size());
    // the target must be contained in the response's closest_nodes
    bool target_exist(false);
    for (int i=0; i < find_value_rsp.closest_nodes_size(); ++i) {
      Contact current(FromProtobuf(find_value_rsp.closest_nodes(i)));
      if (current.node_id() == target_id)
        target_exist = true;
    }
    ASSERT_TRUE(target_exist);
    ASSERT_EQ(2 * test::k + 2, GetRoutingTableSize());
    // the sender must be pushed into the routing table
    Contact pushed_in;
    routing_table_->GetContact(sender_id, &pushed_in);
    ASSERT_EQ(sender_id, pushed_in.node_id());    
  }
  Clear();
  {
    // Search in k populated datastore (not containing the target)
    // but with an empty routing table
    // no alternative_store_
    PopulateDataStore(test::k);
    ASSERT_EQ(test::k, GetDataStoreSize());
    protobuf::FindValueRequest find_value_req;
    protobuf::FindValueResponse find_value_rsp;
    find_value_req.mutable_sender()->CopyFrom(ToProtobuf(sender));
    find_value_req.set_key(target_id.String());
    Service service(routing_table_, data_store_,
                alternative_store_, securifier_);
    service.set_node_joined(true);
    service.FindValue(info_, find_value_req, &find_value_rsp);
    ASSERT_TRUE(find_value_rsp.result());
    ASSERT_EQ(0U, find_value_rsp.closest_nodes_size());
    ASSERT_EQ(1U, GetRoutingTableSize());
    // the sender must be pushed into the routing table
    Contact pushed_in;
    routing_table_->GetContact(sender_id, &pushed_in);
    ASSERT_EQ(sender_id, pushed_in.node_id());
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
    protobuf::FindValueRequest find_value_req;
    protobuf::FindValueResponse find_value_rsp;
    find_value_req.mutable_sender()->CopyFrom(ToProtobuf(sender));
    find_value_req.set_key(target_key);
    Service service(routing_table_, data_store_,
                alternative_store_, securifier_);
    service.set_node_joined(true);
    service.FindValue(info_, find_value_req, &find_value_rsp);
    ASSERT_TRUE(find_value_rsp.result());
    ASSERT_EQ(target_value, (*find_value_rsp.mutable_signed_values(0)).value());
    ASSERT_EQ(0U, find_value_rsp.closest_nodes_size());
    ASSERT_EQ(1U, GetRoutingTableSize());
    // the sender must be pushed into the routing table
    Contact pushed_in;
    routing_table_->GetContact(sender_id, &pushed_in);
    ASSERT_EQ(sender_id, pushed_in.node_id());    
  }
  Clear();
  {
    // Search in k populated datastore (not containing the target)
    // with empty routing table
    // with alternative_store_ (not containing the target)
    PopulateDataStore(test::k);
    ASSERT_EQ(test::k, GetDataStoreSize());
    protobuf::FindValueRequest find_value_req;
    protobuf::FindValueResponse find_value_rsp;
    find_value_req.mutable_sender()->CopyFrom(ToProtobuf(sender));
    find_value_req.set_key(target_key);
    AlternativeStoreFalsePtr
        alternative_store_false_ptr(new AlternativeStoreFalse());
    Service service(routing_table_, data_store_,
                    alternative_store_false_ptr, securifier_);
    service.set_node_joined(true);
    service.FindValue(info_, find_value_req, &find_value_rsp);
    ASSERT_TRUE(find_value_rsp.result());
    ASSERT_EQ(0U, find_value_rsp.mutable_signed_values()->size());
    ASSERT_EQ(Contact(),
        FromProtobuf((*find_value_rsp.mutable_alternative_value_holder())));
    ASSERT_EQ(0U, find_value_rsp.closest_nodes_size());
    ASSERT_EQ(1U, GetRoutingTableSize());
    // the sender must be pushed into the routing table
    Contact pushed_in;
    routing_table_->GetContact(sender_id, &pushed_in);
    ASSERT_EQ(sender_id, pushed_in.node_id());      
  }
  Clear();

  Contact node_contact = ComposeContact(node_id_, 5000);
  {
    // Search in k populated datastore (not containing the target)
    // with empty routing table
    // with alternative_store_ (containing the target)
    PopulateDataStore(test::k);
    ASSERT_EQ(test::k, GetDataStoreSize());
    protobuf::FindValueRequest find_value_req;
    protobuf::FindValueResponse find_value_rsp;
    find_value_req.mutable_sender()->CopyFrom(ToProtobuf(sender));
    find_value_req.set_key(target_key);
    AlternativeStoreTruePtr
        alternative_store_true_ptr(new AlternativeStoreTrue());
    Service service(routing_table_, data_store_,
                    alternative_store_true_ptr, securifier_);                    
    service.set_node_joined(true);
    service.set_node_contact(node_contact);
    service.FindValue(info_, find_value_req, &find_value_rsp);
    ASSERT_TRUE(find_value_rsp.result());
    ASSERT_EQ(0U, find_value_rsp.mutable_signed_values()->size());
    ASSERT_EQ(node_contact,
        FromProtobuf((*find_value_rsp.mutable_alternative_value_holder())));
    ASSERT_EQ(0U, find_value_rsp.closest_nodes_size());
    ASSERT_EQ(1U, GetRoutingTableSize());
    // the sender must be pushed into the routing table
    Contact pushed_in;
    routing_table_->GetContact(sender_id, &pushed_in);
    ASSERT_EQ(sender_id, pushed_in.node_id());     
  }   
}

/*
TEST_F(ServicesTest, BEH_KAD_ServicesPing) {
  // Check failure with ping set incorrectly.
  rpcprotocol::Controller controller;
  PingRequest ping_request;
  ping_request.set_ping("doink");
  ContactInfo *sender_info = ping_request.mutable_sender_info();
  *sender_info = contact_;
  PingResponse ping_response;
  Callback cb_obj;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
                                     (&cb_obj, &Callback::CallbackFunction);
  service_->Ping(&controller, &ping_request, &ping_response, done1);
  while (!ping_response.IsInitialized())
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  EXPECT_TRUE(ping_response.IsInitialized());
  EXPECT_FALSE(ping_response.result());
  EXPECT_FALSE(ping_response.has_echo());
  EXPECT_EQ(node_id_.String(), ping_response.node_id());
  Contact contactback;
  EXPECT_FALSE(routingtable_->GetContact(kademlia::NodeId(contact_.node_id()),
                                         &contactback));
  // Check success.
  ping_request.set_ping("ping");
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
                                     (&cb_obj, &Callback::CallbackFunction);
  ping_response.Clear();
  service_->Ping(&controller, &ping_request, &ping_response, done2);
  while (!ping_response.IsInitialized())
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  EXPECT_TRUE(ping_response.IsInitialized());
  EXPECT_TRUE(ping_response.result());
  EXPECT_EQ("pong", ping_response.echo());
  EXPECT_EQ(node_id_.String(), ping_response.node_id());
  EXPECT_TRUE(routingtable_->GetContact(kademlia::NodeId(contact_.node_id()),
                                        &contactback));
}



TEST_F(ServicesTest, BEH_KAD_ServicesStore) {
  // Store value1
  rpcprotocol::Controller controller;
  StoreRequest store_request;
  std::string hex_key;
  for (int i = 0; i < 128; ++i)
    hex_key += "a";
  std::string value1("Val1"), value2("Val2"), value3("Val10");
  std::string public_key, private_key, public_key_validation, request_signature;
  std::string key = DecodeFromHex(hex_key);
  CreateRSAKeys(&public_key, &private_key);
  CreateSignedRequest(public_key, private_key, key, &public_key_validation,
                      &request_signature);
  store_request.set_key(key);
  store_request.set_value(value1);
  SignedRequest *sig_req = store_request.mutable_request_signature();
  sig_req->set_signer_id("id1");
  sig_req->set_public_key(public_key);
  sig_req->set_public_key_validation(public_key_validation);
  sig_req->set_request_signature(request_signature);
  store_request.set_publish(true);
  store_request.set_ttl(3600*24);
  ContactInfo *sender_info = store_request.mutable_sender_info();
  *sender_info = contact_;
  StoreResponse store_response;
  Callback cb_obj;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done1);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_FALSE(store_response.result());

  store_request.clear_value();

  SignedValue *svalue = store_request.mutable_sig_value();
  svalue->set_value(value1);
  svalue->set_value_signature(crypto_.AsymSign(value1, "", private_key,
      crypto::STRING_STRING));
  std::string ser_sig_value1(svalue->SerializeAsString());

  google::protobuf::Closure *done4 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done4);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_TRUE(store_response.result());
  EXPECT_EQ(node_id_.String(), store_response.node_id());
  std::vector<std::string> values;
  ASSERT_TRUE(datastore_->LoadItem(key, &values));
  EXPECT_EQ(ser_sig_value1, values[0]);
  Contact contactback;
  EXPECT_TRUE(routingtable_->GetContact(kademlia::NodeId(contact_.node_id()),
      &contactback));

  // Store value2
  // Allow thread to sleep so that second value has a different last published
  // time to first value.
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  svalue->Clear();
  svalue->set_value(value2);
  svalue->set_value_signature(crypto_.AsymSign(value2, "", private_key,
      crypto::STRING_STRING));
  std::string ser_sig_value2(svalue->SerializeAsString());
  store_response.Clear();
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done2);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_TRUE(store_response.result());
  EXPECT_EQ(node_id_.String(), store_response.node_id());
  values.clear();
  EXPECT_TRUE(datastore_->LoadItem(key, &values));
  EXPECT_EQ(ser_sig_value1, values[0]);
  EXPECT_EQ(ser_sig_value2, values[1]);

  // Store value3
  // Allow thread to sleep for same reason as above.
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  svalue->Clear();
  svalue->set_value(value3);
  svalue->set_value_signature(crypto_.AsymSign(value3, "", private_key,
      crypto::STRING_STRING));
  std::string ser_sig_value3(svalue->SerializeAsString());
  store_response.Clear();
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done3);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_TRUE(store_response.result());
  EXPECT_EQ(node_id_.String(), store_response.node_id());
  values.clear();
  EXPECT_TRUE(datastore_->LoadItem(key, &values));
  ASSERT_EQ(3, values.size());
  int valuesfound = 0;
  for (unsigned int i = 0; i < values.size(); i++) {
    if (ser_sig_value1 == values[i]) {
      valuesfound++;
      break;
    }
  }
  for (unsigned int i = 0; i < values.size(); i++) {
    if (ser_sig_value2 == values[i]) {
      valuesfound++;
      break;
    }
  }
  for (unsigned int i = 0; i < values.size(); i++) {
    if (ser_sig_value3 == values[i]) {
      valuesfound++;
      break;
    }
  }
  ASSERT_EQ(3, valuesfound);
}

TEST_F(ServicesTest, BEH_KAD_InvalidStoreValue) {
  std::string value("value4"), value1("value5");
  std::string key = crypto_.Hash(value, "", crypto::STRING_STRING, false);
  rpcprotocol::Controller controller;
  StoreRequest store_request;
  StoreResponse store_response;
  store_request.set_key(key);
  store_request.set_value(value);
  store_request.set_ttl(24*3600);
  store_request.set_publish(true);
  ContactInfo *sender_info = store_request.mutable_sender_info();
  *sender_info = contact_;
  Callback cb_obj;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done1);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_FALSE(store_response.result());
  EXPECT_EQ(node_id_.String(), store_response.node_id());
  store_response.Clear();
  std::vector<std::string> values;
  EXPECT_FALSE(datastore_->LoadItem(key, &values));

  std::string public_key, private_key, public_key_validation, request_signature;
  CreateRSAKeys(&public_key, &private_key);
  CreateSignedRequest(public_key, private_key, key, &public_key_validation,
      &request_signature);

  store_request.clear_value();
  SignedValue *sig_value = store_request.mutable_sig_value();
  sig_value->set_value(value);
  sig_value->set_value_signature(crypto_.AsymSign(value, "", private_key,
      crypto::STRING_STRING));
  std::string ser_sig_value = sig_value->SerializeAsString();

  SignedRequest *sig_req = store_request.mutable_request_signature();
  sig_req->set_signer_id("id1");
  sig_req->set_public_key("public_key");
  sig_req->set_public_key_validation(public_key_validation);
  sig_req->set_request_signature(request_signature);

  google::protobuf::Closure *done6 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done6);
  EXPECT_FALSE(store_response.result());
  EXPECT_EQ(node_id_.String(), store_response.node_id());
  store_response.Clear();
  values.clear();
  EXPECT_FALSE(datastore_->LoadItem(key, &values));

  sig_req->set_public_key(public_key);
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done2);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_TRUE(store_response.result());
  EXPECT_EQ(node_id_.String(), store_response.node_id());
  values.clear();
  EXPECT_TRUE(datastore_->LoadItem(key, &values));
  ASSERT_EQ(1, values.size());
  EXPECT_EQ(ser_sig_value, values[0]);

  store_request.clear_value();
  store_request.clear_sig_value();
  store_request.set_value("other value");
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done3);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_FALSE(store_response.result());
  EXPECT_EQ(node_id_.String(), store_response.node_id());
  values.clear();
  EXPECT_TRUE(datastore_->LoadItem(key, &values));
  ASSERT_EQ(1, values.size());
  ASSERT_EQ(ser_sig_value, values[0]);

  // storing a hashable value
  store_request.Clear();
  store_response.Clear();
  SignedValue *sig_value1 = store_request.mutable_sig_value();
  sig_value1->set_value(value1);
  sig_value1->set_value_signature(crypto_.AsymSign(value1, "", private_key,
      crypto::STRING_STRING));
  std::string ser_sig_value1 = sig_value1->SerializeAsString();

  std::string key1 = crypto_.Hash(ser_sig_value1, "", crypto::STRING_STRING,
      false);
  ContactInfo *sender_info1 = store_request.mutable_sender_info();
  *sender_info1 = contact_;
  store_request.set_key(key1);
  store_request.set_publish(true);
  store_request.set_ttl(24*3600);
  public_key_validation = "";
  request_signature = "";
  CreateSignedRequest(public_key, private_key, key1, &public_key_validation,
      &request_signature);
  SignedRequest *sig_req1 = store_request.mutable_request_signature();
  sig_req1->set_signer_id("id1");
  sig_req1->set_public_key(public_key);
  sig_req1->set_public_key_validation(public_key_validation);
  sig_req1->set_request_signature(request_signature);
  google::protobuf::Closure *done4 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done4);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_TRUE(store_response.result());
  EXPECT_EQ(node_id_.String(), store_response.node_id());
  values.clear();
  EXPECT_TRUE(datastore_->LoadItem(key1, &values));
  ASSERT_EQ(1, values.size());
  EXPECT_EQ(ser_sig_value1, values[0]);

  store_request.clear_sig_value();
  sig_value1->Clear();
  sig_value1->set_value("other value");
  sig_value1->set_value_signature(crypto_.AsymSign("other value", "",
      private_key, crypto::STRING_STRING));
  std::string ser_sig_value2 = sig_value1->SerializeAsString();
  google::protobuf::Closure *done5 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &store_request, &store_response, done5);
  EXPECT_TRUE(store_response.IsInitialized());
  EXPECT_FALSE(store_response.result());
  EXPECT_EQ(node_id_.String(), store_response.node_id());
  values.clear();
  EXPECT_TRUE(datastore_->LoadItem(key1, &values));
  ASSERT_EQ(1, values.size());
  ASSERT_EQ(ser_sig_value1, values[0]);
}

TEST_F(ServicesTest, FUNC_KAD_ServicesDownlist) {
  // Set up details of 10 nodes and add 7 of these to the routing table.
  std::vector<Contact> contacts;
  int rt(0);
  for (int i = 0; i < 10; ++i) {
    std::string character = boost::lexical_cast<std::string>(i);
    std::string hex_id, id;
    for (int j = 0; j < 128; ++j)
      hex_id += character;
    id = DecodeFromHex(hex_id);
    std::string ip("127.0.0.6");
    boost::uint16_t port = 9000 + i;
    Contact contact(id, ip, port, ip, port);
    if (rt < 7 && rt == i && 0 == routingtable_->AddContact(contact))
      ++rt;
    contacts.push_back(contact);
  }
  ASSERT_EQ(rt, routingtable_->Size());

  // Check downlisting nodes we don't have returns failure
  rpcprotocol::Controller controller;
  DownlistRequest downlist_request;
  Contact ctc;
  for (int i = rt; i < 10; ++i) {
    std::string dead_node;
    ASSERT_FALSE(routingtable_->GetContact(contacts[i].node_id(), &ctc));
    if (contacts[i].SerialiseToString(&dead_node))
      downlist_request.add_downlist(dead_node);
  }
  ContactInfo *sender_info = downlist_request.mutable_sender_info();
  *sender_info = contact_;
  DownlistResponse downlist_response;
  Callback cb_obj;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->Downlist(&controller, &downlist_request, &downlist_response, done1);
  // Give the function time to allow any ping rpcs to timeout (they shouldn't
  // be called though)
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  EXPECT_EQ(rt + 1, routingtable_->Size());

  // Check downlist works for one we have.
  downlist_request.clear_downlist();
  std::string dead_node;
  ASSERT_TRUE(routingtable_->GetContact(contacts[rt / 2].node_id(), &ctc));
  if (contacts[rt / 2].SerialiseToString(&dead_node))
    downlist_request.add_downlist(dead_node);
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  downlist_response.Clear();
  service_->Downlist(&controller, &downlist_request, &downlist_response, done2);
  int timeout = 8000;  // milliseconds
  int count = 0;
  while (routingtable_->Size() >= size_t(rt) && count < timeout) {
    count += 50;
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  }
  EXPECT_EQ(rt, routingtable_->Size());
  Contact testcontact;
  EXPECT_FALSE(routingtable_->GetContact(contacts[rt / 2].node_id(),
                                         &testcontact));

  // Check downlist works for one we have and one we don't.
  downlist_request.clear_downlist();
  for (int i = rt - 1; i <= rt; ++i) {
    std::string dead_node;
    if (contacts[i].SerialiseToString(&dead_node))
      downlist_request.add_downlist(dead_node);
  }
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  downlist_response.Clear();
  service_->Downlist(&controller, &downlist_request, &downlist_response, done3);
  count = 0;
  while (routingtable_->Size() >= size_t(rt - 1) && count < timeout) {
    count += 50;
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  }
  EXPECT_EQ(rt - 1, routingtable_->Size());
  EXPECT_FALSE(routingtable_->GetContact(contacts[rt - 1].node_id(),
                                         &testcontact));

  // Check downlist with multiple valid nodes
  downlist_request.clear_downlist();
  for (int i = 2; i <= rt - 1; ++i) {
    std::string dead_node;
    if (contacts[i].SerialiseToString(&dead_node))
      downlist_request.add_downlist(dead_node);
  }
  google::protobuf::Closure *done4 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  downlist_response.Clear();
  service_->Downlist(&controller, &downlist_request, &downlist_response, done4);
  count = 0;
  while ((routingtable_->Size() > 2) && (count < timeout)) {
    count += 50;
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  }
  EXPECT_EQ(3, routingtable_->Size());
  for (int i = 0; i < rt - 1; ++i) {
    if (i > 1)
      EXPECT_FALSE(routingtable_->GetContact(contacts[i].node_id(),
                   &testcontact));
    else
      EXPECT_TRUE(routingtable_->GetContact(contacts[i].node_id(),
                  &testcontact));
  }
}

TEST_F(ServicesTest, BEH_KAD_ServicesFindValAltStore) {
  DummyAltStore dummy_alt_store;
  service_->set_alternative_store(&dummy_alt_store);
  // Search in empty alt store, routing table and datastore
  rpcprotocol::Controller controller;
  FindRequest find_value_request;
  std::string hex_key(128, 'a'), public_key, private_key;
  CreateRSAKeys(&public_key, &private_key);
  std::string key = DecodeFromHex(hex_key);
  find_value_request.set_key(key);
  *(find_value_request.mutable_sender_info()) = contact_;
  find_value_request.set_is_boostrap(false);
  FindResponse find_value_response;
  Callback cb_obj;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  service_->FindValue(&controller, &find_value_request, &find_value_response,
                      done1);
  EXPECT_TRUE(find_value_response.IsInitialized());
  EXPECT_TRUE(find_value_response.result());
  EXPECT_EQ(0, find_value_response.closest_nodes_size());
  EXPECT_EQ(0, find_value_response.values_size());
  EXPECT_FALSE(find_value_response.has_requester_ext_addr());
  EXPECT_EQ(node_id_.String(), find_value_response.node_id());
  Contact contactback;
  EXPECT_TRUE(routingtable_->GetContact(kademlia::NodeId(contact_.node_id()),
      &contactback));
  // Populate routing table & datastore & search for non-existant key.  Ensure k
  // contacts have IDs close to key being searched for.
  std::vector<std::string> ids;
  for (int i = 0; i < 50; ++i) {
    std::string character = "1";
    std::string hex_id = "";
    if (i < test_service::K)
      character = "a";
    for (int j = 0; j < 126; ++j)
      hex_id += character;
    hex_id += boost::lexical_cast<std::string>(i+10);
    std::string id = DecodeFromHex(hex_id);
    if (i < test_service::K)
      ids.push_back(id);
    std::string ip = "127.0.0.6";
    boost::uint16_t port = 9000+i;
    Contact ctct;
    ASSERT_FALSE(routingtable_->GetContact(node_id_, &ctct));
    Contact contact(id, ip, port + i, ip, port + i);
    EXPECT_GE(routingtable_->AddContact(contact), 0);
  }
  EXPECT_GE(routingtable_->Size(), static_cast<size_t>(2*test_service::K));
  std::string wrong_hex_key(128, 'b');
  std::string wrong_key = DecodeFromHex(wrong_hex_key);
  EXPECT_TRUE(datastore_->StoreItem(wrong_key, "X", 24*3600, false));
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  find_value_response.Clear();
  service_->FindValue(&controller, &find_value_request, &find_value_response,
                      done2);
  EXPECT_TRUE(find_value_response.IsInitialized());
  EXPECT_TRUE(find_value_response.result());
  EXPECT_EQ(test_service::K, find_value_response.closest_nodes_size());

  std::vector<std::string>::iterator itr;
  for (int i = 0; i < test_service::K; ++i) {
    Contact contact;
    contact.ParseFromString(find_value_response.closest_nodes(i));
    for (itr = ids.begin(); itr < ids.end(); ++itr) {
      if (*itr == contact.node_id().String()) {
        ids.erase(itr);
        break;
      }
    }
  }
  EXPECT_EQ(static_cast<unsigned int>(0), ids.size());
  EXPECT_EQ(0, find_value_response.values_size());
  EXPECT_EQ(0, find_value_response.signed_values_size());
  EXPECT_FALSE(find_value_response.has_alternative_value_holder());
  EXPECT_FALSE(find_value_response.has_needs_cache_copy());
  EXPECT_FALSE(find_value_response.has_requester_ext_addr());
  EXPECT_EQ(node_id_.String(), find_value_response.node_id());

  // Populate datastore & search for existing key
  std::vector<std::string> values;
  for (int i = 0; i < 100; ++i) {
    values.push_back("Value"+boost::lexical_cast<std::string>(i));
    SignedValue sig_value;
    sig_value.set_value(values[i]);
    sig_value.set_value_signature(crypto_.AsymSign(values[i], "", private_key,
        crypto::STRING_STRING));
    std::string ser_sig_value = sig_value.SerializeAsString();
    EXPECT_TRUE(datastore_->StoreItem(key, ser_sig_value, 24*3600, false));
  }
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  find_value_response.Clear();
  service_->FindValue(&controller, &find_value_request, &find_value_response,
      done3);
  EXPECT_TRUE(find_value_response.IsInitialized());
  EXPECT_TRUE(find_value_response.result());
  EXPECT_EQ(0, find_value_response.closest_nodes_size());
  EXPECT_EQ(0, find_value_response.values_size());
  ASSERT_EQ(100, find_value_response.signed_values_size());
  for (int i = 0; i < 100; ++i) {
    bool found = false;
    for (int j = 0; j < 100; ++j) {
      if (values[i] == find_value_response.signed_values(j).value()) {
        found = true;
        break;
      }
    }
    if (!found)
      FAIL() << "value " << values[i] << " not in response";
  }
  EXPECT_FALSE(find_value_response.has_alternative_value_holder());
  EXPECT_FALSE(find_value_response.has_needs_cache_copy());
  EXPECT_FALSE(find_value_response.has_requester_ext_addr());
  EXPECT_EQ(node_id_.String(), find_value_response.node_id());

  // Populate alt store & search for existing key
  dummy_alt_store.Store(key);
  EXPECT_TRUE(dummy_alt_store.Has(key));
  dummy_alt_store.Store(wrong_key);
  EXPECT_TRUE(dummy_alt_store.Has(wrong_key));
  google::protobuf::Closure *done4 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  find_value_response.Clear();
  service_->FindValue(&controller, &find_value_request, &find_value_response,
      done4);

  EXPECT_TRUE(find_value_response.IsInitialized());
  EXPECT_TRUE(find_value_response.result());
  EXPECT_EQ(0, find_value_response.closest_nodes_size());
  EXPECT_EQ(0, find_value_response.values_size());
  EXPECT_TRUE(find_value_response.has_alternative_value_holder());
  EXPECT_EQ(node_id_.String(),
      find_value_response.alternative_value_holder().node_id());
  EXPECT_FALSE(find_value_response.has_needs_cache_copy());
  EXPECT_FALSE(find_value_response.has_requester_ext_addr());
  EXPECT_EQ(node_id_.String(), find_value_response.node_id());

  find_value_request.set_key(wrong_key);
  google::protobuf::Closure *done5 = google::protobuf::NewCallback<Callback>
      (&cb_obj, &Callback::CallbackFunction);
  find_value_response.Clear();
  service_->FindValue(&controller, &find_value_request, &find_value_response,
      done5);
  EXPECT_TRUE(find_value_response.IsInitialized());
  EXPECT_TRUE(find_value_response.result());
  EXPECT_EQ(0, find_value_response.closest_nodes_size());
  EXPECT_EQ(0, find_value_response.values_size());
  EXPECT_TRUE(find_value_response.has_alternative_value_holder());
  EXPECT_EQ(node_id_.String(),
      find_value_response.alternative_value_holder().node_id());
  EXPECT_FALSE(find_value_response.has_needs_cache_copy());
  EXPECT_FALSE(find_value_response.has_requester_ext_addr());
  EXPECT_EQ(node_id_.String(), find_value_response.node_id());
}

TEST_F(ServicesTest, FUNC_KAD_ServiceDelete) {
  // Store value in kademlia::DataStore
  std::string hex_key;
  for (int i = 0; i < 128; ++i)
    hex_key += "a";
  std::string value1("Val1"), value2("Val2");
  std::string public_key, private_key, public_key_validation, request_signature;
  std::string key = DecodeFromHex(hex_key);
  CreateRSAKeys(&public_key, &private_key);
  CreateSignedRequest(public_key, private_key, key, &public_key_validation,
    &request_signature);

  SignedValue svalue;
  svalue.set_value(value1);
  svalue.set_value_signature(crypto_.AsymSign(value1, "", private_key,
      crypto::STRING_STRING));
  std::string ser_svalue(svalue.SerializeAsString());
  ASSERT_TRUE(datastore_->StoreItem(key, ser_svalue, -1, false));
  svalue.Clear();
  svalue.set_value(value2);
  svalue.set_value_signature(crypto_.AsymSign(value2, "", private_key,
      crypto::STRING_STRING));
  ser_svalue = svalue.SerializeAsString();
  ASSERT_TRUE(datastore_->StoreItem(key, ser_svalue, -1, false));

  std::vector<std::string> values;
  ASSERT_TRUE(datastore_->LoadItem(key, &values));
  ASSERT_EQ(2, values.size());
  int values_found = 0;
  for (unsigned int i = 0; i < values.size(); ++i) {
    svalue.Clear();
    EXPECT_TRUE(svalue.ParseFromString(values[i]));
    if (svalue.value() == value1) {
      ++values_found;
      break;
    }
  }
  for (unsigned int i = 0; i < values.size(); ++i) {
    svalue.Clear();
    EXPECT_TRUE(svalue.ParseFromString(values[i]));
    if (svalue.value() == value2) {
      ++values_found;
      break;
    }
  }
  ASSERT_EQ(2, values_found);
  // setting validator class to NULL
  service_->set_signature_validator(NULL);

  rpcprotocol::Controller controller;
  DeleteRequest delete_request;
  delete_request.set_key(key);
  ContactInfo *sender_info = delete_request.mutable_sender_info();
  SignedValue *req_svalue = delete_request.mutable_value();
  *sender_info = contact_;
  req_svalue->set_value(value1);
  req_svalue->set_value_signature(crypto_.AsymSign(value1, "", private_key,
      crypto::STRING_STRING));
  SignedRequest *sreq = delete_request.mutable_request_signature();
  sreq->set_signer_id("id1");
  sreq->set_public_key(public_key);
  sreq->set_public_key_validation(public_key_validation);
  sreq->set_request_signature(request_signature);
  DeleteResponse delete_response;
  Callback cb_obj;
  google::protobuf::Closure *done =
    google::protobuf::NewPermanentCallback<Callback>(&cb_obj,
    &Callback::CallbackFunction);
  service_->Delete(&controller, &delete_request, &delete_response, done);
  EXPECT_TRUE(delete_response.IsInitialized());
  EXPECT_FALSE(delete_response.result());

  // setting validator
  service_->set_signature_validator(&validator_);
  delete_response.Clear();

  // value does not exists
  req_svalue->set_value("othervalue");
  req_svalue->set_value_signature(crypto_.AsymSign("othervalue", "",
      private_key, crypto::STRING_STRING));
  service_->Delete(&controller, &delete_request, &delete_response, done);
  EXPECT_TRUE(delete_response.IsInitialized());
  EXPECT_FALSE(delete_response.result());
  delete_response.Clear();

  // request sent signed with different key
  req_svalue->set_value(value1);
  req_svalue->set_value_signature(crypto_.AsymSign(value1, "", private_key,
      crypto::STRING_STRING));
  std::string public_key1, private_key1, public_key_validation1, request_signature1;
  CreateRSAKeys(&public_key1, &private_key1);
  CreateSignedRequest(public_key1, private_key1, key, &public_key_validation1,
    &request_signature1);
  sreq->Clear();
  sreq->set_signer_id("id1");
  sreq->set_public_key(public_key);
  sreq->set_public_key_validation(public_key_validation1);
  sreq->set_request_signature(request_signature1);
  service_->Delete(&controller, &delete_request, &delete_response, done);
  EXPECT_TRUE(delete_response.IsInitialized());
  EXPECT_FALSE(delete_response.result());
  delete_response.Clear();

  // correct delete (Marked as delete)
  sreq->Clear();
  sreq->set_signer_id("id1");
  sreq->set_public_key(public_key);
  sreq->set_public_key_validation(public_key_validation);
  sreq->set_request_signature(request_signature);

  service_->Delete(&controller, &delete_request, &delete_response, done);
  EXPECT_TRUE(delete_response.IsInitialized());
  EXPECT_TRUE(delete_response.result());

  // validating DataStore no longer returns value1 and in refresh returns
  // the correct signed request
  values.clear();
  ASSERT_TRUE(datastore_->LoadItem(key, &values));
  ASSERT_EQ(1, values.size());
  svalue.Clear();
  ASSERT_TRUE(svalue.ParseFromString(values[0]));
  EXPECT_EQ(value2, svalue.value());

  // refreshing Deleted value
  svalue.Clear();
  svalue.set_value(value1);
  svalue.set_value_signature(crypto_.AsymSign(value1, "", private_key,
      crypto::STRING_STRING));

  std::string ser_req;
  EXPECT_FALSE(datastore_->RefreshItem(key, svalue.SerializeAsString(),
    &ser_req));
  SignedRequest req;
  ASSERT_TRUE(req.ParseFromString(ser_req));
  ASSERT_EQ(sreq->public_key(), req.public_key());
  ASSERT_EQ(sreq->public_key_validation(), req.public_key_validation());
  ASSERT_EQ(sreq->request_signature(), req.request_signature());

  delete done;
}

TEST_F(ServicesTest, FUNC_KAD_RefreshDeletedValue) {
  std::string value("Value");
  std::string public_key, private_key, public_key_validation, request_signature;
  std::string key = crypto_.Hash(RandomString(5), "",
                                 crypto::STRING_STRING, false);

  SignedValue svalue;
  svalue.set_value(value);
  svalue.set_value_signature(crypto_.AsymSign(value, "", private_key,
                                              crypto::STRING_STRING));
  std::string ser_svalue(svalue.SerializeAsString());
  ASSERT_TRUE(datastore_->StoreItem(key, ser_svalue, -1, false));
  CreateRSAKeys(&public_key, &private_key);
  CreateSignedRequest(public_key, private_key, key, &public_key_validation,
                      &request_signature);
  SignedRequest sreq;
  sreq.set_signer_id("id1");
  sreq.set_public_key(public_key);
  sreq.set_public_key_validation(public_key_validation);
  sreq.set_request_signature(request_signature);
  std::string ser_sreq(sreq.SerializeAsString());
  ASSERT_TRUE(datastore_->MarkForDeletion(key, ser_svalue, ser_sreq));

  rpcprotocol::Controller controller;
  StoreRequest request;
  request.set_key(key);
  public_key.clear();
  private_key.clear();
  request_signature.clear();

  CreateRSAKeys(&public_key, &private_key);
  CreateSignedRequest(public_key, private_key, key, &public_key_validation,
                      &request_signature);
  SignedRequest *sig_req = request.mutable_request_signature();
  sig_req->set_signer_id("id2");
  sig_req->set_public_key(public_key);
  sig_req->set_public_key_validation(public_key_validation);
  sig_req->set_request_signature(request_signature);
  request.set_publish(false);
  request.set_ttl(-1);
  ContactInfo *sender_info = request.mutable_sender_info();
  *sender_info = contact_;
  SignedValue *sig_value = request.mutable_sig_value();
  *sig_value = svalue;
  StoreResponse response;
  Callback cb_obj;
  google::protobuf::Closure *done =
      google::protobuf::NewPermanentCallback<Callback>
          (&cb_obj, &Callback::CallbackFunction);
  service_->Store(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_FALSE(response.result());
  ASSERT_TRUE(response.has_request_signature());
  EXPECT_EQ(sreq.signer_id(), response.request_signature().signer_id());
  EXPECT_EQ(sreq.public_key(), response.request_signature().public_key());
  EXPECT_EQ(sreq.public_key_validation(),
            response.request_signature().public_key_validation());
  EXPECT_EQ(sreq.request_signature(), response.request_signature().request_signature());

  response.Clear();
  ASSERT_TRUE(datastore_->MarkAsDeleted(key, ser_svalue));
  service_->Store(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_FALSE(response.result());
  ASSERT_TRUE(response.has_request_signature());
  EXPECT_EQ(sreq.signer_id(), response.request_signature().signer_id());
  EXPECT_EQ(sreq.public_key(), response.request_signature().public_key());
  EXPECT_EQ(sreq.public_key_validation(),
            response.request_signature().public_key_validation());
  EXPECT_EQ(sreq.request_signature(), response.request_signature().request_signature());
  delete done;
}

TEST_F(ServicesTest, BEH_KAD_UpdateValue) {
  std::string public_key, private_key, publickey_signature, request_signature,
              key;
  CreateDecodedKey(&key);
  CreateRSAKeys(&public_key, &private_key);
  CreateSignedRequest(public_key, private_key, key, &publickey_signature,
                      &request_signature);

  // Fail: Request not initialised
  rpcprotocol::Controller controller;
  UpdateRequest request;
  UpdateResponse response;
  Callback cb_obj;
  google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
                                    (&cb_obj, &Callback::CallbackFunction);
  service_->Update(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_FALSE(response.result());
  ASSERT_EQ(node_id_.String(), response.node_id());

  // Fail: Request not properly initialised
  request.set_key(key);
  SignedValue *new_value = request.mutable_new_value();
  SignedValue *old_value = request.mutable_old_value();
  request.set_ttl(86400);
  SignedRequest *request_signature = request.mutable_request();
  ContactInfo *sender_info = request.mutable_sender_info();
  done = google::protobuf::NewCallback<Callback>
         (&cb_obj, &Callback::CallbackFunction);
  response.Clear();
  service_->Update(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_FALSE(response.result());
  ASSERT_EQ(node_id_.String(), response.node_id());

  // Fail: trying to update non-existent value
  crypto::Crypto co;
  std::string nv(RandomString(16));
  new_value->set_value(nv);
  new_value->set_value_signature(co.AsymSign(nv, "", private_key,
                                             crypto::STRING_STRING));
  std::string ov(RandomString(16));
  old_value->set_value(ov);
  old_value->set_value_signature(co.AsymSign(ov, "", private_key,
                                             crypto::STRING_STRING));

  std::string kad_id(co.Hash(public_key + publickey_signature, "",
                             crypto::STRING_STRING, false));
  request_signature->set_signer_id(kad_id);
  request_signature->set_public_key(public_key);
  request_signature->set_public_key_validation(publickey_signature);
  request_signature->set_request_signature(request_signature);
  *sender_info = contact_;
  done = google::protobuf::NewCallback<Callback>
         (&cb_obj, &Callback::CallbackFunction);
  response.Clear();
  service_->Update(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_FALSE(response.result());
  ASSERT_EQ(node_id_.String(), response.node_id());

  // Fail: Value to update doesn't exist
  size_t total_values(5);
  for (size_t n = 0; n < total_values; ++n) {
    SignedValue sv;
    sv.set_value("value" + IntToString(n));
    sv.set_value_signature(co.AsymSign(sv.value(), "", private_key,
                                       crypto::STRING_STRING));
    ASSERT_TRUE(service_->pdatastore_->StoreItem(key, sv.SerializeAsString(),
                                                 3600 * 24, false));
  }
  done = google::protobuf::NewCallback<Callback>
         (&cb_obj, &Callback::CallbackFunction);
  response.Clear();
  service_->Update(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_FALSE(response.result());
  ASSERT_EQ(node_id_.String(), response.node_id());

  // Fail: New value doesn't validate
  old_value = request.mutable_old_value();
  old_value->set_value("value0");
  old_value->set_value_signature(co.AsymSign(old_value->value(), "",
                                             private_key,
                                             crypto::STRING_STRING));
  new_value = request.mutable_new_value();
  new_value->set_value("valueX");
  new_value->set_value_signature("signature of value X");
  done = google::protobuf::NewCallback<Callback>
         (&cb_obj, &Callback::CallbackFunction);
  response.Clear();
  service_->Update(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_FALSE(response.result());
  ASSERT_EQ(node_id_.String(), response.node_id());

  // Fail: Old value doesn't validate
  std::string wrong_public, wrong_private, wrong_publickey_signature,
              wrong_request_signature;
  CreateRSAKeys(&wrong_public, &wrong_private);
  CreateSignedRequest(wrong_public, wrong_private, key,
                      &wrong_publickey_signature, &wrong_request_signature);
  old_value = request.mutable_old_value();
  old_value->set_value("value0");
  old_value->set_value_signature(co.AsymSign(old_value->value(), "",
                                             private_key,
                                             crypto::STRING_STRING));
  new_value = request.mutable_new_value();
  new_value->set_value("valueX");
  new_value->set_value_signature(co.AsymSign(new_value->value(), "",
                                             wrong_private,
                                             crypto::STRING_STRING));
  request_signature = request.mutable_request();
  request_signature->set_signer_id(kad_id);
  request_signature->set_public_key(wrong_public);
  request_signature->set_public_key_validation(wrong_publickey_signature);
  request_signature->set_request_signature(wrong_request_signature);
  done = google::protobuf::NewCallback<Callback>
         (&cb_obj, &Callback::CallbackFunction);
  response.Clear();
  service_->Update(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_FALSE(response.result());
  ASSERT_EQ(node_id_.String(), response.node_id());

  // Fail: Update fails
  old_value = request.mutable_old_value();
  old_value->set_value("value0");
  old_value->set_value_signature(co.AsymSign(old_value->value(), "",
                                             private_key,
                                             crypto::STRING_STRING));
  new_value = request.mutable_new_value();
  new_value->set_value("value2");
  new_value->set_value_signature(co.AsymSign(new_value->value(), "",
                                             private_key,
                                             crypto::STRING_STRING));
  request_signature = request.mutable_request();
  request_signature->set_signer_id(kad_id);
  request_signature->set_public_key(public_key);
  request_signature->set_public_key_validation(publickey_signature);
  request_signature->set_request_signature(request_signature);
  done = google::protobuf::NewCallback<Callback>
         (&cb_obj, &Callback::CallbackFunction);
  response.Clear();
  service_->Update(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_FALSE(response.result());
  ASSERT_EQ(node_id_.String(), response.node_id());

  // Successful updates
  for (size_t a = 0; a < total_values; ++a) {
    old_value = request.mutable_old_value();
    old_value->set_value("value" + IntToString(a));
    old_value->set_value_signature(co.AsymSign(old_value->value(), "",
                                               private_key,
                                               crypto::STRING_STRING));
    new_value = request.mutable_new_value();
    new_value->set_value("value_" + IntToString(a));
    new_value->set_value_signature(co.AsymSign(new_value->value(), "",
                                               private_key,
                                               crypto::STRING_STRING));
    done = google::protobuf::NewCallback<Callback>
           (&cb_obj, &Callback::CallbackFunction);
    response.Clear();
    service_->Update(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    ASSERT_TRUE(response.result());
    ASSERT_EQ(node_id_.String(), response.node_id());
  }
}
*/
}  // namespace test_service

}  // namespace kademlia

}  // namespace maidsafe
