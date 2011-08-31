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

#include <algorithm>
#include <bitset>

#include "maidsafe/common/test.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/dht/kademlia/node_id.h"
#include "maidsafe/dht/kademlia/utils.h"
#include "maidsafe/dht/kademlia/tests/test_utils.h"

namespace arg = std::placeholders;

namespace maidsafe {

namespace dht {

namespace kademlia {

namespace test {

SecurifierGetPublicKeyAndValidation::SecurifierGetPublicKeyAndValidation(
    const std::string &public_key_id,
    const std::string &public_key,
    const std::string &private_key)
        : Securifier(public_key_id, public_key, private_key),
          public_key_id_map_(),
          thread_group_() {}

// Immitating a non-blocking function
void SecurifierGetPublicKeyAndValidation::GetPublicKeyAndValidation(
    const std::string &public_key_id,
    GetPublicKeyAndValidationCallback callback) {
  thread_group_.add_thread(
      new boost::thread(
              &SecurifierGetPublicKeyAndValidation::DummyFind, this,
                  public_key_id, callback));
}

void SecurifierGetPublicKeyAndValidation::Join() {
  thread_group_.join_all();
}

// This method will validate the network lookup for given public_key_id
bool SecurifierGetPublicKeyAndValidation::AddTestValidation(
    const std::string &public_key_id,
    const std::string &public_key) {
  auto itr = public_key_id_map_.insert(std::make_pair(public_key_id,
                                                      public_key));
  return itr.second;
}

void SecurifierGetPublicKeyAndValidation::ClearTestValidationMap() {
  public_key_id_map_.erase(public_key_id_map_.begin(),
                            public_key_id_map_.end());
}

void SecurifierGetPublicKeyAndValidation::DummyFind(
    std::string public_key_id,
    GetPublicKeyAndValidationCallback callback) {
  // Imitating delay in lookup for kNetworkDelay milliseconds
  Sleep(kNetworkDelay);
  auto itr = public_key_id_map_.find(public_key_id);
  if (itr != public_key_id_map_.end())
    callback((*itr).second, "");
  else
    callback("", "");
}



CreateContactAndNodeId::CreateContactAndNodeId(uint16_t k)
    : contact_(),
      node_id_(NodeId::kRandomId),
      routing_table_(new RoutingTable(node_id_, k)) {}

NodeId CreateContactAndNodeId::GenerateUniqueRandomId(const NodeId &holder,
                                                      const int &pos) {
  std::string holder_id = holder.ToStringEncoded(NodeId::kBinary);
  std::bitset<kKeySizeBits> holder_id_binary_bitset(holder_id);
  NodeId new_node;
  std::string new_node_string;
  bool repeat(true);
  uint16_t times_of_try(0);
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

Contact CreateContactAndNodeId::GenerateUniqueContact(
    const NodeId &holder,
    const int &pos,
    const NodeId &target,
    RoutingTableContactsContainer *generated_nodes) {
  std::string holder_id = holder.ToStringEncoded(NodeId::kBinary);
  std::bitset<kKeySizeBits> holder_id_binary_bitset(holder_id);
  NodeId new_node;
  std::string new_node_string;
  bool repeat(true);
  uint16_t times_of_try(0);
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
    ContactsById key_indx = generated_nodes->get<NodeIdTag>();
    auto it = key_indx.find(new_node);
    if (it == key_indx.end()) {
      new_contact = ComposeContact(new_node, 5000);
      RoutingTableContact new_routing_table_contact(new_contact, target, 0);
      generated_nodes->insert(new_routing_table_contact);
      repeat = false;
    }
    ++times_of_try;
  } while (repeat && (times_of_try < 1000));
  // prevent deadlock, throw out an error message in case of deadlock
  if (times_of_try == 1000)
    EXPECT_LT(1000, times_of_try);
  return new_contact;
}

NodeId CreateContactAndNodeId::GenerateRandomId(const NodeId &holder,
                                                const int &pos) {
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

Contact CreateContactAndNodeId::ComposeContact(const NodeId &node_id,
                                               const Port &port) {
  transport::Endpoint end_point("127.0.0.1", port);
  std::vector<transport::Endpoint> local_endpoints(1, end_point);
  Contact contact(node_id, end_point, local_endpoints, end_point, false,
                  false, "", "", "");
  return contact;
}

Contact CreateContactAndNodeId::ComposeContactWithKey(
    const NodeId &node_id,
    const Port &port,
    const crypto::RsaKeyPair &rsa_key_pair) {
  std::string ip("127.0.0.1");
  std::vector<transport::Endpoint> local_endpoints;
  transport::Endpoint end_point(ip, port);
  local_endpoints.push_back(end_point);
  Contact contact(node_id, end_point, local_endpoints, end_point, false,
                  false, node_id.String(), rsa_key_pair.public_key(), "");
  IP ipa = IP::from_string(ip);
  contact.SetPreferredEndpoint(ipa);
  return contact;
}

void CreateContactAndNodeId::PopulateContactsVector(
    const int &count,
    const int &pos,
    std::vector<Contact> *contacts) {
  for (int i = 0; i < count; ++i) {
    NodeId contact_id = GenerateRandomId(node_id_, pos);
    Contact contact = ComposeContact(contact_id, 5000);
    contacts->push_back(contact);
  }
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

protobuf::StoreRequest MakeStoreRequest(
    const Contact &sender,
    const KeyValueSignature &key_value_signature) {
  protobuf::StoreRequest store_request;
  store_request.mutable_sender()->CopyFrom(ToProtobuf(sender));
  store_request.set_key(key_value_signature.key);
  store_request.mutable_signed_value()->set_signature(
      key_value_signature.signature);
  store_request.mutable_signed_value()->set_value(key_value_signature.value);
  store_request.set_ttl(3600*24);
  return store_request;
}

protobuf::DeleteRequest MakeDeleteRequest(
    const Contact &sender,
    const KeyValueSignature &key_value_signature) {
  protobuf::DeleteRequest delete_request;
  delete_request.mutable_sender()->CopyFrom(ToProtobuf(sender));
  delete_request.set_key(key_value_signature.key);
  delete_request.mutable_signed_value()->set_signature(
      key_value_signature.signature);
  delete_request.mutable_signed_value()->set_value(key_value_signature.value);
  return delete_request;
}

void JoinNetworkLookup(SecurifierPtr securifier) {
  SecurifierGPKPtr securifier_gpkv = std::static_pointer_cast
      <SecurifierGetPublicKeyAndValidation>(securifier);
  securifier_gpkv->Join();
}

bool AddTestValidation(SecurifierPtr securifier,
                       std::string public_key_id,
                       std::string public_key) {
  SecurifierGPKPtr securifier_gpkv = std::static_pointer_cast
      <SecurifierGetPublicKeyAndValidation>(securifier);
  return securifier_gpkv->AddTestValidation(public_key_id, public_key);
}

void AddContact(std::shared_ptr<RoutingTable> routing_table,
                const Contact &contact,
                const RankInfoPtr rank_info) {
  routing_table->AddContact(contact, rank_info);
  routing_table->SetValidated(contact.node_id(), true);
}

void SortIds(const NodeId &target_key, std::vector<NodeId> *node_ids) {
  if (!node_ids || node_ids->empty())
    return;
  std::sort(node_ids->begin(), node_ids->end(),
      std::bind(static_cast<bool(*)(const NodeId&,  // NOLINT
                                    const NodeId&,
                                    const NodeId&)>(&NodeId::CloserToTarget),
                arg::_1, arg::_2, target_key));
}

bool WithinKClosest(const NodeId &node_id,
                    const Key &target_key,
                    std::vector<NodeId> node_ids,
                    const uint16_t &k) {
  // Put the k closest first (and sorted) in the vector.
  std::function<bool(const NodeId&, const NodeId&)> predicate =                 // NOLINT (Fraser)
      std::bind(static_cast<bool(*)(const NodeId&, const NodeId&,               // NOLINT (Fraser)
                                    const NodeId&)>(&NodeId::CloserToTarget),
                arg::_1, arg::_2, target_key);
  std::partial_sort(node_ids.begin(), node_ids.begin() + k, node_ids.end(),
                    predicate);
  return (std::find(node_ids.begin(), node_ids.begin() + k, node_id) !=
          node_ids.begin() + k);
}

}  // namespace test

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe
