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
#ifndef MAIDSAFE_DHT_TESTS_KADEMLIA_UTILS_H_
#define MAIDSAFE_DHT_TESTS_KADEMLIA_UTILS_H_

#include "maidsafe-dht/kademlia/rpcs.pb.h"
#include "maidsafe-dht/kademlia/securifier.h"
#include "maidsafe-dht/kademlia/routing_table.h"
#include "maidsafe-dht/kademlia/datastore.h"

namespace maidsafe {

namespace kademlia {

namespace test {

static const boost::uint16_t k = 16;
const boost::posix_time::milliseconds kNetworkDelay(200);


class SecurifierGetPublicKeyAndValidation: public Securifier {
 public:
  SecurifierGetPublicKeyAndValidation(const std::string &public_key_id,
                                              const std::string &public_key,
                                              const std::string &private_key);

  void GetPublicKeyAndValidation(const std::string &public_key_id,
                                 GetPublicKeyAndValidationCallback callback);

  void Join();

  bool AddTestValidation(const std::string &public_key_id,
                         const std::string &public_key);

  void ClearTestValidationMap();

 private:
  void DummyFind(std::string public_key_id,
                 GetPublicKeyAndValidationCallback callback);
  std::map<std::string, std::string> public_key_id_map_;
  boost::thread_group thread_group_;
};

typedef std::shared_ptr<SecurifierGetPublicKeyAndValidation> SecurifierGPKPtr;

class CreateContactAndNodeId {
 public:
  CreateContactAndNodeId();

  NodeId GenerateUniqueRandomId(const NodeId& holder, const int& pos);

  Contact GenerateUniqueContact(const NodeId& holder, const int& pos,
                                RoutingTableContactsContainer& generated_nodes,
                                NodeId target);

  NodeId GenerateRandomId(const NodeId& holder, const int& pos);

  Contact ComposeContact(const NodeId& node_id,
                         boost::uint16_t port);

  Contact ComposeContactWithKey(const NodeId& node_id,
                                boost::uint16_t port,
                                const crypto::RsaKeyPair& crypto_key);

  void PopulateContactsVector(int count,
                              const int& pos,
                              std::vector<Contact> *contacts);

  Contact contact_;
  kademlia::NodeId node_id_;
  std::shared_ptr<RoutingTable> routing_table_;
};

KeyValueSignature MakeKVS(const crypto::RsaKeyPair &rsa_key_pair,
                          const size_t &value_size,
                          std::string key,
                          std::string value);

KeyValueTuple MakeKVT(const crypto::RsaKeyPair &rsa_key_pair,
                      const size_t &value_size,
                      const bptime::time_duration &ttl,
                      std::string key,
                      std::string value);

protobuf::StoreRequest MakeStoreRequest(const Contact& sender,
                                        const KeyValueSignature& kvs);

protobuf::DeleteRequest MakeDeleteRequest(const Contact& sender,
                                          const KeyValueSignature& kvs);

void JoinNetworkLookup(SecurifierPtr securifier);

bool AddTestValidation(SecurifierPtr securifier, std::string public_key_id,
                       std::string public_key);

void AddContact(std::shared_ptr<RoutingTable> routing_table,
                const Contact& contact, const RankInfoPtr rank_info);

}  // namespace test

}  // namespace kademlia

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_TESTS_KADEMLIA_UTILS_H_
