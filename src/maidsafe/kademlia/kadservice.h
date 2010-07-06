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

#ifndef MAIDSAFE_KADEMLIA_KADSERVICE_H_
#define MAIDSAFE_KADEMLIA_KADSERVICE_H_
#include <memory>
#include <string>
#include <vector>
#include "gtest/gtest_prod.h"
#include "maidsafe/maidsafe-dht_config.h"
#include "maidsafe/protobuf/kademlia_service.pb.h"
#include "maidsafe/kademlia/contact.h"
#include "maidsafe/kademlia/natrpc.h"

namespace base {
class SignatureValidator;
class AlternativeStore;
}

namespace kad {
class DataStore;
class Contact;
class KadId;

typedef boost::function<int(Contact, const float&, const bool&)>  // NOLINT
    AddContactFunctor;

typedef boost::function<void(const KadId&)> RemoveContactFunctor;  // NOLINT

typedef boost::function<void(const boost::uint16_t&,
                             const std::vector<Contact>&,
                             std::vector<Contact>*)> GetRandomContactsFunctor;

typedef boost::function<bool(const KadId&, Contact*)> GetContactFunctor;  // NOLINT

typedef boost::function<void(const KadId&, const std::vector<Contact>&,
                             std::vector<Contact>*)> GetKClosestFunctor;

typedef boost::function<void(const Contact&, VoidFunctorOneString)>
    PingFunctor;

struct NatDetectionData {
  Contact newcomer;
  std::string bootstrap_node;
  Contact node_c;
  BootstrapResponse *response;
  google::protobuf::Closure *done;
  rpcprotocol::Controller *controller;
  std::vector<Contact> ex_contacts;
};

struct NatDetectionPingData {
  std::string sender_id;
  NatDetectionResponse *response;
  google::protobuf::Closure *done;
  rpcprotocol::Controller *controller;
};

class KadService : public KademliaService {
 public:
  KadService(const NatRpcs &nat_rpcs, boost::shared_ptr<DataStore> datastore,
             const bool &hasRSAkeys, AddContactFunctor add_cts,
             GetRandomContactsFunctor rand_cts, GetContactFunctor get_ctc,
             GetKClosestFunctor get_kcts, PingFunctor ping,
             RemoveContactFunctor remove_contact);
  void Ping(google::protobuf::RpcController *controller,
            const PingRequest *request, PingResponse *response,
            google::protobuf::Closure *done);
  void FindValue(google::protobuf::RpcController *controller,
                 const FindRequest *request, FindResponse *response,
                 google::protobuf::Closure *done);
  void FindNode(google::protobuf::RpcController *controller,
                const FindRequest *request, FindResponse *response,
                google::protobuf::Closure *done);
  void Store(google::protobuf::RpcController *controller,
             const StoreRequest *request, StoreResponse *response,
             google::protobuf::Closure *done);
  void Downlist(google::protobuf::RpcController *controller,
                const DownlistRequest *request, DownlistResponse *response,
                google::protobuf::Closure *done);
  void NatDetection(google::protobuf::RpcController *controller,
                    const NatDetectionRequest *request,
                    NatDetectionResponse *response,
                    google::protobuf::Closure *done);
  void NatDetectionPing(google::protobuf::RpcController *controller,
                        const NatDetectionPingRequest *request,
                        NatDetectionPingResponse *response,
                        google::protobuf::Closure *done);
  void Bootstrap(google::protobuf::RpcController *controller,
                 const BootstrapRequest *request, BootstrapResponse *response,
                 google::protobuf::Closure *done);
  void Delete(google::protobuf::RpcController *controller,
              const DeleteRequest *request, DeleteResponse *response,
              google::protobuf::Closure *done);
  void Update(google::protobuf::RpcController *controller,
              const UpdateRequest *request,
              UpdateResponse *response,
              google::protobuf::Closure *done);
  inline void set_node_joined(const bool &joined) {
    node_joined_ = joined;
  }
  inline void set_node_info(const ContactInfo &info) {
    node_info_ = info;
  }
  inline void set_alternative_store(base::AlternativeStore* alt_store) {
    alternative_store_ = alt_store;
  }
  inline void set_signature_validator(base::SignatureValidator *sig_validator) {
    signature_validator_ = sig_validator;
  }
 private:
  FRIEND_TEST(NatDetectionTest, BEH_KAD_SendNatDet);
  FRIEND_TEST(NatDetectionTest, BEH_KAD_BootstrapNatDetRv);
  FRIEND_TEST(NatDetectionTest, FUNC_KAD_CompleteBootstrapNatDet);
  FRIEND_TEST(KadServicesTest, BEH_KAD_UpdateValue);
  bool GetSender(const ContactInfo &sender_info, Contact *sender);
  void Bootstrap_NatDetectionRv(const NatDetectionResponse *response,
                                struct NatDetectionData data);
  void Bootstrap_NatDetection(const NatDetectionResponse *response,
                              struct NatDetectionData data);
  void Bootstrap_NatDetectionPing(const NatDetectionPingResponse *response,
                                  struct NatDetectionPingData data);
  void Bootstrap_NatDetectionRzPing(
      const NatDetectionPingResponse *response,
      struct NatDetectionPingData data);
  void SendNatDetection(struct NatDetectionData data);
  bool CheckStoreRequest(const StoreRequest *request, Contact *sender);
  void StoreValueLocal(const std::string &key, const std::string &value,
                       Contact sender, const boost::int32_t &ttl,
                       const bool &publish, StoreResponse *response,
                       rpcprotocol::Controller *ctrl);
  void StoreValueLocal(const std::string &key, const SignedValue &value,
                       Contact sender, const boost::int32_t &ttl,
                       const bool &publish, StoreResponse *response,
                       rpcprotocol::Controller *ctrl);
  bool CanStoreSignedValueHashable(const std::string &key,
                                   const std::string &value, bool *hashable);
  NatRpcs nat_rpcs_;
  boost::shared_ptr<DataStore> pdatastore_;
  bool node_joined_, node_hasRSAkeys_;
  ContactInfo node_info_;
  base::AlternativeStore *alternative_store_;
  AddContactFunctor add_contact_;
  GetRandomContactsFunctor get_random_contacts_;
  GetContactFunctor get_contact_;
  GetKClosestFunctor get_closestK_contacts_;
  PingFunctor ping_;
  RemoveContactFunctor remove_contact_;
  base::SignatureValidator *signature_validator_;
  KadService(const KadService&);
  KadService& operator=(const KadService&);
};

}  // namespace kad
#endif  // MAIDSAFE_KADEMLIA_KADSERVICE_H_
