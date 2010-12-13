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

#include <gtest/gtest_prod.h>

#include <memory>
#include <string>
#include <vector>

#include "maidsafe/maidsafe-dht_config.h"
#include "maidsafe/kademlia/contact.h"
#include "maidsafe/kademlia/kadroutingtable.h"
#include "maidsafe/transport/transportsignals.h"
#include "maidsafe/kademlia/datastore.h"
#include "maidsafe/transport/transport.h"
#include "maidsafe/protobuf/kademlia.pb.h"
#include "maidsafe/base/threadpool.h"

namespace base {
class SignatureValidator;
class AlternativeStore;
}  // namespace base

namespace kademlia {
// class DataStore;
class Contact;
class KadId;

namespace test_kadservice {
class KadServicesTest_BEH_KAD_UpdateValue_Test;
}

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

class KadService : public transport::TransportMessage {
 public:
  KadService(boost::shared_ptr<transport::Transport> transport,
             boost::shared_ptr<RoutingTable> routing_table,
             boost::shared_ptr<base::Threadpool> threadpool,
             boost::shared_ptr<DataStore> datastore,
             const bool &hasRSAkeys);
  void Ping(transport::SocketId &message_id,
            const boost::shared_ptr<transport::PingRequest> request);
  void FindValue(transport::SocketId &message_id,
                 const boost::shared_ptr<transport::FindRequest> request);
  void FindNode(transport::SocketId &message_id,
                const boost::shared_ptr<transport::FindRequest > request);
  void Store(transport::SocketId &message_id,
             const boost::shared_ptr<transport::StoreRequest> request);
  void Downlist(transport::SocketId &message_id,
                const boost::shared_ptr<transport::DownlistRequest> request);
  void Delete(transport::SocketId &message_id,
              const boost::shared_ptr<transport::DeleteRequest> request);
  void Update(transport::SocketId &message_id,
              const boost::shared_ptr<transport::UpdateRequest> request);
  inline void set_node_joined(const bool &joined) { node_joined_ = joined; }
  inline void set_node_info(const ContactInfo &info) { node_info_ = info; }
  inline void set_alternative_store(base::AlternativeStore* alt_store) {
    alternative_store_ = alt_store;
  }
  inline void set_signature_validator(base::SignatureValidator *sig_validator) {
    signature_validator_ = sig_validator;
  }
 private:
  friend class test_kadservice::KadServicesTest_BEH_KAD_UpdateValue_Test;
  bool GetSender(const ContactInfo &sender_info, Contact *sender);
  bool CheckStoreRequest(const transport::StoreRequest *request, Contact *sender);
  void StoreValueLocal(const std::string &key, const std::string &value,
                       Contact sender, const boost::int32_t &ttl,
                       const bool &publish, transport::StoreResponse *response);
  void StoreValueLocal(const std::string &key, const SignedValue &value,
                       Contact sender, const boost::int32_t &ttl,
                       const bool &publish, transport::StoreResponse *response);
  bool CanStoreSignedValueHashable(const std::string &key,
                                   const std::string &value, bool *hashable);
  boost::shared_ptr<transport::Transport> transport_;
  boost::shared_ptr<RoutingTable> routing_table_;
  boost::shared_ptr<base::Threadpool> threadpool_;
  boost::shared_ptr<DataStore> datastore_;
  
  boost::shared_ptr<DataStore> pdatastore_;
  bool node_joined_, node_hasRSAkeys_;
  ContactInfo node_info_;
  base::AlternativeStore *alternative_store_;
//   AddContactFunctor add_contact_;
  GetRandomContactsFunctor get_random_contacts_;
//   GetContactFunctor get_contact_;
//   GetKClosestFunctor get_closestK_contacts_;
//   PingFunctor ping_;
//   RemoveContactFunctor remove_contact_;
  base::SignatureValidator *signature_validator_;
  KadService(const KadService&);
  KadService& operator=(const KadService&);
  transport::Signals request_;
};

}  // namespace kademlia
#endif  // MAIDSAFE_KADEMLIA_KADSERVICE_H_
