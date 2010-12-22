/* Copyright (c) 2010 maidsafe.net limited
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

#ifndef MAIDSAFE_TRANSPORT_SERVICE_H_
#define MAIDSAFE_TRANSPORT_SERVICE_H_

//#include <boost/cstdint.hpp>
//#include <boost/function.hpp>
//
//#include <string>
//#include <vector>
//
//#include "maidsafe/kademlia/config.h"
//#include "maidsafe/protobuf/contact_info.pb.h"
//#include "maidsafe/transport/transport.h"

//namespace base {
//class Threadpool;
//class SignatureValidator;
//class AlternativeStore;
//}  // namespace base
//
//namespace transport {
//class PingRequest;
//class FindRequest;
//class StoreRequest;
//class DownlistRequest;
//class DeleteRequest;
//class UpdateRequest;
//class StoreResponse;
//}  // namespace transport

namespace transport {

//class Contact;
//class DataStore;
//class NodeId;
//class RoutingTable;
//class SignedValue;

//namespace test_service { class ServicesTest_BEH_KAD_UpdateValue_Test; }

//typedef boost::function<int(Contact, float, bool)> AddContactFunctor;  // NOLINT
//
//typedef boost::function<void(NodeId)> RemoveContactFunctor;  // NOLINT
//
//typedef boost::function<void(boost::uint16_t,
//                             std::vector<Contact>,
//                             std::vector<Contact>*)> GetRandomContactsFunctor;
//
//typedef boost::function<bool(const NodeId, Contact*)> GetContactFunctor;  // NOLINT
//
//typedef boost::function<void(NodeId,
//                             std::vector<Contact>,
//                             std::vector<Contact>*)> GetKClosestFunctor;
//
//typedef boost::function<void(Contact, VoidFunctorOneString)> PingFunctor;

class Service {
 public:
  Service(boost::shared_ptr<MessageHandler> transport,
             boost::shared_ptr<RoutingTable> routing_table,
             boost::shared_ptr<base::Threadpool> threadpool,
             boost::shared_ptr<DataStore> datastore,
             bool using_signatures);
  void Ping(transport::SocketId message_id,
            boost::shared_ptr<transport::PingRequest> request);
  void FindValue(transport::SocketId message_id,
                 boost::shared_ptr<transport::FindRequest> request);
  void FindNode(transport::SocketId message_id,
                boost::shared_ptr<transport::FindRequest> request);
  void Store(transport::SocketId message_id,
             boost::shared_ptr<transport::StoreRequest> request);
  void Downlist(transport::SocketId message_id,
                boost::shared_ptr<transport::DownlistRequest> request);
  void Delete(transport::SocketId message_id,
              boost::shared_ptr<transport::DeleteRequest> request);
  void Update(transport::SocketId message_id,
              boost::shared_ptr<transport::UpdateRequest> request);
  void set_node_joined(bool joined) { node_joined_ = joined; }
  void set_node_info(const ContactInfo &info) { node_info_ = info; }
  void set_alternative_store(base::AlternativeStore* alt_store) {
    alternative_store_ = alt_store;
  }
  void set_signature_validator(base::SignatureValidator *sig_validator) {
    signature_validator_ = sig_validator;
  }
 private:
  friend class test_service::ServicesTest_BEH_KAD_UpdateValue_Test;
  Service(const Service&);
  Service& operator=(const Service&);
  void Demux(transport::SocketId message_id,
             transport::TransportMessage message,
             transport::Stats stats);
  bool GetSender(const ContactInfo &sender_info, Contact *sender);
  bool CheckStoreRequest(boost::shared_ptr<transport::StoreRequest> request,
                         Contact *sender);
  void StoreValueLocal(const std::string &key,
                       const std::string &value,
                       Contact sender,
                       const boost::int32_t &ttl,
                       const bool &publish,
                       transport::StoreResponse *response);
  void StoreValueLocal(const std::string &key,
                       const SignedValue &value,
                       Contact sender,
                       const boost::int32_t &ttl,
                       const bool &publish,
                       transport::StoreResponse *response);
  bool CanStoreSignedValueHashable(const std::string &key,
                                   const std::string &value,
                                   bool *hashable);
  boost::shared_ptr<transport::Transport> transport_;
  boost::shared_ptr<RoutingTable> routing_table_;
  boost::shared_ptr<base::Threadpool> threadpool_;
  boost::shared_ptr<DataStore> datastore_;
  bool node_joined_, using_signatures_;
  ContactInfo node_info_;
  base::AlternativeStore *alternative_store_;
  base::SignatureValidator *signature_validator_;
//   AddContactFunctor add_contact_;
//   GetRandomContactsFunctor get_random_contacts_;
//   GetContactFunctor get_contact_;
//   GetKClosestFunctor get_closestK_contacts_;
//   PingFunctor ping_;
//   RemoveContactFunctor remove_contact_;
  boost::signals2::connection connection_to_message_received_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_SERVICE_H_
