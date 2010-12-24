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

#ifndef MAIDSAFE_KADEMLIA_SERVICE_H_
#define MAIDSAFE_KADEMLIA_SERVICE_H_

#include <boost/cstdint.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/function.hpp>

#include <string>
#include <vector>

// #include "maidsafe/kademlia/config.h"
#include "maidsafe/kademlia/contact.h"

namespace base {
class SignatureValidator;
class AlternativeStore;
}  // namespace base

namespace kademlia {

class DataStore;
class NodeId;
class RoutingTable;
class SignedValue;

namespace protobuf {
class PingRequest;
class PingResponse;
class FindValueRequest;
class FindValueResponse;
class FindNodesRequest;
class FindNodesResponse;
class StoreRequest;
class StoreResponse;
class DeleteRequest;
class DeleteResponse;
class UpdateRequest;
class UpdateResponse;
class DownlistRequest;
class DownlistResponse;
}  // namespace protobuf

namespace test_service { class ServicesTest_BEH_KAD_UpdateValue_Test; }

class Service {
 public:
  Service(boost::shared_ptr<RoutingTable> routing_table,
          boost::shared_ptr<DataStore> datastore,
          bool using_signatures);
  void Ping(const Info &info, const protobuf::PingRequest &request,
            protobuf::PingResponse *response);
  void FindValue(const Info &info, const protobuf::FindValueRequest &request,
                 protobuf::FindValueResponse *response);
  void FindNodes(const Info &info, const protobuf::FindNodesRequest &request,
                 protobuf::FindNodesResponse *response);
  void Store(const Info &info, const protobuf::StoreRequest &request,
             protobuf::StoreResponse *response);
  void Delete(const Info &info, const protobuf::DeleteRequest &request,
              protobuf::DeleteResponse *response);
  void Update(const Info &info, const protobuf::UpdateRequest &request,
              protobuf::UpdateResponse *response);
  void Downlist(const Info &info, const protobuf::DownlistRequest &request,
                protobuf::DownlistResponse *response);
  void set_node_joined(bool joined) { node_joined_ = joined; }
  void set_node_contact(const Contact &contact) { node_contact_ = contact; }
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
  bool CheckStoreRequest(const protobuf::StoreRequest &request) const;
  bool StoreValueLocal(const std::string &key,
                       const std::string &value,
                       Contact sender,
                       const boost::int32_t &ttl,
                       const bool &publish);
  void StoreValueLocal(const std::string &key,
                       const SignedValue &value,
                       Contact sender,
                       const boost::int32_t &ttl,
                       const bool &publish,
                       protobuf::StoreResponse *response);
  bool CanStoreSignedValueHashable(const std::string &key,
                                   const std::string &value,
                                   bool *hashable);
  boost::shared_ptr<RoutingTable> routing_table_;
  boost::shared_ptr<DataStore> datastore_;
  bool node_joined_, using_signatures_;
  Contact node_contact_;
  boost::shared_ptr<base::AlternativeStore> alternative_store_;
  boost::shared_ptr<base::SignatureValidator> signature_validator_;
};

}  // namespace kademlia
#endif  // MAIDSAFE_KADEMLIA_SERVICE_H_
