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

#ifndef MAIDSAFE_KADEMLIA_RPCS_H_
#define MAIDSAFE_KADEMLIA_RPCS_H_

#include <boost/cstdint.hpp>
#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>

#include <string>
#include <vector>

#include "maidsafe/kademlia/config.h"
#include "maidsafe/kademlia/contact.h"

namespace transport {
class Endpoint;
}  // namespace transport

namespace kademlia {

class MessageHandler;
class NodeId;

namespace protobuf {
class PingResponse;
class FindValueResponse;
class FindNodesResponse;
class StoreResponse;
class DeleteResponse;
class UpdateResponse;
class DownlistResponse;
}  // namespace protobuf

typedef boost::function<void(bool, std::string)> PingFunctor;
typedef boost::function<void(bool, const std::vector<Contact>&,
                             const std::vector<std::string>&,
                             const std::vector<SignedValue>&,
                             const Contact&, bool)> FindValueFunctor;
typedef boost::function<void(bool, const std::vector<Contact>&)>
    FindNodesFunctor;

template <class TransportType>
class Rpcs {
 public:
  Rpcs() : node_contact_() {}
  void Ping(const transport::Endpoint &endpoint,
            PingFunctor callback);
  void FindValue(const NodeId &key,
                 const transport::Endpoint &endpoint,
                 FindValueFunctor callback);
  void FindNodes(const NodeId &key,
                 const transport::Endpoint &endpoint,
                 FindNodesFunctor callback);
  void Store(const NodeId &key,
             const SignedValue &signed_value,
             const Signature &signature,
             const transport::Endpoint &endpoint,
             const boost::int32_t &ttl,
             const bool &publish,
             VoidFunctorOneBool callback);
  void Store(const NodeId &key,
             const std::string &value,
             const transport::Endpoint &endpoint,
             const boost::int32_t &ttl,
             const bool &publish,
             VoidFunctorOneBool callback);
  void Delete(const NodeId &key,
              const SignedValue &signed_value,
              const Signature &signature,
              const transport::Endpoint &endpoint,
              VoidFunctorOneBool callback);
  void Update(const NodeId &key,
              const SignedValue &new_signed_value,
              const SignedValue &old_signed_value,
              const boost::int32_t &ttl,
              const Signature &signature,
              const transport::Endpoint &endpoint,
              VoidFunctorOneBool callback);
  void Downlist(const std::vector<NodeId> &node_ids,
                const transport::Endpoint &endpoint,
                VoidFunctorOneBool callback);
  void set_node_contact(const Contact &node_contact) {
    node_contact_ = node_contact;
  }
 private:
  void PingCallback(const protobuf::PingResponse &response,
                    PingFunctor callback,
                    boost::shared_ptr<MessageHandler> message_handler,
                    boost::shared_ptr<TransportType> transport);
  void FindValueCallback(const protobuf::FindValueResponse &response,
                         FindValueFunctor callback,
                         boost::shared_ptr<MessageHandler> message_handler,
                         boost::shared_ptr<TransportType> transport);
  void FindNodesCallback(const protobuf::FindNodesResponse &response,
                         FindNodesFunctor callback,
                         boost::shared_ptr<MessageHandler> message_handler,
                         boost::shared_ptr<TransportType> transport);
  void StoreCallback(const protobuf::StoreResponse &response,
                     VoidFunctorOneBool callback,
                     boost::shared_ptr<MessageHandler> message_handler,
                     boost::shared_ptr<TransportType> transport);
  void DeleteCallback(const protobuf::DeleteResponse &response,
                      VoidFunctorOneBool callback,
                      boost::shared_ptr<MessageHandler> message_handler,
                      boost::shared_ptr<TransportType> transport);
  void UpdateCallback(const protobuf::UpdateResponse &response,
                      VoidFunctorOneBool callback,
                      boost::shared_ptr<MessageHandler> message_handler,
                      boost::shared_ptr<TransportType> transport);
  void DownlistCallback(const protobuf::DownlistResponse &response,
                        VoidFunctorOneBool callback,
                        boost::shared_ptr<MessageHandler> message_handler,
                        boost::shared_ptr<TransportType> transport);
  Rpcs(const Rpcs&);
  Rpcs& operator=(const Rpcs&);
  Contact node_contact_;
};

}  // namespace kademlia

#endif  // MAIDSAFE_KADEMLIA_RPCS_H_
