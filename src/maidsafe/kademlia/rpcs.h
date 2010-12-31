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

namespace kademlia {

enum TransportType { kUdt, kTcp, kOther };

class MessageHandler;
class NodeId;

namespace protobuf {
class PingResponse;
class FindValueResponse;
class FindNodesResponse;
class StoreResponse;
class DeleteResponse;
class UpdateResponse;
}  // namespace protobuf

typedef boost::function<void(bool, std::string)> PingFunctor;
typedef boost::function<void(bool, const std::vector<Contact>&,
                             const std::vector<std::string>&,
                             const std::vector<SignedValue>&,
                             const Contact&, bool)> FindValueFunctor;
typedef boost::function<void(bool, const std::vector<Contact>&)>
        FindNodesFunctor;

class Rpcs {
 public:
  Rpcs(boost::shared_ptr<boost::asio::io_service> asio_service)
      : node_contact_(),
        asio_service_(asio_service) {}
  virtual ~Rpcs() {}
  void Ping(const Contact &contact,
            PingFunctor callback,
            TransportType type);
  void FindValue(const NodeId &key,
                 const Contact &contact,
                 FindValueFunctor callback,
                 TransportType type);
  virtual void FindNodes(const NodeId &key,
                         const Contact &contact,
                         FindNodesFunctor callback,
                         TransportType type);
  void Store(const NodeId &key,
             const SignedValue &signed_value,
             const Signature &signature,
             const Contact &contact,
             const boost::int32_t &ttl,
             const bool &publish,
             VoidFunctorOneBool callback,
             TransportType type);
  void Store(const NodeId &key,
             const std::string &value,
             const Contact &contact,
             const boost::int32_t &ttl,
             const bool &publish,
             VoidFunctorOneBool callback,
             TransportType type);
  void Delete(const NodeId &key,
              const SignedValue &signed_value,
              const Signature &signature,
              const Contact &contact,
              VoidFunctorOneBool callback,
              TransportType type);
  void Update(const NodeId &key,
              const SignedValue &new_signed_value,
              const SignedValue &old_signed_value,
              const boost::int32_t &ttl,
              const Signature &signature,
              const Contact &contact,
              VoidFunctorOneBool callback,
              TransportType type);
  void Downlist(const std::vector<NodeId> &node_ids,
                const Contact &contact,
            TransportType type);
  void set_node_contact(const Contact &node_contact) {
    node_contact_ = node_contact;
  }

 private:
  void PingCallback(const protobuf::PingResponse &response,
                    PingFunctor callback,
                    boost::shared_ptr<MessageHandler> message_handler,
                    boost::shared_ptr<transport::Transport> transport);
  void FindValueCallback(const protobuf::FindValueResponse &response,
                         FindValueFunctor callback,
                         boost::shared_ptr<MessageHandler> message_handler,
                         boost::shared_ptr<transport::Transport> transport);
  void FindNodesCallback(const protobuf::FindNodesResponse &response,
                         FindNodesFunctor callback,
                         boost::shared_ptr<MessageHandler> message_handler,
                         boost::shared_ptr<transport::Transport> transport);
  void StoreCallback(const protobuf::StoreResponse &response,
                     VoidFunctorOneBool callback,
                     boost::shared_ptr<MessageHandler> message_handler,
                     boost::shared_ptr<transport::Transport> transport);
  void DeleteCallback(const protobuf::DeleteResponse &response,
                      VoidFunctorOneBool callback,
                      boost::shared_ptr<MessageHandler> message_handler,
                      boost::shared_ptr<transport::Transport> transport);
  void UpdateCallback(const protobuf::UpdateResponse &response,
                      VoidFunctorOneBool callback,
                      boost::shared_ptr<MessageHandler> message_handler,
                      boost::shared_ptr<transport::Transport> transport);
  boost::shared_ptr<transport::Transport> CreateTransport(TransportType type);

  Rpcs(const Rpcs&);
  Rpcs& operator=(const Rpcs&);
  Contact node_contact_;
  boost::shared_ptr<boost::asio::io_service> asio_service_;
};

}  // namespace kademlia

#endif  // MAIDSAFE_KADEMLIA_RPCS_H_
