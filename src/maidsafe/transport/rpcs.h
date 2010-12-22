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

#ifndef MAIDSAFE_TRANSPORT_KADRPC_H_
#define MAIDSAFE_TRANSPORT_KADRPC_H_

#include <boost/cstdint.hpp>
#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>

#include <string>
#include <vector>

#include "maidsafe/maidsafe-dht_config.h"
#include "maidsafe/kademlia/config.h"
#include "maidsafe/kademlia/kademlia.pb.h"
#include "maidsafe/kademlia/rpcs.pb.h"
#include "maidsafe/transport/udttransport.h"
#include "maidsafe/transport/tcptransport2.h"

namespace transport {

 class NodeId;
 typedef boost::function<void(bool, const std::vector<Contact>&)>
                              FindNodesFunctor;
 typedef boost::function<void(bool, const std::vector<Contact>&)>
                              FindValueFunctor;
 typedef boost::function<void(bool, std::string)> PingFunctor;
 typedef boost::function<void(bool)> StoreFunctor;
 typedef boost::function<void(bool, protobuf::SignedRequest)> StoreSigFunctor;
 typedef boost::function<void(bool)> DownlistFunctor;
 typedef boost::function<void(bool)> DeleteFunctor;
 typedef boost::function<void(bool)> UpdateFunctor;

template <class T>
class Rpcs {
 public:
  Rpcs() {}
 
  void FindNodes(const NodeId &key,
                 const Endpoint &ep,
                 FindNodesFunctor callback);
  void FindValue(const NodeId &key,
                 const Endpoint &ep,
                 FindValueFunctor callback);
  void Ping(const Endpoint &ep,
            PingFunctor callback);
  void Store(const NodeId &key,
             const protobuf::SignedValue &value,
             const protobuf::SignedRequest &sig_req,
             const Endpoint &ep,
             const boost::int32_t &ttl,
             const bool &publish,
             StoreSigFunctor callback );
  void Store(const NodeId &key,
             const std::string &value,
             const Endpoint &ep,
             const boost::int32_t &ttl,
             const bool &publish,
             StoreFunctor callback);
  void Downlist(const std::vector<std::string> downlist,
                const Endpoint &ep,
                DownlistFunctor callback);
  void Delete(const NodeId &key,
              const protobuf::SignedValue &value,
              const protobuf::SignedRequest &sig_req,
              const Endpoint &ep,
              DeleteFunctor callback);
  void Update(const NodeId &key,
              const protobuf::SignedValue &new_value,
              const protobuf::SignedValue &old_value,
              const boost::int32_t &ttl,
              const protobuf::SignedRequest &sig_req,
              const Endpoint &ep,
              UpdateFunctor callback);
  inline void set_info(const protobuf::Contact &info) { info_ = info; }
private:
  void FindNodesCallback(const protobuf::FindNodesResponse &response,
                       FindNodesFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler,
                       boost::shared_ptr<transport::Transport> transport);
  void FindValueCallback(const protobuf::FindValueResponse &response,
                       FindValueFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler,
                       boost::shared_ptr<transport::Transport> transport);
  void PingCallback(const protobuf::PingResponse &response,
                       PingFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler,
                       boost::shared_ptr<transport::Transport> transport);
  void StoreSigCallback(const protobuf::StoreResponse &response,
                       StoreSigFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler,
                       boost::shared_ptr<transport::Transport>transport);
  void StoreCallback(const protobuf::StoreResponse &response,
                       StoreFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler);
  void DownlistCallback(const protobuf::DownlistResponse &response,
                       DownlistFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler);
  void DeleteCallback(const protobuf::DeleteResponse &response,
                       DeleteFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler);
  void UpdateCallback(const protobuf::UpdateResponse &response,
                       UpdateFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler);
  Rpcs(const Rpcs&);
  Rpcs& operator=(const Rpcs&);
  protobuf::Contact info_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_KADRPC_H_
