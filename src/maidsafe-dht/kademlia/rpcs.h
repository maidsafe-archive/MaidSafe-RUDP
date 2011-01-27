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

#ifndef MAIDSAFE_DHT_KADEMLIA_RPCS_H_
#define MAIDSAFE_DHT_KADEMLIA_RPCS_H_

#include <string>
#include <vector>

#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "boost/signals2/connection.hpp"
#include "boost/tuple/tuple.hpp"

#include "maidsafe-dht/kademlia/config.h"
#include "maidsafe-dht/kademlia/contact.h"
#include "maidsafe-dht/transport/transport.h"

namespace bs2 = boost::signals2;

namespace maidsafe {

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

class Rpcs {
 public:
  typedef boost::function<void(RankInfoPtr, const int&)> PingFunctor,
      StoreFunctor, DeleteFunctor, UpdateFunctor;
  typedef boost::function<void(RankInfoPtr, const int&,
      const std::vector<std::string>&, const std::vector<Contact>&,
      const Contact&)> FindValueFunctor;
  typedef boost::function<void(RankInfoPtr, const int&,
      const std::vector<Contact>&)> FindNodesFunctor;

  Rpcs(IoServicePtr asio_service, SecurifierPtr default_securifier)
      : contact_(),
        asio_service_(asio_service),
        default_securifier_(default_securifier) {}
  virtual ~Rpcs() {}
  void Ping(SecurifierPtr securifier,
            const Contact &peer,
            PingFunctor callback,
            TransportType type);
  void FindValue(const Key &key,
                 SecurifierPtr securifier,
                 const Contact &peer,
                 FindValueFunctor callback,
                 TransportType type);
  virtual void FindNodes(const Key &key,
                         SecurifierPtr securifier,
                         const Contact &peer,
                         FindNodesFunctor callback,
                         TransportType type);
  void Store(const Key &key,
             const std::string &value,
             const std::string &signature,
             const boost::posix_time::seconds &ttl,
             bool publish,
             SecurifierPtr securifier,
             const Contact &peer,
             StoreFunctor callback,
             TransportType type);
  void Delete(const Key &key,
              const std::string &value,
              const std::string &signature,
              SecurifierPtr securifier,
              const Contact &peer,
              DeleteFunctor callback,
              TransportType type);
  void Update(const Key &key,
              const std::string &new_value,
              const std::string &new_signature,
              const std::string &old_value,
              const std::string &old_signature,
              const boost::posix_time::seconds &ttl,
              SecurifierPtr securifier,
              const Contact &peer,
              UpdateFunctor callback,
              TransportType type);
  void Downlist(const std::vector<NodeId> &node_ids,
                SecurifierPtr securifier,
                const Contact &peer,
                TransportType type);
  void set_contact(const Contact &contact) { contact_ = contact; }

 private:
  typedef boost::tuple<TransportPtr, MessageHandlerPtr, bs2::connection,
                       bs2::connection> ConnectedObjects;
  Rpcs(const Rpcs&);
  Rpcs& operator=(const Rpcs&);
  void PingCallback(const std::string &random_data,
                    const transport::TransportCondition &transport_condition,
                    const transport::Info &info,
                    const protobuf::PingResponse &response,
                    ConnectedObjects connected_objects,
                    PingFunctor callback);
  void FindValueCallback(
      const transport::TransportCondition &transport_condition,
      const transport::Info &info,
      const protobuf::FindValueResponse &response,
      ConnectedObjects connected_objects,
      FindValueFunctor callback);
  void FindNodesCallback(
      const transport::TransportCondition &transport_condition,
      const transport::Info &info,
      const protobuf::FindNodesResponse &response,
      ConnectedObjects connected_objects,
      FindNodesFunctor callback);
  void StoreCallback(const transport::TransportCondition &transport_condition,
                     const transport::Info &info,
                     const protobuf::StoreResponse &response,
                     ConnectedObjects connected_objects,
                     StoreFunctor callback);
  void DeleteCallback(const transport::TransportCondition &transport_condition,
                      const transport::Info &info,
                      const protobuf::DeleteResponse &response,
                      ConnectedObjects connected_objects,
                      DeleteFunctor callback);
  void UpdateCallback(const transport::TransportCondition &transport_condition,
                      const transport::Info &info,
                      const protobuf::UpdateResponse &response,
                      ConnectedObjects connected_objects,
                      UpdateFunctor callback);
  ConnectedObjects Prepare(TransportType type, SecurifierPtr securifier);
  Contact contact_;
  IoServicePtr asio_service_;
  SecurifierPtr default_securifier_;
};

}  // namespace kademlia

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_RPCS_H_
