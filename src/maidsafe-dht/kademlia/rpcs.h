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

#ifdef __MSVC__
#pragma warning(push)
#pragma warning(disable:4512)
#endif
#include "boost/signals2/connection.hpp"
#ifdef __MSVC__
#pragma warning(pop)
#endif

#include "boost/tuple/tuple.hpp"

#include "maidsafe-dht/kademlia/config.h"
#include "maidsafe-dht/kademlia/contact.h"
#include "maidsafe-dht/transport/transport.h"
#include "maidsafe-dht/kademlia/rpcs_objects.h"

namespace bs2 = boost::signals2;

namespace maidsafe {

namespace kademlia {

enum TransportType { kTcp, kOther };

class MessageHandler;
class NodeId;

namespace protobuf {
class PingResponse;
class FindValueResponse;
class FindNodesResponse;
class StoreResponse;
class StoreRefreshResponse;
class DeleteResponse;
class DeleteRefreshResponse;
class UpdateResponse;
}  // namespace protobuf

struct RpcsFailurePeer {
 public:
  RpcsFailurePeer() : peer(), rpcs_failure(1) {}
  Contact peer;
  boost::uint16_t rpcs_failure;
};

class Rpcs {
 public:
  typedef boost::function<void(RankInfoPtr, const int&)> PingFunctor,
      StoreFunctor, StoreRefreshFunctor, DeleteFunctor, DeleteRefreshFunctor;
  typedef boost::function<void(RankInfoPtr, const int&,
      const std::vector<std::string>&, const std::vector<Contact>&,
      const Contact&)> FindValueFunctor;
  typedef boost::function<void(RankInfoPtr, const int&,
      const std::vector<Contact>&)> FindNodesFunctor;

  Rpcs(IoServicePtr asio_service, SecurifierPtr default_securifier)
      : asio_service_(asio_service),
        contact_(),
        default_securifier_(default_securifier),
        connected_objects_() {}
  virtual ~Rpcs() {}
  virtual void Ping(SecurifierPtr securifier,
                    const Contact &peer,
                    PingFunctor callback,
                    TransportType type);
  virtual void FindValue(const Key &key,
                         SecurifierPtr securifier,
                         const Contact &peer,
                         FindValueFunctor callback,
                         TransportType type);
  virtual void FindNodes(const Key &key,
                         SecurifierPtr securifier,
                         const Contact &peer,
                         FindNodesFunctor callback,
                         TransportType type);
  virtual void Store(const Key &key,
                     const std::string &value,
                     const std::string &signature,
                     const boost::posix_time::seconds &ttl,
                     SecurifierPtr securifier,
                     const Contact &peer,
                     StoreFunctor callback,
                     TransportType type);
  virtual void StoreRefresh(
      const std::string &serialised_store_request,
      const std::string &serialised_store_request_signature,
      SecurifierPtr securifier, const Contact &peer, StoreFunctor callback,
      TransportType type);
  virtual void Delete(const Key &key,
                      const std::string &value,
                      const std::string &signature,
                      SecurifierPtr securifier,
                      const Contact &peer,
                      DeleteFunctor callback,
                      TransportType type);
  virtual void DeleteRefresh(
      const std::string &serialised_delete_request,
      const std::string &serialised_delete_request_signature,
      SecurifierPtr securifier, const Contact &peer, DeleteFunctor callback,
      TransportType type);
  virtual void Downlist(const std::vector<NodeId> &node_ids,
                        SecurifierPtr securifier,
                        const Contact &peer,
                        TransportType type);
  void set_contact(const Contact &contact) { contact_ = contact; }

  virtual void Prepare(TransportType type,
                       SecurifierPtr securifier,
                       TransportPtr &transport,
                       MessageHandlerPtr &message_handler);

 protected:
  IoServicePtr asio_service_;

 private:
  Rpcs(const Rpcs&);
  Rpcs& operator=(const Rpcs&);
  void PingCallback(const std::string &random_data,
                    const transport::TransportCondition &transport_condition,
                    const transport::Info &info,
                    const protobuf::PingResponse &response,
                    const boost::uint32_t &index,
                    PingFunctor callback,
                    const std::string &message,
                    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer);

  void FindValueCallback(
      const transport::TransportCondition &transport_condition,
      const transport::Info &info,
      const protobuf::FindValueResponse &response,
      const boost::uint32_t &index,
      FindValueFunctor callback,
      const std::string &message,
      std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer);

  void FindNodesCallback(
      const transport::TransportCondition &transport_condition,
      const transport::Info &info,
      const protobuf::FindNodesResponse &response,
      const boost::uint32_t &index,
      FindNodesFunctor callback,
      const std::string &message,
      std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer);

  void StoreCallback(const transport::TransportCondition &transport_condition,
                     const transport::Info &info,
                     const protobuf::StoreResponse &response,
                     const boost::uint32_t &index,
                     StoreFunctor callback,
                     const std::string &message,
                     std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer);

  void StoreRefreshCallback(
      const transport::TransportCondition &transport_condition,
      const transport::Info &info,
      const protobuf::StoreRefreshResponse &response,
      const boost::uint32_t &index,
      StoreRefreshFunctor callback,
      const std::string &message,
      std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer);

  void DeleteCallback(const transport::TransportCondition &transport_condition,
                      const transport::Info &info,
                      const protobuf::DeleteResponse &response,
                      const boost::uint32_t &index,
                      DeleteFunctor callback,
                      const std::string &message,
                      std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer);

  void DeleteRefreshCallback(
      const transport::TransportCondition &transport_condition,
      const transport::Info &info,
      const protobuf::DeleteRefreshResponse &response,
      const boost::uint32_t &index,
      DeleteRefreshFunctor callback,
      const std::string &message,
      std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer);

  Contact contact_;
  SecurifierPtr default_securifier_;
  ConnectedObjectsList connected_objects_;
};

}  // namespace kademlia

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_RPCS_H_
