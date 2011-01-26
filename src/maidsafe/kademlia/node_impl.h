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

#ifndef MAIDSAFE_KADEMLIA_NODEIMPL_H_
#define MAIDSAFE_KADEMLIA_NODEIMPL_H_

#include <boost/asio/io_service.hpp>
#include <boost/cstdint.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/signals2/connection.hpp>

#include <memory>
#include <string>
#include <vector>

#include "maidsafe/kademlia/config.h"
#include "maidsafe/kademlia/node-api.h"

namespace maidsafe {

namespace kademlia {

class DataStore;
class Service;
class RoutingTable;
class Rpcs;
struct LookupContact;
struct ContactAndTargetKey;
struct FindNodesParams;
struct FindNodesArgs;
struct FindNodesRpcArgs;

enum SearchMarking { kSearchDown, kSearchContacted };

bool CompareContact(const ContactAndTargetKey &first,
                    const ContactAndTargetKey &second);

void SortContactGroup(const NodeId &target_key,
                      std::vector<Contact> *contact_group);

void SortLookupContact(const NodeId &target_key,
                       std::vector<LookupContact> *contact_group);

class Node::Impl {
 public:
  Impl(IoServicePtr asio_service,
       TransportPtr listening_transport,
       SecurifierPtr default_securifier,
       AlternativeStorePtr alternative_store,
       bool client_only_node,
       const boost::uint16_t &k,
       const boost::uint16_t &alpha,
       const boost::uint16_t &beta,
       const boost::posix_time::seconds &mean_refresh_interval);
  // virtual destructor to allow tests to use a derived Impl and befriend it
  // rather than polluting this with friend tests.
  virtual ~Impl();
  void Join(const NodeId &node_id,
            const Port &port,
            const std::vector<Contact> &bootstrap_contacts,
            JoinFunctor callback);
  void Leave(std::vector<Contact> *bootstrap_contacts);
  void Store(const Key &key,
             const std::string &value,
             const std::string &signature,
             const boost::posix_time::seconds &ttl,
             SecurifierPtr securifier,
             StoreFunctor callback);
  void Delete(const Key &key,
              const std::string &value,
              const std::string &signature,
              SecurifierPtr securifier,
              DeleteFunctor callback);
  void Update(const Key &key,
              const std::string &new_value,
              const std::string &new_signature,
              const std::string &old_value,
              const std::string &old_signature,
              SecurifierPtr securifier,
              const boost::posix_time::seconds &ttl,
              UpdateFunctor callback);
  void FindValue(const Key &key,
                 SecurifierPtr securifier,
                 FindValueFunctor callback);
  void FindNodes(const Key &key, FindNodesFunctor callback);
  void GetContact(const NodeId &node_id, GetContactFunctor callback);
  void SetLastSeenToNow(const Contact &contact);
  void IncrementFailedRpcs(const Contact &contact);
  void UpdateRankInfo(const Contact &contact, RankInfoPtr rank_info);
  RankInfoPtr GetLocalRankInfo(const Contact &contact);
  void GetAllContacts(std::vector<Contact> *contacts);
  void GetBootstrapContacts(std::vector<Contact> *contacts);
  Contact contact() const;
  bool joined() const;
  IoServicePtr asio_service();
  AlternativeStorePtr alternative_store();
  OnOnlineStatusChangePtr on_online_status_change();
  bool client_only_node() const;
  boost::uint16_t k() const;
  boost::uint16_t alpha() const;
  boost::uint16_t beta() const;
  boost::uint32_t mean_refresh_interval() const;

 private:
  Impl(const Impl&);
  Impl &operator=(const Impl&);
  void AddContactsToContainer(const std::vector<Contact> contacts,
                              std::shared_ptr<FindNodesArgs> find_nodes_args);
  bool MarkResponse(const Contact &contact,
                    std::shared_ptr<FindNodesArgs> find_nodes_args,
                    SearchMarking mark,
                    std::vector<Contact> *response_nodes);
  int NodesPending(std::shared_ptr<FindNodesArgs> find_nodes_args);
  void MarkAsAlpha(const std::vector<Contact> &contacts,
                   boost::shared_ptr<FindNodesArgs> fna);
  bool HandleIterationStructure(const Contact &contact,
                                std::shared_ptr<FindNodesArgs> find_nodes_args,
                                int round,
                                SearchMarking mark,
                                std::vector<Contact> *nodes,
                                bool *top_nodes_done,
                                bool *calledback,
                                int *nodes_pending);
  void FindNodes(const FindNodesParams &find_nodes_params);
  virtual void IterativeSearch(std::shared_ptr<FindNodesArgs> find_nodes_args,
                               bool top_nodes_done,
                               bool calledback,
                               std::vector<Contact> *contacts);
  void IterativeSearchResponse(
      bool,
      const std::vector<Contact>&,
      std::shared_ptr<FindNodesRpcArgs> find_nodes_rpc_args);
  void PingOldestContact(const Contact &oldest_contact,
                         const Contact &replacement_contact,
                         RankInfoPtr replacement_rank_info);
  void PingOldestContactCallback(Contact oldest_contact,
                                 RankInfoPtr oldest_rank_info,
                                 const int &result,
                                 Contact replacement_contact,
                                 RankInfoPtr replacement_rank_info);

  IoServicePtr asio_service_;
  TransportPtr listening_transport_;
  SecurifierPtr default_securifier_;
  AlternativeStorePtr alternative_store_;
  OnOnlineStatusChangePtr on_online_status_change_;
  bool client_only_node_;
  const boost::uint16_t k_;
  const boost::uint16_t kAlpha_;
  const boost::uint16_t kBeta_;
  const boost::posix_time::seconds kMeanRefreshInterval_;
  std::shared_ptr<DataStore> data_store_;
  std::shared_ptr<Service> service_;
  std::shared_ptr<RoutingTable> routing_table_;
  std::shared_ptr<Rpcs> rpcs_;
  bool joined_, refresh_routine_started_, stopping_;
  boost::signals2::connection routing_table_connection_;
};

}  // namespace kademlia

}  // namespace maidsafe

#endif  // MAIDSAFE_KADEMLIA_NODEIMPL_H_
