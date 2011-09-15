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

#ifndef MAIDSAFE_DHT_KADEMLIA_NODE_IMPL_H_
#define MAIDSAFE_DHT_KADEMLIA_NODE_IMPL_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "boost/asio/io_service.hpp"
#include "boost/asio/deadline_timer.hpp"
#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "boost/signals2/connection.hpp"
#include "boost/thread/shared_mutex.hpp"
#include "boost/thread/locks.hpp"

#include "maidsafe/dht/kademlia/node_impl_structs.h"
#include "maidsafe/dht/kademlia/config.h"
#include "maidsafe/dht/kademlia/node-api.h"
#include "maidsafe/dht/kademlia/contact.h"
#include "maidsafe/dht/kademlia/node_container.h"


namespace bptime = boost::posix_time;

namespace maidsafe {

namespace dht {

namespace kademlia {

class DataStore;
struct KeyValueTuple;
class Service;
class RoutingTable;
template <typename T>
class Rpcs;

namespace test {
class NodeImplTest;
class MockNodeImplTest;
class MockNodeImplTest_BEH_ValidateContact_Test;
class MockNodeImplTest_BEH_PingOldestContact_Test;
class MockNodeImplTest_BEH_Join_Test;
class MockNodeImplTest_BEH_Getters_Test;
class MockNodeImplTest_BEH_FindNodes_Test;
class MockNodeImplTest_BEH_FindValue_Test;
class NodeImplTest_FUNC_StoreRefreshInvalidSigner_Test;
}  // namespace test

typedef std::function<void(RankInfoPtr, const int&)> StoreRefreshFunctor;

class NodeImpl {
 public:
  NodeImpl(AsioService &asio_service,                         // NOLINT (Fraser)
           TransportPtr listening_transport,
           MessageHandlerPtr message_handler,
           SecurifierPtr default_securifier,
           AlternativeStorePtr alternative_store,
           bool client_only_node,
           const uint16_t &k,
           const uint16_t &alpha,
           const uint16_t &beta,
           const bptime::time_duration &mean_refresh_interval);

  // virtual destructor to allow tests to use a derived NodeImpl and befriend it
  // rather than polluting this with friend tests.
  virtual ~NodeImpl();

  void Join(const NodeId &node_id,
            std::vector<Contact> bootstrap_contacts,
            JoinFunctor callback);

  void Leave(std::vector<Contact> *bootstrap_contacts);

  /** Function to STORE data to the Kademlia network.
   *  @param[in] Key The key to find
   *  @param[in] value The value to store.
   *  @param[in] signature The signature to store.
   *  @param[in] ttl The ttl for the new data.
   *  @param[in] securifier The securifier to pass further.
   *  @param[in] callback The callback to report the results. */
  void Store(const Key &key,
             const std::string &value,
             const std::string &signature,
             const bptime::time_duration &ttl,
             SecurifierPtr securifier,
             StoreFunctor callback);

  /** Function to DELETE the content of a <key, value> in the Kademlia network.
   *  The operation will delete the original one then store the new one.
   *  @param[in] Key The key to find
   *  @param[in] value The value to delete.
   *  @param[in] signature The signature to delete.
   *  @param[in] securifier The securifier to use.
   *  @param[in] callback The callback to report the results. */
  void Delete(const Key &key,
              const std::string &value,
              const std::string &signature,
              SecurifierPtr securifier,
              DeleteFunctor callback);

  /** Function to UPDATE the content of a <key, value> in the Kademlia network.
   *  The operation will delete the original one then store the new one.
   *  @param[in] Key The key to find
   *  @param[in] new_value The new_value to store.
   *  @param[in] new_signature The new_signature to store.
   *  @param[in] old_value The old_value to delete.
   *  @param[in] old_signature The old_signature to delete.
   *  @param[in] ttl The ttl for the new data.
   *  @param[in] securifier The securifier to pass further.
   *  @param[in] callback The callback to report the results. */
  void Update(const Key &key,
              const std::string &new_value,
              const std::string &new_signature,
              const std::string &old_value,
              const std::string &old_signature,
              const bptime::time_duration &ttl,
              SecurifierPtr securifier,
              UpdateFunctor callback);

  /** Function to FIND VALUES of the Key from the Kademlia network.
   *  @param[in] Key The key to find
   *  @param[in] securifier The securifier to pass further.
   *  @param[in] callback The callback to report the results.
   *  @param[in] extra_contacts The number of additional to k contacts to
   *  return.
   *  @param[in] cache Whether to cache the value(s) if found. */
  void FindValue(const Key &key,
                 SecurifierPtr securifier,
                 FindValueFunctor callback,
                 const uint16_t &extra_contacts = 0,
                 bool cache = true);

  /** Function to FIND k-closest NODES to the Key from the Kademlia network.
   *  @param[in] Key The key to locate
   *  @param[in] callback The callback to report the results.
   *  @param[in] extra_contacts The number of additional to k contacts to
   *  return. */
  void FindNodes(const Key &key,
                 FindNodesFunctor callback,
                 const uint16_t &extra_contacts = 0);

  /** Function to get a contact info from the Kademlia network.
   *  @param[in] node_id The node_id to locate
   *  @param[in] callback The callback to report the results. */
  void GetContact(const NodeId &node_id, GetContactFunctor callback);

  /** Investigates the contact's online/offline status
   *  @param[in] contact the contact to be pinged
   *  @param[in] callback The callback to report the result. */
  void Ping(const Contact &contact, PingFunctor callback);

  /** Function to set the contact's last_seen to now.
   *  @param[in] contact The contact to set */
  void SetLastSeenToNow(const Contact &contact);

  /** Function to set the contact's last_seen to now.
   *  @param[in] contact The contact to set */
  void IncrementFailedRpcs(const Contact &contact);

  /** Function to update the contact's rank_info.
   *  @param[in] contact The contact to update
   *  @param[in] rank_info The rank info to update */
  void UpdateRankInfo(const Contact &contact, RankInfoPtr rank_info);

  /** Get the local RankInfo of the contact
   *  @param[in] contact The contact to find
   *  @return The localRankInfo of the contact */
  RankInfoPtr GetLocalRankInfo(const Contact &contact) const;

  /** Get all contacts in the routing table
   *  @param[out] contacts All contacts in the routing table */
  void GetAllContacts(std::vector<Contact> *contacts);

  /** Get Bootstrap contacts in the routing table
   *  @param[out] contacts Bootstrap contacts in the routing table */
  void GetBootstrapContacts(std::vector<Contact> *contacts);

  Contact contact() const { return contact_; }

  bool joined() const { return joined_; }

  AlternativeStorePtr alternative_store() { return alternative_store_; }

  OnOnlineStatusChangePtr on_online_status_change() {
    return on_online_status_change_;
  }

  bool client_only_node() const { return client_only_node_; }

  uint16_t k() const { return k_; }

  friend class NodeContainer<maidsafe::dht::kademlia::NodeImpl>;
  friend class test::NodeImplTest;
  friend class test::MockNodeImplTest;
  friend class test::MockNodeImplTest_BEH_ValidateContact_Test;
  friend class test::MockNodeImplTest_BEH_PingOldestContact_Test;
  friend class test::MockNodeImplTest_BEH_Join_Test;
  friend class test::MockNodeImplTest_BEH_Getters_Test;
  friend class test::MockNodeImplTest_BEH_FindNodes_Test;
  friend class test::MockNodeImplTest_BEH_FindValue_Test;
  friend class test::NodeImplTest_FUNC_StoreRefreshInvalidSigner_Test;

 private:
  NodeImpl(const NodeImpl&);
  NodeImpl &operator=(const NodeImpl&);

  void JoinFindValueCallback(FindValueReturns find_value_returns,
                             std::vector<Contact> bootstrap_contacts,
                             const NodeId &node_id,
                             JoinFunctor callback,
                             bool none_reached);

  void JoinSucceeded(JoinFunctor callback);

  void JoinFailed(JoinFunctor callback, int result);

  template <typename T>
  void NotJoined(T callback);

  template <typename T>
  void FailedValidation(T callback);

  /** Returns the closest contacts to key from this node's routing table.  If
   *  this node is within the required closest, it is included in the result. */
  OrderedContacts GetClosestContactsLocally(const Key &key,
                                            const uint16_t &total_contacts);

  /** If signature is empty, it is set to the signature of value.  If not, it is
   *  validated. */
  bool ValidateOrSign(const std::string &value,
                      SecurifierPtr securifier,
                      std::string *signature);

  /** Runs the FindValue callback for the case where this node has the value(s)
   *  locally (i.e. in its alternative_store_ or data_store_). */
  void FoundValueLocally(const FindValueReturns &find_value_returns,
                         FindValueFunctor callback);

  /** Runs the GetContact callback for the case where it's this node's Contact
   *  which is the target. */
  void GetOwnContact(GetContactFunctor callback);

  /** Callback used if we hold the target's contact details in our own routing
   *  table - i.e. we only did a Ping rather than an iterative lookup. */
  void GetContactPingCallback(RankInfoPtr rank_info,
                              int result,
                              Contact peer,
                              GetContactFunctor callback);

  void PingCallback(RankInfoPtr rank_info,
                    int result,
                    Contact peer,
                    PingFunctor callback);

  void StartLookup(LookupArgsPtr lookup_args);

  /** Function to execute iterative rpc->findnode or findvalue requests.
   *  @param[in] find_args The arguments struct holding all shared info. */
  void DoLookupIteration(LookupArgsPtr lookup_args);

  /** Callback from the rpc->findvalue or findnodes requests.
   *  @param[in] rank_info rank info
   *  @param[in] result Indicator from the rpc. Any negative value shall be
   *  considered as the enquired contact got some problems.
   *  @param[in] values_and_signatures The values and signatures of the key.
   *  @param[in] contacts The closest contacts.
   *  @param[in] alternative_store The alternative store contact.
   *  @param[in] peer The Contact being queried.
   *  @param[in] lookup_args The arguments struct holding all shared info. */
  void IterativeFindCallback(
      RankInfoPtr rank_info,
      int result,
      const std::vector<ValueAndSignature> &values_and_signatures,
      const std::vector<Contact> &contacts,
      const Contact &alternative_store,
      Contact peer,
      LookupArgsPtr lookup_args);

  bool AbortLookup(int result,
                   const std::vector<ValueAndSignature> &values_and_signatures,
                   const std::vector<Contact> &contacts,
                   const Contact &alternative_store,
                   const Contact &peer,
                   bool second_node,
                   LookupArgsPtr lookup_args);

  LookupContacts::iterator GetShortlistUpperBound(LookupArgsPtr lookup_args);

  /** Moves any Contacts found in the downlist from "contacts" to the
   *  downlist */
  void RemoveDownlistedContacts(LookupArgsPtr lookup_args,
                                LookupContacts::iterator this_peer,
                                OrderedContacts *contacts);

  /** Adds "contacts" to the current lookup shortlist and return an iterator to
   *  the current (n+1)th closest where n is the number of contacts requested */
  LookupContacts::iterator InsertCloseContacts(
      const OrderedContacts &contacts,
      LookupArgsPtr lookup_args,
      LookupContacts::iterator this_peer);

  void AssessLookupState(LookupArgsPtr lookup_args,
                         LookupContacts::iterator shortlist_upper_bound,
                         bool *iteration_complete,
                         int *shortlist_ok_count);

  void HandleCompletedLookup(LookupArgsPtr lookup_args,
                             LookupContacts::iterator closest_upper_bound,
                             const int &closest_count);

  void InitiateStorePhase(StoreArgsPtr store_args,
                          LookupContacts::iterator closest_upper_bound,
                          const int &closest_count);

  void InitiateDeletePhase(DeleteArgsPtr delete_args,
                           LookupContacts::iterator closest_upper_bound,
                           const int &closest_count);

  void InitiateUpdatePhase(UpdateArgsPtr update_args,
                           LookupContacts::iterator closest_upper_bound,
                           const int &closest_count);

  void InitiateRefreshPhase(RefreshArgsPtr refresh_args,
                            LookupContacts::iterator closest_upper_bound,
                            const int &closest_count);

  void HandleStoreToSelf(StoreArgsPtr store_args);

  void HandleDeleteToSelf(DeleteArgsPtr delete_args);

  void HandleUpdateToSelf(UpdateArgsPtr update_args);

  /** Callback from the rpc->store requests, during the Store operation.
   *  @param[in] rank_info rank info
   *  @param[in] result Indicator from the rpc->store. Any negative value shall
   *  be considered as the enquired contact got some problems.
   *  @param[in] peer The Contact being queried.
   *  @param[in] store_args The arguments struct holding all shared info. */
  void StoreCallback(RankInfoPtr rank_info,
                     int result,
                     Contact peer,
                     StoreArgsPtr store_args);

  /** Callback from the rpc->delete requests. Need to calculate number of
   *  success and report back the final result.  Used by: Delete, Update
   *  @param[in] rank_info rank info
   *  @param[in] result Indicator from the rpc->delete. Any negative value shall
   *  be considered as the enquired contact got some problems.
   *  @param[in] peer The Contact being queried.
   *  @param[in] args The arguments struct holding all shared info */
  void DeleteCallback(RankInfoPtr rank_info,
                      int result,
                      Contact peer,
                      LookupArgsPtr args);

  /** Callback from the rpc->store requests, during the Update operation.
   *  @param[in] rank_info rank info
   *  @param[in] result Indicator from the rpc->store. Any negative value shall
   *  be considered as the enquired contact got some problems.
   *  @param[in] peer The Contact being queried.
   *  @param[in] update_args The arguments struct holding all shared info. */
  void UpdateCallback(RankInfoPtr rank_info,
                     int result,
                     Contact peer,
                     UpdateArgsPtr update_args);

  template <typename T>
  void HandleSecondPhaseCallback(int result, T args);

  void SendDownlist(const Downlist &downlist);

  void RefreshDataStore(const boost::system::error_code &error_code);

  void RefreshData(const KeyValueTuple &key_value_tuple);

  /** returns true if the code conveys that the node has not been reached 
   *  @param[in] code  the code denoting the response type*/
  bool NodeContacted(const int &code);

  /** Function to be connected with the ping_oldest_contact signal in routing
   *  table. Will try to ping the report in oldest contact
   *  @param[in] oldest_contact The report in oldest_contact
   *  @param[in] replacement_contact The contact trying to replace the oldest
   *  @param[in] replacement_rank_info Rank info of the replacement contact */
  void PingOldestContact(const Contact &oldest_contact,
                         const Contact &replacement_contact,
                         RankInfoPtr replacement_rank_info);

  /** Callback Function of the PingOldestContact
   *  Will try to replace the oldest with the new one if no response from the
   *  oldest
   *  @param[in] oldest_contact The report in oldest_contact
   *  @param[in] oldest_rank_info Rank info of the oldest contact
   *  @param[in] result Result from the Ping. Any negative value indicates fail
   *  @param[in] replacement_contact The contact trying to replace the oldest
   *  @param[in] replacement_rank_info Rank info of the replacement contact */
  void PingOldestContactCallback(Contact oldest_contact,
                                 RankInfoPtr oldest_rank_info,
                                 const int &result,
                                 Contact replacement_contact,
                                 RankInfoPtr replacement_rank_info);

  /** Will connect the ping_oldest_contact signal in routing table to
   *  PingOldestContact if not already done. */
  void ConnectPingOldestContact();

  /** Function to be connected with the validate_contact signal in routing
   *  table. Will try to validate the contact
   *  @param[in] contact The contact needs to be validated */
  void ValidateContact(const Contact &contact);

  /** Callback Functionof the ValidateContact
   *  @param[in] contact The contact needs to be validated
   *  @param[in] public_key The public_key of the contact
   *  @param[in] public_key_validation The contact's public_key_validation */
  void ValidateContactCallback(Contact contact,
                               std::string public_key,
                               std::string public_key_validation);

  /** Will connect the validate_contact signal in routing table to
   *  ValidateContact if not already done. */
  void ConnectValidateContact();

  /** Function to be connected with the ping_down_contact signal in routing
   *  table. Will try to ping the downlisted contact
   *  @param[in] down_contact The reported downlisted contact */
  void PingDownContact(const Contact &down_contact);

  /** Callback Function of the PingDownContact
   *  @param[in] down_contact The reported downlisted contact
   *  @param[in] rank_info Rank info of the reported downlisted contact
   *  @param[in] result Result from the Ping. Any negative value indicates
   *  failure */
  void PingDownContactCallback(Contact down_contact,
                               RankInfoPtr rank_info,
                               const int &result);

  /** Will connect the ping_down_contact signal in routing table to
   *  PingDownContact if not already done. */
  void ConnectPingDownContact();

  /** All RPCs should update the routing table for the given contact using this
   *  method */
  void HandleRpcCallback(const Contact &contact,
                         RankInfoPtr rank_info,
                         const int &result);

  /** Posts HandleRpcCallback to asio service */
  void AsyncHandleRpcCallback(const Contact &contact,
                              RankInfoPtr rank_info,
                              const int &result);

  AsioService &asio_service_;
  TransportPtr listening_transport_;
  MessageHandlerPtr message_handler_;
  SecurifierPtr default_securifier_;
  AlternativeStorePtr alternative_store_;
  OnOnlineStatusChangePtr on_online_status_change_;
  bool client_only_node_;
  /** Kademlia k parameter */
  const uint16_t k_;
  /** Kademlia alpha parameter to define how many contacts are to be queried
   *  per lookup iteration */
  const uint16_t kAlpha_;
  /** Kademlia beta parameter to define how many contacts are required to have
   *  responded in a lookup iteration before starting a new iteration */
  const uint16_t kBeta_;
  const bptime::seconds kMeanRefreshInterval_, kDataStoreCheckInterval_;
  std::shared_ptr<DataStore> data_store_;
  std::shared_ptr<Service> service_;
  std::shared_ptr<RoutingTable> routing_table_;
  std::shared_ptr<Rpcs<transport::TcpTransport>> rpcs_;
  /** Own info of nodeid, ip and port */
  Contact contact_;
  bool joined_;
  boost::signals2::connection ping_oldest_contact_, validate_contact_,
                              ping_down_contact_;
  boost::asio::deadline_timer refresh_data_store_timer_;
};

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_NODE_IMPL_H_
