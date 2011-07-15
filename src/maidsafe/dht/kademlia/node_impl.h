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
#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "boost/signals2/connection.hpp"
#include "boost/thread/shared_mutex.hpp"
#include "boost/thread/locks.hpp"
#include "boost/thread.hpp"
#include "boost/enable_shared_from_this.hpp"

#include "maidsafe/dht/kademlia/node_impl_structs.h"
#include "maidsafe/dht/kademlia/config.h"
#include "maidsafe/dht/kademlia/node-api.h"
#include "maidsafe/dht/kademlia/contact.h"
#include "maidsafe/dht/kademlia/datastore.h"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace dht {

namespace kademlia {

class DataStore;
class Service;
class RoutingTable;
class Rpcs;

namespace test {
class NodeImplTest;
class MockNodeImplTest;
class MockNodeImplTest_FUNC_KAD_HandleIterationStructure_Test;
class MockNodeImplTest_BEH_KAD_Join_Test;
class MockNodeImplTest_BEH_KAD_Getters_Test;
class MockNodeImplTest_BEH_KAD_Leave_Test;
class MockNodeImplTest_BEH_KAD_DownlistClient_Test;
class MockNodeApiTest_BEH_KAD_Join_Server_Test;
class MockNodeImplTest_BEH_KAD_ValidateContact_Test;
class MockNodeImplTest_BEH_KAD_PingOldestContact_Test;
}  // namespace test

enum SearchMarking { kSearchDown, kSearchContacted };

typedef std::shared_ptr<boost::signals2::signal<void(const Contact&)>>
        ReportDownContactPtr;
typedef std::function<void(RankInfoPtr, const int&)> StoreRefreshFunctor;

class Node::Impl {
 public:
  Impl(AsioService &asio_service,                             // NOLINT (Fraser)
       TransportPtr listening_transport,
       MessageHandlerPtr message_handler,
       SecurifierPtr default_securifier,
       AlternativeStorePtr alternative_store,
       bool client_only_node,
       const uint16_t &k,
       const uint16_t &alpha,
       const uint16_t &beta,
       const bptime::time_duration &mean_refresh_interval);
  // virtual destructor to allow tests to use a derived Impl and befriend it
  // rather than polluting this with friend tests.
  virtual ~Impl();
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
   *  @param[in] securifier The securifier to pass further.
   *  @param[in] ttl The ttl for the new data.
   *  @param[in] callback The callback to report the results. */
  void Update(const Key &key,
              const std::string &new_value,
              const std::string &new_signature,
              const std::string &old_value,
              const std::string &old_signature,
              SecurifierPtr securifier,
              const bptime::time_duration &ttl,
              UpdateFunctor callback);
  /** Function to FIND VALUES of the Key from the Kademlia network.
   *  @param[in] Key The key to find
   *  @param[in] securifier The securifier to pass further.
   *  @param[in] callback The callback to report the results. */
  void FindValue(const Key &key,
                 SecurifierPtr securifier,
                 FindValueFunctor callback);
  /** Function to FIND k-closest NODES to the Key from the Kademlia network.
   *  @param[in] Key The key to locate
   *  @param[in] callback The callback to report the results. */
  void FindNodes(const Key &key, FindNodesFunctor callback);
  /** Function to get a contact info from the Kademlia network.
   *  @param[in] node_id The node_id to locate
   *  @param[in] callback The callback to report the results. */
  void GetContact(const NodeId &node_id, GetContactFunctor callback);
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
  /** Getter.
   *  @return The contact_ */
  Contact contact() const;
  /** Getter.
   *  @return The joined_ */
  bool joined() const;
  /** Getter.
   *  @return The alternative_store_ */
  AlternativeStorePtr alternative_store();
  /** Getter.
   *  @return The on_online_status_change_ */
  OnOnlineStatusChangePtr on_online_status_change();
  /** Getter.
   *  @return The client_only_node flag. */
  bool client_only_node() const;
  /** Getter.
   *  @return The k_ */
  uint16_t k() const;
  /** Getter.
   *  @return The kAlpha_ */
  uint16_t alpha() const;
  /** Getter.
   *  @return The kBeta_ */
  uint16_t beta() const;
  /** Getter.
   *  @return The kMeanRefreshInterval_ */
  bptime::time_duration mean_refresh_interval() const;
  /** Setter. Will connect the signal in service as well.
   *  @param[in] service The service to connect */
  void SetService(std::shared_ptr<Service> service);
  bool refresh_thread_running() const;
  bool downlist_thread_running() const;

  friend class test::NodeImplTest;
  friend class test::MockNodeImplTest;
  friend class test::MockNodeImplTest_FUNC_KAD_HandleIterationStructure_Test;
  friend class test::MockNodeImplTest_BEH_KAD_Join_Test;
  friend class test::MockNodeImplTest_BEH_KAD_Getters_Test;
  friend class test::MockNodeImplTest_BEH_KAD_Leave_Test;
  friend class test::MockNodeImplTest_BEH_KAD_DownlistClient_Test;
  friend class test::MockNodeImplTest_BEH_KAD_ValidateContact_Test;
  friend class test::MockNodeImplTest_BEH_KAD_PingOldestContact_Test;

 private:
  Impl(const Impl&);
  Impl &operator=(const Impl&);

  /** Setter. Will connect the ping_oldest_contact signal in routing table. */
  void EnablePingOldestContact();
  /** Setter. Will connect the validate_contact signal in routing table. */
  void EnableValidateContact();

  /** Callback from the rpc->findnode request for GetContact.
   *  @param[in] result_size The number of closest contacts find.
   *  @param[in] contacts the k-closest contacts to the node_id
   *  @param[in] node_id The node_id of the contact to search.
   *  @param[in] callback The callback to report the results. */
  void GetContactCallBack(int result_size,
                          const std::vector<Contact> &contacts,
                          const NodeId &node_id,
                          GetContactFunctor callback);

  /** Function to add acquired closest contacts into shared struct info, during
   *  the execution of iterative search.
   *  Used by: FindNodes, FindValue
   *  @param[in] T FindNodesArgs, FindValueArgs
   *  @param[in] contacts The closest contacts.
   *  @param[in] find_args The arguments struct holding all shared info. */
  template <class T>
  void AddContactsToContainer(const std::vector<Contact> contacts,
                              std::shared_ptr<T> find_args);

  /** Function to execute iterative rpc->findnode requests.
   *  Used by: FindNodes, FindValue
   *  @param[in] T FindNodesArgs, FindValueArgs
   *  @param[in] find_args The arguments struct holding all shared info. */
  template <class T>
  void IterativeSearch(std::shared_ptr<T> find_args);

  /** Callback from the rpc->findvalue requests, during the FindValue operation.
   *  @param[in] rank_info rank info
   *  @param[in] result Indicator from the rpc->findvalue. Any negative
   *  value shall be considered as the enquired contact got some problems.
   *  @param[in] values The values of the key.
   *  @param[in] contacts The closest contacts.
   *  @param[in] alternative_store The alternative store contact.
   *  @param[in] find_value_rpc_args The arguments struct holding all shared
   *  info. */
  void IterativeSearchValueResponse(RankInfoPtr rank_info,
                                    int result,
                                    const std::vector<std::string> &values,
                                    const std::vector<Contact> &contacts,
                                    const Contact &alternative_store,
                                    RpcArgsPtr find_value_rpc_args);

  /** Callback from the rpc->findnodes requests, during the FindNodes operation.
   *  @param[in] rank_info rank info
   *  @param[in] result Indicator from the rpc->findnodes. Any negative
   *  value shall be considered as the enquired contact got some problems.
   *  @param[in] contacts The closest contacts.
   *  @param[in] find_nodes_rpc_args The arguments struct holding all shared
   *  info. */
  void IterativeSearchNodeResponse(RankInfoPtr rank_info,
                                   int result,
                                   const std::vector<Contact> &contacts,
                                   RpcArgsPtr find_nodes_rpc_args);

  /** Function to handle the iteration search structure.
   *  Used by: FindNodes, FindValue
   *  @param[in] T FindNodesArgs, FindValueArgs
   *  @param[in] contact The current responding contact
   *  @param[in] find_args The arguments struct holding all shared info.
   *  @param[in] mark Indicate if the current responding contact is down or not
   *  @param[out] response_code The response_code in case of search can be
   *  stopped.
   *  @param[out] closest_contacts The closest contacts in case of search can be
   *  stopped.
   *  @param[out] cur_iteration_done Indicates if a new iteration can be
   *  started.
   *  @param[out] called_back Indicates if a the search can be stopped. */
  template <class T>
  bool HandleIterationStructure(const Contact &contact,
                                std::shared_ptr<T> find_args,
                                NodeSearchState mark,
                                int *response_code,
                                std::vector<Contact> *closest_contacts,
                                bool *cur_iteration_done,
                                bool *called_back);

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

  /** Function to be connected with the ping_downlist_contact signal in service.
   *  Will try to ping the report in down contact.
   *  @param[in] contact The report in down_contact */
  void PingDownlistContact(const Contact &contact);

  /** Callback Function of the PingDownlistContact
   *  Will increase the RpcFailure of the contact by one if got no response
   *  @param[in] contact The report in down_contact
   *  @param[in] rank_info Rank info of the down contact
   *  @param[in] result Result from the Ping. Any negative value indicates a
   *             failure */
  void PingDownlistContactCallback(Contact contact,
                                   RankInfoPtr rank_info,
                                   const int &result);

  /** Template Callback from the rpc->findnode requests.
   *  Used by: Store, Delete, Update
   *  @param[in] T StoreArgs, UpdateArgs, DeleteArgs
   *  @param[in] contacts the k-closest nodes to the key
   *  @param[in] Key The key to be passed further.
   *  @param[in] value The value to be passed further.
   *  @param[in] signature The signature to be passed further.
   *  @param[in] ttl The ttl to be passed further.
   *  @param[in] securifier The securifier to be passed further.
   *  @param[in] args The arguments struct holding all shared info. */
  template <class T>
  void OperationFindNodesCB(int result,
                            const std::vector<Contact> &contacts,
                            const Key &key,
                            const std::string &value,
                            const std::string &signature,
                            const bptime::time_duration &ttl,
                            SecurifierPtr securifier,
                            std::shared_ptr<T> args);

  /** Callback from the rpc->store requests, during the Store operation.
   *  @param[in] rank_info rank info
   *  @param[in] response_code Indicator from the rpc->store. Any negative
   *  value shall be considered as the enquired contact got some problems.
   *  @param[in] store_rpc_args The arguments struct holding all shared info.
   *  @param[in] Key The key to be passed further.
   *  @param[in] value The value to be passed further.
   *  @param[in] signature The signature to be passed further.
   *  @param[in] securifier The securifier to be passed further. */
  void StoreResponse(RankInfoPtr rank_info,
                     int response_code,
                     RpcArgsPtr store_rpc_args,
                     const Key &key,
                     const std::string &value,
                     const std::string &signature,
                     SecurifierPtr securifier);

  /** Callback from the rpc->store requests, during the Update operation.
   *  @param[in] rank_info rank info
   *  @param[in] response_code Indicator from the rpc->store. Any negative
   *  value shall be considered as the enquired contact got some problems.
   *  @param[in] update_rpc_args The arguments struct holding all shared info.
   *  @param[in] Key The key to be passed further.
   *  @param[in] securifier The securifier to be passed further. */
  void UpdateStoreResponse(RankInfoPtr rank_info,
                           int response_code,
                           RpcArgsPtr update_rpc_args,
                           const Key &key,
                           SecurifierPtr securifier);

  /** Template Callback from the rpc->delete requests. Need to calculate number
   *  of success and report back the final result.
   *  Used by: Delete, Update
   *  @param[in] T UpdateArgs, DeleteArgs
   *  @param[in] rank_info rank info
   *  @param[in] response_code Indicator from the rpc->delete. Any negative
   *  value shall be considered as the enquired contact got some problems.
   *  @param[in] delete_rpc_args The arguments struct holding all shared info. */
  template <class T>
  void DeleteResponse(RankInfoPtr rank_info,
                      int response_code,
                      RpcArgsPtr delete_rpc_args);

  /** Callback from the single rpc->delete request. Just report the contact as
   *  down if necessary. Nothing else needs to be undertaken.
   *  Used only during the Store process in case of failure to delete the
   *  previous stored data. */
  void SingleDeleteResponse(RankInfoPtr rank_info,
                            int response_code,
                            const Contact &contact);

  /** Function bound to the slot of report_down_contact_ to collect any
   *  emitted signal. Any down_contact captured from signals will be pushed into
   *  the down_contacts_ queue.
   *  @param[in] down_contact The contact detected as down during any operation,
   *  reported via a signal. */
  void ReportDownContact(const Contact &down_contact);

  /** Thread function keeps monitoring the down_contacts_, once detect any
   *  entries in the queue, notify the k-closest in the routingtable about
   *  the downlist */
  void MonitoringDownlistThread();

  void JoinFindNodesCallback(const int &result,
                             const std::vector<Contact> &returned_contacts,
                             std::vector<Contact> bootstrap_contacts,
                             const NodeId &node_id,
                             JoinFunctor callback);
  void JoinFindValueCallback(FindValueReturns find_value_returns,
                             std::vector<Contact> bootstrap_contacts,
                             const NodeId &node_id,
                             JoinFunctor callback);
  void RefreshDataStore();
  // void StoreRefreshCallback(RankInfoPtr rank_info, const int &result);
  void PostStoreRefresh(const KeyValueTuple &key_value_tuple);
  void StoreRefresh(int result,
                    std::vector<Contact> contacts,
                    const KeyValueTuple &key_value_tuple);
  void StoreRefreshCallback(RankInfoPtr rank_info,
                            const int &result,
                            const Contact &contact);

  AsioService &asio_service_;
  TransportPtr listening_transport_;
  MessageHandlerPtr message_handler_;
  SecurifierPtr default_securifier_;
  AlternativeStorePtr alternative_store_;
  OnOnlineStatusChangePtr on_online_status_change_;

  /** If the node is Client Only, then it shall not put anything into its local
   *  routing table. Only Vault is allowed to do so. */
  bool client_only_node_;

  /** Global K parameter */
  const uint16_t k_;

  /** Global threshold to define the number of succeed required to consider a
   *  Store, Delete or Update to be success */
  int threshold_;

  /** Alpha parameter to define how many contacts to be enquired during one
   *  iteration */
  const uint16_t kAlpha_;

  /** Beta parameter to define how many contacted contacts required in one
   *  iteration before starting a new iteration */
  const uint16_t kBeta_;
  const bptime::seconds kMeanRefreshInterval_;
  std::shared_ptr<DataStore> data_store_;
  std::shared_ptr<Service> service_;
  std::shared_ptr<RoutingTable> routing_table_;
  std::shared_ptr<Rpcs> rpcs_;

  /** Own info of nodeid, ip and port */
  Contact contact_;
  bool joined_, refresh_routine_started_, stopping_;

  /** Signal to be fired when there is one contact detected as DOWN during any
   *  operations */
  ReportDownContactPtr report_down_contact_;

  /** Mutex lock to protect down_contacts_ */
  boost::mutex mutex_;

  /** Conditional Variable to wait/notify the thread monitoring down_contacts_*/
  boost::condition_variable condition_downlist_;

  /** The mutex queue temporally holding the down_contacts before notifying */
  std::vector<NodeId> down_contacts_;

  /** The thread group to hold all monitoring treads
   *  Used by: MonitoringDownlistThread */
  std::shared_ptr<boost::thread_group> thread_group_;
  bool refresh_thread_running_,
       downlist_thread_running_,
       validate_contact_running_;
};

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_NODE_IMPL_H_
