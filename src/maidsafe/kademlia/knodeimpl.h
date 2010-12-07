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

#ifndef MAIDSAFE_KADEMLIA_KNODEIMPL_H_
#define MAIDSAFE_KADEMLIA_KNODEIMPL_H_

#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/cstdint.hpp>
#include <gtest/gtest_prod.h>

#include <string>
#include <vector>
#include <list>
#include <map>
#include <memory>

#include "maidsafe/base/alternativestore.h"
#include "maidsafe/base/calllatertimer.h"
#include "maidsafe/base/validationinterface.h"
#include "maidsafe/kademlia/kadrpc.h"
#include "maidsafe/kademlia/kadservice.h"
#include "maidsafe/kademlia/knodeimplstructs.h"
#include "maidsafe/protobuf/general_messages.pb.h"
#include "maidsafe/protobuf/kademlia_service.pb.h"
#include "maidsafe/upnp/upnpclient.h"

namespace base {
class PublicRoutingTableHandler;
}

namespace kad {

class ContactInfo;
class DataStore;
class KadService;
class RoutingTable;
struct LookupContact;
struct ContactAndTargetKey;

bool CompareContact(const ContactAndTargetKey &first,
                    const ContactAndTargetKey &second);

void SortContactList(const KadId &target_key,
                     std::list<Contact> *contact_list);

void SortLookupContact(const KadId &target_key,
                       std::list<LookupContact> *contact_list);

namespace test_knodeimpl {
class TestKNodeImpl_BEH_KNodeImpl_ExecuteRPCs_Test;
class TestKNodeImpl_BEH_KNodeImpl_NotJoined_Test;
class TestKNodeImpl_BEH_KNodeImpl_AddContactsToContainer_Test;
class TestKNodeImpl_BEH_KNodeImpl_GetAlphas_Test;
class TestKNodeImpl_BEH_KNodeImpl_MarkNode_Test;
class TestKNodeImpl_BEH_KNodeImpl_BetaDone_Test;
class TestKNodeImpl_BEH_KNodeImpl_IterativeSearchResponse_Test;
class TestKNodeImpl_BEH_KNodeImpl_IterativeSearchHappy_Test;
class TestKNodeImpl_BEH_KNodeImpl_FindNodesHappy_Test;
class TestKNodeImpl_BEH_KNodeImpl_FindNodesContactsInReponse_Test;
}  // namespace test

class KNodeImpl {
 public:
  // constructor used to set up parameters k, alpha, and beta for kademlia
  KNodeImpl(boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager,
            boost::shared_ptr<transport::Transport> transport,
            const KnodeConstructionParameters &knode_parameters);
  virtual ~KNodeImpl();

  virtual void Join(const KadId &node_id, const std::string &kad_config_file,
                    VoidFunctorOneString callback);
  virtual void Join(const std::string &kad_config_file,
                    VoidFunctorOneString callback);

  // Use this join for the first node in the network
  void JoinFirstNode(const KadId &node_id, const std::string &kad_config_file,
                     const IP &external_ip, const Port &external_port,
                     VoidFunctorOneString callback);
  void JoinFirstNode(const std::string &kad_config_file, const IP &external_ip,
                     const Port &external_port, VoidFunctorOneString callback);

  void Leave();
  virtual void StoreValue(const KadId &key, const SignedValue &signed_value,
                          const SignedRequest &signed_request,
                          const boost::int32_t &ttl,
                          VoidFunctorOneString callback);
  virtual void StoreValue(const KadId &key, const std::string &value,
                          const boost::int32_t &ttl,
                          VoidFunctorOneString callback);
  virtual void DeleteValue(const KadId &key, const SignedValue &signed_value,
                           const SignedRequest &signed_request,
                           VoidFunctorOneString callback);
  virtual void UpdateValue(const KadId &key, const SignedValue &old_value,
                           const SignedValue &new_value,
                           const SignedRequest &signed_request,
                           boost::uint32_t ttl, VoidFunctorOneString callback);
  virtual void FindValue(const KadId &key, const bool &check_alternative_store,
                         VoidFunctorOneString callback);
  void GetNodeContactDetails(const KadId &node_id,
                             VoidFunctorOneString callback, const bool &local);
  virtual void FindKClosestNodes(const KadId &node_id,
                                 VoidFunctorOneString callback);
  void GetKNodesFromRoutingTable(const KadId &key,
                                 const std::vector<Contact> &exclude_contacts,
                                 std::vector<Contact> *close_nodes);
  virtual void Ping(const KadId &node_id, VoidFunctorOneString callback);
  virtual void Ping(const Contact &remote, VoidFunctorOneString callback);
  int AddContact(Contact new_contact, const float &rtt, const bool &only_db);
  void RemoveContact(const KadId &node_id);
  bool GetContact(const KadId &id, Contact *contact);
  bool FindValueLocal(const KadId &key, std::vector<std::string> *values);
  bool StoreValueLocal(const KadId &key, const std::string &value,
                       const boost::int32_t &ttl);
  bool RefreshValueLocal(const KadId &key, const std::string &value,
                         const boost::int32_t &ttl);
  bool DelValueLocal(const KadId &key, const SignedValue &value,
                     const SignedRequest &req);
  void GetRandomContacts(const size_t &count,
                         const std::vector<Contact> &exclude_contacts,
                         std::vector<Contact> *contacts);
  void HandleDeadRendezvousServer(const bool &dead_server);
  ConnectionType CheckContactLocalAddress(const KadId &id, const IP &ip,
                                          const Port &port, const IP &ext_ip);
  void UpdatePDRTContactToRemote(const KadId &node_id,
                                 const IP &host_ip);
  ContactInfo contact_info() const;
  inline KadId node_id() const {
    return (type_ == CLIENT || type_ == CLIENT_PORT_MAPPED)
        ? fake_kClientId_ : node_id_;
  }
  boost::uint32_t KeyLastRefreshTime(const KadId &key,
                                     const std::string &value);
  boost::uint32_t KeyExpireTime(const KadId &key, const std::string &value);
  inline IP host_ip() const { return host_ip_; }
  inline Port host_port() const { return host_port_; }
  inline IP local_host_ip() const { return local_host_ip_; }
  inline Port local_host_port() const { return local_host_port_; }
  inline IP rendezvous_ip() const { return rv_ip_; }
  inline Port rendezvous_port() const { return rv_port_; }
  inline bool is_joined() const { return is_joined_; }
  inline boost::shared_ptr<KadRpcs> kadrpcs() { return kadrpcs_; }
  bool HasRSAKeys();
  boost::int32_t KeyValueTTL(const KadId &key, const std::string &value) const;
  inline void set_alternative_store(base::AlternativeStore* alt_store) {
    alternative_store_ = alt_store;
    if (premote_service_.get() != NULL)
      premote_service_->set_alternative_store(alternative_store_);
  }
  inline base::AlternativeStore *alternative_store() {
    return alternative_store_;
  }
  inline void set_signature_validator(base::SignatureValidator *validator) {
    signature_validator_ = validator;
    if (premote_service_ != 0)
      premote_service_->set_signature_validator(signature_validator_);
  }
  inline NatType host_nat_type() { return host_nat_type_; }

 private:
  friend class test_knodeimpl::TestKNodeImpl_BEH_KNodeImpl_ExecuteRPCs_Test;
  friend class test_knodeimpl::TestKNodeImpl_BEH_KNodeImpl_NotJoined_Test;
  friend class test_knodeimpl::
      TestKNodeImpl_BEH_KNodeImpl_AddContactsToContainer_Test;
  friend class test_knodeimpl::TestKNodeImpl_BEH_KNodeImpl_GetAlphas_Test;
  friend class test_knodeimpl::TestKNodeImpl_BEH_KNodeImpl_MarkNode_Test;
  friend class test_knodeimpl::TestKNodeImpl_BEH_KNodeImpl_BetaDone_Test;
  friend class test_knodeimpl::
      TestKNodeImpl_BEH_KNodeImpl_IterativeSearchResponse_Test;
  friend class test_knodeimpl::
      TestKNodeImpl_BEH_KNodeImpl_IterativeSearchHappy_Test;
  friend class test_knodeimpl::TestKNodeImpl_BEH_KNodeImpl_FindNodesHappy_Test;
  friend class test_knodeimpl::
      TestKNodeImpl_BEH_KNodeImpl_FindNodesContactsInReponse_Test;

  KNodeImpl &operator=(const KNodeImpl&);
  KNodeImpl(const KNodeImpl&);
  inline void CallbackWithFailure(VoidFunctorOneString callback);
  void Join_Bootstrapping(const bool &got_external_address,
                          VoidFunctorOneString callback);
  void Join_RefreshNode(VoidFunctorOneString callback,
                        const bool &port_forwarded);
  void SaveBootstrapContacts();
  boost::int16_t LoadBootstrapContacts();
  void RefreshRoutine();
  void StartSearchIteration(const KadId &key, const RemoteFindMethod &method,
                            VoidFunctorOneString callback);
  void SearchIteration_ExtendShortList(const FindResponse *response,
                                       FindCallbackArgs callback_data);
  void SearchIteration(boost::shared_ptr<IterativeLookUpData> data);
  void FinalIteration(boost::shared_ptr<IterativeLookUpData> data);
  void SendDownlist(boost::shared_ptr<IterativeLookUpData> data);
  void SendFindRpc(Contact remote, boost::shared_ptr<IterativeLookUpData> data,
                   const ConnectionType &conn_type);
  void SearchIteration_CancelActiveProbe(
      Contact sender,
      boost::shared_ptr<IterativeLookUpData> data);
  void SearchIteration_Callback(boost::shared_ptr<IterativeLookUpData> data);
  void SendFinalIteration(boost::shared_ptr<IterativeLookUpData> data);
  void StoreValue_IterativeStoreValue(const StoreResponse *response,
                                      StoreCallbackArgs callback_data);
  void StoreValue_ExecuteStoreRPCs(const std::string &result, const KadId &key,
                                   const std::string &value,
                                   const SignedValue &sig_value,
                                   const SignedRequest &sig_req,
                                   const bool &publish,
                                   const boost::int32_t &ttl,
                                   VoidFunctorOneString callback);
  void DelValue_ExecuteDeleteRPCs(const std::string &result, const KadId &key,
                                  const SignedValue &value,
                                  const SignedRequest &sig_req,
                                  VoidFunctorOneString callback);
  void DelValue_IterativeDeleteValue(const DeleteResponse *response,
                                     DeleteCallbackArgs callback_data);
  void ExecuteUpdateRPCs(const std::string &result, const KadId &key,
                         const SignedValue &old_value,
                         const SignedValue &new_value,
                         const SignedRequest &sig_req,
                         boost::uint32_t ttl, VoidFunctorOneString callback);
  void UpdateValueResponses(boost::shared_ptr<UpdateCallbackArgs> uca);
  void FindNode_GetNode(const std::string &result, const KadId &node_id,
                        VoidFunctorOneString callback);
  void Ping_HandleResult(const PingResponse *response,
                         PingCallbackArgs callback_data);
  void Ping_SendPing(const std::string &result, VoidFunctorOneString callback);
  void ReBootstrapping_Callback(const std::string &result);
  void RegisterKadService();
  void UnRegisterKadService();
  void UPnPMap(Port host_port);
  void UnMapUPnP();
  void CheckToInsert(const Contact &new_contact);
  void CheckToInsert_Callback(const std::string &result, KadId id,
                              Contact new_contact);
  void CheckAddContacts();
  void RefreshValuesRoutine();
  void RefreshValue(const KadId &key, const std::string &value,
                    const boost::int32_t &ttl, VoidFunctorOneString callback);
  void RefreshValueCallback(const std::string &result, const KadId &key,
                            const std::string &value, const boost::int32_t &ttl,
                            const boost::uint32_t &total_refreshes,
                            boost::shared_ptr<boost::uint32_t> refreshes_done);

  boost::mutex routingtable_mutex_, kadconfig_mutex_, extendshortlist_mutex_,
               joinbootstrapping_mutex_, leave_mutex_, activeprobes_mutex_,
               pendingcts_mutex_;
  boost::shared_ptr<base::CallLaterTimer> ptimer_;
  boost::shared_ptr<transport::Transport> transport_;
  boost::shared_ptr<rpcprotocol::ChannelManager> pchannel_manager_;
  boost::shared_ptr<rpcprotocol::Channel> pservice_channel_;
  boost::shared_ptr<DataStore> pdata_store_;
  boost::shared_ptr<KadService> premote_service_;
  boost::shared_ptr<RoutingTable> prouting_table_;
  boost::shared_ptr<KadRpcs> kadrpcs_;
  boost::shared_ptr<boost::thread> addcontacts_routine_;
  boost::shared_ptr<base::PublicRoutingTableHandler> prth_;
  base::AlternativeStore *alternative_store_;
  base::SignatureValidator *signature_validator_;
  upnp::UpnpIgdClient upnp_;
  KadId node_id_, fake_kClientId_;
  IP host_ip_, rv_ip_, local_host_ip_;
  Port host_port_, rv_port_, local_host_port_, upnp_mapped_port_;
  NodeType type_;
  NatType host_nat_type_;
  std::vector<Contact> bootstrapping_nodes_, exclude_bs_contacts_;
  std::list<Contact> contacts_to_add_;
  const boost::uint16_t K_, alpha_, beta_;
  bool is_joined_, refresh_routine_started_, stopping_, port_forwarded_,
       use_upnp_;
  boost::filesystem::path kad_config_path_;
  boost::condition_variable add_ctc_cond_;
  std::string private_key_, public_key_;

  void AddContactsToContainer(const std::vector<Contact> contacts,
                              boost::shared_ptr<FindNodesArgs> fna);
  bool MarkResponse(const Contact &contact,
                    boost::shared_ptr<FindNodesArgs> fna, SearchMarking mark,
                    std::list<Contact> *response_nodes);
  void AnalyseIteration(boost::shared_ptr<FindNodesArgs> fna,
                        int round, std::list<Contact> *contacts,
                        bool *top_nodes_done, bool *calledback);
  void FindNodes(const FindNodesParams &fnp);
  virtual void IterativeSearch(boost::shared_ptr<FindNodesArgs> fna,
                               int round);
  void IterativeSearchResponse(boost::shared_ptr<FindNodesRpc> fnrpc);
};

}  // namespace kad

#endif  // MAIDSAFE_KADEMLIA_KNODEIMPL_H_
