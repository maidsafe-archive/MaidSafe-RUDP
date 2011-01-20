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

#include "maidsafe/common/platform_config.h"
#include "maidsafe/common/alternativestore.h"
#include "maidsafe/common/calllatertimer.h"
#include "maidsafe/common/validationinterface.h"
#include "maidsafe/kademlia/rpcs.h"
#include "maidsafe/kademlia/service.h"
#include "maidsafe/kademlia/nodeimplstructs.h"
#include "maidsafe/kademlia/kademlia.pb.h"
#include "maidsafe/kademlia/config.h"
#include "maidsafe/transport/udttransport.h"
#include "maidsafe/upnp/upnpclient.h"

namespace maidsafe {

class PublicRoutingTableHandler;

namespace kademlia {

//class ContactInfo;
class DataStore;
class Service;
class RoutingTable;
struct LookupContact;
struct ContactAndTargetKey;

bool CompareContact(const ContactAndTargetKey &first,
                    const ContactAndTargetKey &second);

void SortContactList(const NodeId &target_key,
                     std::list<Contact> *contact_list);

void SortLookupContact(const NodeId &target_key,
                       std::list<LookupContact> *contact_list);

namespace test_nodeimpl {
class TestNodeImpl_BEH_NodeImpl_ExecuteRPCs_Test;
class TestNodeImpl_BEH_NodeImpl_NotJoined_Test;
class TestNodeImpl_BEH_NodeImpl_AddContactsToContainer_Test;
class TestNodeImpl_BEH_NodeImpl_GetAlphas_Test;
class TestNodeImpl_BEH_NodeImpl_MarkNode_Test;
class TestNodeImpl_BEH_NodeImpl_BetaDone_Test;
class TestNodeImpl_BEH_NodeImpl_IterativeSearchResponse_Test;
class TestNodeImpl_BEH_NodeImpl_IterativeSearchHappy_Test;
class TestNodeImpl_BEH_NodeImpl_FindNodesHappy_Test;
class TestNodeImpl_BEH_NodeImpl_FindNodesContactsInReponse_Test;
}  // namespace test_nodeimpl

class NodeImpl {
 public:
  NodeImpl(boost::shared_ptr<transport::Transport> transport,
        const NodeConstructionParameters &node_parameters);
  virtual ~NodeImpl();

  void Join(const NodeId &node_id, const std::string &kad_config_file,
            VoidFunctorOneString callback) {}
  void Join(const std::string &kad_config_file, VoidFunctorOneString callback) {}
  void JoinFirstNode(const NodeId &node_id,
                     const std::string &kad_config_file,
                     const IP &ip,
                     const Port &port,
                     VoidFunctorOneString callback);
  void JoinFirstNode(const std::string &kad_config_file,
                     const IP &ip,
                     const Port &port,
                     VoidFunctorOneString callback);
  void Leave();
  void StoreValue(const NodeId &key, const protobuf::SignedValue &signed_value,
                  const protobuf::MessageSignature &request_signature,
                  const boost::int32_t &ttl, VoidFunctorOneString callback) {}
  void StoreValue(const NodeId &key, const std::string &value,
                  const boost::int32_t &ttl, VoidFunctorOneString callback) {}
  void DeleteValue(const NodeId &key, const protobuf::SignedValue &signed_value,
                   const protobuf::MessageSignature &request_signature,
                   VoidFunctorOneString callback) {}
  void UpdateValue(const NodeId &key,
                   const protobuf::SignedValue &old_value,
                   const protobuf::SignedValue &new_value,
                   const protobuf::MessageSignature &request_signature,
                   boost::uint32_t ttl,
                   VoidFunctorOneString callback) {}
  void FindValue(const NodeId &key, const bool &check_alternative_store,
                 VoidFunctorOneString callback) {}
  void GetNodeContactDetails(const NodeId &node_id,
                             VoidFunctorOneString callback, const bool &local) {}
  void FindKClosestNodes(const NodeId &key, VoidFunctorOneString callback) {}
  void GetNodesFromRoutingTable(const NodeId &key,
                                const std::vector<Contact> &exclude_contacts,
                                std::vector<Contact> *close_nodes) {}
  void Ping(const NodeId &node_id, VoidFunctorOneString callback) {}
  void Ping(const Contact &remote, VoidFunctorOneString callback) {}

  int AddContact(Contact new_contact, const float &rtt, const bool &only_db);
  void RemoveContact(const NodeId &node_id) {}
  bool GetContact(const NodeId &id, Contact *contact) { return false; }
  bool FindValueLocal(const NodeId &key, std::vector<std::string> *values) { return false; }
  bool StoreValueLocal(const NodeId &key, const std::string &value,
                       const boost::int32_t &ttl) { return false; }
  bool RefreshValueLocal(const NodeId &key, const std::string &value,
                         const boost::int32_t &ttl) { return false; }
  void GetRandomContacts(const size_t &count,
                         const std::vector<Contact> &exclude_contacts,
                         std::vector<Contact> *contacts) {}
  void HandleDeadRendezvousServer(const bool &dead_server) {}

  ConnectionType CheckContactLocalAddress(const NodeId &id,
                                          const IP &ip,
                                          const Port &port,
                                          const IP &ext_ip) { return LOCAL; }
  void UpdatePDRTContactToRemote(const NodeId &node_id,
                                 const IP &ip) {}

  Contact contact_info() const { return Contact(); }
  NodeId node_id() const { return NodeId(); }
  IP ip() const { return IP(); }
  Port port() const { return Port(0); }
  IP local_ip() const { return IP(); }
  Port local_port() const { return Port(0); }
  IP rendezvous_ip() const { return IP(); }
  Port rendezvous_port() const { return Port(0); }
  bool is_joined() const { return is_joined_; }

  boost::shared_ptr<Rpcs> rpcs() { return rpcs_; }

  boost::uint32_t KeyLastRefreshTime(const NodeId &key,
                                     const std::string &value) { return 0; }
  boost::uint32_t KeyExpireTime(const NodeId &key, const std::string &value) { return 0; }

  bool using_signatures() { return false; }
  boost::int32_t KeyValueTTL(const NodeId &key, const std::string &value) const { return 0; }
  void set_alternative_store(AlternativeStore *alternative_store) {}
  AlternativeStore *alternative_store() { return alternative_store_; }
  void set_signature_validator(SignatureValidator *validator) {}

 private:
  friend class test_nodeimpl::TestNodeImpl_BEH_NodeImpl_ExecuteRPCs_Test;
  friend class test_nodeimpl::TestNodeImpl_BEH_NodeImpl_NotJoined_Test;
  friend class test_nodeimpl::
      TestNodeImpl_BEH_NodeImpl_AddContactsToContainer_Test;
  friend class test_nodeimpl::TestNodeImpl_BEH_NodeImpl_GetAlphas_Test;
  friend class test_nodeimpl::TestNodeImpl_BEH_NodeImpl_MarkNode_Test;
  friend class test_nodeimpl::TestNodeImpl_BEH_NodeImpl_BetaDone_Test;
  friend class test_nodeimpl::
      TestNodeImpl_BEH_NodeImpl_IterativeSearchResponse_Test;
  friend class test_nodeimpl::
      TestNodeImpl_BEH_NodeImpl_IterativeSearchHappy_Test;
  friend class test_nodeimpl::TestNodeImpl_BEH_NodeImpl_FindNodesHappy_Test;
  friend class test_nodeimpl::
      TestNodeImpl_BEH_NodeImpl_FindNodesContactsInReponse_Test;

  NodeImpl &operator=(const NodeImpl&);
  NodeImpl(const NodeImpl&);
  void AddContactsToContainer(const std::vector<Contact> contacts,
                              boost::shared_ptr<FindNodesArgs> fna);
  bool MarkResponse(const Contact &contact,
                    boost::shared_ptr<FindNodesArgs> fna, SearchMarking mark,
                    std::list<Contact> *response_nodes);
  int NodesPending(boost::shared_ptr<FindNodesArgs> fna);
  void MarkAsAlpha(const std::list<Contact> &contacts,
                   boost::shared_ptr<FindNodesArgs> fna);
  bool HandleIterationStructure(const Contact &contact,
                                boost::shared_ptr<FindNodesArgs> fna,
                                int round,
                                SearchMarking mark,
                                std::list<Contact> *nodes,
                                bool *top_nodes_done,
                                bool *calledback,
                                int *nodes_pending);
  void FindNodes(const FindNodesParams &fnp);
  virtual void IterativeSearch(boost::shared_ptr<FindNodesArgs> fna,
                               bool top_nodes_done,
                               bool calledback,
                               std::list<Contact> *contacts);
  void IterativeSearchResponse(bool, const std::vector<Contact>&,
                               boost::shared_ptr<FindNodesRpc> fnrpc);

  boost::shared_ptr<boost::asio::io_service> asio_service_;
  boost::shared_ptr<transport::Transport> listening_transport_;


  bool client_only_node,
       const boost::uint16_t &k,
       const boost::uint16_t &alpha,
       const boost::uint16_t &beta,
       const boost::uint32_t &refresh_frequency,
       const std::string &private_key,
       const std::string &public_key  




  boost::mutex routingtable_mutex_, kadconfig_mutex_, extendshortlist_mutex_,
               joinbootstrapping_mutex_, leave_mutex_, activeprobes_mutex_,
               pendingcts_mutex_;
  boost::shared_ptr<CallLaterTimer> ptimer_;
  boost::shared_ptr<DataStore> pdata_store_;
  boost::shared_ptr<Service> premote_service_;
  boost::shared_ptr<RoutingTable> prouting_table_;
  boost::shared_ptr<Rpcs> rpcs_;
  boost::shared_ptr<boost::thread> addcontacts_routine_;
  boost::shared_ptr<PublicRoutingTableHandler> prth_;
  AlternativeStore *alternative_store_;
  SignatureValidator *signature_validator_;
  upnp::UpnpIgdClient upnp_;
  NodeId node_id_, fake_kClientId_;
  IP ip_, rv_ip_, local_ip_;
  Port port_, rv_port_, local_port_, upnp_mapped_port_;
  NodeType type_;
  std::vector<Contact> bootstrapping_nodes_, exclude_bs_contacts_;
  std::list<Contact> contacts_to_add_;
  const boost::uint16_t K_, alpha_, beta_;
  bool is_joined_, refresh_routine_started_, stopping_, port_forwarded_,
       use_upnp_;
  boost::filesystem::path kad_config_path_;
  boost::condition_variable add_ctc_cond_;
  std::string private_key_, public_key_;
};

}  // namespace kademlia

}  // namespace maidsafe

#endif  // MAIDSAFE_KADEMLIA_NODEIMPL_H_
