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

#include "maidsafe-dht/kademlia/node_impl.h"
#include "maidsafe-dht/kademlia/datastore.h"
#include "maidsafe-dht/kademlia/node_id.h"
#include "maidsafe-dht/kademlia/rpcs.h"
#include "maidsafe-dht/kademlia/routing_table.h"
#include "maidsafe-dht/kademlia/securifier.h"
#include "maidsafe-dht/kademlia/service.h"
#include "maidsafe-dht/kademlia/utils.h"

namespace maidsafe {

namespace kademlia {

// some tools which will be used in the implementation of Node::Impl class

Node::Impl::Impl(IoServicePtr asio_service,
                 TransportPtr listening_transport,
                 SecurifierPtr default_securifier,
                 AlternativeStorePtr alternative_store,
                 bool client_only_node,
                 const boost::uint16_t &k,
                 const boost::uint16_t &alpha,
                 const boost::uint16_t &beta,
                 const boost::posix_time::time_duration &mean_refresh_interval)
    : asio_service_(asio_service),
      listening_transport_(listening_transport),
      default_securifier_(default_securifier),
      alternative_store_(alternative_store),
      on_online_status_change_(new OnOnlineStatusChangePtr::element_type),
      client_only_node_(client_only_node),
      k_(k),
      threshold_((k_ * 3) / 4),
      kAlpha_(alpha),
      kBeta_(beta),
      kMeanRefreshInterval_(mean_refresh_interval.is_special() ? 3600 :
                            mean_refresh_interval.total_seconds()),
      data_store_(new DataStore(kMeanRefreshInterval_)),
      service_(),
      routing_table_(),
      rpcs_(new Rpcs(asio_service_, default_securifier)),
      contact_(),
      joined_(false),
      refresh_routine_started_(false),
      stopping_(false),
      routing_table_connection_(),
      report_down_contact_(new ReportDownContactPtr::element_type) {}

Node::Impl::~Impl() {
  if (joined_)
    Leave(NULL);
}

ReportDownContactPtr Node::Impl::report_down_contact() {
  return report_down_contact_;
}

void Node::Impl::Join(const NodeId &/*node_id*/,
                      const Port &/*port*/,
                      const std::vector<Contact> &/*bootstrap_contacts*/,
                      JoinFunctor /*callback*/) {
}

void Node::Impl::Leave(std::vector<Contact> *bootstrap_contacts) {
  routing_table_connection_.disconnect();
  routing_table_->GetBootstrapContacts(bootstrap_contacts);
}

void Node::Impl::Store(const Key &key,
                       const std::string &value,
                       const std::string &signature,
                       const boost::posix_time::time_duration &ttl,
                       SecurifierPtr securifier,
                       StoreFunctor callback) {
  FindNodes(key, boost::bind(&Node::Impl::StoreFindNodesCallback,
                             this, _1, _2,
                             key, value, signature, ttl,
                             securifier, callback));
}

void Node::Impl::StoreFindNodesCallback(int result_size,
                               const std::vector<Contact> &cs,
                               const Key &key,
                               const std::string &value,
                               const std::string &signature,
                               const boost::posix_time::time_duration &ttl,
                               SecurifierPtr securifier,
                               StoreFunctor callback) {
  if (result_size < threshold_) {
    if (result_size < 0) {
      callback(-1);
    } else {
      callback(-3);
    }
  } else {
    boost::posix_time::seconds ttl_s(ttl.seconds());
    std::shared_ptr<StoreArgs> sa(new StoreArgs(callback));
    auto it = cs.begin();
    auto it_end = cs.end();
    
    while (it != it_end) {
        NodeContainerTuple nct((*it), key);
        nct.state = kSelectedAlpha;
        sa->nc.insert(nct);
        ++it;
    }

    it = cs.begin();
    while (it != it_end) {
      std::shared_ptr<RpcArgs> srpc(new RpcArgs((*it), sa));
      rpcs_->Store(key, value, signature, ttl_s, securifier, (*it),
                   boost::bind(&Node::Impl::StoreResponse,
                               this, _1, _2, srpc, key, value,
                               signature, securifier),
                   kTcp);
      ++it;
    }
  }
}

void Node::Impl::StoreResponse(RankInfoPtr rank_info,
                               int response_code,
                               std::shared_ptr<RpcArgs> srpc,
                               const Key &key,
                               const std::string &value,
                               const std::string &signature,
                               SecurifierPtr securifier) {
  std::shared_ptr<StoreArgs> sa =
      std::static_pointer_cast<StoreArgs> (srpc->rpc_a);
  boost::mutex::scoped_lock loch_surlaplage(sa->mutex);
  NodeSearchState mark(kContacted);
  if (response_code < 0) {
    mark = kDown;   
    // fire a signal here to notify this contact is down
    (*report_down_contact_)(srpc->contact);
  }
  // Mark the enquired contact
  NodeContainerByNodeId key_node_indx = sa->nc.get<nc_id>();
  auto it_tuple = key_node_indx.find(srpc->contact.node_id());
  key_node_indx.modify(it_tuple, ChangeState(mark));
  
  auto pit_pending = sa->nc.get<nc_state>().equal_range(kSelectedAlpha);
  int num_of_pending = std::distance(pit_pending.first, pit_pending.second);

  auto pit_contacted = sa->nc.get<nc_state>().equal_range(kContacted);
  int num_of_contacted= std::distance(pit_contacted.first,
                                      pit_contacted.second);

  auto pit_down = sa->nc.get<nc_state>().equal_range(kDown);
  int num_of_down= std::distance(pit_down.first, pit_down.second);

  if (!sa->calledback) {
    if (num_of_down > (k_ - threshold_)) {
      // report back a failure once has more down contacts than the margin
      sa->callback(-2);
      sa->calledback = true;
    }
    if (num_of_contacted >= threshold_) {
      // report back once has enough succeed contacts
      sa->callback(num_of_contacted);
      sa->calledback = true;
    }
  }
  // delete those succeeded contacts if a failure was report back
  // the response for the last responded contact shall be responsible to do it
  if ((num_of_pending == 0) && (num_of_contacted < threshold_)) {
    auto it = pit_down.first;
    while (it != pit_down.second) {
      rpcs_->Delete(key, value, signature, securifier, (*it).contact,
                    boost::bind(&Node::Impl::SingleDeleteResponse,
                                this, _1, _2, (*it).contact),
                    kTcp);
      ++it;
    }
  }
}

void Node::Impl::SingleDeleteResponse(RankInfoPtr rank_info,
                                      int response_code,
                                      const Contact &contact) {
  if (response_code < 0) {
    // fire a signal here to notify this contact is down
    (*report_down_contact_)(contact);
  }
}

void Node::Impl::Delete(const Key &key,
                        const std::string &value,
                        const std::string &signature,
                        SecurifierPtr securifier,
                        DeleteFunctor callback) {
  FindNodes(key, boost::bind(&Node::Impl::DeleteFindNodesCallback,
                             this, _1, _2,
                             key, value, signature,
                             securifier, callback));
}

void Node::Impl::DeleteFindNodesCallback(int result_size,
                               const std::vector<Contact> &cs,
                               const Key &key,
                               const std::string &value,
                               const std::string &signature,
                               SecurifierPtr securifier,
                               DeleteFunctor callback) {
  if (result_size < threshold_) {
    if (result_size < 0) {
      callback(-1);
    } else {
      callback(-3);
    }
  } else {
    std::shared_ptr<DeleteArgs> da(new DeleteArgs(callback));
    auto it = cs.begin();
    auto it_end = cs.end();
    while (it != it_end) {
        NodeContainerTuple nct((*it), key);
        nct.state = kSelectedAlpha;
        da->nc.insert(nct);
        ++it;
    }

    it = cs.begin();
    while (it != it_end) {
      std::shared_ptr<RpcArgs> drpc(new RpcArgs((*it), da));
      rpcs_->Delete(key, value, signature, securifier, (*it),
                    boost::bind(&Node::Impl::DeleteResponse,
                                this, _1, _2, drpc),
                    kTcp);
      ++it;
    }
  }
}

void Node::Impl::DeleteResponse(RankInfoPtr rank_info,
                                int response_code,
                                std::shared_ptr<RpcArgs> drpc) {
  std::shared_ptr<DeleteArgs> da =
      std::static_pointer_cast<DeleteArgs> (drpc->rpc_a);
  // calledback flag needs to be protected by the mutex lock
  boost::mutex::scoped_lock loch_surlaplage(da->mutex);
  if (da->calledback)
    return;

  NodeSearchState mark(kContacted);
  if (response_code < 0) {
    mark = kDown;
    // fire a signal here to notify this contact is down
    (*report_down_contact_)(drpc->contact);
  }
  // Mark the enquired contact
  NodeContainerByNodeId key_node_indx = da->nc.get<nc_id>();
  auto it_tuple = key_node_indx.find(drpc->contact.node_id());
  key_node_indx.modify(it_tuple, ChangeState(mark));

  auto pit_pending = da->nc.get<nc_state>().equal_range(kSelectedAlpha);
  int num_of_pending = std::distance(pit_pending.first, pit_pending.second);

  auto pit_contacted = da->nc.get<nc_state>().equal_range(kContacted);
  int num_of_contacted= std::distance(pit_contacted.first,
                                      pit_contacted.second);

  auto pit_down = da->nc.get<nc_state>().equal_range(kDown);
  int num_of_down= std::distance(pit_down.first, pit_down.second);

  if (num_of_down > (k_ - threshold_)) {
    // report back a failure once has more down contacts than the margin
    da->callback(-2);
    da->calledback = true;
  }
  if (num_of_contacted >= threshold_) {
    // report back once has enough succeed contacts
    da->callback(num_of_contacted);
    da->calledback = true;
  }

  // by far only report failure defined, unlike to what happens in Store,
  // there is no restore (undo those success deleted) operation in delete
}

void Node::Impl::Update(const Key &key,
                        const std::string &new_value,
                        const std::string &new_signature,
                        const std::string &old_value,
                        const std::string &old_signature,
                        SecurifierPtr securifier,
                        const boost::posix_time::time_duration &ttl,
                        UpdateFunctor callback) {
  std::shared_ptr<UpdateArgs> ua (new UpdateArgs(new_value, new_signature,
                                                 old_value, old_signature,
                                                 callback));
  FindNodes(key, boost::bind(&Node::Impl::UpdateFindNodesCallback,
                             this, _1, _2, key, securifier, ttl, ua, callback));
}

void Node::Impl::UpdateFindNodesCallback(int result_size,
                               const std::vector<Contact> &cs,
                               const Key &key,
                               SecurifierPtr securifier,
                               const boost::posix_time::time_duration &ttl,
                               std::shared_ptr<UpdateArgs> ua,
                               UpdateFunctor callback) {
  if (result_size < threshold_) {
    if (result_size < 0) {
      callback(-1);
    } else {
      callback(-3);
    }
  } else {
    boost::posix_time::seconds ttl_s(ttl.seconds());
    auto it = cs.begin();
    auto it_end = cs.end();

    while (it != it_end) {
        NodeContainerTuple nct((*it), key);
        nct.state = kSelectedAlpha;
        ua->nc.insert(nct);
        ++it;
    }

    it = cs.begin();
    while (it != it_end) {
      std::shared_ptr<RpcArgs> urpc(new RpcArgs((*it), ua));
      rpcs_->Store(key, ua->new_value, ua->new_signature, ttl_s,
                   securifier, (*it),
                   boost::bind(&Node::Impl::UpdateStoreResponse,
                               this, _1, _2, urpc, key, securifier),
                   kTcp);
      ++it;
    }
  }
}

void Node::Impl::UpdateStoreResponse(RankInfoPtr rank_info,
                                     int response_code,
                                     std::shared_ptr<RpcArgs> urpc,
                                     const Key &key,
                                     SecurifierPtr securifier) {
  std::shared_ptr<UpdateArgs> ua =
      std::static_pointer_cast<UpdateArgs> (urpc->rpc_a);
  boost::mutex::scoped_lock loch_surlaplage(ua->mutex);
  if (response_code < 0) {
    // once store operation failed, the contact will be marked as DOWN
    // and no DELETE operation for that contact will be executed
    NodeContainerByNodeId key_node_indx = ua->nc.get<nc_id>();
    auto it_tuple = key_node_indx.find(urpc->contact.node_id());
    key_node_indx.modify(it_tuple, ChangeState(kDown));
    // fire a signal here to notify this contact is down
    (*report_down_contact_)(urpc->contact);
  } else {
    rpcs_->Delete(key, ua->old_value, ua->old_signature,
                  securifier, urpc->contact,
                  boost::bind(&Node::Impl::UpdateDeleteResponse,
                              this, _1, _2, urpc),
                  kTcp);
  }
}

void Node::Impl::UpdateDeleteResponse(RankInfoPtr rank_info,
                                      int response_code,
                                      std::shared_ptr<RpcArgs> drpc) {
  std::shared_ptr<UpdateArgs> da =
      std::static_pointer_cast<UpdateArgs> (drpc->rpc_a);
  // calledback flag needs to be protected by the mutex lock
  boost::mutex::scoped_lock loch_surlaplage(da->mutex);
  if (da->calledback)
    return;

  NodeSearchState mark(kContacted);
  if (response_code < 0) {
    mark = kDown;
    // fire a signal here to notify this contact is down
    (*report_down_contact_)(drpc->contact);
  }
  // Mark the enquired contact
  NodeContainerByNodeId key_node_indx = da->nc.get<nc_id>();
  auto it_tuple = key_node_indx.find(drpc->contact.node_id());
  key_node_indx.modify(it_tuple, ChangeState(mark));

  auto pit_pending = da->nc.get<nc_state>().equal_range(kSelectedAlpha);
  int num_of_pending = std::distance(pit_pending.first, pit_pending.second);

  auto pit_contacted = da->nc.get<nc_state>().equal_range(kContacted);
  int num_of_contacted= std::distance(pit_contacted.first,
                                      pit_contacted.second);

  auto pit_down = da->nc.get<nc_state>().equal_range(kDown);
  int num_of_down= std::distance(pit_down.first, pit_down.second);

  if (num_of_down > (k_ - threshold_)) {
    // report back a failure once has more down contacts than the margin
    da->callback(-2);
    da->calledback = true;
  }
  if (num_of_contacted >= threshold_) {
    // report back once has enough succeed contacts
    da->callback(num_of_contacted);
    da->calledback = true;
  }

  // by far only report failure defined, unlike to what happens in Store,
  // there is no restore (undo those success stored/deleted) operations in
  // update
}

void Node::Impl::FindValue(const Key &/*key*/,
                           SecurifierPtr /*securifier*/,
                           FindValueFunctor /*callback*/) {
}

void Node::Impl::GetContact(const NodeId &/*node_id*/,
                            GetContactFunctor /*callback*/) {
}

void Node::Impl::SetLastSeenToNow(const Contact &/*contact*/) {
}

void Node::Impl::IncrementFailedRpcs(const Contact &/*contact*/) {
}

void Node::Impl::UpdateRankInfo(const Contact &/*contact*/,
                                RankInfoPtr /*rank_info*/) {
}

RankInfoPtr Node::Impl::GetLocalRankInfo(const Contact &/*contact*/) {
  return RankInfoPtr();
}

void Node::Impl::GetAllContacts(std::vector<Contact> * /*contacts*/) {
}

void Node::Impl::GetBootstrapContacts(std::vector<Contact> * /*contacts*/) {
}

Contact Node::Impl::contact() const {
  return contact_;
}

bool Node::Impl::joined() const {
  return joined_;
}

IoServicePtr Node::Impl::asio_service() {
  return asio_service_;
}

AlternativeStorePtr Node::Impl::alternative_store() {
  return alternative_store_;
}

OnOnlineStatusChangePtr Node::Impl::on_online_status_change() {
  return on_online_status_change_;
}

bool Node::Impl::client_only_node() const {
  return client_only_node_;
}

boost::uint16_t Node::Impl::k() const {
  return k_;
}

boost::uint16_t Node::Impl::alpha() const {
  return kAlpha_;
}

boost::uint16_t Node::Impl::beta() const {
  return kBeta_;
}

boost::posix_time::time_duration Node::Impl::mean_refresh_interval() const {
  return kMeanRefreshInterval_;
}


// void Node::Impl::JoinFirstNode(const NodeId &node_id,
//                             const std::string &kad_config_file,
//                             const IP &ip, const Port &port,
//                             VoidFunctorOneString callback) {
//  protobuf::GeneralResponse local_result;
//  std::string local_result_str;
//  if (joined_ || !node_id.IsValid()) {
//    if (joined_) {
//      local_result.set_result(true);
//    } else {
//      local_result.set_result(false);
//    }
//    local_result.SerializeToString(&local_result_str);
//    callback(local_result_str);
//    return;
//  }
//
////  RegisterService();
//
//  node_id_ = node_id;
//  if (type_ == CLIENT || type_ == CLIENT_PORT_MAPPED) {
//    // Client nodes can not start a network on their own
//    local_result.set_result(false);
//    local_result.SerializeToString(&local_result_str);
//    callback(local_result_str);
//    return;
//  }
//
//  local_port_ = port;
//  if (use_upnp_) {
////    UPnPMap(local_port_);
////    if (upnp_mapped_port_ != 0) {
////      port_ = upnp_mapped_port_;
////      // It is now directly connected
////    } else {
////      local_result.set_result(false);
////      local_result.SerializeToString(&local_result_str);
////      callback(local_result_str);
////      return;
////    }
//  } else if (/*ip.empty() || */port == 0) {
//    local_result.set_result(false);
//    local_result.SerializeToString(&local_result_str);
//    callback(local_result_str);
//    return;
//  } else {
//    ip_ = ip;
//    port_ = port;
//  }
//
//  // Set kad_config_path_
//  routing_table_.reset(new RoutingTable(node_id_, K_));
//  routing_table_connection_ =
//               routing_table_->on_ping_oldest_contact()->connect(
//      boost::bind(&Node::Impl::PingOldestContact, this, _1, _2, _3));
//
//  joined_ = true;
////  service_->set_node_joined(true);
//
//  addcontacts_routine_.reset(new boost::thread(&Node::Impl::CheckAddContacts,
////                                               this));
//  if (!refresh_routine_started_) {
////    ptimer_->AddCallLater(kRefreshTime * 1000,
////                          boost::bind(&Node::Impl::RefreshRoutine, this));
//    ptimer_->AddCallLater(2000, boost::bind(&Node::Impl::RefreshValuesRoutine,
////                                            this));
//    refresh_routine_started_ = true;
//  }
//  local_result.set_result(true);
//  local_result.SerializeToString(&local_result_str);
//  callback(local_result_str);
// }
//
// void Node::Impl::JoinFirstNode(const std::string &kad_config_file,
//                             const IP &ip, const Port &port,
//                             VoidFunctorOneString callback) {
//  JoinFirstNode(NodeId(NodeId::kRandomId),
//                  kad_config_file, ip, port, callback);
// }
//
// void Node::Impl::Leave() {
//  if (joined_) {
//    if (upnp_mapped_port_ != 0) {
////      UnMapUPnP();
//    }
//    stopping_ = true;
//    {
//      boost::mutex::scoped_lock lock(leave_mutex_);
//      joined_ = false;
////      service_->set_node_joined(false);
//      ptimer_->CancelAll();
////      pchannel_manager_->ClearCallLaters();
////      UnRegisterService();
//      data_store_->Clear();
//      add_ctc_cond_.notify_one();
////      addcontacts_routine_->join();
////      SaveBootstrapContacts();
//      exclude_bs_contacts_.clear();
//      routing_table_->Clear();
//      prth_->Clear();
//    }
//    stopping_ = false;
//  }
// }

void Node::Impl::AddContactsToContainer(const std::vector<Contact> contacts,
                                        std::shared_ptr<FindNodesArgs> fna) {
  // Only insert the tuple when it not existed in the container
  boost::mutex::scoped_lock loch_lavitesse(fna->mutex);
  NodeContainerByNodeId key_node_indx = fna->nc.get<nc_id>();
  for (size_t n = 0; n < contacts.size(); ++n) {
    auto it_tuple = key_node_indx.find(contacts[n].node_id());
    if (it_tuple == key_node_indx.end()) {
      NodeContainerTuple nct(contacts[n], fna->key);
      fna->nc.insert(nct);
    }
  }
}

bool Node::Impl::HandleIterationStructure(const Contact &contact,
                                          std::shared_ptr<FindNodesArgs> fna,
                                          NodeSearchState mark,
                                          bool *cur_iteration_done,
                                          bool *calledback) {
  bool result = false;
  boost::mutex::scoped_lock loch_surlaplage(fna->mutex);

  // Mark the enquired contact
  NodeContainerByNodeId key_node_indx = fna->nc.get<nc_id>();
  auto it_tuple = key_node_indx.find(contact.node_id());
  key_node_indx.modify(it_tuple, ChangeState(mark));

  NodeContainerByDistance distance_node_indx = fna->nc.get<nc_distance>();
  auto it = distance_node_indx.begin();
  auto it_end = distance_node_indx.end();
  int num_new_contacts(0);
  int num_candidates(0);
  while ((it != it_end) && (num_candidates < k_)) {
    if ((*it).state == kNew)
      ++num_new_contacts;
    if ((*it).state != kDown)
      ++num_candidates;
    ++it;
  }

  // To tell if the current iteration is done or not, only need to test:
  //    if number of pending(waiting for response) contacts
  //    is not greater than (kAlpha_ - kBeta_)
  // always check with the latest round, no need to worry about the previous
  auto pit = fna->nc.get<nc_state_round>().equal_range(
                 boost::make_tuple(kSelectedAlpha, fna->round));
  int num_of_round_pending = std::distance(pit.first, pit.second);
  if (num_of_round_pending <= (kAlpha_ - kBeta_))
      *cur_iteration_done = true;

  auto pit_pending = fna->nc.get<nc_state>().equal_range(kSelectedAlpha);
  int num_of_total_pending = std::distance(pit_pending.first,
                                           pit_pending.second);
  {
    //     no kNew contacts among the top K
    // And no kSelectedAlpha (pending) contacts in total
    if ((num_new_contacts == 0) && (num_of_total_pending == 0))
      *calledback = true;
  }
  {
    // To prevent the situation that may keep requesting contacts if there
    // is any pending contacts, the request will be halted once got k-closest
    // contacted in the result (i.e. wait till all pending contacts cleared)
    if ((num_candidates == k_) && (num_of_total_pending != 0))
      *cur_iteration_done = false;
  }

  // If the search can be stopped, then we callback (report the result list)
  if (*calledback) {
    auto it = distance_node_indx.begin();
    auto it_end = distance_node_indx.end();
    std::vector<Contact> top_k_contacts;
    while ((it != it_end) && (top_k_contacts.size() < k_)) {
      if ((*it).state == kContacted)
        top_k_contacts.push_back((*it).contact);
      ++it;
    }
    fna->calledback = true;
    fna->callback(top_k_contacts.size(), top_k_contacts);
    // main part of memory resource in fna can be released here
    fna->nc.clear();
  }
  result = true;
  return result;
}

void Node::Impl::FindNodes(const Key &key, FindNodesFunctor callback) {
  std::vector<Contact> close_nodes, excludes;
  std::shared_ptr<FindNodesArgs> fna(new FindNodesArgs(key, callback));

  // initialize with local k closest as a seed
  routing_table_->GetCloseContacts(key, k_, excludes, &close_nodes);
  AddContactsToContainer(close_nodes, fna);

  IterativeSearch(fna);
}

void Node::Impl::IterativeSearch(std::shared_ptr<FindNodesArgs> fna) {
  boost::mutex::scoped_lock loch_surlaplage(fna->mutex);

  auto pit = fna->nc.get<nc_state_distance>().equal_range(
      boost::make_tuple(kNew));
  int num_of_candidates = std::distance(pit.first, pit.second);

  if (num_of_candidates == 0) {
    // All contacted or in waitingresponse state, then just do nothing here
    return;
  }

  // find Alpha closest contacts to enquire
  // or all the left contacts if less than Alpha contacts haven't been tried
  boost::uint16_t counter = 0;
  auto it_begin = pit.first;
  auto it_end = pit.second;
  std::vector<NodeId> to_contact;
  while ((it_begin != it_end) && (counter < kAlpha_)) {
    // note, change the state value here may cause re-sorting of the
    // multi-index container. So we can only collect the node_id of the
    // contacts need to be changed, then change their state value later
    to_contact.push_back((*it_begin).contact_id);
    ++it_begin;
    ++counter;
  }

  NodeContainerByNodeId key_node_indx = fna->nc.get<nc_id>();
  // Update contacts' state
  for (auto it = to_contact.begin(); it != to_contact.end(); ++it) {
    auto it_tuple = key_node_indx.find(*it);
    key_node_indx.modify(it_tuple, ChangeState(kSelectedAlpha));
    key_node_indx.modify(it_tuple, ChangeRound(fna->round+1));
  }
  ++fna->round;
  // Better to change the value in a bunch and then issue RPCs in a bunch
  // to avoid any possibilities of cross-interference
  for (auto it = to_contact.begin(); it != to_contact.end(); ++it) {
    auto it_tuple = key_node_indx.find(*it);
    std::shared_ptr<RpcArgs> fnrpc(new RpcArgs((*it_tuple).contact, fna));
    rpcs_->FindNodes(fna->key, default_securifier_, (*it_tuple).contact,
                     boost::bind(&Node::Impl::IterativeSearchResponse,
                                      this, _1, _2, _3, fnrpc), kTcp);
  }
}

void Node::Impl::IterativeSearchResponse(
                                  RankInfoPtr rank_info,
                                  int result,
                                  const std::vector<Contact> &contacts,
                                  std::shared_ptr<RpcArgs> fnrpc) {
  // If already calledback, i.e. result has already been reported
  // then do nothing, just return
  std::shared_ptr<FindNodesArgs> fna =
      std::static_pointer_cast<FindNodesArgs> (fnrpc->rpc_a);
  if (fna->calledback) {
    return;
  }

  NodeSearchState mark(kContacted);
  if (result < 0) {
    mark = kDown;
    // fire a signal here to notify this contact is down
    (*report_down_contact_)(fnrpc->contact);
  } else {
    AddContactsToContainer(contacts, fna);
  }

  bool curr_iteration_done(false), calledback(false);
  if (!HandleIterationStructure(fnrpc->contact, fna,
                                mark, &curr_iteration_done, &calledback)) {
    printf("Well, that's just too freakishly odd. Daaaaamn, brotha!\n");
  }

  if ((!calledback) && (curr_iteration_done))
    IterativeSearch(fna);
}

void Node::Impl::PingOldestContact(const Contact &oldest_contact,
                                   const Contact &replacement_contact,
                                   RankInfoPtr replacement_rank_info) {
  Rpcs::PingFunctor callback(boost::bind(&Node::Impl::PingOldestContactCallback,
      this, oldest_contact, _1, _2, replacement_contact,
      replacement_rank_info));
  rpcs_->Ping(SecurifierPtr(), oldest_contact, callback, kTcp);
}

void Node::Impl::PingOldestContactCallback(Contact /*oldest_contact*/,
                                           RankInfoPtr /*oldest_rank_info*/,
                                           const int &/*result*/,
                                           Contact /*replacement_contact*/,
                                           RankInfoPtr
                                             /*replacement_rank_info*/) {
//  if(result == 0) {
//    add new contact - or ++ failed count?
//  } else {
//    remove old contact
//      add new contact
//  }
}

void Node::Impl::ValidateContact(const Contact &contact) {
  GetPublicKeyAndValidationCallback callback(boost::bind(
      &Node::Impl::ValidateContactCallback, this, contact, _1, _2));
  default_securifier_->GetPublicKeyAndValidation(contact.public_key_id(),
                                                 callback);
}

void Node::Impl::ValidateContactCallback(Contact contact,
                                         std::string public_key,
                                         std::string public_key_validation) {
  bool valid = default_securifier_->Validate("", "", contact.public_key_id(),
                                             public_key, public_key_validation,
                                             contact.node_id().String());
  routing_table_->SetValidated(contact.node_id(), valid);
}

}  // namespace kademlia

}  // namespace maidsafe
