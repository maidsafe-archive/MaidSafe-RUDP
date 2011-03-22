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
      report_down_contact_(new ReportDownContactPtr::element_type),
      mutex_(),
      condition_downlist_(),
      down_contacts_(),
      thread_group_() {}

Node::Impl::~Impl() {
  if (joined_)
    Leave(NULL);
}

void Node::Impl::Leave(std::vector<Contact> *bootstrap_contacts) {
  thread_group_.interrupt_all();
  thread_group_.join_all();
  routing_table_connection_.disconnect();
  routing_table_->GetBootstrapContacts(bootstrap_contacts);
  joined_ = false;
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

void Node::Impl::Store(const Key &key,
                       const std::string &value,
                       const std::string &signature,
                       const boost::posix_time::time_duration &ttl,
                       SecurifierPtr securifier,
                       StoreFunctor callback) {
  std::shared_ptr<StoreArgs> sa(new StoreArgs(callback));
  FindNodes(key, boost::bind(&Node::Impl::OperationFindNodesCB<StoreArgs>,
                             this, _1, _2,
                             key, value, signature, ttl,
                             securifier, sa));
}

void Node::Impl::Delete(const Key &key,
                        const std::string &value,
                        const std::string &signature,
                        SecurifierPtr securifier,
                        DeleteFunctor callback) {
  std::shared_ptr<DeleteArgs> da(new DeleteArgs(callback));
  boost::posix_time::time_duration ttl;
  FindNodes(key, boost::bind(&Node::Impl::OperationFindNodesCB<DeleteArgs>,
                             this, _1, _2,
                             key, value, signature, ttl,
                             securifier, da));
}

void Node::Impl::Update(const Key &key,
                        const std::string &new_value,
                        const std::string &new_signature,
                        const std::string &old_value,
                        const std::string &old_signature,
                        SecurifierPtr securifier,
                        const boost::posix_time::time_duration &ttl,
                        UpdateFunctor callback) {
  std::shared_ptr<UpdateArgs> ua(new UpdateArgs(new_value, new_signature,
                                                 old_value, old_signature,
                                                 callback));
  FindNodes(key, boost::bind(&Node::Impl::OperationFindNodesCB<UpdateArgs>,
                             this, _1, _2,
                             key, "", "", ttl,
                             securifier, ua));
}

template <class T>
void Node::Impl::OperationFindNodesCB(int result_size,
                               const std::vector<Contact> &cs,
                               const Key &key,
                               const std::string &value,
                               const std::string &signature,
                               const boost::posix_time::time_duration &ttl,
                               SecurifierPtr securifier,
                               std::shared_ptr<T> args) {
//  boost::mutex::scoped_lock loch_surlaplage(args->mutex);
  if (result_size < threshold_) {
    if (result_size < 0) {
      args->callback(-1);
    } else {
      args->callback(-3);
    }
  } else {
    auto it = cs.begin();
    auto it_end = cs.end();
    while (it != it_end) {
        NodeContainerTuple nct((*it), key);
        nct.state = kSelectedAlpha;
        args->nc.insert(nct);
        ++it;
    }

    it = cs.begin();
    while (it != it_end) {
      std::shared_ptr<RpcArgs> rpc(new RpcArgs((*it), args));
      switch (args->operation_type) {
        case kOpDelete:
          rpcs_->Delete(key, value, signature, securifier, (*it),
                        boost::bind(&Node::Impl::DeleteResponse<DeleteArgs>,
                                    this, _1, _2, rpc),
                        kTcp);
          break;
        case kOpStore: {
          boost::posix_time::seconds ttl_s(ttl.seconds());
          rpcs_->Store(key, value, signature, ttl_s, securifier, (*it),
                       boost::bind(&Node::Impl::StoreResponse,
                                   this, _1, _2, rpc, key, value,
                                   signature, securifier),
                       kTcp);
        }
          break;
        case kOpUpdate: {
          std::shared_ptr<UpdateArgs> ua =
            std::dynamic_pointer_cast<UpdateArgs> (args);
          boost::posix_time::seconds ttl_s(ttl.seconds());
          rpcs_->Store(key, ua->new_value, ua->new_signature, ttl_s,
                      securifier, (*it),
                      boost::bind(&Node::Impl::UpdateStoreResponse,
                                  this, _1, _2, rpc, key, securifier),
                      kTcp);
        }
          break;
      }
      ++it;
    }
  }
}

template <class T>
void Node::Impl::DeleteResponse(RankInfoPtr rank_info,
                                int response_code,
                                std::shared_ptr<RpcArgs> drpc) {
  std::shared_ptr<T> da = std::static_pointer_cast<T> (drpc->rpc_a);
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
  NodeContainerByNodeId key_node_indx = drpc->rpc_a->nc.get<nc_id>();
  auto it_tuple = key_node_indx.find(drpc->contact.node_id());
  key_node_indx.modify(it_tuple, ChangeState(mark));

  auto pit_pending =
      drpc->rpc_a->nc.get<nc_state>().equal_range(kSelectedAlpha);
  int num_of_pending = std::distance(pit_pending.first, pit_pending.second);

  auto pit_contacted = drpc->rpc_a->nc.get<nc_state>().equal_range(kContacted);
  int num_of_contacted= std::distance(pit_contacted.first,
                                      pit_contacted.second);

  auto pit_down = drpc->rpc_a->nc.get<nc_state>().equal_range(kDown);
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

void Node::Impl::UpdateStoreResponse(RankInfoPtr rank_info,
                                     int response_code,
                                     std::shared_ptr<RpcArgs> urpc,
                                     const Key &key,
                                     SecurifierPtr securifier) {
  std::shared_ptr<UpdateArgs> ua =
      std::static_pointer_cast<UpdateArgs> (urpc->rpc_a);
  if (response_code < 0) {
    boost::mutex::scoped_lock loch_surlaplage(ua->mutex);
    // once store operation failed, the contact will be marked as DOWN
    // and no DELETE operation for that contact will be executed
    NodeContainerByNodeId key_node_indx = ua->nc.get<nc_id>();
    auto it_tuple = key_node_indx.find(urpc->contact.node_id());
    key_node_indx.modify(it_tuple, ChangeState(kDown));

    // ensure this down contact is not the last one, prevent a deadend
    auto pit_pending = ua->nc.get<nc_state>().equal_range(kSelectedAlpha);
    int num_of_total_pending = std::distance(pit_pending.first,
                                             pit_pending.second);
    if (num_of_total_pending == 0) {
      ua->callback(-2);
      ua->calledback = true;
    }
    // fire a signal here to notify this contact is down
    (*report_down_contact_)(urpc->contact);
  } else {
    rpcs_->Delete(key, ua->old_value, ua->old_signature,
                  securifier, urpc->contact,
                  boost::bind(&Node::Impl::DeleteResponse<UpdateArgs>,
                              this, _1, _2, urpc),
                  kTcp);
  }
}

void Node::Impl::FindValue(const Key &key,
                           SecurifierPtr securifier,
                           FindValueFunctor callback) {
  std::shared_ptr<FindValueArgs> fva(new FindValueArgs(key, securifier,
                                                       callback));
  // initialize with local k closest as a seed
  std::vector<Contact> close_nodes, excludes;
  routing_table_->GetCloseContacts(key, k_, excludes, &close_nodes);
  AddContactsToContainer<FindValueArgs>(close_nodes, fva);
  IterativeSearch<FindValueArgs>(fva);
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

void Node::Impl::Join(const NodeId &node_id,
          const Port &port,
          const std::vector<Contact> &bootstrap_contacts,
          JoinFunctor callback) {
  joined_ = true;
  report_down_contact_->connect(
      ReportDownContactPtr::element_type::slot_type(
          &Node::Impl::ReportDownContact, this, _1));
  thread_group_.create_thread(
                    boost::bind(&Node::Impl::MonitoringDownlistThread, this));
}

// TODO(qi.ma@maidsafe.net): the info of the node reporting these k-closest
// contacts will need to be recorded during the FindValue process once the
// CACHE methodology is decided
template <class T>
void Node::Impl::AddContactsToContainer(const std::vector<Contact> contacts,
                                        std::shared_ptr<T> fa) {
  // Only insert the tuple when it does not existed in the container
  boost::mutex::scoped_lock loch_lavitesse(fa->mutex);
  NodeContainerByNodeId key_node_indx = fa->nc.template get<nc_id>();
  for (size_t n = 0; n < contacts.size(); ++n) {
    auto it_tuple = key_node_indx.find(contacts[n].node_id());
    if (it_tuple == key_node_indx.end()) {
      NodeContainerTuple nct(contacts[n], fa->key);
      fa->nc.insert(nct);
    }
  }
}

template <class T>
bool Node::Impl::HandleIterationStructure(const Contact &contact,
                                    std::shared_ptr<T> fa,
                                    NodeSearchState mark,
                                    int *response_code,
                                    std::vector<Contact> *closest_contacts,
                                    bool *cur_iteration_done,
                                    bool *calledback) {
  bool result = false;
  boost::mutex::scoped_lock loch_surlaplage(fa->mutex);

  // Mark the enquired contact
  NodeContainerByNodeId key_node_indx = fa->nc.template get<nc_id>();
  auto it_tuple = key_node_indx.find(contact.node_id());
  key_node_indx.modify(it_tuple, ChangeState(mark));

  NodeContainerByDistance distance_node_indx =
                                    fa->nc.template get<nc_distance>();
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
  auto pit = fa->nc.template get<nc_state_round>().equal_range(
                 boost::make_tuple(kSelectedAlpha, fa->round));
  int num_of_round_pending = std::distance(pit.first, pit.second);
  if (num_of_round_pending <= (kAlpha_ - kBeta_))
      *cur_iteration_done = true;

  auto pit_pending = fa->nc.template get<nc_state>().equal_range(
                                                              kSelectedAlpha);
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
    while ((it != it_end) && (closest_contacts->size() < k_)) {
      if ((*it).state == kContacted)
        closest_contacts->push_back((*it).contact);
      ++it;
    }
    *response_code = closest_contacts->size();
    // main part of memory resource in fa can be released here
    fa->nc.clear();
  }
  result = true;
  return result;
}

void Node::Impl::FindNodes(const Key &key, FindNodesFunctor callback) {
  std::vector<Contact> close_nodes, excludes;
  std::shared_ptr<FindNodesArgs> fna(new FindNodesArgs(key, callback));

  // initialize with local k closest as a seed
  routing_table_->GetCloseContacts(key, k_, excludes, &close_nodes);
  AddContactsToContainer<FindNodesArgs>(close_nodes, fna);

  IterativeSearch<FindNodesArgs>(fna);
}

template <class T>
void Node::Impl::IterativeSearch(std::shared_ptr<T> fa) {
  boost::mutex::scoped_lock loch_surlaplage(fa->mutex);

  auto pit = fa->nc. template get<nc_state_distance>().equal_range(
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

  NodeContainerByNodeId key_node_indx = fa->nc.template get<nc_id>();
  // Update contacts' state
  for (auto it = to_contact.begin(); it != to_contact.end(); ++it) {
    auto it_tuple = key_node_indx.find(*it);
    key_node_indx.modify(it_tuple, ChangeState(kSelectedAlpha));
    key_node_indx.modify(it_tuple, ChangeRound(fa->round+1));
  }
  ++fa->round;
  // Better to change the value in a bunch and then issue RPCs in a bunch
  // to avoid any possibilities of cross-interference
  for (auto it = to_contact.begin(); it != to_contact.end(); ++it) {
    auto it_tuple = key_node_indx.find(*it);
    std::shared_ptr<RpcArgs> frpc(new RpcArgs((*it_tuple).contact, fa));
    switch (fa->operation_type) {
      case kOpFindNode: {
        rpcs_->FindNodes(fa->key, default_securifier_, (*it_tuple).contact,
                         boost::bind(&Node::Impl::IterativeSearchNodeResponse,
                                     this, _1, _2, _3, frpc),
                         kTcp);
        }
        break;
      case kOpFindValue: {
        std::shared_ptr<FindValueArgs> fva =
          std::dynamic_pointer_cast<FindValueArgs> (fa);
        rpcs_->FindValue(fva->key, fva->securifier, (*it_tuple).contact,
                  boost::bind(&Node::Impl::IterativeSearchValueResponse,
                              this, _1, _2, _3, _4, _5, frpc),
                  kTcp);
        }
        break;
    }
  }
}

void Node::Impl::IterativeSearchValueResponse(
                                  RankInfoPtr rank_info,
                                  int result,
                                  const std::vector<std::string> &values,
                                  const std::vector<Contact> &contacts,
                                  const Contact &alternative_store,
                                  std::shared_ptr<RpcArgs> frpc) {
  std::shared_ptr<FindValueArgs> fva =
      std::static_pointer_cast<FindValueArgs> (frpc->rpc_a);
  if (fva->calledback)
    return;
  // once got some result, terminate the search and report the result back
  // immediately
  bool curr_iteration_done(false), calledback(false);
  int response_code(0);
  std::vector<Contact> closest_contacts;
  if (values.size() > 0) {
    calledback = true;
    response_code = values.size();
  } else {
    NodeSearchState mark(kContacted);
    if (result < 0) {
      mark = kDown;
      // fire a signal here to notify this contact is down
      (*report_down_contact_)(frpc->contact);
    } else {
      AddContactsToContainer<FindValueArgs>(contacts, fva);
    }

    if (!HandleIterationStructure<FindValueArgs>(frpc->contact, fva, mark,
                                                 &response_code,
                                                 &closest_contacts,
                                                 &curr_iteration_done,
                                                 &calledback)) {
      printf("Well, that's just too freakishly odd. Daaaaamn, brotha!\n");
    }
    response_code = -2;
    if ((!calledback) && (curr_iteration_done))
      IterativeSearch<FindValueArgs>(fva);
  }

  if (calledback) {
    boost::mutex::scoped_lock loch_surlaplage(fva->mutex);
    // TODO(qi.ma@maidsafe.net): the cache contact shall be populated once the
    // methodology of CACHE is decided
    Contact cache_contact;
    fva->callback(response_code, values, closest_contacts,
                  alternative_store, cache_contact);
    fva->calledback = true;
  }
}

void Node::Impl::IterativeSearchNodeResponse(
                                  RankInfoPtr rank_info,
                                  int result,
                                  const std::vector<Contact> &contacts,
                                  std::shared_ptr<RpcArgs> fnrpc) {
  std::shared_ptr<FindNodesArgs> fna =
      std::static_pointer_cast<FindNodesArgs> (fnrpc->rpc_a);
  // If already calledback, i.e. result has already been reported
  // then do nothing, just return
  if (fna->calledback) {
    return;
  }
  bool curr_iteration_done(false), calledback(false);
  int response_code(0);
  std::vector<Contact> closest_contacts;
  NodeSearchState mark(kContacted);
  if (result < 0) {
    mark = kDown;
    // fire a signal here to notify this contact is down
    (*report_down_contact_)(fnrpc->contact);
  } else {
    AddContactsToContainer<FindNodesArgs>(contacts, fna);
  }

  if (!HandleIterationStructure<FindNodesArgs>(fnrpc->contact, fna, mark,
                                               &response_code,
                                               &closest_contacts,
                                               &curr_iteration_done,
                                               &calledback)) {
    printf("Well, that's just too freakishly odd. Daaaaamn, brotha!\n");
  }

  if (!calledback) {
    if (curr_iteration_done)
      IterativeSearch<FindNodesArgs>(fna);
  } else {
    boost::mutex::scoped_lock loch_surlaplage(fna->mutex);
    fna->callback(response_code, closest_contacts);
    fna->calledback = true;
  }
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

void Node::Impl::ReportDownContact(const Contact &down_contact) {
  boost::mutex::scoped_lock loch_surlaplage(mutex_);
  down_contacts_.push_back(down_contact.node_id());
  condition_downlist_.notify_one();
}

void Node::Impl::MonitoringDownlistThread() {
  while (joined_) {
    boost::mutex::scoped_lock loch_surlaplage(mutex_);
    while (down_contacts_.empty())
      condition_downlist_.wait(loch_surlaplage);

    // report the downlist to local k-closest contacts
    std::vector<Contact> close_nodes, excludes;
    routing_table_->GetContactsClosestToOwnId(k_, excludes, &close_nodes);
//     routing_table_->GetCloseContacts(contact_.node_id(), k_,
//                                      excludes, &close_nodes);
    auto it = close_nodes.begin();
    auto it_end = close_nodes.end();
    while (it != it_end) {
      rpcs_->Downlist(down_contacts_, default_securifier_, (*it), kTcp);
      ++it;
    }
    down_contacts_.clear();
  }
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
