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

// #include <algorithm>
// #include <vector>
// #include <set>
//
// #include "boost/assert.hpp"
// #include "boost/bind.hpp"
// #include "boost/lexical_cast.hpp"
//
// #include "maidsafe-dht/common/crypto.h"
// #include "maidsafe-dht/common/log.h"
// #include "maidsafe-dht/common/online.h"
// #include "maidsafe-dht/common/routing_table.h"
// #include "maidsafe-dht/common/utils.h"
// #include "maidsafe-dht/common/platform_config.h"
#include "maidsafe-dht/common/securifier.h"
#include "maidsafe-dht/kademlia/datastore.h"
#include "maidsafe-dht/kademlia/node_id.h"
#include "maidsafe-dht/kademlia/rpcs.h"
#include "maidsafe-dht/kademlia/routing_table.h"
#include "maidsafe-dht/kademlia/service.h"
#include "maidsafe-dht/kademlia/node_impl_structs.h"
#include "maidsafe-dht/kademlia/utils.h"
// #include "maidsafe-dht/kademlia/kademlia.pb.h"
// #include "maidsafe-dht/kademlia/node_id.h"
// #include "maidsafe-dht/transport/transport.h"
// #include "maidsafe-dht/transport/utils.h"

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
      routing_table_connection_() {}

Node::Impl::~Impl() {
  if (joined_)
    Leave(NULL);
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

void Node::Impl::Store(const Key &/*key*/,
                       const std::string &/*value*/,
                       const std::string &/*signature*/,
                       const boost::posix_time::time_duration &/*ttl*/,
                       SecurifierPtr /*securifier*/,
                       StoreFunctor /*callback*/) {
}

void Node::Impl::Delete(const Key &/*key*/,
                        const std::string &/*value*/,
                        const std::string &/*signature*/,
                        SecurifierPtr /*securifier*/,
                        DeleteFunctor /*callback*/) {
}

void Node::Impl::Update(const Key &/*key*/,
                        const std::string &/*new_value*/,
                        const std::string &/*new_signature*/,
                        const std::string &/*old_value*/,
                        const std::string &/*old_signature*/,
                        SecurifierPtr /*securifier*/,
                        const boost::posix_time::time_duration &/*ttl*/,
                        UpdateFunctor /*callback*/) {
}

void Node::Impl::FindValue(const Key &/*key*/,
                           SecurifierPtr /*securifier*/,
                           FindValueFunctor /*callback*/) {
}

void Node::Impl::FindNodes(const Key &/*key*/, FindNodesFunctor /*callback*/) {
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
//
// void Node::Impl::AddContactsToContainer(const std::vector<Contact> contacts,
//                                       boost::shared_ptr<FindNodesArgs> fna) {
//  boost::mutex::scoped_lock loch_lavitesse(fna->mutex);
//  for (size_t n = 0; n < contacts.size(); ++n) {
//    NodeContainerTuple nct(contacts[n]);
//    fna->nc.insert(nct);
//  }
// }
//
// bool Node::Impl::MarkResponse(const Contact &contact,
//                             boost::shared_ptr<FindNodesArgs> fna,
//                             SearchMarking mark,
//                             std::list<Contact> *response_nodes) {
//  if (!response_nodes->empty()) {
//    while (!response_nodes->empty()) {
//      NodeContainerTuple nct(response_nodes->front());
//      fna->nc.insert(nct);
//      response_nodes->pop_front();
//    }
//  }
//
//  NodeContainerByContact &index_contact = fna->nc.get<nc_contact>();
//  NodeContainerByContact::iterator it = index_contact.find(contact);
//  if (it != index_contact.end()) {
//    NodeContainerTuple nct = *it;
//    if (mark == kSearchDown)
//      nct.state = kDown;
//    else
//      nct.state = kContacted;
//    index_contact.replace(it, nct);
//    return true;
//  }
//
//  return false;
// }
//
// int Node::Impl::NodesPending(boost::shared_ptr<FindNodesArgs> fna) {
//  NodeContainerByState &index_state = fna->nc.get<nc_state>();
//  std::pair<NCBSit, NCBSit> p = index_state.equal_range(kSelectedAlpha);
//  int count(0);
//  while (p.first != p.second) {
//    ++count;
//    ++p.first;
//  }
//  return count;
// }
//
// bool Node::Impl::HandleIterationStructure(const Contact &contact,
//                                         boost::shared_ptr<FindNodesArgs> fna,
//                                         int round,
//                                         SearchMarking mark,
//                                         std::list<Contact> *nodes,
//                                         bool *top_nodes_done,
//                                         bool *calledback,
//                                         int *nodes_pending) {
//  boost::mutex::scoped_lock loch_surlaplage(fna->mutex);
//  if (fna->calledback) {
//    *nodes_pending = NodesPending(fna);
//    *top_nodes_done = true;
//    *calledback = true;
//    nodes->clear();
//    return true;
//  } else {
//  printf("Node::Impl::AnalyseIteration - Search not complete at Round(%d) - "
////           "%d alphas\n", round, nodes->size());
//  }
//
//  bool b = MarkResponse(contact, fna, mark, nodes);
//  *nodes_pending = NodesPending(fna);
//
//  // Check how many of the nodes of the iteration are back
//  NodeContainerByRound &index_car = fna->nc.get<nc_round>();
//  std::pair<NCBRit, NCBRit> pr = index_car.equal_range(round);
//  int alphas_replied(0), alphas_sent(0);
//  for (; pr.first != pr.second; ++pr.first) {
//    ++alphas_sent;
//    if ((*pr.first).state == kContacted)
//      ++alphas_replied;
//  }
//
//  printf("Node::Impl::HandleIterationStructure - Total(%d), Done(%d), "
//         "Round(%d)\n", alphas_sent, alphas_replied, round);
//  // Decide if another iteration is needed and pick the alphas
//  if ((alphas_sent > kBeta && alphas_replied >= kBeta) ||
//      (alphas_sent <= kBeta && alphas_replied == alphas_sent)) {
//
//    // Get all contacted nodes that aren't down and sort them
//    NodeContainer::iterator node_it = fna->nc.begin();
//    for (; node_it != fna->nc.end(); ++node_it) {
//      if ((*node_it).state != kDown)
//        nodes->push_back((*node_it).contact);
//    }
//    SortContactList(fna->key, nodes);
//
//    // Only interested in the K closest
//    if (nodes->size() > size_t(K_))
//      nodes->resize(size_t(K_));
//
//    printf("%s -- %s\n",
//           nodes->back().node_id().ToStringEncoded(NodeId::kBase64).c_str(),
//           fna->kth_closest.ToStringEncoded(NodeId::kBase64).c_str());
//    if (nodes->back().node_id() == fna->kth_closest) {
//      // Check the top K nodes to see if they're all done
//      int new_nodes(0), contacted_nodes(0), alpha_nodes(0);
//      std::list<Contact>::iterator done_it = nodes->begin();
//      for (; done_it != nodes->end(); ++done_it) {
//        NodeContainerByContact &index_contact = fna->nc.get<nc_contact>();
//        NCBCit contact_it = index_contact.find(*done_it);
//        if (contact_it != index_contact.end()) {
//          if ((*contact_it).state == kNew)
//            ++new_nodes;
//          else if ((*contact_it).state == kSelectedAlpha)
//            ++alpha_nodes;
//          else if ((*contact_it).state == kContacted)
//            ++contacted_nodes;
//        }
//      }
//      printf("Node::Impl::HandleIterationStructure - New(%d), Alpha(%d),"
//             " Contacted(%d)\n", new_nodes, alpha_nodes, contacted_nodes);
//
//      if (new_nodes == 0 && alpha_nodes == 0 && *nodes_pending == 0) {
//        // We're done
//        *calledback = fna->calledback;
//        if (!fna->calledback)
//          fna->calledback = true;
//        *top_nodes_done = true;
//        return b;
//      }
//    }
//
//    fna->kth_closest = nodes->back().node_id();
//    ++fna->round;
//    std::list<Contact> alphas;
//    std::list<Contact>::iterator it_conts = nodes->begin();
//    boost::uint16_t times(0);
//    for (; it_conts != nodes->end() && times < kAlpha; ++it_conts) {
//      NodeContainerByContact &index_contact = fna->nc.get<nc_contact>();
//      NCBCit contact_it = index_contact.find(*it_conts);
//      if (contact_it != index_contact.end()) {
//        if ((*contact_it).state == kNew) {
//          NodeContainerTuple nct = *contact_it;
//          nct.state = kSelectedAlpha;
//          nct.round = fna->round;
//          index_contact.replace(contact_it, nct);
//          ++times;
//          alphas.push_back((*contact_it).contact);
//        }
//      } else {
//        printf("This shouldn't happen. Ever! Ever ever ever!\n");
//      }
//    }
//    *nodes = alphas;
//  }
//
//  return b;
// }
//
// void Node::Impl::FindNodes(const FindNodesParams &fnp) {
//  std::vector<Contact> close_nodes, excludes;
//  boost::shared_ptr<FindNodesArgs> fna(
//      new FindNodesArgs(fnp.key, fnp.callback));
//  if (fnp.use_routingtable) {
//    routing_table_->FindCloseNodes(fnp.key, K_, excludes, &close_nodes);
//    AddContactsToContainer(close_nodes, fna);
//  }
//
//  if (!fnp.start_nodes.empty()) {
//    AddContactsToContainer(fnp.start_nodes, fna);
//  }
//
//  if (!fnp.exclude_nodes.empty()) {
//    for (size_t n = 0; n < fnp.exclude_nodes.size(); ++n) {
//      NodeContainerByContact &index_contact = fna->nc.get<nc_contact>();
//      NodeContainerByContact::iterator it =
//          index_contact.find(fnp.exclude_nodes[n]);
//      if (it != index_contact.end())
//        index_contact.erase(it);
//    }
//  }
//
//  // Get all contacted nodes that aren't down and sort them
//  NodeContainer::iterator node_it = fna->nc.begin();
//  std::list<Contact> alphas;
////  boost::uint16_t a(0);
//  for (; node_it != fna->nc.end(); ++node_it) {
//    alphas.push_back((*node_it).contact);
//  }
//  SortContactList(fna->key, &alphas);
//  if (alphas.size() > K_)
//    alphas.resize(K_);
//  fna->kth_closest = alphas.back().node_id();
//
//  if (alphas.size() > kAlpha)
//    alphas.resize(kAlpha);
//
//  std::list<Contact>::iterator node_it_alpha(alphas.begin());
//  for (; node_it_alpha != alphas.end(); ++node_it_alpha) {
//    NodeContainerByContact &index_contact = fna->nc.get<nc_contact>();
//    NodeContainerByContact::iterator it =
//        index_contact.find(*node_it_alpha);
//    if (it != index_contact.end()) {
//      NodeContainerTuple nct = *it;
//      nct.round = fna->round;
//      nct.state = kSelectedAlpha;
//      index_contact.replace(it, nct);
//    }
//  }
//
//  IterativeSearch(fna, false, false, &alphas);
// }
//
// void Node::Impl::IterativeSearch(boost::shared_ptr<FindNodesArgs> fna,
//                               bool top_nodes_done,
//                               bool calledback,
//                               std::list<Contact> *contacts) {
//  if (top_nodes_done) {
//    if (!calledback) {
//      DLOG(INFO) << "Node::Impl::IterativeSearch - Done" << std::endl;
//      fna->callback(*contacts);
//    }
//    return;
//  }
//
//  if (contacts->empty())
//    return;
//
// printf("Node::Impl::IterativeSearch - Sending %d alphas\n",
//           contacts->size());
//  std::list<Contact>::iterator it = contacts->begin();
//  for (; it != contacts->end(); ++it) {
//    boost::shared_ptr<FindNodesRpcArgs> fnrpc(new FindNodesRpcArgs(*it, fna));
//    rpcs_->FindNodes(fna->key, *it,
//                     boost::bind(&Node::Impl::IterativeSearchResponse, this,
//                                 _1, _2, fnrpc),
//                     kUdt);
//  }
// }
//
// void Node::Impl::IterativeSearchResponse(bool result,
//                                       const std::vector<Contact> &contacts,
//                                boost::shared_ptr<FindNodesRpcArgs> fnrpc) {
//  SearchMarking mark(kSearchContacted);
//  if (!result)
//    mark = kSearchDown;
//
//  // Get nodes from response and add them to the list
//  std::list<Contact> close_nodes;
//  if (mark == kSearchContacted && !contacts.empty()) {
//    for (size_t n = 0; n < contacts.size(); ++n)
//      close_nodes.push_back(contacts.at(n));
//  }
//
//  bool done(false), calledback(false);
//  int nodes_pending(0);
//  if (!HandleIterationStructure(fnrpc->contact, fnrpc->rpc_fna, fnrpc->round,
//                                mark, &close_nodes, &done, &calledback,
//                                &nodes_pending)) {
//    printf("Well, that's just too freakishly odd. Daaaaamn, brotha!\n");
//  }
//
//  IterativeSearch(fnrpc->rpc_fna, done, calledback, &close_nodes);
// }
void Node::Impl::PingOldestContact(const Contact &oldest_contact,
                                   const Contact &replacement_contact,
                                   RankInfoPtr replacement_rank_info) {
  Rpcs::PingFunctor callback(boost::bind(&Node::Impl::PingOldestContactCallback,
      this, oldest_contact, _1, _2, replacement_contact,
      replacement_rank_info));
  rpcs_->Ping(SecurifierPtr(), oldest_contact, callback, kUdt);
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
