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

#include "maidsafe/kademlia/nodeimpl.h"

#include <boost/assert.hpp>
#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <google/protobuf/descriptor.h>

#include <algorithm>
#include <iostream>  // NOLINT Fraser - required for handling .kadconfig file
#include <fstream>  // NOLINT
#include <vector>
#include <set>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/online.h"
#include "maidsafe/common/routingtable.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/kademlia/datastore.h"
#include "maidsafe/kademlia/nodeid.h"
#include "maidsafe/kademlia/routingtable.h"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace kademlia {

// some tools which will be used in the implementation of NodeImpl class

inline void dummy_callback(const std::string&) {}

inline void dummy_downlist_callback() { }

bool CompareContact(const ContactAndTargetKey &first,
                    const ContactAndTargetKey &second) {
  NodeId id;
  if (first.contact.node_id() == id)
    return true;
  else if (second.contact.node_id() == id)
    return false;
  return NodeId::CloserToTarget(first.contact.node_id(),
      second.contact.node_id(), first.target_key);
}

// sort the contact list according the distance to the target key
void SortContactList(const NodeId &target_key,
                     std::list<Contact> *contact_list) {
  if (contact_list->empty()) {
    return;
  }
  std::list<ContactAndTargetKey> temp_list;
  std::list<Contact>::iterator it;
  // clone the contacts into a temporary list together with the target key
  for (it = contact_list->begin(); it != contact_list->end(); ++it) {
    ContactAndTargetKey new_ck;
    new_ck.contact = *it;
    new_ck.target_key = target_key;
    temp_list.push_back(new_ck);
  }
  temp_list.sort(CompareContact);
  // restore the sorted contacts from the temporary list.
  contact_list->clear();
  std::list<ContactAndTargetKey>::iterator it1;
  for (it1 = temp_list.begin(); it1 != temp_list.end(); ++it1) {
    contact_list->push_back(it1->contact);
  }
}

// sort the contact list according the distance to the target key
void SortLookupContact(const NodeId &target_key,
                       std::list<LookupContact> *contact_list) {
  if (contact_list->empty()) {
    return;
  }
  std::list<ContactAndTargetKey> temp_list;
  std::list<LookupContact>::iterator it;
  // clone the contacts into a temporary list together with the target key
  for (it = contact_list->begin(); it != contact_list->end(); ++it) {
    ContactAndTargetKey new_ck;
    new_ck.contact = it->kad_contact;
    new_ck.target_key = target_key;
    new_ck.contacted = it->contacted;
    temp_list.push_back(new_ck);
  }
  temp_list.sort(CompareContact);
  // restore the sorted contacts from the temporary list.
  contact_list->clear();
  std::list<ContactAndTargetKey>::iterator it1;
  for (it1 = temp_list.begin(); it1 != temp_list.end(); ++it1) {
    struct LookupContact ctc;
    ctc.kad_contact = it1->contact;
    ctc.contacted = it1->contacted;
    contact_list->push_back(ctc);
  }
}

NodeImpl::NodeImpl(boost::shared_ptr<transport::Transport> transport,
                   const NodeConstructionParameters &node_parameters)
        : asio_service_(new boost::asio::io_service()),
          routingtable_mutex_(),
          kadconfig_mutex_(),
          extendshortlist_mutex_(),
          joinbootstrapping_mutex_(),
          leave_mutex_(),
          activeprobes_mutex_(),
          pendingcts_mutex_(),
          ptimer_(new CallLaterTimer),
          transport_(transport),
          pdata_store_(new DataStore(node_parameters.refresh_time)),
          premote_service_(),
          prouting_table_(),
          rpcs_(new Rpcs(asio_service_)),
          addcontacts_routine_(),
          prth_(),
          alternative_store_(NULL),
          signature_validator_(NULL),
          upnp_(),
          node_id_(),
          fake_kClientId_(),
          ip_(),
          rv_ip_(),
          local_ip_(),
          port_(node_parameters.port),
          rv_port_(0),
          local_port_(0),
          upnp_mapped_port_(0),
          type_(node_parameters.type),
          bootstrapping_nodes_(),
          exclude_bs_contacts_(),
          contacts_to_add_(),
          K_(node_parameters.k),
          alpha_(node_parameters.alpha),
          beta_(node_parameters.beta),
          is_joined_(false),
          refresh_routine_started_(false),
          stopping_(false),
          port_forwarded_(node_parameters.port_forwarded),
          use_upnp_(node_parameters.use_upnp),
          kad_config_path_(""),
          add_ctc_cond_(),
          private_key_(node_parameters.private_key),
          public_key_(node_parameters.public_key) {
  prth_ = (*PublicRoutingTable::GetInstance())
              [boost::lexical_cast<std::string>(port_)];
}


NodeImpl::~NodeImpl() {
  if (is_joined_)
    Leave();
}

void NodeImpl::JoinFirstNode(const NodeId &node_id,
                             const std::string &kad_config_file,
                             const IP &ip, const Port &port,
                             VoidFunctorOneString callback) {
  protobuf::GeneralResponse local_result;
  std::string local_result_str;
  if (is_joined_ || !node_id.IsValid()) {
    if (is_joined_) {
      local_result.set_result(true);
    } else {
      local_result.set_result(false);
    }
    local_result.SerializeToString(&local_result_str);
    callback(local_result_str);
    return;
  }

//  RegisterService();

  node_id_ = node_id;
  if (type_ == CLIENT || type_ == CLIENT_PORT_MAPPED) {
    // Client nodes can not start a network on their own
    local_result.set_result(false);
    local_result.SerializeToString(&local_result_str);
    callback(local_result_str);
    return;
  }

  local_port_ = port;
  if (use_upnp_) {
//    UPnPMap(local_port_);
//    if (upnp_mapped_port_ != 0) {
//      port_ = upnp_mapped_port_;
//      // It is now directly connected
//    } else {
//      local_result.set_result(false);
//      local_result.SerializeToString(&local_result_str);
//      callback(local_result_str);
//      return;
//    }
  } else if (/*ip.empty() || */port == 0) {
    local_result.set_result(false);
    local_result.SerializeToString(&local_result_str);
    callback(local_result_str);
    return;
  } else {
    ip_ = ip;
    port_ = port;
  }

  // Set kad_config_path_
  kad_config_path_ = fs::path(kad_config_file);
  prouting_table_.reset(new RoutingTable(node_id_, K_));

  is_joined_ = true;
//  premote_service_->set_node_joined(true);

//  addcontacts_routine_.reset(new boost::thread(&NodeImpl::CheckAddContacts,
//                                               this));
  if (!refresh_routine_started_) {
//    ptimer_->AddCallLater(kRefreshTime * 1000,
//                          boost::bind(&NodeImpl::RefreshRoutine, this));
//    ptimer_->AddCallLater(2000, boost::bind(&NodeImpl::RefreshValuesRoutine,
//                                            this));
    refresh_routine_started_ = true;
  }
  local_result.set_result(true);
  local_result.SerializeToString(&local_result_str);
  callback(local_result_str);
}

void NodeImpl::JoinFirstNode(const std::string &kad_config_file,
                             const IP &ip, const Port &port,
                             VoidFunctorOneString callback) {
  JoinFirstNode(NodeId(NodeId::kRandomId), kad_config_file, ip, port, callback);
}

void NodeImpl::Leave() {
  if (is_joined_) {
    if (upnp_mapped_port_ != 0) {
//      UnMapUPnP();
    }
    stopping_ = true;
    {
      boost::mutex::scoped_lock gaurd(leave_mutex_);
      is_joined_ = false;
//      premote_service_->set_node_joined(false);
      ptimer_->CancelAll();
//      pchannel_manager_->ClearCallLaters();
//      UnRegisterService();
      pdata_store_->Clear();
      add_ctc_cond_.notify_one();
//      addcontacts_routine_->join();
//      SaveBootstrapContacts();
      exclude_bs_contacts_.clear();
      prouting_table_->Clear();
      prth_->Clear();
    }
    stopping_ = false;
  }
}

int NodeImpl::AddContact(Contact new_contact, const float &rtt,
                          const bool &only_db) {
  int result = -1;
  if (new_contact.node_id().String() != kClientId &&
      new_contact.node_id() != node_id_) {
    if (!only_db) {
      boost::mutex::scoped_lock gaurd(routingtable_mutex_);
      new_contact.SetLastSeenToNow(GetEpochMilliseconds());
      result = prouting_table_->AddContact(new_contact);
    } else {
      result = 0;
    }

    // Adding to routing table db
//    IP remote_ip, rendezvous_ip;
//    remote_ip = IpBytesToAscii(new_contact.ip());
//    if (!new_contact.rendezvous_ip().empty()) {
//      rendezvous_ip = IpBytesToAscii(new_contact.rendezvous_ip());
//    }
//    PublicRoutingTableTuple tuple(new_contact.node_id().String(),
//                                        remote_ip,
//                                        new_contact.port(),
//                                        rendezvous_ip,
//                                        new_contact.rendezvous_port(),
//                                        new_contact.node_id().String(),
//                                        rtt, 0, 0);
//    prth_->AddTuple(tuple);
    if (result == 2 && is_joined_) {
      {
        boost::mutex::scoped_lock gaurd(pendingcts_mutex_);
        contacts_to_add_.push_back(new_contact);
      }
      add_ctc_cond_.notify_one();
    }
  }
  return result;
}

void NodeImpl::AddContactsToContainer(const std::vector<Contact> contacts,
                                       boost::shared_ptr<FindNodesArgs> fna) {
  boost::mutex::scoped_lock loch_lavitesse(fna->mutex);
  for (size_t n = 0; n < contacts.size(); ++n) {
    NodeContainerTuple nct(contacts[n]);
    fna->nc.insert(nct);
  }
}

bool NodeImpl::MarkResponse(const Contact &contact,
                            boost::shared_ptr<FindNodesArgs> fna,
                            SearchMarking mark,
                            std::list<Contact> *response_nodes) {
  if (!response_nodes->empty()) {
    while (!response_nodes->empty()) {
      NodeContainerTuple nct(response_nodes->front());
      fna->nc.insert(nct);
      response_nodes->pop_front();
    }
  }

  NodeContainerByContact &index_contact = fna->nc.get<nc_contact>();
  NodeContainerByContact::iterator it = index_contact.find(contact);
  if (it != index_contact.end()) {
    NodeContainerTuple nct = *it;
    if (mark == SEARCH_DOWN)
      nct.state = kDown;
    else
      nct.state = kContacted;
    index_contact.replace(it, nct);
    return true;
  }

  return false;
}

void NodeImpl::MarkAsAlpha(const std::list<Contact> &contacts,
                           boost::shared_ptr<FindNodesArgs> fna) {
  auto it_conts = contacts.begin();
  for (; it_conts != contacts.end(); ++it_conts) {
    NodeContainerByContact &index_contact = fna->nc.get<nc_contact>();
    NCBCit contact_it = index_contact.find(*it_conts);
    if (contact_it != index_contact.end()) {
      if ((*contact_it).state == kNew) {
        NodeContainerTuple nct = *contact_it;
//        printf("New %s\n",
//               nct.contact.node_id().ToStringEncoded(NodeId::kBase64).c_str());
        nct.state = kSelectedAlpha;
        nct.round = fna->round;
        index_contact.replace(contact_it, nct);
//        ++times;
//        alphas.push_back((*contact_it).contact);
      }
    } else {
      DLOG(WARNING) << "NodeImpl::MarkAsAlpha - This shouldn't happen ever. "
                       "Serious review needed." << std::endl;
    }
  }
}

int NodeImpl::NodesPending(boost::shared_ptr<FindNodesArgs> fna) {
  NodeContainerByState &index_state = fna->nc.get<nc_state>();
  std::pair<NCBSit, NCBSit> p = index_state.equal_range(kSelectedAlpha);
  int count(0);
  while (p.first != p.second) {
    ++count;
    ++p.first;
  }
  return count;
}

bool NodeImpl::HandleIterationStructure(const Contact &contact,
                                        boost::shared_ptr<FindNodesArgs> fna,
                                        int round,
                                        SearchMarking mark,
                                        std::list<Contact> *nodes,
                                        bool *top_nodes_done,
                                        bool *calledback,
                                        int *nodes_pending) {
  boost::mutex::scoped_lock loch_surlaplage(fna->mutex);
//  printf("--- %s\n",
//         contact.node_id().ToStringEncoded(NodeId::kBase64).c_str());
  if (fna->calledback) {
    *nodes_pending = NodesPending(fna);
    *top_nodes_done = true;
    *calledback = true;
    nodes->clear();
    return true;
  } else {
//    printf("NodeImpl::AnalyseIteration - Search not complete at Round(%d) - "
//           "%d alphas\n", round, nodes->size());
  }

  bool b = MarkResponse(contact, fna, mark, nodes);
//  if (!nodes->empty())
//    printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
  *nodes_pending = NodesPending(fna);

  // Check how many of the nodes of the iteration are back
  NodeContainerByRound &index_car = fna->nc.get<nc_round>();
  std::pair<NCBRit, NCBRit> pr = index_car.equal_range(round);
  int alphas_replied(0), alphas_sent(0);
  for (; pr.first != pr.second; ++pr.first) {
    ++alphas_sent;
    if ((*pr.first).state == kContacted)
      ++alphas_replied;
  }
//  printf("%d - n(%d) - NP(%d) - AS(%d) - AR(%d)\n", fna->nc.size(),
//         nodes->size(), *nodes_pending, alphas_sent, alphas_replied);

//  printf("NodeImpl::HandleIterationStructure - Total(%d), Done(%d), "
//         "Round(%d)\n", alphas_sent, alphas_replied, round);
  // Decide if another iteration is needed and pick the alphas
  if ((alphas_sent > kBeta && alphas_replied >= kBeta) ||
      (alphas_sent <= kBeta && alphas_replied == alphas_sent)) {

//    if (alphas_sent > kBeta && alphas_replied >= kBeta)
//      printf("11111111111111111111\n");
//    if (alphas_sent <= kBeta && alphas_replied == alphas_sent)
//      printf("22222222222222222222 %d of %d\n", alphas_replied, alphas_sent);

    // Get all contacted nodes that aren't down and sort them
    NodeContainer::iterator node_it = fna->nc.begin();
    for (; node_it != fna->nc.end(); ++node_it) {
      if ((*node_it).state != kDown)
        nodes->push_back((*node_it).contact);
    }
    SortContactList(fna->key, nodes);

    // Only interested in the K closest
    if (nodes->size() > size_t(K_))
      nodes->resize(size_t(K_));

    // Printing the IDs of the last node and the other possible candidate
//    printf("%s -- %s\n",
//           nodes->back().node_id().ToStringEncoded(NodeId::kBase64).c_str(),
//           fna->kth_closest.ToStringEncoded(NodeId::kBase64).c_str());

    if (nodes->back().node_id() == fna->kth_closest) {
      // Check the top K nodes to see if they're all done
      int new_nodes(0), contacted_nodes(0), alpha_nodes(0);
      std::list<Contact>::iterator done_it = nodes->begin();
      for (; done_it != nodes->end(); ++done_it) {
        NodeContainerByContact &index_contact = fna->nc.get<nc_contact>();
        NCBCit contact_it = index_contact.find(*done_it);
        if (contact_it != index_contact.end()) {
          if ((*contact_it).state == kNew)
            ++new_nodes;
          else if ((*contact_it).state == kSelectedAlpha)
            ++alpha_nodes;
          else if ((*contact_it).state == kContacted)
            ++contacted_nodes;
          else
            DLOG(WARNING) << "NodeImpl::HandleIterationStructure - No other"
                             " state should occur.";
        }
      }
//      printf("New(%d), Alpha(%d), Contacted(%d)\n",
//             new_nodes, alpha_nodes, contacted_nodes);

      if (new_nodes == 0 && alpha_nodes == 0 && *nodes_pending == 0) {
        // We're done
        *calledback = fna->calledback;
        if (!fna->calledback)
          fna->calledback = true;
        *top_nodes_done = true;
        return b;
      }
    }

    fna->kth_closest = nodes->back().node_id();
    ++fna->round;
    std::list<Contact> alphas;
    std::list<Contact>::iterator it_conts = nodes->begin();
    boost::uint16_t times(0)/*, nodes_examined(0)*/;
    for (; it_conts != nodes->end() && times < kAlpha; ++it_conts) {
      NodeContainerByContact &index_contact = fna->nc.get<nc_contact>();
      NCBCit contact_it = index_contact.find(*it_conts);
      if (contact_it != index_contact.end()) {
        if ((*contact_it).state == kNew) {
          NodeContainerTuple nct = *contact_it;
//          printf("New %s\n",
//                 nct.contact.node_id().ToStringEncoded(NodeId::kBase64).c_str());
          nct.state = kSelectedAlpha;
          nct.round = fna->round;
          index_contact.replace(contact_it, nct);
          ++times;
          alphas.push_back((*contact_it).contact);
        }
      } else {
        DLOG(WARNING) << "NodeImpl::MarkAsAlpha - This shouldn't happen ever. "
                         "Serious review needed." << std::endl;
      }
    }
    *nodes = alphas;
  }

  return b;
}

void NodeImpl::FindNodes(const FindNodesParams &fnp) {
  std::vector<Contact> close_nodes, excludes;
  boost::shared_ptr<FindNodesArgs> fna(
      new FindNodesArgs(fnp.key, fnp.callback));
  if (fnp.use_routingtable) {
    prouting_table_->FindCloseNodes(fnp.key, K_, excludes, &close_nodes);
    AddContactsToContainer(close_nodes, fna);
  }

  if (!fnp.start_nodes.empty()) {
    AddContactsToContainer(fnp.start_nodes, fna);
  }

  if (!fnp.exclude_nodes.empty()) {
    for (size_t n = 0; n < fnp.exclude_nodes.size(); ++n) {
      NodeContainerByContact &index_contact = fna->nc.get<nc_contact>();
      NodeContainerByContact::iterator it =
          index_contact.find(fnp.exclude_nodes[n]);
      if (it != index_contact.end())
        index_contact.erase(it);
    }
  }

  // Get all contacted nodes that aren't down and sort them
  NodeContainer::iterator node_it = fna->nc.begin();
  std::list<Contact> alphas;
//  boost::uint16_t a(0);
  for (; node_it != fna->nc.end(); ++node_it) {
    alphas.push_back((*node_it).contact);
  }
  SortContactList(fna->key, &alphas);
  if (alphas.size() > K_)
    alphas.resize(K_);
  fna->kth_closest = alphas.back().node_id();

  if (alphas.size() > kAlpha)
    alphas.resize(kAlpha);

  std::list<Contact>::iterator node_it_alpha(alphas.begin());
  for (; node_it_alpha != alphas.end(); ++node_it_alpha) {
    NodeContainerByContact &index_contact = fna->nc.get<nc_contact>();
    NodeContainerByContact::iterator it =
        index_contact.find(*node_it_alpha);
    if (it != index_contact.end()) {
      NodeContainerTuple nct = *it;
      nct.round = fna->round;
      nct.state = kSelectedAlpha;
      index_contact.replace(it, nct);
    }
  }

  IterativeSearch(fna, false, false, &alphas);
}

void NodeImpl::IterativeSearch(boost::shared_ptr<FindNodesArgs> fna,
                               bool top_nodes_done,
                               bool calledback,
                               std::list<Contact> *contacts) {
  if (top_nodes_done) {
    if (!calledback) {
      DLOG(INFO) << "NodeImpl::IterativeSearch - Done" << std::endl;
      fna->callback(*contacts);
    }
    return;
  }

  if (contacts->empty())
    return;

//  printf("NodeImpl::IterativeSearch - Sending %d alphas\n", contacts->size());
  std::list<Contact>::iterator it = contacts->begin();
  for (; it != contacts->end(); ++it) {
    boost::shared_ptr<FindNodesRpc> fnrpc(new FindNodesRpc(*it, fna));
    rpcs_->FindNodes(fna->key, *it,
                     boost::bind(&NodeImpl::IterativeSearchResponse, this,
                                 _1, _2, fnrpc),
                     kUdt);
  }
}

void NodeImpl::IterativeSearchResponse(bool result,
                                       const std::vector<Contact> &contacts,
                                       boost::shared_ptr<FindNodesRpc> fnrpc) {
  SearchMarking mark(SEARCH_CONTACTED);
  if (!result)
    mark = SEARCH_DOWN;

  // Get nodes from response and add them to the list
  std::list<Contact> close_nodes;
  if (mark == SEARCH_CONTACTED && !contacts.empty()) {
    for (size_t n = 0; n < contacts.size(); ++n)
      close_nodes.push_back(contacts.at(n));
  }

  bool done(false), calledback(false);
  int nodes_pending(0);
  if (!HandleIterationStructure(fnrpc->contact, fnrpc->rpc_fna, fnrpc->round,
                                mark, &close_nodes, &done, &calledback,
                                &nodes_pending)) {
    DLOG(WARNING) << "NodeImpl::IterativeSearchResponse - Failure "
                     "handling response." << std::endl;
  }
//  printf("IterativeSearchResponse (%s)\n",
//         fnrpc->contact.node_id().ToStringEncoded(NodeId::kBase64).c_str());

  IterativeSearch(fnrpc->rpc_fna, done, calledback, &close_nodes);
}

}  // namespace kademlia

}  // namespace maidsafe
