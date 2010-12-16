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

#include "maidsafe/base/crypto.h"
#include "maidsafe/base/log.h"
#include "maidsafe/base/online.h"
#include "maidsafe/base/routingtable.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/kademlia/datastore.h"
#include "maidsafe/kademlia/nodeid.h"
#include "maidsafe/kademlia/routingtable.h"
#include "maidsafe/protobuf/contact_info.pb.h"
#include "maidsafe/protobuf/signed_kadvalue.pb.h"
#include "maidsafe/transport/transport.h"

namespace fs = boost::filesystem;

namespace kademlia {

// some tools which will be used in the implementation of NodeImpl class

inline void dummy_callback(const std::string&) {}

inline void dummy_downlist_callback(DownlistResponse *response,
                                    rpcprotocol::Controller *ctrler) {
  delete response;
  delete ctrler;
}

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

NodeImpl::NodeImpl(
    boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager,
    boost::shared_ptr<transport::Transport> transport,
    const NodeConstructionParameters &node_parameters)
        : routingtable_mutex_(),
          kadconfig_mutex_(),
          extendshortlist_mutex_(),
          joinbootstrapping_mutex_(),
          leave_mutex_(),
          activeprobes_mutex_(),
          pendingcts_mutex_(),
          ptimer_(new base::CallLaterTimer),
          transport_(transport),
          pchannel_manager_(channel_manager),
          pservice_channel_(),
          pdata_store_(new DataStore(node_parameters.refresh_time)),
          premote_service_(),
          prouting_table_(),
          rpcs_(new Rpcs(channel_manager, transport)),
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
          nat_type_(kSymmetric),
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
  prth_ = (*base::PublicRoutingTable::GetInstance())
              [boost::lexical_cast<std::string>(port_)];
}


NodeImpl::~NodeImpl() {
  if (is_joined_)
    Leave();
}

inline void NodeImpl::CallbackWithFailure(VoidFunctorOneString callback) {
  base::GeneralResponse result_msg;
  result_msg.set_result(false);
  std::string result(result_msg.SerializeAsString());
  callback(false);
}

void NodeImpl::Join_Bootstrapping(const bool&, VoidFunctorOneString callback) {
//  printf("NodeImpl::Join_Bootstrapping\n");
  if (bootstrapping_nodes_.empty()) {
    base::GeneralResponse local_result;
    if (type_ == VAULT) {
      local_result.set_result(true);
      is_joined_ = true;
      nat_type_ = kDirectConnected;
      premote_service_->set_node_joined(true);
      premote_service_->set_node_info(contact_info());
      addcontacts_routine_.reset(new boost::thread(&NodeImpl::CheckAddContacts,
                                                   this));
      if (!refresh_routine_started_) {
        ptimer_->AddCallLater(kRefreshTime * 1000,
                              boost::bind(&NodeImpl::RefreshRoutine, this));
        ptimer_->AddCallLater(2000,
                              boost::bind(&NodeImpl::RefreshValuesRoutine,
                                          this));
        refresh_routine_started_ = true;
      }
    } else {
      // Client nodes can not start a network on their own
      local_result.set_result(false);
      UnRegisterService();
    }
    rpcs_->set_info(contact_info());
    DLOG(WARNING) << "No more bootstrap contacts\n";
    std::string local_result_str(local_result.SerializeAsString());
    callback(local_result_str);
    return;
  }

  Contact bootstrap_candidate = bootstrapping_nodes_.back();
  bootstrapping_nodes_.pop_back();
  AddContact(bootstrap_candidate, 0.0, false);
  nat_type_ = kDirectConnected;
  StartSearchIteration(node_id_, BOOTSTRAP, callback);
}

void NodeImpl::Join_RefreshNode(VoidFunctorOneString callback,
                                 const bool &got_address) {
//  printf("NodeImpl::Join_RefreshNode\n");
  if (stopping_)
    return;
  // build list of bootstrapping nodes
  LoadBootstrapContacts();
  // Initiate the Kademlia joining sequence - perform a search for this
  // node's own ID
  // Getting local IP and temporarily setting ip_ == local_ip_
  std::vector<IP> local_ips = base::GetLocalAddresses();
  bool got_local_address = false;
  for (size_t i = 0; i < bootstrapping_nodes_.size() &&
       !got_local_address; ++i) {
    IP remote_ip = base::IpBytesToAscii(bootstrapping_nodes_[i].ip());
    for (size_t j = 0; j < local_ips.size() && !got_local_address; ++j) {
      if (!got_address) {
        ip_ = local_ips[j];
//        printf("NodeImpl::Join_RefreshNode - %s\n", ip_.c_str());
      }
      local_ip_ = local_ips[j];
      got_local_address = true;
    }
  }
  if (!got_local_address) {
    boost::asio::ip::address local_address;
    if (base::GetLocalAddress(&local_address)) {
      if (!got_address)
        ip_ = local_address.to_string();
      local_ip_ = local_address.to_string();
    }
  }
  rpcs_->set_info(contact_info());
  Join_Bootstrapping(got_address, callback);
}

void NodeImpl::Join(const NodeId &node_id, const std::string &kad_config_file,
                     VoidFunctorOneString callback) {
  if (is_joined_ || !node_id.IsValid()) {
    base::GeneralResponse local_result;
    if (is_joined_)
      local_result.set_result(true);
    else
      local_result.set_result(false);
    local_result.set_result(true);
    std::string local_result_str(local_result.SerializeAsString());
    callback(local_result_str);
    return;
  }

  if (port_ == 0) {
    if (!transport_->listening_ports().empty())
      port_ = transport_->listening_ports().at(0);
    else
      printf("Well, I don't really know what to do in this case yet!\n");
  }
  local_port_ = port_;

  // Adding the services
  RegisterService();

  node_id_ = node_id;

  bool got_address = false;
  if (use_upnp_) {
    UPnPMap(local_port_);
    if (upnp_mapped_port_ != 0) {
      port_ = upnp_mapped_port_;
      // It is now directly connected
      rv_ip_ = "";
      rv_port_ = 0;
      got_address = true;
    }
  }

  // Set kad_config_path_
  kad_config_path_ = fs::path(kad_config_file);
  prouting_table_.reset(new RoutingTable(node_id_, K_));
  Join_RefreshNode(callback, got_address);
}

void NodeImpl::Join(const std::string &kad_config_file,
                     VoidFunctorOneString callback) {
  Join(NodeId(NodeId::kRandomId), kad_config_file, callback);
}

void NodeImpl::JoinFirstNode(const NodeId &node_id,
                              const std::string &kad_config_file,
                              const IP &ip, const Port &port,
                              VoidFunctorOneString callback) {
  base::GeneralResponse local_result;
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

  RegisterService();

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
    UPnPMap(local_port_);
    if (upnp_mapped_port_ != 0) {
      port_ = upnp_mapped_port_;
      // It is now directly connected
    } else {
      local_result.set_result(false);
      local_result.SerializeToString(&local_result_str);
      callback(local_result_str);
      return;
    }
  } else if (ip.empty() || port == 0) {
    local_result.set_result(false);
    local_result.SerializeToString(&local_result_str);
    callback(local_result_str);
    return;
  } else {
    ip_ = ip;
    port_ = port;
  }
  boost::asio::ip::address local_address;
  if (base::GetLocalAddress(&local_address))
    local_ip_ = local_address.to_string();
  rv_ip_ = "";
  rv_port_ = 0;
  // Set kad_config_path_
  kad_config_path_ = fs::path(kad_config_file);
  prouting_table_.reset(new RoutingTable(node_id_, K_));

  is_joined_ = true;
  nat_type_ = kDirectConnected;
  premote_service_->set_node_joined(true);
  premote_service_->set_node_info(contact_info());

  addcontacts_routine_.reset(new boost::thread(&NodeImpl::CheckAddContacts,
                                               this));
  if (!refresh_routine_started_) {
    ptimer_->AddCallLater(kRefreshTime * 1000,
                          boost::bind(&NodeImpl::RefreshRoutine, this));
    ptimer_->AddCallLater(2000, boost::bind(&NodeImpl::RefreshValuesRoutine,
                                            this));
    refresh_routine_started_ = true;
  }
  rpcs_->set_info(contact_info());
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
      UnMapUPnP();
    }
    stopping_ = true;
    {
      boost::mutex::scoped_lock gaurd(leave_mutex_);
      is_joined_ = false;
      premote_service_->set_node_joined(false);
      ptimer_->CancelAll();
      pchannel_manager_->ClearCallLaters();
      UnRegisterService();
      pdata_store_->Clear();
      add_ctc_cond_.notify_one();
      addcontacts_routine_->join();
      SaveBootstrapContacts();
      exclude_bs_contacts_.clear();
      prouting_table_->Clear();
      prth_->Clear();
    }
    stopping_ = false;
    nat_type_ = kSymmetric;
  }
}

void NodeImpl::SaveBootstrapContacts() {
  try {
    std::vector<Contact> exclude_contacts, bs_contacts;
    bool reached_max(false);
    boost::uint32_t added_nodes(0);
    {
      boost::mutex::scoped_lock gaurd(routingtable_mutex_);
      std::vector<Contact> contacts_i;
      prouting_table_->GetFurthestContacts(node_id_, -1, exclude_bs_contacts_,
                                           &contacts_i);
      for (size_t j = 0; j < contacts_i.size() && !reached_max; ++j) {
        // store only the nodes that are directly connected to bootstrap vector
        if (contacts_i[j].rendezvous_ip().empty() &&
            contacts_i[j].rendezvous_port() == 0) {
          bs_contacts.push_back(contacts_i[j]);
          ++added_nodes;
        }
        reached_max = added_nodes >= kMaxBootstrapContacts;
      }
    }
    // Save contacts to .kadconfig
    base::KadConfig kad_config;
    NodeId node0_id;
    if (!bootstrapping_nodes_.empty()) {
      node0_id = bootstrapping_nodes_[0].node_id();
      base::KadConfig::Contact *kad_contact = kad_config.add_contact();
      kad_contact->set_node_id(
          bootstrapping_nodes_[0].node_id().ToStringEncoded(NodeId::kHex));
      IP dec_ext_ip(base::IpBytesToAscii(
          bootstrapping_nodes_[0].ip()));
      kad_contact->set_ip(dec_ext_ip);
      kad_contact->set_port(bootstrapping_nodes_[0].port());
      if (!bootstrapping_nodes_[0].local_ip().empty()) {
        IP dec_lip(base::IpBytesToAscii(
            bootstrapping_nodes_[0].local_ip()));
        kad_contact->set_local_ip(dec_lip);
        kad_contact->set_local_port(bootstrapping_nodes_[0].local_port());
      }
    }
    std::vector<Contact>::iterator it;
    for (it = bs_contacts.begin(); it < bs_contacts.end(); ++it) {
      if (it->node_id() != node0_id) {
        base::KadConfig::Contact *kad_contact = kad_config.add_contact();
        kad_contact->set_node_id(it->node_id().ToStringEncoded(NodeId::kHex));
        IP dec_ext_ip(base::IpBytesToAscii(it->ip()));
        kad_contact->set_ip(dec_ext_ip);
        kad_contact->set_port(it->port());
        if (it->local_ip() != "") {
          IP dec_lip(base::IpBytesToAscii(it->local_ip()));
          kad_contact->set_local_ip(dec_lip);
          kad_contact->set_local_port(it->local_port());
        }
      }
    }
    {
      boost::mutex::scoped_lock gaurd(kadconfig_mutex_);
      std::fstream output(kad_config_path_.string().c_str(),
                          std::ios::out | std::ios::trunc | std::ios::binary);
      kad_config.SerializeToOstream(&output);
      output.close();
    }
  }
  catch(const std::exception &ex) {
    DLOG(ERROR) << "Failed to updated kademlia config file " << kad_config_path_
        << ". Error: " << ex.what() << std::endl;
  }
}

boost::int16_t NodeImpl::LoadBootstrapContacts() {
  // Get the saved contacts - most recent are listed last
  base::KadConfig kad_config;
  try {
    if (fs::exists(kad_config_path_)) {
      std::ifstream input(kad_config_path_.string().c_str(),
                          std::ios::in | std::ios::binary);
      if (!kad_config.ParseFromIstream(&input)) {
        DLOG(ERROR) << "Failed to parse kademlia config file\n";
        return -1;
      }
      input.close();
      if (0 == kad_config.contact_size()) {
        DLOG(ERROR) << "Kademlia config file has no bootstrap nodes\n";
        return -1;
      }
    }
  }
  catch(const std::exception &ex) {
    DLOG(ERROR) << "Failed to access kademlia config file " << kad_config_path_
        << ". Error: " << ex.what() << std::endl;
    return -1;
  }
  bootstrapping_nodes_.clear();
  for (int i = 0; i < kad_config.contact_size(); ++i) {
    IP dec_id = base::DecodeFromHex(kad_config.contact(i).node_id());
    Contact bootstrap_contact(dec_id, kad_config.contact(i).ip(),
                              static_cast<Port>(kad_config.contact(i).port()),
                              kad_config.contact(i).local_ip(),
                              kad_config.contact(i).local_port());
    bootstrapping_nodes_.push_back(bootstrap_contact);
  }
  return 0;
}

void NodeImpl::RefreshRoutine() {
  if (is_joined_) {
    SaveBootstrapContacts();
    // Refresh the k-buckets
    pdata_store_->DeleteExpiredValues();
    StartSearchIteration(node_id_, FIND_NODE, &dummy_callback);
    // schedule the next refresh routine
    ptimer_->AddCallLater(kRefreshTime*1000,
                          boost::bind(&NodeImpl::RefreshRoutine, this));
  } else {
    refresh_routine_started_ = false;
  }
}

void NodeImpl::StoreValue_IterativeStoreValue(
    const StoreResponse *response, StoreCallbackArgs callback_data) {
  if (!is_joined_ || stopping_ || callback_data.data->is_callbacked)
    // Only call back once and check if node is in process of leaving or
    // has left
    return;

  SignedRequest del_req;
  if (response != NULL) {
    if (response->IsInitialized() && response->has_node_id() &&
        response->node_id() !=
            callback_data.remote_ctc.node_id().String()) {
      if (callback_data.retry) {
        delete response;
        StoreResponse *resp = new StoreResponse;
        UpdatePDRTContactToRemote(callback_data.remote_ctc.node_id(),
            callback_data.remote_ctc.ip());
        callback_data.retry = false;
        // send RPC to this contact's remote address because local failed
        google::protobuf::Closure *done1 = google::protobuf::NewCallback<
            NodeImpl, const StoreResponse*, StoreCallbackArgs > (this,
            &NodeImpl::StoreValue_IterativeStoreValue, resp, callback_data);
        if (using_signatures()) {
          rpcs_->Store(callback_data.data->key,
              callback_data.data->sig_value,
              callback_data.data->sig_request,
              callback_data.remote_ctc.ip(),
              callback_data.remote_ctc.port(),
              callback_data.remote_ctc.rendezvous_ip(),
              callback_data.remote_ctc.rendezvous_port(),
              resp, callback_data.rpc_ctrler, done1, callback_data.data->ttl,
              callback_data.data->publish);
        } else {
          rpcs_->Store(callback_data.data->key, callback_data.data->value,
              callback_data.remote_ctc.ip(),
              callback_data.remote_ctc.port(),
              callback_data.remote_ctc.rendezvous_ip(),
              callback_data.remote_ctc.rendezvous_port(),
              resp, callback_data.rpc_ctrler, done1, callback_data.data->ttl,
              callback_data.data->publish);
        }
        return;
      }
    }
    if (response->IsInitialized() && !callback_data.rpc_ctrler->Failed()) {
      if (response->result()) {
        ++callback_data.data->save_nodes;
      } else if (response->has_signed_request() &&
                 callback_data.data->sig_value.IsInitialized()) {
        if (DelValueLocal(callback_data.data->key,
            callback_data.data->sig_value, response->signed_request()))
          del_req = response->signed_request();
      }
      AddContact(callback_data.remote_ctc, callback_data.rpc_ctrler->rtt(),
                 false);
    } else {
      // it has timeout
      RemoveContact(callback_data.remote_ctc.node_id());
    }
    // nodes has been contacted -- timeout, responded with failure or success
    ++callback_data.data->contacted_nodes;
    delete callback_data.rpc_ctrler;
    callback_data.rpc_ctrler = NULL;
    delete response;
  }
  if (callback_data.data->contacted_nodes >=
      callback_data.data->closest_nodes.size() || del_req.IsInitialized()) {
    // Finish storing
    StoreResponse store_value_result;
    boost::uint32_t d(static_cast<boost::uint32_t>
      (K_ * kMinSuccessfulPecentageStore));
    if (callback_data.data->save_nodes >= d) {
      // Succeeded - min. number of copies were stored
      store_value_result.set_result(true);
    } else if (del_req.IsInitialized()) {
      // While refreshing a value, found that it has been Deleted with the
      // Delete RPC
      store_value_result.set_result(false);
      SignedRequest *sreq = store_value_result.mutable_signed_request();
      *sreq = del_req;
      DLOG(WARNING) << "Found during refresh that value has been deleted\n";
    } else {
      // Failed to store min. number of copies
      // TODO(Fraser#5#): 2009-05-15 - Need to handle failure properly, i.e.
      //                  delete those that did get stored, or try another full
      //                  store to equivalent number of nodes that failed, or
      //                  recursively try until we've either stored min.
      //                  allowed number of copies or tried every node in our
      //                  routing table.
      store_value_result.set_result(false);
      DLOG(ERROR) << "Successful Store rpc's " << callback_data.data->save_nodes
        << "\nSuccessful Store rpc's required " <<
        K_ * kMinSuccessfulPecentageStore << std::endl;
    }
    std::string store_value_result_str(store_value_result.SerializeAsString());
    callback_data.data->is_callbacked = true;
    callback_data.data->callback(store_value_result_str);
  } else {
    // Continues...
    // send RPC to this contact
    ++callback_data.data->index;
    if (callback_data.data->index >= callback_data.data->closest_nodes.size())
      return;  // all requested were sent out, wait for the result
    Contact next_node =
        callback_data.data->closest_nodes[callback_data.data->index];
    StoreResponse *resp = new StoreResponse;
    StoreCallbackArgs callback_args(callback_data.data);
    callback_args.remote_ctc = next_node;
    callback_args.rpc_ctrler = new rpcprotocol::Controller;

    ConnectionType conn_type = CheckContactLocalAddress(next_node.node_id(),
      next_node.local_ip(), next_node.local_port(), next_node.ip());
    IP contact_ip, rendezvous_ip;
    Port contact_port, rendezvous_port(0);
    if (conn_type == LOCAL) {
      callback_args.retry = true;
      contact_ip = next_node.local_ip();
      contact_port = next_node.local_port();
    } else {
      contact_ip = next_node.ip();
      contact_port = next_node.port();
      rendezvous_ip = next_node.rendezvous_ip();
      rendezvous_port = next_node.rendezvous_port();
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<
        NodeImpl, const StoreResponse*, StoreCallbackArgs > (
            this, &NodeImpl::StoreValue_IterativeStoreValue, resp,
            callback_args);

    if (callback_data.data->sig_value.IsInitialized()) {
      rpcs_->Store(callback_data.data->key, callback_data.data->sig_value,
          callback_data.data->sig_request,
          contact_ip, contact_port, rendezvous_ip, rendezvous_port,
          resp, callback_args.rpc_ctrler, done, callback_data.data->ttl,
          callback_data.data->publish);
    } else {
      rpcs_->Store(callback_data.data->key, callback_data.data->value,
          contact_ip, contact_port, rendezvous_ip, rendezvous_port, resp,
          callback_args.rpc_ctrler, done, callback_data.data->ttl,
          callback_data.data->publish);
    }
  }
}

void NodeImpl::StoreValue_ExecuteStoreRPCs(const std::string &result,
                                            const NodeId &key,
                                            const std::string &value,
                                            const SignedValue &sig_value,
                                            const SignedRequest &sig_req,
                                            const bool &publish,
                                            const boost::int32_t &ttl,
                                            VoidFunctorOneString callback) {
  if (!is_joined_)
    return;
  // validate the result
  bool is_valid = true;
  FindResponse result_msg;
  if (!result_msg.ParseFromString(result)) {
    is_valid = false;
  } else if (result_msg.closest_nodes_size() == 0) {
    is_valid = false;
  }
  if ((is_valid) || (result_msg.result())) {
    std::vector<Contact> closest_nodes;
    for (int i = 0; i < result_msg.closest_nodes_size(); ++i) {
      Contact node;
      node.ParseFromString(result_msg.closest_nodes(i));
      closest_nodes.push_back(node);
    }
    if (!closest_nodes.empty()) {
      bool stored_local = false;
      if (type_ != CLIENT) {
        // If this node itself is closer to the key than the last (furthest)
        // node in the returned list, store the value at this node as well.
        if (closest_nodes.size() < K_) {
          stored_local = true;
        } else {
          stored_local = NodeId::CloserToTarget(node_id_,
              closest_nodes.back().node_id(), key);
        }
        if (stored_local) {
          bool local_result;
          std::string local_value;
          if (sig_value.IsInitialized()) {
            local_value = sig_value.SerializeAsString();
          } else {
            local_value = value;
          }
          if (publish) {
            local_result = StoreValueLocal(key, local_value, ttl);
          } else {
            local_result = RefreshValueLocal(key, local_value, ttl);
          }
          if (local_result && closest_nodes.size() >= K_) {
            closest_nodes.pop_back();
            DLOG(INFO) << "StoreValue_ExecuteStoreRPCs storing locally - "
                          "port(" << port_ << ")" << std::endl;
          }
        }
      }
      boost::shared_ptr<IterativeStoreValueData>
          data(new struct IterativeStoreValueData(closest_nodes, key, value,
               callback, publish, ttl, sig_value, sig_req));
      if (stored_local)
        ++data->save_nodes;
      // decide the parallel level
      int parallel_size;
      if (data->closest_nodes.size() > alpha_)
        parallel_size = alpha_;
      else
        parallel_size = data->closest_nodes.size();
      for (int i = 0; i < parallel_size; ++i) {
        StoreCallbackArgs callback_args(data);
        StoreValue_IterativeStoreValue(NULL, callback_args);
      }
      return;
    }
    StoreResponse local_result;
    local_result.set_result(false);
    std::string local_result_str(local_result.SerializeAsString());
    callback(local_result_str);
  } else {
    CallbackWithFailure(callback);
  }
}

void NodeImpl::StoreValue(const NodeId &key, const SignedValue &signed_value,
                           const SignedRequest &signed_request,
                           const boost::int32_t &ttl,
                           VoidFunctorOneString callback) {
  if (!signed_value.IsInitialized() || !signed_request.IsInitialized()) {
    StoreResponse resp;
    resp.set_result(false);
    std::string ser_resp(resp.SerializeAsString());
    callback(ser_resp);
    return;
  }
  FindKClosestNodes(key, boost::bind(&NodeImpl::StoreValue_ExecuteStoreRPCs,
                                     this, _1, key, "", signed_value,
                                     signed_request, true, ttl, callback));
}

void NodeImpl::StoreValue(const NodeId &key, const std::string &value,
                           const boost::int32_t &ttl,
                           VoidFunctorOneString callback) {
  SignedValue svalue;
  SignedRequest sreq;
  FindKClosestNodes(key, boost::bind(&NodeImpl::StoreValue_ExecuteStoreRPCs,
                    this, _1, key, value, svalue, sreq, true, ttl, callback));
}

void NodeImpl::FindValue(const NodeId &key, const bool &check_alternative_store,
                          VoidFunctorOneString callback) {
  // Search in own alternative store first if check_alternative_store == true
  kademlia::FindResponse result_msg;
  if (check_alternative_store && alternative_store_ != NULL) {
    if (alternative_store_->Has(key.String())) {
      result_msg.set_result(true);
      *result_msg.mutable_alternative_value_holder() = contact_info();
      DLOG(INFO) << "In NodeImpl::FindValue - node " <<
        result_msg.alternative_value_holder().node_id().substr(0, 20) <<
        " got value in alt store.\n";
      std::string ser_find_result(result_msg.SerializeAsString());
      callback(ser_find_result);
      return;
    }
  }
  std::vector<std::string> values;
  //  Searching for value in local DataStore
  if (FindValueLocal(key, &values)) {
    result_msg.set_result(true);
    if (using_signatures()) {
      for (size_t n = 0; n < values.size(); ++n) {
        SignedValue *sig_value = result_msg.add_signed_values();
        sig_value->ParseFromString(values[n]);
      }
    } else {
      for (size_t n = 0; n < values.size(); ++n)
        result_msg.add_values(values[n]);
    }
    std::string ser_find_result(result_msg.SerializeAsString());
    callback(ser_find_result);
    return;
  }
  //  Value not found locally, looking for it in the network
  StartSearchIteration(key, FIND_VALUE, callback);
}

void NodeImpl::FindNode_GetNode(const std::string &result,
                                 const NodeId &node_id,
                                 VoidFunctorOneString callback) {
  // validate the result
  bool is_valid = true;
  FindResponse result_msg;
  FindNodeResult find_node_result;
  std::string find_node_result_str;
  if (!result_msg.ParseFromString(result))
    is_valid = false;
  else if ((!result_msg.has_result())||
        (result_msg.closest_nodes_size() == 0)) {
      is_valid = false;
  }
  if ((is_valid)||(result_msg.result())) {
    for (int i = 0; i < result_msg.closest_nodes_size(); ++i) {
      Contact node;
      node.ParseFromString(result_msg.closest_nodes(i));
      if (node.node_id() == node_id) {
        find_node_result.set_result(true);
        std::string node_str;
        node.SerialiseToString(&node_str);
        find_node_result.set_contact(node_str);
        find_node_result.SerializeToString(&find_node_result_str);
        callback(find_node_result_str);
        return;
      }
    }
  }
  // Failed to get any result
  find_node_result.set_result(false);
  find_node_result.SerializeToString(&find_node_result_str);
  callback(find_node_result_str);
}

void NodeImpl::GetNodeContactDetails(const NodeId &node_id,
                                      VoidFunctorOneString callback,
                                      const bool &local) {
  if (!local) {
    FindKClosestNodes(node_id, boost::bind(&NodeImpl::FindNode_GetNode, this,
                                           _1, node_id, callback));
  } else {
    FindNodeResult result;
    std::string ser_result;
    Contact contact;
    if (GetContact(node_id, &contact)) {
      result.set_result(true);
      std::string ser_contact;
      contact.SerialiseToString(&ser_contact);
      result.set_contact(ser_contact);
    } else {
      result.set_result(false);
    }
    result.SerializeToString(&ser_result);
    callback(ser_result);
  }
}

void NodeImpl::FindKClosestNodes(const NodeId &node_id,
                                  VoidFunctorOneString callback) {
  std::vector<Contact> start_up_short_list;
  StartSearchIteration(node_id, FIND_NODE, callback);
}

void NodeImpl::GetNodesFromRoutingTable(
    const NodeId &key, const std::vector<Contact> &exclude_contacts,
    std::vector<Contact> *close_nodes) {
  boost::mutex::scoped_lock gaurd(routingtable_mutex_);
  prouting_table_->FindCloseNodes(key, K_, exclude_contacts, close_nodes);
}

void NodeImpl::Ping_HandleResult(const PingResponse *response,
                                  PingCallbackArgs callback_data) {
  if (!is_joined_) {
    delete response;
    delete callback_data.rpc_ctrler;
    return;
  }

  if (response->IsInitialized() && response->has_node_id() &&
      response->node_id()
          != callback_data.remote_ctc.node_id().String()) {
    if (callback_data.retry) {
      delete response;
      PingResponse *resp = new PingResponse;
      UpdatePDRTContactToRemote(callback_data.remote_ctc.node_id(),
          callback_data.remote_ctc.ip());
      callback_data.retry = false;
      google::protobuf::Closure *done = google::protobuf::NewCallback<
          NodeImpl, const PingResponse*, PingCallbackArgs > (
              this, &NodeImpl::Ping_HandleResult, resp, callback_data);
      rpcs_->Ping(callback_data.remote_ctc.ip(),
          callback_data.remote_ctc.port(),
          callback_data.remote_ctc.rendezvous_ip(),
          callback_data.remote_ctc.rendezvous_port(),
          resp, callback_data.rpc_ctrler, done);
      return;
    }
  }

  PingResponse result_msg;
  if (!response->IsInitialized() || callback_data.rpc_ctrler->Failed()) {
    result_msg.set_result(false);
    RemoveContact(callback_data.remote_ctc.node_id());
  } else {
    result_msg = *response;
    if (response->result()) {
      AddContact(callback_data.remote_ctc, callback_data.rpc_ctrler->rtt(),
                 false);
    } else {
      RemoveContact(callback_data.remote_ctc.node_id());
    }
  }
  std::string result_msg_str(result_msg.SerializeAsString());
  callback_data.callback(result_msg_str);
  delete response;
  delete callback_data.rpc_ctrler;
}

void NodeImpl::Ping_SendPing(const std::string &result,
                              VoidFunctorOneString callback) {
  if (!is_joined_)
    return;
  FindNodeResult result_msg;
  if (result_msg.ParseFromString(result))
    if (result_msg.result()) {
      Contact remote;
      if (remote.ParseFromString(result_msg.contact())) {
        Ping(remote, callback);
        return;
      }
    }
  // Failed to get any result
  PingResponse ping_result;
  ping_result.set_result(false);
  std::string ping_result_str(ping_result.SerializeAsString());
  callback(ping_result_str);
}

void NodeImpl::Ping(const NodeId &node_id, VoidFunctorOneString callback) {
  GetNodeContactDetails(node_id, boost::bind(&NodeImpl::Ping_SendPing, this,
                                             _1, callback), false);
}

void NodeImpl::Ping(const Contact &remote, VoidFunctorOneString callback) {
  if (!is_joined_) {
    PingResponse resp;
    resp.set_result(false);
    std::string ser_resp(resp.SerializeAsString());
    callback(ser_resp);
    return;
  } else {
    PingResponse *resp = new PingResponse;
    PingCallbackArgs  callback_args(callback);
    callback_args.remote_ctc = remote;
    callback_args.rpc_ctrler = new rpcprotocol::Controller;
    ConnectionType conn_type = CheckContactLocalAddress(remote.node_id(),
                                                        remote.local_ip(),
                                                        remote.local_port(),
                                                        remote.ip());
    IP contact_ip, rendezvous_ip;
    Port contact_port, rendezvous_port(0);
    if (conn_type == LOCAL) {
      callback_args.retry = true;
      contact_ip = remote.local_ip();
      contact_port = remote.local_port();
    } else {
      contact_ip = remote.ip();
      contact_port = remote.port();
      rendezvous_ip = remote.rendezvous_ip();
      rendezvous_port = remote.rendezvous_port();
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<
        NodeImpl, const PingResponse*, PingCallbackArgs >
        (this, &NodeImpl::Ping_HandleResult, resp, callback_args);
    rpcs_->Ping(contact_ip, contact_port, rendezvous_ip, rendezvous_port,
                  resp, callback_args.rpc_ctrler, done);
  }
}

int NodeImpl::AddContact(Contact new_contact, const float &rtt,
                          const bool &only_db) {
  int result = -1;
  if (new_contact.node_id().String() != kClientId &&
      new_contact.node_id() != node_id_) {
    if (!only_db) {
      boost::mutex::scoped_lock gaurd(routingtable_mutex_);
      new_contact.set_last_seen(base::GetEpochMilliseconds());
      result = prouting_table_->AddContact(new_contact);
    } else {
      result = 0;
    }
    // Adding to routing table db
    IP remote_ip, rendezvous_ip;
    remote_ip = base::IpBytesToAscii(new_contact.ip());
    if (!new_contact.rendezvous_ip().empty()) {
      rendezvous_ip = base::IpBytesToAscii(new_contact.rendezvous_ip());
    }
    base::PublicRoutingTableTuple tuple(new_contact.node_id().String(),
                                        remote_ip,
                                        new_contact.port(),
                                        rendezvous_ip,
                                        new_contact.rendezvous_port(),
                                        new_contact.node_id().String(),
                                        rtt, 0, 0);
    prth_->AddTuple(tuple);
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

void NodeImpl::RemoveContact(const NodeId &node_id) {
  prth_->DeleteTupleByKadId(node_id.String());
  boost::mutex::scoped_lock gaurd(routingtable_mutex_);
  prouting_table_->RemoveContact(node_id, false);
}

bool NodeImpl::GetContact(const NodeId &id, Contact *contact) {
  boost::mutex::scoped_lock gaurd(routingtable_mutex_);
  return prouting_table_->GetContact(id, contact);
}

bool NodeImpl::FindValueLocal(const NodeId &key,
                               std::vector<std::string> *values) {
  return pdata_store_->LoadItem(key.String(), values);
}

bool NodeImpl::StoreValueLocal(const NodeId &key, const std::string &value,
                                const boost::int32_t &ttl) {
  bool hashable = false;
  std::string str_key(key.String());
  if (using_signatures()) {
    std::vector< std::pair<std::string, bool> > attr;
    attr = pdata_store_->LoadKeyAppendableAttr(str_key);
    if (attr.empty()) {
      crypto::Crypto cobj;
      cobj.set_hash_algorithm(crypto::SHA_512);
      if (key.String() == cobj.Hash(value, "", crypto::STRING_STRING,
                                             false))
        hashable = true;
    } else if (attr.size() == 1) {
      hashable = attr[0].second;
      if (hashable && value != attr[0].first)
        return false;
    }
  }
  return pdata_store_->StoreItem(str_key, value, ttl, hashable);
}

bool NodeImpl::RefreshValueLocal(const NodeId &key, const std::string &value,
                                  const boost::int32_t &ttl) {
  std::string ser_del_request;
  if (pdata_store_->RefreshItem(key.String(), value, &ser_del_request))
    return true;
  return StoreValueLocal(key, value, ttl);
}

void NodeImpl::GetRandomContacts(const size_t &count,
                                  const std::vector<Contact> &exclude_contacts,
                                  std::vector<Contact> *contacts) {
  contacts->clear();
  std::vector<Contact> all_contacts;
  {
    boost::mutex::scoped_lock gaurd(routingtable_mutex_);
    size_t kbuckets = prouting_table_->KbucketSize();
    for (size_t i = 0; i < kbuckets; ++i) {
      std::vector<Contact> contacts_i;
      prouting_table_->GetContacts(i, exclude_contacts, &contacts_i);
      for (size_t j = 0; j < contacts_i.size(); ++j)
        all_contacts.push_back(contacts_i[j]);
    }
  }
  std::random_shuffle(all_contacts.begin(), all_contacts.end());
  all_contacts.resize(std::min(all_contacts.size(), count));
  *contacts = all_contacts;
}

void NodeImpl::HandleDeadRendezvousServer(const bool &dead_server ) {
  if (stopping_)
    return;
  if (dead_server) {
    DLOG(WARNING) << "(" << local_port_ << ")--Failed to ping RV server\n";
    if (rv_ip_.empty() && rv_port_ == 0) {
      // node has no rendezvous server, it does not need to rejoin, just finding
      // out if it is offline by trying to connect with one of its contacts
      std::vector<Contact> ctcs, ex_ctcs;
      for (size_t i = 0; i < prouting_table_->KbucketSize(); ++i) {
        std::vector<Contact> tmp_ctcs;
        prouting_table_->GetContacts(i, ex_ctcs, &tmp_ctcs);
        for (unsigned int j = 0; j < tmp_ctcs.size(); ++j)
          if (tmp_ctcs[j].rendezvous_ip().empty() &&
              tmp_ctcs[j].rendezvous_port() == 0)
            ctcs.push_back(tmp_ctcs[j]);
      }
      for (unsigned int i = 0; i < ctcs.size(); ++i) {
        // checking connection
/******************************************************************************/
//     if (udt_transport_->CanConnect(ctcs[i].ip(), ctcs[i].port())) {
//       udt_transport_->StartPingRendezvous(false, ctcs[i].ip(),
//                                           ctcs[i].port());
//          return;
//     }
/******************************************************************************/
      }
    }
    // setting status to be offline
    base::OnlineController::Instance()->SetOnline(local_port_, false);
    Leave();
    stopping_ = false;
    Join(node_id_, kad_config_path_.string(),
         boost::bind(&NodeImpl::ReBootstrapping_Callback, this, _1));
  }
}

void NodeImpl::ReBootstrapping_Callback(const std::string &result) {
  base::GeneralResponse local_result;
  if (stopping_) {
    return;
  }
  if (!local_result.ParseFromString(result) || !local_result.result()) {
    // TODO(David): who should we inform if after trying to bootstrap again
    // because the rendezvous server died, the bootstrap operation fails?
    DLOG(WARNING) << "(" << local_port_ << ") -- Failed to rejoin ..."
        << " Retrying.\n";
    is_joined_ = false;
    stopping_ = false;
    Join(node_id_, kad_config_path_.string(),
         boost::bind(&NodeImpl::ReBootstrapping_Callback, this, _1));
  } else {
    DLOG(INFO) << "(" << local_port_ << ") Rejoining successful.\n";
    is_joined_ = true;
    premote_service_->set_node_joined(true);
    premote_service_->set_node_info(contact_info());
  }
}

void NodeImpl::RegisterService() {
  premote_service_.reset(new Service(
      pdata_store_,
      using_signatures(),
      boost::bind(&NodeImpl::AddContact, this, _1, _2, _3),
      boost::bind(&NodeImpl::GetRandomContacts, this, _1, _2, _3),
      boost::bind(&NodeImpl::GetContact, this, _1, _2),
      boost::bind(&NodeImpl::GetNodesFromRoutingTable, this, _1, _2, _3),
      boost::bind(static_cast<void(NodeImpl::*)(const Contact&,
                  VoidFunctorOneString)>(&NodeImpl::Ping), this, _1, _2),
      boost::bind(&NodeImpl::RemoveContact, this, _1)));
  premote_service_->set_node_info(contact_info());
  premote_service_->set_alternative_store(alternative_store_);
  premote_service_->set_signature_validator(signature_validator_);
  pservice_channel_.reset(new rpcprotocol::Channel(pchannel_manager_));
  pservice_channel_->SetService(premote_service_.get());
  pchannel_manager_->RegisterChannel(
      premote_service_->GetDescriptor()->name(), pservice_channel_.get());
}

void NodeImpl::UnRegisterService() {
  pchannel_manager_->UnRegisterChannel(
      premote_service_->GetDescriptor()->name());
  pchannel_manager_->ClearCallLaters();
  pservice_channel_.reset();
  premote_service_.reset();
}

ConnectionType NodeImpl::CheckContactLocalAddress(const NodeId &id,
                                                   const IP &ip,
                                                   const Port &port,
                                                   const IP &ext_ip) {
  if (ip.empty() || port == 0)
    return REMOTE;
  std::string str_id(id.String());
  int result = prth_->ContactLocal(str_id);
  ConnectionType conn_type(UNKNOWN);
  IP ext_ip_dec;
  switch (result) {
    case LOCAL: conn_type = LOCAL;
                break;
    case REMOTE: conn_type = REMOTE;
                 break;
    case UNKNOWN: ext_ip_dec = base::IpBytesToAscii(ext_ip);
                  if (ip_ != ext_ip_dec) {
                    conn_type = REMOTE;
//                  } else if (udt_transport_->CanConnect(ip, port)) {
//                    conn_type = LOCAL;
//                    prth_->UpdateContactLocal(str_id, ip, conn_type);
                  } else {
                    conn_type = REMOTE;
                    prth_->UpdateContactLocal(str_id, ext_ip, conn_type);
                  }
                  break;
  }
  return conn_type;
}


void NodeImpl::UpdatePDRTContactToRemote(const NodeId &node_id,
                                          const IP &ip) {
  prth_->UpdateContactLocal(node_id.String(), ip, REMOTE);
}

ContactInfo NodeImpl::contact_info() const {
  ContactInfo info;

  info.set_ip(ip_);
  info.set_local_ips(local_ip_);
  info.set_rendezvous_ip(rv_ip_);
 
  if (type_ == CLIENT || type_ == CLIENT_PORT_MAPPED) {
    info.set_node_id(fake_kClientId_.String());
  } else {
    info.set_node_id(node_id_.String());
  }
  info.set_port(port_);
  info.set_local_port(local_port_);
  info.set_rendezvous_port(rv_port_);
  return info;
}

void NodeImpl::CheckToInsert(const Contact &new_contact) {
  if (!is_joined_)
    return;
  int index = prouting_table_->KBucketIndex(new_contact.node_id());
  Contact last_seen;
  last_seen = prouting_table_->GetLastSeenContact(index);
//  DLOG(INFO) << "Pinging last seen node in routing table to try to insert "
//             << "contact\n" << new_contact.DebugString();
  Ping(last_seen,
       boost::bind(&NodeImpl::CheckToInsert_Callback, this, _1,
                   new_contact.node_id(), new_contact));
}

void NodeImpl::CheckToInsert_Callback(const std::string &result, NodeId id,
                                       Contact new_contact) {
  if (!is_joined_)
    return;
  PingResponse result_msg;
  if (!result_msg.ParseFromString(result) ||
      !result_msg.result()) {
    boost::mutex::scoped_lock gaurd(routingtable_mutex_);
    prouting_table_->RemoveContact(id, true);
    prouting_table_->AddContact(new_contact);
  }
}

void NodeImpl::CheckAddContacts() {
  while (true) {
    {
      boost::mutex::scoped_lock guard(pendingcts_mutex_);
      while (contacts_to_add_.empty() && is_joined_)
        add_ctc_cond_.wait(guard);
    }
    if (!is_joined_ )
      return;
    Contact new_contact;
    bool add_contact = false;
    {
      boost::mutex::scoped_lock guard(pendingcts_mutex_);
      if (!contacts_to_add_.empty()) {
        new_contact = contacts_to_add_.front();
        contacts_to_add_.pop_front();
        add_contact = true;
      }
    }
    if (add_contact)
      CheckToInsert(new_contact);
  }
}

void NodeImpl::StartSearchIteration(const NodeId &key,
                                     const RemoteFindMethod &method,
                                     VoidFunctorOneString callback) {
//  printf("NodeImpl::StartSearchIteration\n");
  // Getting the first alpha contacts
  std::vector<Contact> close_nodes, exclude_contacts;
  {
    boost::mutex::scoped_lock gaurd(routingtable_mutex_);
    prouting_table_->FindCloseNodes(key, alpha_, exclude_contacts,
                                    &close_nodes);
  }
  if (close_nodes.empty()) {
    CallbackWithFailure(callback);
    return;
  }
  boost::shared_ptr<IterativeLookUpData> data(
      new IterativeLookUpData(method, key, callback));
  for (size_t i = 0; i < close_nodes.size(); ++i) {
    struct LookupContact ctc;
    ctc.kad_contact = close_nodes[i];
    data->short_list.push_back(ctc);
  }
  SearchIteration(data);
}

void NodeImpl::SendFindRpc(Contact remote,
                            boost::shared_ptr<IterativeLookUpData> data,
                            const ConnectionType &conn_type) {
//  printf("NodeImpl::SendFindRpc\n");
  if (!is_joined_ && data->method != BOOTSTRAP)
    return;
  FindResponse *resp = new FindResponse;
  FindCallbackArgs callback_args(data);
  callback_args.remote_ctc = remote;
  callback_args.rpc_ctrler = new rpcprotocol::Controller;
  IP contact_ip, rendezvous_ip;
  Port contact_port, rendezvous_port(0);
  if (conn_type == LOCAL) {
    callback_args.retry = true;
    contact_ip = remote.local_ip();
    contact_port = remote.local_port();
  } else {
    contact_ip = remote.ip();
    contact_port = remote.port();
    rendezvous_ip = remote.rendezvous_ip();
    rendezvous_port = remote.rendezvous_port();
  }
  google::protobuf::Closure *done =
      google::protobuf::NewCallback<NodeImpl, const FindResponse*,
                                    FindCallbackArgs>
      (this, &NodeImpl::SearchIteration_ExtendShortList, resp, callback_args);
  if (data->method == FIND_NODE || data->method == BOOTSTRAP) {
    if (data->method == BOOTSTRAP) {
      kademlia::Contact tmp_contact(node_id(), ip_, port_, local_ip_,
                               local_port_, rv_ip_, rv_port_);
      std::string contact_str;
      tmp_contact.SerialiseToString(&contact_str);
      resp->set_requester_ext_addr(contact_str);
    }
    if (data->key == remote.node_id())
      data->wait_for_key = true;
    rpcs_->FindNode(data->key, contact_ip, contact_port, rendezvous_ip,
                      rendezvous_port, resp, callback_args.rpc_ctrler, done);
  } else if (data->method == FIND_VALUE) {
    rpcs_->FindValue(data->key, contact_ip, contact_port, rendezvous_ip,
                       rendezvous_port, resp, callback_args.rpc_ctrler, done);
  } else {
    delete done;
    delete resp;
    delete callback_args.rpc_ctrler;
  }
}

void NodeImpl::SearchIteration(boost::shared_ptr<IterativeLookUpData> data) {
//  printf("NodeImpl::SearchIteration\n");
  if (data->is_callbacked || (!is_joined_ && data->method != BOOTSTRAP))
    return;
  // Found an alternative value holder or the actual value
  if (data->method == FIND_VALUE && (!data->values_found.empty() ||
      !data->sig_values_found.empty() ||
      !data->alternative_value_holder.node_id().empty()))
    SearchIteration_Callback(data);

  // sort the active contacts
  SortContactList(data->key, &data->active_contacts);
  // sort the short_list
  SortLookupContact(data->key, &data->short_list);
  // Wait for beta to start the iteration
  activeprobes_mutex_.lock();
  unsigned int remaining_of_iter = data->current_alpha.size();
  activeprobes_mutex_.unlock();
  if (remaining_of_iter > beta_ || data->wait_for_key) {
    return;
  }

  // check if there are closer nodes than the ones already seen
  bool closer_nodes = false;
  if (data->active_contacts.empty()) {
    closer_nodes = true;
  } else {
    std::list<LookupContact>::iterator it;
    ContactAndTargetKey last_active;
    last_active.contact = data->active_contacts.back();
    last_active.target_key = data->key;
    for (it = data->short_list.begin(); it != data->short_list.end(); ++it) {
      if (!it->contacted) {
        ContactAndTargetKey notcontated;
        notcontated.contact = it->kad_contact;
        notcontated.target_key = data->key;
        if (CompareContact(notcontated, last_active)) {
          closer_nodes = true;
          break;
        }
      }
    }
  }
  if (!closer_nodes) {
    // waiting for all the rpc's sent in the iteration
    if (remaining_of_iter > 0)
      return;
    SendFinalIteration(data);
  } else {
    // send Rpc Find to alpha contacts
    activeprobes_mutex_.lock();
    data->current_alpha.clear();
    activeprobes_mutex_.unlock();
    int contacted_now = 0;
    std::list<LookupContact>::iterator it;
    std::vector<Contact> pending_to_contact;
    for (it = data->short_list.begin(); it != data->short_list.end() &&
         contacted_now < alpha_; ++it) {
      if (!it->contacted) {
        Contact remote;
        remote = it->kad_contact;
        activeprobes_mutex_.lock();
        data->current_alpha.push_back(remote);
        data->active_probes.push_back(remote);
        activeprobes_mutex_.unlock();
        it->contacted = true;
        pending_to_contact.push_back(remote);
        ++contacted_now;
      }
    }
    if (contacted_now == 0) {
      if (!data->active_probes.empty()) {
        // wait for the active probes
        return;
      } else if (data->active_contacts.empty()) {
        // try with another alpha contacts just
        std::vector<Contact> close_nodes, exclude_contacts;
        {
          boost::mutex::scoped_lock gaurd(routingtable_mutex_);
          prouting_table_->FindCloseNodes(data->key, alpha_, exclude_contacts,
                                          &close_nodes);
        }
        if (close_nodes.empty()) {
          SearchIteration_Callback(data);
          return;
        }
        for (unsigned int i = 0; i < close_nodes.size(); ++i) {
          struct LookupContact ctc;
          ctc.kad_contact = close_nodes[i];
          data->short_list.push_back(ctc);
        }
        SearchIteration(data);
      } else {
        SearchIteration_Callback(data);
      }
    } else {
      for (unsigned int i = 0; i < pending_to_contact.size(); ++i) {
        ConnectionType conn_type = CheckContactLocalAddress(
            pending_to_contact[i].node_id(), pending_to_contact[i].local_ip(),
            pending_to_contact[i].local_port(),
            pending_to_contact[i].ip());
        SendFindRpc(pending_to_contact[i], data, conn_type);
      }
    }
  }
}

void NodeImpl::SearchIteration_ExtendShortList(
    const FindResponse *response,
    FindCallbackArgs callback_data) {
//  printf("NodeImpl::SearchIteration_ExtendShortList\n");
  if (!is_joined_ && callback_data.data->method != BOOTSTRAP) {
    delete response;
    delete callback_data.rpc_ctrler;
    return;
  }
  bool is_valid = true;
  if ((!response->IsInitialized() || callback_data.rpc_ctrler->Failed()) &&
      callback_data.data->method != BOOTSTRAP) {
    RemoveContact(callback_data.remote_ctc.node_id());
    is_valid = false;
    callback_data.data->dead_ids.push_back(
        callback_data.remote_ctc.node_id().String());
  }

  if (is_valid) {
    // Check id and retry if it was sent
    if (response->has_node_id() &&
        response->node_id() !=
            callback_data.remote_ctc.node_id().String()) {
      if (callback_data.retry) {
        delete response;
        delete callback_data.rpc_ctrler;
        callback_data.rpc_ctrler = NULL;
        UpdatePDRTContactToRemote(callback_data.remote_ctc.node_id(),
                                  callback_data.remote_ctc.ip());
        SendFindRpc(callback_data.remote_ctc, callback_data.data, REMOTE);
        return;
      }
    }
  }

  if (!is_valid || !response->result()) {
    SearchIteration_CancelActiveProbe(callback_data.remote_ctc,
        callback_data.data);
    delete response;
    delete callback_data.rpc_ctrler;
    callback_data.rpc_ctrler = NULL;
    if (callback_data.data->is_callbacked) {
      if (callback_data.data->active_probes.empty() &&
          callback_data.data->method != BOOTSTRAP) {
        SendDownlist(callback_data.data);
      }
      return;
    }
  } else {
    if (!is_joined_ && callback_data.data->method != BOOTSTRAP) {
      delete response;
      delete callback_data.rpc_ctrler;
      callback_data.rpc_ctrler = NULL;
      return;
    }
    AddContact(callback_data.remote_ctc, callback_data.rpc_ctrler->rtt(),
               false);
    if (callback_data.data->is_callbacked) {
      SearchIteration_CancelActiveProbe(callback_data.remote_ctc,
                                        callback_data.data);
      delete response;
      delete callback_data.rpc_ctrler;
      callback_data.rpc_ctrler = NULL;
      if (callback_data.data->active_probes.empty() &&
          callback_data.data->method != BOOTSTRAP) {
        SendDownlist(callback_data.data);
      }
      return;
    }

    // Mark this node as active
    callback_data.data->active_contacts.push_back(callback_data.remote_ctc);

    // extend the value list if there are any new values found
    std::list<std::string>::iterator it1;
    bool is_new;
    for (int i = 0; i < response->values_size(); ++i) {
      is_new = true;
      for (it1 = callback_data.data->values_found.begin();
           it1 != callback_data.data->values_found.end(); ++it1) {
        if (*it1 == response->values(i)) {
          is_new = false;
          break;
        }
      }
      if (is_new) {
        callback_data.data->values_found.push_back(response->values(i));
      }
    }
    std::list<kademlia::SignedValue>::iterator it_svals;
    for (int i = 0; i < response->signed_values_size(); ++i) {
      is_new = true;
      for (it_svals = callback_data.data->sig_values_found.begin();
           it_svals != callback_data.data->sig_values_found.end(); ++it_svals) {
        if (it_svals->value() == response->signed_values(i).value() &&
            it_svals->value_signature() ==
              response->signed_values(i).value_signature()) {
          is_new = false;
          break;
        }
      }
      if (is_new) {
        callback_data.data->sig_values_found.push_back(
          response->signed_values(i));
      }
    }

    // Now extend short list with the returned contacts
    std::list<LookupContact>::iterator it2;
    for (int i = 0; i < response->closest_nodes_size(); ++i) {
      Contact test_contact;
      if (!test_contact.ParseFromString(response->closest_nodes(i)))
        continue;
      // AddContact(test_contact, false);
      is_new = true;
      for (it2 = callback_data.data->short_list.begin();
           it2 != callback_data.data->short_list.end(); ++it2) {
        if (test_contact.Equals(it2->kad_contact)) {
          is_new = false;
          break;
        }
      }
      if (is_new) {
        // add to the front
        Contact self_node(node_id_, ip_, port_, local_ip_,
                          local_port_);
        if (!test_contact.Equals(self_node)) {
          LookupContact ctc;
          ctc.kad_contact = test_contact;
          callback_data.data->short_list.push_front(ctc);
        }
      }
      // Implementation of downlist algorithm
      // Add to the downlist as a candidate with the is_down flag set to false
      // by default
      struct DownListCandidate candidate;
      candidate.node = test_contact;
      candidate.is_down = false;
      bool is_appended = false;
      std::list<struct DownListData>::iterator it5;
      for (it5 = callback_data.data->downlist.begin();
           it5 != callback_data.data->downlist.end(); ++it5) {
        if (it5->giver.Equals(callback_data.remote_ctc)) {
          it5->candidate_list.push_back(candidate);
          is_appended = true;
          break;
        }
      }
      if (!is_appended) {
        struct DownListData downlist_data;
        downlist_data.giver = callback_data.remote_ctc;
        downlist_data.candidate_list.push_back(candidate);
        callback_data.data->downlist.push_back(downlist_data);
      }
      // End of implementation downlist algorithm
    }
    SearchIteration_CancelActiveProbe(callback_data.remote_ctc,
                                      callback_data.data);
    delete callback_data.rpc_ctrler;
    callback_data.rpc_ctrler = NULL;
    delete response;
  }
  if (callback_data.data->in_final_iteration) {
    FinalIteration(callback_data.data);
  } else {
    SearchIteration(callback_data.data);
  }
}

void NodeImpl::SendFinalIteration(
    boost::shared_ptr<IterativeLookUpData> data) {
//  printf("NodeImpl::SendFinalIteration\n");
  if (data->active_contacts.size() >= K_) {
    if (!data->active_contacts.empty()) {
      // checking if the active probes are closer than the Kth closest node
      std::list<Contact>::iterator it1;
      std::list<Contact>::iterator it2 = data->active_contacts.begin();
      for (int i = 1; i < K_; ++i)
        ++it2;
      ContactAndTargetKey kth_contact;
      kth_contact.contact = *it2;
      kth_contact.target_key = data->key;
      activeprobes_mutex_.lock();
      for (it1 = data->active_probes.begin(); it1 != data->active_probes.end();
          ++it1) {
        ContactAndTargetKey active_ctc;
        active_ctc.contact = *it1;
        active_ctc.target_key = data->key;
        if (CompareContact(active_ctc, kth_contact)) {
          activeprobes_mutex_.unlock();
          return;
        }
      }
      activeprobes_mutex_.unlock();
    }
    SearchIteration_Callback(data);
    return;
  }
  if (data->in_final_iteration)
    return;
  int rpc_to_send = K_ - data->active_contacts.size();
  int contacted = 0;
  std::vector<Contact> pending_to_contact;
  data->in_final_iteration = true;
  std::list<LookupContact>::iterator it;
  for (it = data->short_list.begin(); it != data->short_list.end() &&
       contacted < rpc_to_send; ++it) {
    if (!it->contacted) {
      Contact remote;
      remote = it->kad_contact;
      data->active_probes.push_back(remote);
      it->contacted = true;
      ++contacted;
      pending_to_contact.push_back(remote);
    }
  }
  if (contacted == 0) {
    SearchIteration_Callback(data);
  } else {
    for (unsigned int i = 0; i < pending_to_contact.size(); ++i) {
      ConnectionType conn_type = CheckContactLocalAddress(
          pending_to_contact[i].node_id(), pending_to_contact[i].local_ip(),
          pending_to_contact[i].local_port(), pending_to_contact[i].ip());
      SendFindRpc(pending_to_contact[i], data, conn_type);
    }
  }
}

void NodeImpl::FinalIteration(boost::shared_ptr<IterativeLookUpData> data) {
//  printf("NodeImpl::FinalIteration\n");
  if ((data->is_callbacked)||(!is_joined_ && data->method != BOOTSTRAP))
    return;

  activeprobes_mutex_.lock();
  if (!data->active_probes.empty()) {
    activeprobes_mutex_.unlock();
    return;
  }
  activeprobes_mutex_.unlock();

  // sort the active contacts
  SortContactList(data->key, &data->active_contacts);
  // check whether thare are any closer nodes
  SortLookupContact(data->key, &data->short_list);

  // check if there are closer nodes than the ones already seen and send the rpc
  int contacted = 0;
  std::list<LookupContact>::iterator it;
  ContactAndTargetKey last_active;
  last_active.contact = data->active_contacts.back();
  last_active.target_key = data->key;
  for (it = data->short_list.begin(); it != data->short_list.end(); ++it) {
    if (!it->contacted) {
      ContactAndTargetKey notcontated;
      notcontated.contact = it->kad_contact;
      notcontated.target_key = data->key;
      if (CompareContact(notcontated, last_active)) {
        Contact remote;
        remote = it->kad_contact;
        data->active_probes.push_back(remote);
        ConnectionType conn_type = CheckContactLocalAddress(remote.node_id(),
                                                            remote.local_ip(),
                                                            remote.local_port(),
                                                            remote.ip());
        SendFindRpc(remote, data, conn_type);
        it->contacted = true;
        ++contacted;
      }
    }
  }
  if (contacted == 0) {
    SearchIteration_Callback(data);
  }
}

void NodeImpl::SearchIteration_CancelActiveProbe(
    Contact sender,
    boost::shared_ptr<IterativeLookUpData> data) {
  if (!is_joined_ && data->method != BOOTSTRAP)
    return;
  std::list<Contact>::iterator it;

  activeprobes_mutex_.lock();
  for (it = data->active_probes.begin(); it != data->active_probes.end();
       ++it) {
    if (sender.Equals(*it) && !data->active_probes.empty()) {
      data->active_probes.erase(it);
      break;
    }
  }
  std::list<Contact>::iterator it1;
  for (it1 = data->current_alpha.begin(); it1 != data->current_alpha.end();
       ++it1) {
    if (sender.node_id() == data->key)
      data->wait_for_key = false;
    if (sender.Equals(*it1) && !data->current_alpha.empty()) {
      data->current_alpha.erase(it1);
      break;
    }
  }
  activeprobes_mutex_.unlock();
}

void NodeImpl::SearchIteration_Callback(
    boost::shared_ptr<IterativeLookUpData> data) {
//  printf("NodeImpl::SearchIteration_Callback\n");
  std::string ser_result;
  // If we're bootstrapping, we are only now finished.  In this case the
  // callback should be of type base::GeneralResponse
  if (data->is_callbacked)
    return;
  data->is_callbacked = true;
  if (data->method == BOOTSTRAP) {
    base::GeneralResponse result;
    if (data->active_contacts.empty()) {
      // no active contacts
      result.set_result(false);
      is_joined_ = false;
    } else {
      result.set_result(true);
      if (!is_joined_) {
        is_joined_ = true;
        premote_service_->set_node_joined(true);
        premote_service_->set_node_info(contact_info());
        addcontacts_routine_.reset(
            new boost::thread(&NodeImpl::CheckAddContacts, this));
        // start a schedule to delete expired key/value pairs only once
        if (!refresh_routine_started_) {
          ptimer_->AddCallLater(kRefreshTime * 1000,
                                boost::bind(&NodeImpl::RefreshRoutine, this));
          ptimer_->AddCallLater(2000,
                                boost::bind(&NodeImpl::RefreshValuesRoutine,
                                            this));
          refresh_routine_started_ = true;
//          printf("SearchIteration_Callback - %d\n", kRefreshTime * 1000);
        }
      }
    }
    result.SerializeToString(&ser_result);
  } else {
    if (!is_joined_)
      return;
    // take K closest contacts from active contacts as the closest nodes
    std::list<Contact>::iterator it1;
    int count;
    FindResponse result;
    if (data->method == FIND_VALUE &&
        !data->alternative_value_holder.node_id().empty()) {
      result.set_result(true);
      *result.mutable_alternative_value_holder() =
          data->alternative_value_holder;
    } else if (data->method == FIND_VALUE && (!data->values_found.empty() ||
               !data->sig_values_found.empty())) {
      result.set_result(true);
      for (std::list<std::string>::iterator it2 = data->values_found.begin();
           it2 != data->values_found.end(); ++it2) {
        result.add_values(*it2);
      }
      for (std::list<SignedValue>::iterator it2 =
           data->sig_values_found.begin(); it2 != data->sig_values_found.end();
           ++it2) {
        SignedValue *svalue = result.add_signed_values();
        *svalue = *it2;
      }
    } else {
      for (it1 = data->active_contacts.begin(), count = 0;
           it1 != data->active_contacts.end() && count < K_; ++it1, ++count) {
        std::string ser_contact;
        // Adding contact info of nodes contacted in the iterative search
        // the nodes are ordered from closest to furthest away from the key/node
        // id searched
        if (it1->SerialiseToString(&ser_contact))
          result.add_closest_nodes(ser_contact);
      }
      if (result.closest_nodes_size() > 0 && data->method == FIND_NODE)
        result.set_result(true);
      else
        result.set_result(false);
    }

    // Add the last seen contact that didn't reply with the value from the
    // alternative store to to the alternative_value_holder field.
    if (data->method == FIND_VALUE) {
      boost::mutex::scoped_lock lock(activeprobes_mutex_);
      std::list<Contact>::iterator itr = data->current_alpha.begin();
      while (itr != data->current_alpha.end()) {
        if (itr->node_id().String()
            != data->alternative_value_holder.node_id()) {
          std::string ser_contact;
          if (itr->SerialiseToString(&ser_contact))
            result.set_needs_cache_copy(ser_contact);
          break;
        }
        ++itr;
      }
    }

    result.SerializeToString(&ser_result);
  }
  data->callback(ser_result);
  activeprobes_mutex_.lock();
  if (!data->active_probes.empty()) {
    activeprobes_mutex_.unlock();
    return;
  }
  activeprobes_mutex_.unlock();
  SendDownlist(data);
}

void NodeImpl::SendDownlist(boost::shared_ptr<IterativeLookUpData> data) {
  // Implementation of downlist algorithm
  // At the end of the search the corresponding entries of the downlist are sent
  // to all peers which gave those entries to this node during its search
  if (data->downlist_sent || !is_joined_) return;
  if (data->dead_ids.empty()) {
    data->downlist_sent = true;
    return;
  }
  std::list<struct DownListData>::iterator it1;

  for (it1 = data->downlist.begin(); it1 != data->downlist.end(); ++it1) {
    std::vector<std::string> downlist;
    std::list<struct DownListCandidate>::iterator it2;
    for (it2 = it1->candidate_list.begin(); it2 != it1->candidate_list.end();
         ++it2) {
      std::list<std::string>::iterator it3;
      for (it3 = data->dead_ids.begin(); it3 != data->dead_ids.end(); ++it3) {
        if (*it3 == it2->node.node_id().String()) {
          it2->is_down = true;
        }
      }
      if (it2->is_down) {
        std::string dead_node;
        if (it2->node.SerialiseToString(&dead_node))
          downlist.push_back(dead_node);
      }
    }
    if (!downlist.empty()) {
      // TODO(Haiyang): restrict the parallel level to Alpha
      ConnectionType conn_type = CheckContactLocalAddress(it1->giver.node_id(),
          it1->giver.local_ip(), it1->giver.local_port(), it1->giver.ip());
      IP contact_ip, rendezvous_ip;
      Port contact_port, rendezvous_port(0);
      if (conn_type == LOCAL) {
        contact_ip = it1->giver.local_ip();
        contact_port = it1->giver.local_port();
      } else {
        contact_ip = it1->giver.ip();
        contact_port = it1->giver.port();
        rendezvous_ip = it1->giver.rendezvous_ip();
        rendezvous_port = it1->giver.rendezvous_port();
      }
      DownlistResponse *resp = new DownlistResponse;
      rpcprotocol::Controller *ctrl = new rpcprotocol::Controller;
      google::protobuf::Closure *done = google::protobuf::NewCallback
          <DownlistResponse*, rpcprotocol::Controller*>
          (&dummy_downlist_callback, resp, ctrl);
      rpcs_->Downlist(downlist, contact_ip, contact_port, rendezvous_ip,
                        rendezvous_port, resp, ctrl, done);
    }
  }
  data->downlist_sent = true;
  // End of downlist
}

boost::uint32_t NodeImpl::KeyLastRefreshTime(const NodeId &key,
                                              const std::string &value) {
  return pdata_store_->LastRefreshTime(key.String(), value);
}

boost::uint32_t NodeImpl::KeyExpireTime(const NodeId &key,
                                         const std::string &value) {
  return pdata_store_->ExpireTime(key.String(), value);
}

bool NodeImpl::using_signatures() {
  if (private_key_.empty() || public_key_.empty())
    return false;
  return true;
}

boost::int32_t NodeImpl::KeyValueTTL(const NodeId &key,
                                      const std::string &value) const {
  return pdata_store_->TimeToLive(key.String(), value);
}

void NodeImpl::RefreshValue(const NodeId &key, const std::string &value,
                             const boost::int32_t &ttl,
                             VoidFunctorOneString callback) {
  if (!is_joined_ || !refresh_routine_started_  || stopping_)
    return;
  SignedRequest sreq;
  SignedValue svalue;
  if (using_signatures()) {
    crypto::Crypto cobj;
    cobj.set_hash_algorithm(crypto::SHA_512);
    if (!svalue.ParseFromString(value))
      return;
    sreq.set_signer_id(node_id_.String());
    sreq.set_public_key(public_key_);
    sreq.set_signed_public_key(cobj.AsymSign(public_key_, "", private_key_,
                               crypto::STRING_STRING));
    sreq.set_signed_request(cobj.AsymSign(
        cobj.Hash(public_key_ + sreq.signed_public_key() + key.String(), "",
                  crypto::STRING_STRING, true),
        "", private_key_, crypto::STRING_STRING));
    FindKClosestNodes(key, boost::bind(&NodeImpl::StoreValue_ExecuteStoreRPCs,
                                       this, _1, key, "", svalue, sreq, false,
                                       ttl, callback));
  } else {
    FindKClosestNodes(key, boost::bind(&NodeImpl::StoreValue_ExecuteStoreRPCs,
                                       this, _1, key, value, svalue, sreq,
                                       false, ttl, callback));
  }
}

void NodeImpl::RefreshValueCallback(
    const std::string &result, const NodeId &key, const std::string &value,
    const boost::int32_t &ttl, const boost::uint32_t &total_refreshes,
    boost::shared_ptr<boost::uint32_t> refreshes_done) {
  if (!is_joined_ || !refresh_routine_started_  || stopping_)
    return;
  StoreResponse refresh_result;
  if (!refresh_result.ParseFromString(result) ||
      refresh_result.result() ||
      !refresh_result.has_signed_request())
    RefreshValueLocal(key, value, ttl);
  ++(*refreshes_done);
  if (total_refreshes == *refreshes_done) {
    ptimer_->AddCallLater(2000, boost::bind(&NodeImpl::RefreshValuesRoutine,
                                            this));
  }
}

void NodeImpl::RefreshValuesRoutine() {
//  printf("NodeImpl::RefreshValuesRoutine\n");
  if (is_joined_ && refresh_routine_started_  && !stopping_) {
    std::vector<refresh_value> values = pdata_store_->ValuesToRefresh();
    if (values.empty()) {
      ptimer_->AddCallLater(2000, boost::bind(&NodeImpl::RefreshValuesRoutine,
                                              this));
    } else  {
      boost::shared_ptr<boost::uint32_t> refreshes_done(new boost::uint32_t(0));
      // *refreshes_done = 0;
      for (size_t i = 0; i < values.size(); ++i) {
        NodeId id_key;
        switch (values[i].del_status_) {
          case NOT_DELETED: id_key = NodeId(values[i].key_);
                            RefreshValue(
                                id_key, values[i].value_, values[i].ttl_,
                                boost::bind(&NodeImpl::RefreshValueCallback,
                                            this, _1, id_key, values[i].value_,
                                            values[i].ttl_, values.size(),
                                            refreshes_done));
                            break;
         case MARKED_FOR_DELETION: pdata_store_->MarkAsDeleted(
                                       values[i].key_, values[i].value_);
                                   break;
         case DELETED: pdata_store_->DeleteItem(values[i].key_,
                                                values[i].value_);
                       break;
        }
      }
    }
  }
}

void NodeImpl::DeleteValue(const NodeId &key, const SignedValue &signed_value,
                            const SignedRequest &signed_request,
                            VoidFunctorOneString callback) {
  if (!signed_value.IsInitialized() || !signed_request.IsInitialized()) {
    DeleteResponse resp;
    resp.set_result(false);
    std::string ser_resp(resp.SerializeAsString());
    callback(ser_resp);
    return;
  }
  FindKClosestNodes(key, boost::bind(&NodeImpl::DelValue_ExecuteDeleteRPCs,
                                     this, _1, key, signed_value,
                                     signed_request, callback));
}

void NodeImpl::DelValue_ExecuteDeleteRPCs(const std::string &result,
                                           const NodeId &key,
                                           const SignedValue &value,
                                           const SignedRequest &sig_req,
                                           VoidFunctorOneString callback) {
  if (!is_joined_)
    return;
  // validate the result
  bool is_valid = true;
  FindResponse result_msg;
  if (!result_msg.ParseFromString(result)) {
    is_valid = false;
  } else if (result_msg.closest_nodes_size() == 0) {
    is_valid = false;
  }
  if ((is_valid) || (result_msg.result())) {
    std::vector<Contact> closest_nodes;
    for (int i = 0; i < result_msg.closest_nodes_size(); ++i) {
      Contact node;
      node.ParseFromString(result_msg.closest_nodes(i));
      closest_nodes.push_back(node);
    }
    if (closest_nodes.size() > 0) {
      bool deleted_local(false);
      if (type_ != CLIENT) {
        // Try to delete value from node
        if (DelValueLocal(key, value, sig_req))
          deleted_local = true;
      }
      boost::shared_ptr<IterativeDelValueData>
          data(new struct IterativeDelValueData(closest_nodes, key, value,
              sig_req, callback));
      if (deleted_local)
        ++data->del_nodes;
      // decide the parallel level
      int parallel_size;
      if (data->closest_nodes.size() > alpha_)
        parallel_size = alpha_;
      else
        parallel_size = data->closest_nodes.size();
      for (int i = 0; i< parallel_size; ++i) {
        DeleteCallbackArgs callback_args(data);
        DelValue_IterativeDeleteValue(NULL, callback_args);
      }
      return;
    }
    DeleteResponse local_result;
    local_result.set_result(false);
    std::string local_result_str(local_result.SerializeAsString());
    callback(local_result_str);
    DLOG(WARNING) << "NodeImpl::DelValue_ExecuteDeleteRPCs - No nodes."
                  << std::endl;
  } else {
    DeleteResponse local_result;
    local_result.set_result(false);
    std::string local_result_str(local_result.SerializeAsString());
    callback(local_result_str);
    DLOG(WARNING) << "NodeImpl::DelValue_ExecuteDeleteRPCs - Invalid or fail."
                  << std::endl;
  }
}

bool NodeImpl::DelValueLocal(const NodeId &key, const SignedValue &value,
                              const SignedRequest &req) {
  if (signature_validator_ == NULL)
    return false;
  // validating request
  std::string str_key(key.String());
  if (!signature_validator_->ValidateSignerId(req.signer_id(),
      req.signed_public_key(), str_key) ||
      !signature_validator_->ValidateRequest(req.signed_request(),
      req.public_key(), req.signed_public_key(), str_key))
    return false;

  // only the signer of the value can delete it
  std::vector<std::string> values_str;
  if (!pdata_store_->LoadItem(str_key, &values_str))
    return false;
  crypto::Crypto cobj;
  if (cobj.AsymCheckSig(value.value(), value.value_signature(),
      req.public_key(), crypto::STRING_STRING)) {
    if (pdata_store_->MarkForDeletion(key.String(),
        value.SerializeAsString(), req.SerializeAsString()))
      return true;
  }
  return false;
}

void NodeImpl::DelValue_IterativeDeleteValue(
    const DeleteResponse *response,
    DeleteCallbackArgs callback_data) {
  if (!is_joined_)
    return;
  if (callback_data.data->is_callbacked)
    // Only call back once
    return;

  if (response != NULL) {
    if (response->IsInitialized() && response->has_node_id() &&
        response->node_id() != callback_data.remote_ctc.node_id().String()) {
      if (callback_data.retry) {
        delete response;
        DeleteResponse *resp = new DeleteResponse;
        UpdatePDRTContactToRemote(callback_data.remote_ctc.node_id(),
            callback_data.remote_ctc.ip());
        callback_data.retry = false;
        // send RPC to this contact's remote address because local failed
        google::protobuf::Closure *done1 = google::protobuf::NewCallback
            <NodeImpl, const DeleteResponse*, DeleteCallbackArgs>
            (this, &NodeImpl::DelValue_IterativeDeleteValue, resp,
             callback_data);
        rpcs_->Delete(callback_data.data->key, callback_data.data->value,
                        callback_data.data->sig_request,
                        callback_data.remote_ctc.ip(),
                        callback_data.remote_ctc.port(),
                        callback_data.remote_ctc.rendezvous_ip(),
                        callback_data.remote_ctc.rendezvous_port(), resp,
                        callback_data.rpc_ctrler, done1);
        return;
      }
    }
    if (response->IsInitialized() && !callback_data.rpc_ctrler->Failed()) {
      if (response->result()) {
        ++callback_data.data->del_nodes;
      }
      AddContact(callback_data.remote_ctc, callback_data.rpc_ctrler->rtt(),
                 false);
    } else {
      // it has timeout
      RemoveContact(callback_data.remote_ctc.node_id());
    }
    // nodes has been contacted -- timeout, responded with failure or success
    ++callback_data.data->contacted_nodes;
    delete callback_data.rpc_ctrler;
    callback_data.rpc_ctrler = NULL;
    delete response;
  }
  if (callback_data.data->contacted_nodes >=
      callback_data.data->closest_nodes.size()) {
    // Finish storing
    DeleteResponse del_value_result;
    boost::uint32_t d(static_cast<boost::uint32_t>
      (K_ * kMinSuccessfulPecentageStore));
    if (callback_data.data->del_nodes >= d) {
      // Succeeded - min. number of copies were stored
      del_value_result.set_result(true);
    } else {
      del_value_result.set_result(false);
      DLOG(ERROR) << "Successful Delete rpc's " << callback_data.data->del_nodes
                  << "\nSuccessful Delete rpc's required "
                  << K_ * kMinSuccessfulPecentageStore << std::endl;
    }
    std::string del_value_result_str(del_value_result.SerializeAsString());
    callback_data.data->is_callbacked = true;
    callback_data.data->callback(del_value_result_str);
  } else {
    // Continues...
    // send RPC to this contact
    ++callback_data.data->index;
    if (callback_data.data->index >= callback_data.data->closest_nodes.size())
      return;  // all requested were sent out, wait for the result
    Contact next_node =
        callback_data.data->closest_nodes[callback_data.data->index];
    DeleteResponse *resp = new DeleteResponse;
    DeleteCallbackArgs callback_args(callback_data.data);
    callback_args.remote_ctc = next_node;
    callback_args.rpc_ctrler = new rpcprotocol::Controller;

    ConnectionType conn_type = CheckContactLocalAddress(next_node.node_id(),
                                                        next_node.local_ip(),
                                                        next_node.local_port(),
                                                        next_node.ip());
    IP contact_ip, rendezvous_ip;
    Port contact_port, rendezvous_port(0);
    if (conn_type == LOCAL) {
      callback_args.retry = true;
      contact_ip = next_node.local_ip();
      contact_port = next_node.local_port();
    } else {
      contact_ip = next_node.ip();
      contact_port = next_node.port();
      rendezvous_ip = next_node.rendezvous_ip();
      rendezvous_port = next_node.rendezvous_port();
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback
        <NodeImpl, const DeleteResponse*, DeleteCallbackArgs >
        (this, &NodeImpl::DelValue_IterativeDeleteValue, resp, callback_args);

    rpcs_->Delete(callback_data.data->key, callback_data.data->value,
                    callback_data.data->sig_request, contact_ip, contact_port,
                    rendezvous_ip, rendezvous_port, resp,
                    callback_args.rpc_ctrler, done);
  }
}

void NodeImpl::UpdateValue(const NodeId &key,
                            const SignedValue &old_value,
                            const SignedValue &new_value,
                            const SignedRequest &signed_request,
                            boost::uint32_t ttl,
                            VoidFunctorOneString callback) {
  if (!old_value.IsInitialized() || !new_value.IsInitialized() ||
      !signed_request.IsInitialized()) {
    DeleteResponse resp;
    resp.set_result(false);
    std::string ser_resp(resp.SerializeAsString());
    callback(ser_resp);
    DLOG(WARNING) << "NodeImpl::UpdateValue - uninitialised values or request"
                  << std::endl;
    return;
  }
  FindKClosestNodes(key, boost::bind(&NodeImpl::ExecuteUpdateRPCs,
                                     this, _1, key, old_value, new_value,
                                     signed_request, ttl, callback));
}

void NodeImpl::ExecuteUpdateRPCs(const std::string &result,
                                  const NodeId &key,
                                  const SignedValue &old_value,
                                  const SignedValue &new_value,
                                  const SignedRequest &sig_req,
                                  boost::uint32_t ttl,
                                  VoidFunctorOneString callback) {
  if (!is_joined_)
    return;

  FindResponse result_msg;
  if (!result_msg.ParseFromString(result) ||
      !result_msg.result() ||
      result_msg.closest_nodes_size() == 0) {
    DeleteResponse resp;
    resp.set_result(false);
    std::string ser_resp(resp.SerializeAsString());
    callback(ser_resp);
    DLOG(WARNING) << "NodeImpl::ExecuteUpdateRPCs - failed find nodes"
                  << std::endl;
    return;
  }

  std::vector<Contact> closest_nodes;
  for (int i = 0; i < result_msg.closest_nodes_size(); ++i) {
    Contact node;
    if (node.ParseFromString(result_msg.closest_nodes(i)))
      closest_nodes.push_back(node);
  }

  if (closest_nodes.size() < size_t(kMinSuccessfulPecentageStore * K_)) {
    DeleteResponse resp;
    resp.set_result(false);
    std::string ser_resp(resp.SerializeAsString());
    callback(ser_resp);
    DLOG(WARNING) << "NodeImpl::ExecuteUpdateRPCs - Not enough nodes"
                  << std::endl;
    return;
  }

  boost::uint8_t nodes(closest_nodes.size());
  boost::shared_ptr<UpdateValueData> uvd(new UpdateValueData(key, old_value,
                                                             new_value, sig_req,
                                                             callback, nodes));

  for (size_t n = 0; n < closest_nodes.size(); ++n) {
    boost::shared_ptr<UpdateCallbackArgs> uca(new UpdateCallbackArgs());
    uca->uvd = uvd;
    uca->contact = closest_nodes[n];
    uca->response = new UpdateResponse;
    UpdatePDRTContactToRemote(closest_nodes[n].node_id(),
                              closest_nodes[n].ip());
    uca->controller = new rpcprotocol::Controller;
    google::protobuf::Closure *done = google::protobuf::NewCallback
                                      <NodeImpl,
                                       boost::shared_ptr<UpdateCallbackArgs> >
                                      (this, &NodeImpl::UpdateValueResponses,
                                       uca);
    ConnectionType conn_type = CheckContactLocalAddress(
                                   closest_nodes[n].node_id(),
                                   closest_nodes[n].local_ip(),
                                   closest_nodes[n].local_port(),
                                   closest_nodes[n].ip());
    IP contact_ip, rendezvous_ip;
    Port contact_port(0), rendezvous_port(0);
    uca->ct = conn_type;
    if (conn_type == LOCAL) {
      uca->uvd->retries = 1;
      contact_ip = closest_nodes[n].local_ip();
      contact_port = closest_nodes[n].local_port();
    } else {
      contact_ip = closest_nodes[n].ip();
      contact_port = closest_nodes[n].port();
      rendezvous_ip = closest_nodes[n].rendezvous_ip();
      rendezvous_port = closest_nodes[n].rendezvous_port();
    }
    rpcs_->Update(key, new_value, old_value, ttl, sig_req, contact_ip,
                    contact_port, rendezvous_ip, rendezvous_port,
                    uca->response, uca->controller, done);
  }
}

void NodeImpl::UpdateValueResponses(
    boost::shared_ptr<UpdateCallbackArgs> uca) {
  if (uca->response->IsInitialized()) {
    if (!uca->response->has_node_id() ||
        uca->response->node_id() != uca->contact.node_id().String()) {
      // Check if a retry is warranted
      if (uca->uvd->retries < 1) {
        ++uca->uvd->retries;
        uca->response = new UpdateResponse;
        uca->controller = new rpcprotocol::Controller;
        google::protobuf::Closure *done;
        done = google::protobuf::NewCallback
               <NodeImpl, boost::shared_ptr<UpdateCallbackArgs> >
               (this, &NodeImpl::UpdateValueResponses, uca);
        rpcs_->Update(uca->uvd->uvd_key, uca->uvd->uvd_new_value,
                        uca->uvd->uvd_old_value, uca->uvd->ttl,
                        uca->uvd->uvd_request_signature, uca->contact.ip(),
                        uca->contact.port(),
                        uca->contact.rendezvous_ip(),
                        uca->contact.rendezvous_port(), uca->response,
                        uca->controller, done);
        return;
      // No retry: failed
      } else {
        RemoveContact(uca->contact.node_id());
        ++uca->uvd->uvd_calledback;
      }
    // The RPC came back successfully
    } else {
      AddContact(uca->contact, uca->controller->rtt(), false);
      ++uca->uvd->uvd_calledback;
      ++uca->uvd->uvd_succeeded;
    }
  }

  delete uca->response;
  delete uca->controller;

  if (uca->uvd->uvd_calledback == uca->uvd->found_nodes) {
    UpdateResponse update_result;
    if (uca->uvd->uvd_succeeded <
        boost::uint8_t(K_ * kMinSuccessfulPecentageStore)) {
      // Sadly, we didn't gather the numbers to ensure success
      update_result.set_result(false);

      DLOG(WARNING) << "NodeImpl::ExecuteUpdateRPCs - Not enough succ in RPCs"
                    << std::endl;

    } else {
      update_result.set_result(true);
    }
    std::string serialised_result(update_result.SerializeAsString());
    uca->uvd->uvd_callback(serialised_result);
  }
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
  if (fna->calledback) {
    *nodes_pending = NodesPending(fna);
    *top_nodes_done = true;
    *calledback = true;
    nodes->clear();
    return true;
  } else {
    printf("NodeImpl::AnalyseIteration - Search not complete at Round(%d) - %d times - %d alphas\n", round, times, contacts->size());
  }

  bool b = MarkResponse(contact, fna, mark, nodes);
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

  printf("NodeImpl::HandleIterationStructure - Total(%d), Done(%d), "
         "Round(%d)\n", alphas_sent, alphas_replied, round);
  // Decide if another iteration is needed and pick the alphas
  if ((alphas_sent > kBeta && alphas_replied >= kBeta) ||
      (alphas_sent <= kBeta && alphas_replied == alphas_sent)) {

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

    printf("%s -- %s\n",
           nodes->back().node_id().ToStringEncoded(KadId::kBase64).c_str(),
           fna->kth_closest.ToStringEncoded(KadId::kBase64).c_str());
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
        }
      }
      printf("NodeImpl::HandleIterationStructure - New(%d), Alpha(%d),"
             " Contacted(%d)\n", new_nodes, alpha_nodes, contacted_nodes);

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
    boost::uint16_t times(0);
    for (; it_conts != nodes->end() && times < kAlpha; ++it_conts) {
      NodeContainerByContact &index_contact = fna->nc.get<nc_contact>();
      NCBCit contact_it = index_contact.find(*it_conts);
      if (contact_it != index_contact.end()) {
        if ((*contact_it).state == kNew) {
          NodeContainerTuple nct = *contact_it;
          nct.state = kSelectedAlpha;
          nct.round = fna->round;
          index_contact.replace(contact_it, nct);
          ++times;
          alphas.push_back((*contact_it).contact);
        }
      } else {
        printf("This shouldn't happen. Ever! Ever ever ever!\n");
      }
    }
    *nodes = alphas;
  }

  return b;
}

bool NodeImpl::HandleIterationStructure(const Contact &contact,
                                         boost::shared_ptr<FindNodesArgs> fna,
                                         int round,
                                         SearchMarking mark,
                                         std::list<Contact> *nodes,
                                         bool *top_nodes_done,
                                         bool *calledback) {
  boost::mutex::scoped_lock loch_surlaplage(fna->mutex);
  if (fna->calledback) {
    *top_nodes_done = true;
    *calledback = true;
    nodes->clear();
    return true;
  }

  bool b = MarkResponse(contact, fna, mark, nodes);

  // Check how many of the nodes of the iteration are back
  NodeContainerByRound &index_car = fna->nc.get<nc_round>();
  std::pair<NCBRit, NCBRit> pr = index_car.equal_range(round);
  int alphas_replied(0), alphas_sent(0);
  for (; pr.first != pr.second; ++pr.first) {
    ++alphas_sent;
    if ((*pr.first).state == kContacted)
      ++alphas_replied;
  }

  printf("NodeImpl::HandleIterationStructure - Total(%d), Done(%d), "
         "Round(%d)\n", alphas_sent, alphas_replied, round);
  // Decide if another iteration is needed and pick the alphas
  if ((alphas_sent > kBeta && alphas_replied >= kBeta) ||
      (alphas_sent <= kBeta && alphas_replied == alphas_sent)) {

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

    printf("%s -- %s\n",
           nodes->back().node_id().ToStringEncoded(KadId::kBase64).c_str(),
           fna->kth_closest.ToStringEncoded(KadId::kBase64).c_str());
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
        }
      }
      printf("NodeImpl::HandleIterationStructure - New(%d), Alpha(%d),"
             " Contacted(%d)\n", new_nodes, alpha_nodes, contacted_nodes);

      if (new_nodes == 0 && alpha_nodes == 0) {
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
    boost::uint16_t times(0);
    for (; it_conts != nodes->end() && times < kAlpha; ++it_conts) {
      NodeContainerByContact &index_contact = fna->nc.get<nc_contact>();
      NCBCit contact_it = index_contact.find(*it_conts);
      if (contact_it != index_contact.end()) {
        if ((*contact_it).state == kNew) {
          NodeContainerTuple nct = *contact_it;
          nct.state = kSelectedAlpha;
          nct.round = fna->round;
          index_contact.replace(contact_it, nct);
          ++times;
          alphas.push_back((*contact_it).contact);
        }
      } else {
        printf("This shouldn't happen. Ever! Ever ever ever!\n");
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

  IterativeSearch(fna, false, false, &alphas, 0);
}

void NodeImpl::IterativeSearch(boost::shared_ptr<FindNodesArgs> fna,
                                bool top_nodes_done, bool calledback,
                                std::list<Contact> *contacts,
                                int nodes_pending) {
  if (top_nodes_done) {
    if (!calledback) {
      FindResponse fr;
      fr.set_result(true);
      std::list<Contact>::iterator it = contacts->begin();
      for (; it != contacts->end(); ++it) {
        fr.add_closest_nodes((*it).SerialiseAsString());
      }
      DLOG(INFO) << "NodeImpl::IterativeSearch - Done" << std::endl;
      fna->callback(fr.SerializeAsString());
    }
    return;
  }

  if (contacts->empty())
    return;

  printf("NodeImpl::IterativeSearch - Sending %d alphas\n", contacts->size());
  std::list<Contact>::iterator it = contacts->begin();
  for (; it != contacts->end(); ++it) {
    boost::shared_ptr<FindNodesRpc> fnrpc(new FindNodesRpc(*it, fna));
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<NodeImpl,
                                      boost::shared_ptr<FindNodesRpc> >
        (this, &NodeImpl::IterativeSearchResponse, fnrpc);
    kadrpcs_->FindNode(fna->key, (*it).ip(), (*it).port(),
                       (*it).rendezvous_ip(), (*it).rendezvous_port(),
                       fnrpc->response, fnrpc->ctler, done);
  }
}

void NodeImpl::IterativeSearchResponse(boost::shared_ptr<FindNodesRpc> fnrpc) {
  SearchMarking mark(SEARCH_CONTACTED);
  if (!fnrpc->response->IsInitialized())
    mark = SEARCH_DOWN;

  // Get nodes from response and add them to the list
  std::list<Contact> close_nodes;
  if (mark == SEARCH_CONTACTED && fnrpc->response->result() &&
      fnrpc->response->closest_nodes_size() > 0) {
    for (int n = 0; n < fnrpc->response->closest_nodes_size(); ++n) {
      Contact c;
      if (c.ParseFromString(fnrpc->response->closest_nodes(n)))
        close_nodes.push_back(c);
    }
  }

  bool done(false), calledback(false);
  int nodes_pending(0);
  if (!HandleIterationStructure(fnrpc->contact, fnrpc->rpc_fna, fnrpc->round,
                                mark, &close_nodes, &done, &calledback,
                                &nodes_pending)) {
    printf("Well, that's just too freakishly odd. Daaaaamn, brotha!\n");
  }

  IterativeSearch(fnrpc->rpc_fna, done, calledback, &close_nodes,
                  nodes_pending);
}

}  // namespace kademlia
