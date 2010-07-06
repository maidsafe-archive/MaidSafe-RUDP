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


#include <boost/assert.hpp>
#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <google/protobuf/descriptor.h>
#include <algorithm>
#include <iostream>  // NOLINT Fraser - required for handling .kadconfig file
#include <fstream>  // NOLINT
#include <vector>
#include "maidsafe/base/log.h"
#include "maidsafe/base/alternativestore.h"
#include "maidsafe/base/crypto.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/rpcprotocol/channelmanager-api.h"
#include "maidsafe/rpcprotocol/channel-api.h"
#include "maidsafe/base/routingtable.h"
#include "maidsafe/transport/transport-api.h"
#include "maidsafe/transport/transporthandler-api.h"
#include "maidsafe/protobuf/contact_info.pb.h"
#include "maidsafe/protobuf/signed_kadvalue.pb.h"
#include "maidsafe/base/online.h"
#include "maidsafe/base/validationinterface.h"
#include "maidsafe/kademlia/kadid.h"
#include "maidsafe/kademlia/knodeimpl.h"

namespace fs = boost::filesystem;

namespace kad {

// some tools which will be used in the implementation of KNode class
struct ContactAndTargetKey {
  ContactAndTargetKey() : contact(), target_key(), contacted(false) {}
  Contact contact;
  KadId target_key;
  bool contacted;
};

bool CompareContact(const ContactAndTargetKey &first,
                    const ContactAndTargetKey &second) {
  KadId id;
  if (first.contact.node_id() == id)
    return true;
  else if (second.contact.node_id() == id)
    return false;
  return KadId::CloserToTarget(first.contact.node_id(),
      second.contact.node_id(), first.target_key);
}

// sort the contact list according the distance to the target key
void SortContactList(std::list<Contact> *contact_list,
                     const KadId &target_key) {
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
void SortLookupContact(std::list<LookupContact> *contact_list,
                       const KadId &target_key) {
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

void InsertKadContact(const KadId &key,
                      const kad::Contact &new_contact,
                      std::vector<kad::Contact> *contacts) {
  std::list<kad::Contact> contact_list(contacts->begin(), contacts->end());
  contact_list.push_back(new_contact);
  SortContactList(&contact_list, key);
  contacts->clear();
  for (std::list<kad::Contact>::iterator it = contact_list.begin();
       it != contact_list.end(); ++it) {
    contacts->push_back(*it);
  }
}

KNodeImpl::KNodeImpl(rpcprotocol::ChannelManager *channel_manager,
                     transport::TransportHandler *transport_handler,
                     NodeType type, const std::string &private_key,
                     const std::string &public_key, const bool &port_forwarded,
                     const bool &use_upnp, const boost::uint16_t &k)
    : routingtable_mutex_(), kadconfig_mutex_(),
      extendshortlist_mutex_(), joinbootstrapping_mutex_(), leave_mutex_(),
      activeprobes_mutex_(), pendingcts_mutex_(),
      ptimer_(new base::CallLaterTimer), pchannel_manager_(channel_manager),
      transport_handler_(transport_handler), transport_id_(0),
      pservice_channel_(), pdata_store_(new DataStore(kRefreshTime)),
      alternative_store_(NULL), premote_service_(), kadrpcs_(channel_manager,
      transport_handler), natrpcs_(channel_manager, transport_handler),
      is_joined_(false), prouting_table_(), node_id_(), fake_kClientId_(),
      host_ip_(), type_(type), host_port_(0), rv_ip_(),
      rv_port_(0), bootstrapping_nodes_(), K_(k), alpha_(kAlpha), beta_(kBeta),
      refresh_routine_started_(false), kad_config_path_(), local_host_ip_(),
      local_host_port_(0), stopping_(false), port_forwarded_(port_forwarded),
      use_upnp_(use_upnp), contacts_to_add_(), addcontacts_routine_(),
      add_ctc_cond_(), private_key_(private_key), public_key_(public_key),
      host_nat_type_(NONE), recheck_nat_type_(false), upnp_(),
      upnp_mapped_port_(0), signature_validator_(NULL),
      exclude_bs_contacts_() {}

KNodeImpl::KNodeImpl(rpcprotocol::ChannelManager *channel_manager,
                     transport::TransportHandler *transport_handler,
                     NodeType type, const boost::uint16_t &k,
                     const boost::uint16_t &alpha, const boost::uint16_t &beta,
                     const boost::uint32_t &refresh_time,
                     const std::string &private_key,
                     const std::string &public_key,
                     const bool &port_forwarded, const bool &use_upnp)
    : routingtable_mutex_(), kadconfig_mutex_(), extendshortlist_mutex_(),
      joinbootstrapping_mutex_(), leave_mutex_(), activeprobes_mutex_(),
      pendingcts_mutex_(), ptimer_(new base::CallLaterTimer),
      pchannel_manager_(channel_manager), transport_handler_(transport_handler),
      transport_id_(0), pservice_channel_(),
      pdata_store_(new DataStore(refresh_time)), alternative_store_(NULL),
      premote_service_(), kadrpcs_(channel_manager, transport_handler),
      natrpcs_(channel_manager, transport_handler), is_joined_(false),
      prouting_table_(), node_id_(), fake_kClientId_(), host_ip_(), type_(type),
      host_port_(0), rv_ip_(), rv_port_(0), bootstrapping_nodes_(), K_(k),
      alpha_(alpha), beta_(beta), refresh_routine_started_(false),
      kad_config_path_(), local_host_ip_(), local_host_port_(0),
      stopping_(false), port_forwarded_(port_forwarded), use_upnp_(use_upnp),
      contacts_to_add_(), addcontacts_routine_(), add_ctc_cond_(),
      private_key_(private_key), public_key_(public_key), host_nat_type_(NONE),
      recheck_nat_type_(false), upnp_(), upnp_mapped_port_(0),
      signature_validator_(NULL), exclude_bs_contacts_() {}

KNodeImpl::~KNodeImpl() {
  if (is_joined_) {
    UnRegisterKadService();
    is_joined_ = false;
    pdata_store_->Clear();
  }
  if (upnp_mapped_port_ != 0) {
    UnMapUPnP();
  }
}

inline void KNodeImpl::CallbackWithFailure(VoidFunctorOneString callback) {
  base::GeneralResponse result_msg;
  result_msg.set_result(kRpcResultFailure);
  std::string result(result_msg.SerializeAsString());
  callback(result);
}

void KNodeImpl::Bootstrap_Callback(const BootstrapResponse *response,
                                   BootstrapData data) {
  BootstrapResponse result_msg;
  if (response->IsInitialized())
    result_msg = *response;
  else
    result_msg.set_result(kRpcResultFailure);
  std::string result_str(result_msg.SerializeAsString());
  delete data.rpc_ctrler;
  delete response;
  data.callback(result_str);
}

void KNodeImpl::Bootstrap(const std::string &bootstrap_ip,
                          const boost::uint16_t &bootstrap_port,
                          VoidFunctorOneString callback,
                          const bool &dir_connected) {
  struct BootstrapData data = {callback, bootstrap_ip, bootstrap_port, NULL};
  data.rpc_ctrler = new rpcprotocol::Controller;
  // send RPC to a bootstrapping node candidate
  BootstrapResponse *resp = new BootstrapResponse;
  google::protobuf::Closure *done = google::protobuf::NewCallback<
      KNodeImpl, const BootstrapResponse*, struct BootstrapData>
      (this, &KNodeImpl::Bootstrap_Callback, resp, data);
  if (dir_connected) {
    kadrpcs_.Bootstrap(fake_kClientId_, host_ip_, host_port_, bootstrap_ip,
        bootstrap_port, type_, resp, data.rpc_ctrler, done);
  } else {
    kadrpcs_.Bootstrap(node_id(), host_ip_, host_port_, bootstrap_ip,
        bootstrap_port, type_, resp, data.rpc_ctrler, done);
  }
}

void KNodeImpl::Join_Bootstrapping_Iteration_Client(
      const std::string& result, boost::shared_ptr<struct BootstrapArgs> args,
      const std::string bootstrap_ip, const boost::uint16_t bootstrap_port,
      const std::string local_bs_ip, const boost::uint16_t local_bs_port) {
  if (args->is_callbacked || stopping_)
    return;
  --args->active_process;
  BootstrapResponse result_msg;
  if ((result_msg.ParseFromString(result)) &&
      (result_msg.result() == kRpcResultSuccess)) {
    kad::Contact bootstrap_node(result_msg.bootstrap_id(), bootstrap_ip,
        bootstrap_port, local_bs_ip, local_bs_port);
    AddContact(bootstrap_node, 0.0, false);
    host_ip_ = result_msg.newcomer_ext_ip();
    host_port_ = result_msg.newcomer_ext_port();
    DLOG(INFO) << "external address " << host_ip_ << ":" << host_port_
        << std::endl;
    transport_handler_->StartPingRendezvous(false, bootstrap_node.host_ip(),
        bootstrap_node.host_port(), transport_id_);
    kadrpcs_.set_info(contact_info());
    args->is_callbacked = true;
    if (type_ != CLIENT)
      host_nat_type_ = DIRECT_CONNECTED;
    StartSearchIteration(node_id_, BOOTSTRAP, args->callback);
    // start a schedule to delete expired key/value pairs only once
    if (!refresh_routine_started_) {
      ptimer_->AddCallLater(kRefreshTime*1000,
                            boost::bind(&KNodeImpl::RefreshRoutine, this));
      refresh_routine_started_ = true;
    }
  } else if (!args->cached_nodes.empty()) {
    Contact bootstrap_candidate = args->cached_nodes.back();
    args->cached_nodes.pop_back();  // inefficient!!!!
    Bootstrap(bootstrap_candidate.host_ip(), bootstrap_candidate.host_port(),
        boost::bind(&KNodeImpl::Join_Bootstrapping_Iteration_Client,
        this, _1, args, bootstrap_candidate.host_ip(),
        bootstrap_candidate.host_port(), bootstrap_candidate.local_ip(),
        bootstrap_candidate.local_port()), args->dir_connected);
    ++args->active_process;
  } else if (args->active_process == 0) {
    base::GeneralResponse local_result;
    local_result.set_result(kRpcResultFailure);
    std::string local_result_str(local_result.SerializeAsString());
    args->is_callbacked = true;
    args->callback(local_result_str);
  }
}

void KNodeImpl::Join_Bootstrapping_Iteration(
    const std::string& result, boost::shared_ptr<struct BootstrapArgs> args,
    const std::string bootstrap_ip, const boost::uint16_t bootstrap_port,
    const std::string local_bs_ip, const boost::uint16_t local_bs_port) {
  if (args->is_callbacked || stopping_)
    return;
  --args->active_process;
  BootstrapResponse result_msg;
  if ((result_msg.ParseFromString(result)) &&
      (result_msg.result() == kRpcResultSuccess)) {
    kad::Contact bootstrap_node(result_msg.bootstrap_id(), bootstrap_ip,
                                bootstrap_port, local_bs_ip, local_bs_port);
    AddContact(bootstrap_node, 0.0, false);
    bool directlyconnected = false;
    if (host_ip_ == result_msg.newcomer_ext_ip() &&
        host_port_ == result_msg.newcomer_ext_port())
      directlyconnected = true;
    host_ip_ = result_msg.newcomer_ext_ip();
    host_port_ = result_msg.newcomer_ext_port();
    if (!result_msg.has_nat_type()) {
      // this is when bootstrapping to a node that has no contacts
      // assuming that the node is directly connected
      DLOG(INFO) << "Node directly connected. Address " << host_ip_ <<
          ":" << host_port_ << std::endl;
      rv_ip_ = "";
      rv_port_ = 0;
      host_nat_type_ = DIRECT_CONNECTED;
    } else if (result_msg.nat_type() == 1) {
      // Direct connection
      DLOG(INFO) << "Node is behind NAT of type 1\n";
      rv_ip_ = "";
      rv_port_ = 0;
      host_nat_type_ = DIRECT_CONNECTED;
    } else if (result_msg.nat_type() == 2) {
      // need rendezvous server
      DLOG(INFO) << "Node is behind NAT of type 2 (needs rendezvous server)\n";
      rv_ip_ = bootstrap_node.host_ip();
      rv_port_ = bootstrap_node.host_port();
      host_nat_type_ = RESTRICTED;
    } else if (result_msg.nat_type() == 3) {
      // behind symmetric router or no connection
      DLOG(INFO) << "Node is behind NAT of type 3\n";
      UPnPMap(local_host_port_);
      if (upnp_mapped_port_ != 0) {
        host_port_ = upnp_mapped_port_;
        // It is now directly connected
        rv_ip_ = "";
        rv_port_ = 0;
      } else if (type_ == CLIENT_PORT_MAPPED) {
        host_port_ = local_host_port_;
        host_ip_ = local_host_ip_;
        rv_ip_ = "";
        rv_port_ = 0;
      } else {
        base::GeneralResponse local_result;
        local_result.set_result(kRpcResultFailure);
        std::string local_result_str(local_result.SerializeAsString());
        args->is_callbacked = true;
        UnRegisterKadService();
        args->callback(local_result_str);
        return;
      }
    }
    transport_handler_->StartPingRendezvous(false, bootstrap_node.host_ip(),
                                            bootstrap_node.host_port(),
                                            transport_id_);
    kadrpcs_.set_info(contact_info());
    args->is_callbacked = true;
    StartSearchIteration(node_id_, BOOTSTRAP, args->callback);
    recheck_nat_type_ = false;
  } else if (result_msg.result() == kRpcResultFailure &&
             !result_msg.has_nat_type()) {
    DLOG(INFO) << "Going to have to re-check that NAT, mister" << std::endl;
    recheck_nat_type_ = true;
    rv_ip_ = "";
    rv_port_ = 0;
    host_nat_type_ = DIRECT_CONNECTED;
    kad::Contact bootstrap_node(result_msg.bootstrap_id(), bootstrap_ip,
                                bootstrap_port, local_bs_ip, local_bs_port);
    AddContact(bootstrap_node, 0.0, false);
    host_ip_ = result_msg.newcomer_ext_ip();
    host_port_ = result_msg.newcomer_ext_port();
    transport_handler_->StartPingRendezvous(false, bootstrap_node.host_ip(),
                                            bootstrap_node.host_port(),
                                            transport_id_);
    kadrpcs_.set_info(contact_info());
    args->is_callbacked = true;
    StartSearchIteration(node_id_, BOOTSTRAP, args->callback);
  } else if (!args->cached_nodes.empty()) {
    Contact bootstrap_candidate = args->cached_nodes.back();
    args->cached_nodes.pop_back();  // inefficient!!!!
    Bootstrap(bootstrap_candidate.host_ip(), bootstrap_candidate.host_port(),
              boost::bind(&KNodeImpl::Join_Bootstrapping_Iteration, this, _1,
                          args, bootstrap_candidate.host_ip(),
                          bootstrap_candidate.host_port(),
                          bootstrap_candidate.local_ip(),
                          bootstrap_candidate.local_port()),
              args->dir_connected);
    ++args->active_process;
  } else if (args->active_process == 0) {
    base::GeneralResponse local_result;
    local_result.set_result(kRpcResultFailure);
    std::string local_result_str(local_result.SerializeAsString());
    args->is_callbacked = true;
    rv_ip_ = "";
    rv_port_ = 0;
    args->callback(local_result_str);
  }
}

void KNodeImpl::Join_Bootstrapping(VoidFunctorOneString callback,
                                   std::vector<Contact> &cached_nodes,
                                   const bool &got_external_address) {
  if (cached_nodes.empty()) {
    base::GeneralResponse local_result;
    if (type_ == VAULT) {
      local_result.set_result(kRpcResultSuccess);
      is_joined_ = true;
      host_nat_type_ = DIRECT_CONNECTED;
      premote_service_->set_node_joined(true);
      premote_service_->set_node_info(contact_info());
      // since it is a 1 network node, so it has no rendezvous server to ping
      transport_handler_->StartPingRendezvous(true, rv_ip_, rv_port_,
                                              transport_id_);
      addcontacts_routine_.reset(new boost::thread(&KNodeImpl::CheckAddContacts,
                                                   this));
      if (!refresh_routine_started_) {
        ptimer_->AddCallLater(kRefreshTime * 1000,
                              boost::bind(&KNodeImpl::RefreshRoutine, this));
        ptimer_->AddCallLater(2000,
                              boost::bind(&KNodeImpl::RefreshValuesRoutine,
                                          this));
        refresh_routine_started_ = true;
      }
    } else {
      // Client nodes can not start a network on their own
      local_result.set_result(kRpcResultFailure);
      UnRegisterKadService();
    }
    kadrpcs_.set_info(contact_info());
    DLOG(WARNING) << "No more bootstrap contacts\n";
    std::string local_result_str(local_result.SerializeAsString());
    callback(local_result_str);
    return;
  }

  boost::shared_ptr<struct BootstrapArgs> args(new struct BootstrapArgs);
  args->callback = callback;
  args->active_process = 0;
  args->is_callbacked = false;
  boost::uint16_t parallel_size = 0;
  if (static_cast<int>(cached_nodes.size()) > 1)
    parallel_size = 1;
    // TODO(Fraser#5#): 2009-04-06 - Make it constant later
  else
    parallel_size = cached_nodes.size();
  for (int i = 0; i < parallel_size; ++i) {
    if (cached_nodes.empty())
      break;
    Contact bootstrap_candidate = cached_nodes.back();
    cached_nodes.pop_back();
    args->cached_nodes = cached_nodes;
    if (port_forwarded_ || got_external_address || type_ == CLIENT) {
      args->dir_connected = true;
      Bootstrap(bootstrap_candidate.host_ip(), bootstrap_candidate.host_port(),
                boost::bind(&KNodeImpl::Join_Bootstrapping_Iteration_Client,
                            this, _1, args, bootstrap_candidate.host_ip(),
                            bootstrap_candidate.host_port(),
                            bootstrap_candidate.local_ip(),
                            bootstrap_candidate.local_port()), true);
    } else {
      Bootstrap(bootstrap_candidate.host_ip(), bootstrap_candidate.host_port(),
                boost::bind(&KNodeImpl::Join_Bootstrapping_Iteration, this,
                            _1, args, bootstrap_candidate.host_ip(),
                            bootstrap_candidate.host_port(),
                            bootstrap_candidate.local_ip(),
                            bootstrap_candidate.local_port()), false);
    }
    ++args->active_process;
  }
}

void KNodeImpl::Join_RefreshNode(VoidFunctorOneString callback,
                                 const bool &got_external_address) {
  if (stopping_)
    return;
  // build list of bootstrapping nodes
  LoadBootstrapContacts();
  // Initiate the Kademlia joining sequence - perform a search for this
  // node's own ID
  kadrpcs_.set_info(contact_info());
  // Getting local IP and temporarily setting host_ip_ == local_host_ip_
  std::vector<std::string> local_ips = base::GetLocalAddresses();
  bool got_local_address = false;
  for (unsigned int i = 0; i < bootstrapping_nodes_.size()
       && !got_local_address; ++i) {
    std::string remote_ip =
        base::IpBytesToAscii(bootstrapping_nodes_[i].host_ip());
    for (unsigned int j = 0; j < local_ips.size() && !got_local_address; ++j) {
      if (transport_handler_->IsAddressUsable(local_ips[j], remote_ip,
          bootstrapping_nodes_[i].host_port(), transport_id_)) {
        if (!got_external_address)
          host_ip_ = local_ips[j];
        local_host_ip_ = local_ips[j];
        got_local_address = true;
      }
    }
  }
  if (!got_local_address) {
    boost::asio::ip::address local_address;
    if (base::GetLocalAddress(&local_address)) {
      if (!got_external_address)
          host_ip_ = local_address.to_string();
      local_host_ip_ = local_address.to_string();
    }
  }
  Join_Bootstrapping(callback, bootstrapping_nodes_, got_external_address);
}

void KNodeImpl::Join(const KadId &node_id, const std::string &kad_config_file,
                     VoidFunctorOneString callback) {
  if (is_joined_ || !node_id.IsValid()) {
    base::GeneralResponse local_result;
    if (is_joined_)
      local_result.set_result(kRpcResultSuccess);
    else
      local_result.set_result(kRpcResultFailure);
    local_result.set_result(kRpcResultSuccess);
    std::string local_result_str(local_result.SerializeAsString());
    callback(local_result_str);
    return;
  }
  if (host_port_ == 0)
    host_port_ = transport_handler_->listening_port(transport_id_);
  local_host_port_ = transport_handler_->listening_port(transport_id_);
  // Adding the services
  RegisterKadService();

  node_id_ = node_id;

  bool got_external_address = false;
  if (use_upnp_) {
    UPnPMap(local_host_port_);
    if (upnp_mapped_port_ != 0) {
      host_port_ = upnp_mapped_port_;
      // It is now directly connected
      rv_ip_ = "";
      rv_port_ = 0;
      got_external_address = true;
    }
  }

  // Set kad_config_path_
  kad_config_path_ = fs::path(kad_config_file, fs::native);
  prouting_table_.reset(new RoutingTable(node_id_, K_));
  Join_RefreshNode(callback, got_external_address);
}

void KNodeImpl::Join(const std::string &kad_config_file,
                     VoidFunctorOneString callback) {
  Join(KadId(KadId::kRandomId), kad_config_file, callback);
}

void KNodeImpl::Join(const KadId &node_id, const std::string &kad_config_file,
                     const std::string &external_ip,
                     const boost::uint16_t &external_port,
                     VoidFunctorOneString callback) {
  base::GeneralResponse local_result;
  std::string local_result_str;
  if (is_joined_ || !node_id.IsValid()) {
    if (is_joined_)
      local_result.set_result(kRpcResultSuccess);
    else
      local_result.set_result(kRpcResultFailure);
    local_result.SerializeToString(&local_result_str);
    callback(local_result_str);
    return;
  }

  RegisterKadService();

  node_id_ = node_id;
  if (type_ == CLIENT || type_ == CLIENT_PORT_MAPPED) {
    // Client nodes can not start a network on their own
    local_result.set_result(kRpcResultFailure);
    local_result.SerializeToString(&local_result_str);
    callback(local_result_str);
    return;
  }
  local_host_port_ = transport_handler_->listening_port(transport_id_);

  if (use_upnp_) {
    UPnPMap(local_host_port_);
    if (upnp_mapped_port_ != 0) {
      host_port_ = upnp_mapped_port_;
      // It is now directly connected
    } else {
      local_result.set_result(kRpcResultFailure);
      local_result.SerializeToString(&local_result_str);
      callback(local_result_str);
      return;
    }
  } else if (external_ip.empty() || external_port == 0) {
    local_result.set_result(kRpcResultFailure);
    local_result.SerializeToString(&local_result_str);
    callback(local_result_str);
    return;
  } else {
    host_ip_ = external_ip;
    host_port_ = external_port;
  }
  boost::asio::ip::address local_address;
  if (base::GetLocalAddress(&local_address))
    local_host_ip_ = local_address.to_string();
  rv_ip_ = "";
  rv_port_ = 0;
  // Set kad_config_path_
  kad_config_path_ = fs::path(kad_config_file, fs::native);
  prouting_table_.reset(new RoutingTable(node_id_, K_));

  is_joined_ = true;
  host_nat_type_ = DIRECT_CONNECTED;
  premote_service_->set_node_joined(true);
  premote_service_->set_node_info(contact_info());
  // since it is a 1 network node, so it has no rendezvous server to ping
  transport_handler_->StartPingRendezvous(true, rv_ip_, rv_port_,
                                          transport_id_);
  addcontacts_routine_.reset(new boost::thread(&KNodeImpl::CheckAddContacts,
      this));
  if (!refresh_routine_started_) {
    ptimer_->AddCallLater(kRefreshTime*1000,
                          boost::bind(&KNodeImpl::RefreshRoutine, this));
    ptimer_->AddCallLater(2000, boost::bind(&KNodeImpl::RefreshValuesRoutine,
                                            this));
    refresh_routine_started_ = true;
  }
  kadrpcs_.set_info(contact_info());
  local_result.set_result(kRpcResultSuccess);
  local_result.SerializeToString(&local_result_str);
  callback(local_result_str);
}

void KNodeImpl::Join(const std::string &kad_config_file,
                     const std::string &external_ip,
                     const boost::uint16_t &external_port,
                     VoidFunctorOneString callback) {
  Join(KadId(KadId::kRandomId), kad_config_file, external_ip, external_port,
       callback);
}

void KNodeImpl::Leave() {
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
      transport_handler_->StopPingRendezvous();
      UnRegisterKadService();
      pdata_store_->Clear();
      add_ctc_cond_.notify_one();
      addcontacts_routine_->join();
      SaveBootstrapContacts();
      exclude_bs_contacts_.clear();
      prouting_table_->Clear();
      (*base::PublicRoutingTable::GetInstance())
          [base::IntToString(host_port_)]->Clear();
    }
    stopping_ = false;
    host_nat_type_ = NONE;
    recheck_nat_type_ = true;
  }
}

void KNodeImpl::SaveBootstrapContacts() {
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
    KadId node0_id;
    if (!bootstrapping_nodes_.empty()) {
      node0_id = bootstrapping_nodes_[0].node_id();
      base::KadConfig::Contact *kad_contact = kad_config.add_contact();
      kad_contact->set_node_id(
          bootstrapping_nodes_[0].node_id().ToStringEncoded(KadId::kHex));
      std::string dec_ext_ip(base::IpBytesToAscii(
          bootstrapping_nodes_[0].host_ip()));
      kad_contact->set_ip(dec_ext_ip);
      kad_contact->set_port(bootstrapping_nodes_[0].host_port());
      if (bootstrapping_nodes_[0].local_ip() != "") {
        std::string dec_lip(base::IpBytesToAscii(
            bootstrapping_nodes_[0].local_ip()));
        kad_contact->set_local_ip(dec_lip);
        kad_contact->set_local_port(bootstrapping_nodes_[0].local_port());
      }
    }
    std::vector<Contact>::iterator it;
    for (it = bs_contacts.begin(); it < bs_contacts.end(); ++it) {
      if (it->node_id() != node0_id) {
        base::KadConfig::Contact *kad_contact = kad_config.add_contact();
        kad_contact->set_node_id(it->node_id().ToStringEncoded(KadId::kHex));
        std::string dec_ext_ip(base::IpBytesToAscii(it->host_ip()));
        kad_contact->set_ip(dec_ext_ip);
        kad_contact->set_port(it->host_port());
        if (it->local_ip() != "") {
          std::string dec_lip(base::IpBytesToAscii(it->local_ip()));
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

boost::int16_t KNodeImpl::LoadBootstrapContacts() {
  // Get the saved contacts - most recent are listed last
  base::KadConfig kad_config;
  try {
    if (fs::exists(kad_config_path_)) {
      std::ifstream input_(kad_config_path_.string().c_str(),
                           std::ios::in | std::ios::binary);
      if (!kad_config.ParseFromIstream(&input_)) {
        DLOG(ERROR) << "Failed to parse kademlia config file\n";
        return -1;
      }
      input_.close();
      if (0 == kad_config.contact_size()) {
        DLOG(ERROR) << "Kademlia config file has no bootstrap nodes\n";
        return -1;
      }
    }
  }
  catch(const std::exception ex) {
    DLOG(ERROR) << "Failed to access kademlia config file " << kad_config_path_
        << ". Error: " << ex.what() << std::endl;
    return -1;
  }
  bootstrapping_nodes_.clear();
  for (int i = 0; i < kad_config.contact_size(); ++i) {
    std::string dec_id = base::DecodeFromHex(kad_config.contact(i).node_id());
    Contact bootstrap_contact(dec_id, kad_config.contact(i).ip(),
        static_cast<boost::uint16_t>(kad_config.contact(i).port()),
        kad_config.contact(i).local_ip(), kad_config.contact(i).local_port());
    bootstrapping_nodes_.push_back(bootstrap_contact);
  }
  return 0;
}

void KNodeImpl::RefreshRoutine() {
  if (is_joined_) {
    SaveBootstrapContacts();
    // Refresh the k-buckets
    pdata_store_->DeleteExpiredValues();
    StartSearchIteration(node_id_, FIND_NODE, &dummy_callback);
    // schedule the next refresh routine
    ptimer_->AddCallLater(kRefreshTime*1000,
                          boost::bind(&KNodeImpl::RefreshRoutine, this));
  } else {
    refresh_routine_started_ = false;
  }
}

void KNodeImpl::StoreValue_IterativeStoreValue(
    const StoreResponse *response,
    StoreCallbackArgs callback_data) {
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
            callback_data.remote_ctc.host_ip());
        callback_data.retry = false;
      // send RPC to this contact's remote address because local failed
        google::protobuf::Closure *done1 = google::protobuf::NewCallback<
            KNodeImpl, const StoreResponse*, StoreCallbackArgs > (this,
            &KNodeImpl::StoreValue_IterativeStoreValue, resp, callback_data);
        if (HasRSAKeys()) {
          kadrpcs_.Store(callback_data.data->key, callback_data.data->sig_value,
              callback_data.data->sig_request,
              callback_data.remote_ctc.host_ip(),
              callback_data.remote_ctc.host_port(),
              callback_data.remote_ctc.rendezvous_ip(),
              callback_data.remote_ctc.rendezvous_port(),
              resp, callback_data.rpc_ctrler, done1, callback_data.data->ttl,
              callback_data.data->publish);
        } else {
          kadrpcs_.Store(callback_data.data->key, callback_data.data->value,
              callback_data.remote_ctc.host_ip(),
              callback_data.remote_ctc.host_port(),
              callback_data.remote_ctc.rendezvous_ip(),
              callback_data.remote_ctc.rendezvous_port(),
              resp, callback_data.rpc_ctrler, done1, callback_data.data->ttl,
              callback_data.data->publish);
        }
        return;
      }
    }
    if (response->IsInitialized() && !callback_data.rpc_ctrler->Failed()) {
      if (response->result() == kRpcResultSuccess) {
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
      store_value_result.set_result(kRpcResultSuccess);
    } else if (del_req.IsInitialized()) {
      // While refreshing a value, found that it has been Deleted with the
      // Delete RPC
      store_value_result.set_result(kRpcResultFailure);
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
      store_value_result.set_result(kRpcResultFailure);
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
      next_node.local_ip(), next_node.local_port(), next_node.host_ip());
    std::string contact_ip, rendezvous_ip("");
    boost::uint16_t contact_port, rendezvous_port(0);
    if (conn_type == LOCAL) {
      callback_args.retry = true;
      contact_ip = next_node.local_ip();
      contact_port = next_node.local_port();
    } else {
      contact_ip = next_node.host_ip();
      contact_port = next_node.host_port();
      rendezvous_ip = next_node.rendezvous_ip();
      rendezvous_port = next_node.rendezvous_port();
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<
        KNodeImpl, const StoreResponse*, StoreCallbackArgs > (
            this, &KNodeImpl::StoreValue_IterativeStoreValue, resp,
            callback_args);

    if (callback_data.data->sig_value.IsInitialized()) {
      kadrpcs_.Store(callback_data.data->key, callback_data.data->sig_value,
          callback_data.data->sig_request,
          contact_ip, contact_port, rendezvous_ip, rendezvous_port,
          resp, callback_args.rpc_ctrler, done, callback_data.data->ttl,
          callback_data.data->publish);
    } else {
      kadrpcs_.Store(callback_data.data->key, callback_data.data->value,
          contact_ip, contact_port, rendezvous_ip, rendezvous_port, resp,
          callback_args.rpc_ctrler, done, callback_data.data->ttl,
          callback_data.data->publish);
    }
  }
}

void KNodeImpl::StoreValue_ExecuteStoreRPCs(const std::string &result,
                                            const KadId &key,
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
  if ((is_valid) || (result_msg.result() == kRpcResultSuccess)) {
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
          stored_local = KadId::CloserToTarget(node_id_,
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
            DLOG(INFO) << "StoreValue_ExecuteStoreRPCs storing locally\n";
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
    local_result.set_result(kRpcResultFailure);
    std::string local_result_str(local_result.SerializeAsString());
    callback(local_result_str);
  } else {
    CallbackWithFailure(callback);
  }
}

void KNodeImpl::StoreValue(const KadId &key, const SignedValue &signed_value,
                           const SignedRequest &signed_request,
                           const boost::int32_t &ttl,
                           VoidFunctorOneString callback) {
  if (!signed_value.IsInitialized() || !signed_request.IsInitialized()) {
    StoreResponse resp;
    resp.set_result(kad::kRpcResultFailure);
    std::string ser_resp(resp.SerializeAsString());
    callback(ser_resp);
    return;
  }
  FindKClosestNodes(key, boost::bind(&KNodeImpl::StoreValue_ExecuteStoreRPCs,
                    this, _1, key, "", signed_value, signed_request, true, ttl,
                    callback));
}

void KNodeImpl::StoreValue(const KadId &key, const std::string &value,
                           const boost::int32_t &ttl,
                           VoidFunctorOneString callback) {
  SignedValue svalue;
  SignedRequest sreq;
  FindKClosestNodes(key, boost::bind(&KNodeImpl::StoreValue_ExecuteStoreRPCs,
                    this, _1, key, value, svalue, sreq, true, ttl, callback));
}

void KNodeImpl::FindValue(const KadId &key, const bool &check_alternative_store,
                          VoidFunctorOneString callback) {
  // Search in own alternative store first if check_alternative_store == true
  kad::FindResponse result_msg;
  if (check_alternative_store && alternative_store_ != NULL) {
    if (alternative_store_->Has(key.String())) {
      result_msg.set_result(kad::kRpcResultSuccess);
      *result_msg.mutable_alternative_value_holder() = contact_info();
      DLOG(INFO) << "In KNodeImpl::FindValue - node " <<
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
    result_msg.set_result(kad::kRpcResultSuccess);
    if (HasRSAKeys()) {
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

void KNodeImpl::FindNode_GetNode(const std::string &result,
                                 const KadId &node_id,
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
  if ((is_valid)||(result_msg.result() == kRpcResultSuccess)) {
    for (int i = 0; i < result_msg.closest_nodes_size(); ++i) {
      Contact node;
      node.ParseFromString(result_msg.closest_nodes(i));
      if (node.node_id() == node_id) {
        find_node_result.set_result(kRpcResultSuccess);
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
  find_node_result.set_result(kRpcResultFailure);
  find_node_result.SerializeToString(&find_node_result_str);
  callback(find_node_result_str);
}

void KNodeImpl::GetNodeContactDetails(const KadId &node_id,
                                      VoidFunctorOneString callback,
                                      const bool &local) {
  if (!local) {
    FindKClosestNodes(node_id, boost::bind(&KNodeImpl::FindNode_GetNode, this,
                      _1, node_id, callback));
  } else {
    FindNodeResult result;
    std::string ser_result;
    Contact contact;
    if (GetContact(node_id, &contact)) {
      result.set_result(kRpcResultSuccess);
      std::string ser_contact;
      contact.SerialiseToString(&ser_contact);
      result.set_contact(ser_contact);
    } else {
      result.set_result(kRpcResultFailure);
    }
    result.SerializeToString(&ser_result);
    callback(ser_result);
  }
}

void KNodeImpl::FindKClosestNodes(const KadId &node_id,
                                  VoidFunctorOneString callback) {
  std::vector<Contact> start_up_short_list;
  StartSearchIteration(node_id, FIND_NODE, callback);
}

void KNodeImpl::GetKNodesFromRoutingTable(
    const KadId &key,
    const std::vector<Contact> &exclude_contacts,
    std::vector<Contact> *close_nodes) {
  boost::mutex::scoped_lock gaurd(routingtable_mutex_);
  prouting_table_->FindCloseNodes(key, K_, exclude_contacts, close_nodes);
}

void KNodeImpl::Ping_HandleResult(const PingResponse *response,
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
          callback_data.remote_ctc.host_ip());
      callback_data.retry = false;
      google::protobuf::Closure *done = google::protobuf::NewCallback<
          KNodeImpl, const PingResponse*, PingCallbackArgs > (
              this, &KNodeImpl::Ping_HandleResult, resp, callback_data);
      kadrpcs_.Ping(callback_data.remote_ctc.host_ip(),
          callback_data.remote_ctc.host_port(),
          callback_data.remote_ctc.rendezvous_ip(),
          callback_data.remote_ctc.rendezvous_port(),
          resp, callback_data.rpc_ctrler, done);
      return;
    }
  }

  PingResponse result_msg;
  if (!response->IsInitialized() || callback_data.rpc_ctrler->Failed()) {
    result_msg.set_result(kRpcResultFailure);
    RemoveContact(callback_data.remote_ctc.node_id());
  } else {
    result_msg = *response;
    if (response->result() == kRpcResultSuccess) {
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

void KNodeImpl::Ping_SendPing(const std::string &result,
                              VoidFunctorOneString callback) {
  if (!is_joined_)
    return;
  FindNodeResult result_msg;
  if (result_msg.ParseFromString(result))
    if (result_msg.result() == kRpcResultSuccess) {
      Contact remote;
      if (remote.ParseFromString(result_msg.contact())) {
        Ping(remote, callback);
        return;
      }
    }
  // Failed to get any result
  PingResponse ping_result;
  ping_result.set_result(kRpcResultFailure);
  std::string ping_result_str(ping_result.SerializeAsString());
  callback(ping_result_str);
}

void KNodeImpl::Ping(const KadId &node_id, VoidFunctorOneString callback) {
  GetNodeContactDetails(node_id, boost::bind(&KNodeImpl::Ping_SendPing, this,
                                             _1, callback), false);
}

void KNodeImpl::Ping(const Contact &remote, VoidFunctorOneString callback) {
  if (!is_joined_) {
    PingResponse resp;
    resp.set_result(kRpcResultFailure);
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
                                                        remote.host_ip());
    std::string contact_ip, rendezvous_ip;
    boost::uint16_t contact_port, rendezvous_port(0);
    if (conn_type == LOCAL) {
      callback_args.retry = true;
      contact_ip = remote.local_ip();
      contact_port = remote.local_port();
    } else {
      contact_ip = remote.host_ip();
      contact_port = remote.host_port();
      rendezvous_ip = remote.rendezvous_ip();
      rendezvous_port = remote.rendezvous_port();
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<
        KNodeImpl, const PingResponse*, PingCallbackArgs >
        (this, &KNodeImpl::Ping_HandleResult, resp, callback_args);
    kadrpcs_.Ping(contact_ip, contact_port, rendezvous_ip, rendezvous_port,
                  resp, callback_args.rpc_ctrler, done);
  }
}

int KNodeImpl::AddContact(Contact new_contact, const float & rtt,
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
    std::string remote_ip, rendezvous_ip;
    remote_ip = base::IpBytesToAscii(new_contact.host_ip());
    if (!new_contact.rendezvous_ip().empty()) {
      rendezvous_ip = base::IpBytesToAscii(new_contact.rendezvous_ip());
    }
    base::PublicRoutingTableTuple tuple(new_contact.node_id().String(),
                                        remote_ip,
                                        new_contact.host_port(),
                                        rendezvous_ip,
                                        new_contact.rendezvous_port(),
                                        new_contact.node_id().String(),
                                        rtt, 0, 0);
    (*base::PublicRoutingTable::GetInstance())[boost::lexical_cast<std::string>
        (host_port_)]->AddTuple(tuple);
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

void KNodeImpl::RemoveContact(const KadId &node_id) {
  (*base::PublicRoutingTable::GetInstance())[boost::lexical_cast<std::string>
      (host_port_)]->DeleteTupleByKadId(node_id.String());
  boost::mutex::scoped_lock gaurd(routingtable_mutex_);
  prouting_table_->RemoveContact(node_id, false);
}

bool KNodeImpl::GetContact(const KadId &id, Contact *contact) {
  boost::mutex::scoped_lock gaurd(routingtable_mutex_);
  return prouting_table_->GetContact(id, contact);
}

bool KNodeImpl::FindValueLocal(const KadId &key,
                               std::vector<std::string> *values) {
  return pdata_store_->LoadItem(key.String(), values);
}

bool KNodeImpl::StoreValueLocal(const KadId &key, const std::string &value,
                                const boost::int32_t &ttl) {
  bool hashable = false;
  std::string str_key(key.String());
  if (HasRSAKeys()) {
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

bool KNodeImpl::RefreshValueLocal(const KadId &key, const std::string &value,
                                  const boost::int32_t &ttl) {
  std::string ser_del_request;
  if (pdata_store_->RefreshItem(key.String(), value, &ser_del_request))
    return true;
  return StoreValueLocal(key, value, ttl);
}

void KNodeImpl::GetRandomContacts(const size_t &count,
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

void KNodeImpl::HandleDeadRendezvousServer(const bool &dead_server ) {
  if (stopping_)
    return;
  if (dead_server) {
    DLOG(WARNING) << "(" << local_host_port_ << ")--Failed to ping RV server\n";
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
        if (transport_handler_->CanConnect(ctcs[i].host_ip(),
            ctcs[i].host_port(), transport_id_)) {
          transport_handler_->StartPingRendezvous(false, ctcs[i].host_ip(),
                                                  ctcs[i].host_port(),
                                                  transport_id_);
          return;
        }
      }
    }
    // setting status to be offline
    base::OnlineController::Instance()->SetOnline(local_host_port_, false);
    Leave();
    stopping_ = false;
    Join(node_id_, kad_config_path_.string(),
         boost::bind(&KNodeImpl::ReBootstrapping_Callback, this, _1));
  }
}

void KNodeImpl::ReBootstrapping_Callback(const std::string &result) {
  base::GeneralResponse local_result;
  if (stopping_) {
    return;
  }
  if (!local_result.ParseFromString(result) ||
      local_result.result() == kRpcResultFailure) {
    // TODO(David): who should we inform if after trying to bootstrap again
    // because the rendezvous server died, the bootstrap operation fails?
    DLOG(WARNING) << "(" << local_host_port_ << ") -- Failed to rejoin ..."
        << " Retrying.\n";
    is_joined_ = false;
    stopping_ = false;
    Join(node_id_, kad_config_path_.string(),
         boost::bind(&KNodeImpl::ReBootstrapping_Callback, this, _1));
  } else {
    DLOG(INFO) << "(" << local_host_port_ << ") Rejoining successful.\n";
    is_joined_ = true;
    premote_service_->set_node_joined(true);
    premote_service_->set_node_info(contact_info());
  }
}

void KNodeImpl::RegisterKadService() {
  premote_service_.reset(new KadService(
      natrpcs_,
      pdata_store_,
      HasRSAKeys(),
      boost::bind(&KNodeImpl::AddContact, this, _1, _2, _3),
      boost::bind(&KNodeImpl::GetRandomContacts, this, _1, _2, _3),
      boost::bind(&KNodeImpl::GetContact, this, _1, _2),
      boost::bind(&KNodeImpl::GetKNodesFromRoutingTable, this, _1, _2, _3),
      boost::bind(static_cast<void(KNodeImpl::*)(const Contact&,
                  VoidFunctorOneString)>(&KNodeImpl::Ping), this, _1, _2),
      boost::bind(&KNodeImpl::RemoveContact, this, _1)));
  premote_service_->set_node_info(contact_info());
  premote_service_->set_alternative_store(alternative_store_);
  premote_service_->set_signature_validator(signature_validator_);
  pservice_channel_.reset(new rpcprotocol::Channel(pchannel_manager_,
                                                   transport_handler_));
  pservice_channel_->SetService(premote_service_.get());
  pchannel_manager_->RegisterChannel(
      premote_service_->GetDescriptor()->name(), pservice_channel_.get());
}

void KNodeImpl::UnRegisterKadService() {
  pchannel_manager_->UnRegisterChannel(
      premote_service_->GetDescriptor()->name());
  pchannel_manager_->ClearCallLaters();
  pservice_channel_.reset();
  premote_service_.reset();
}

ConnectionType KNodeImpl::CheckContactLocalAddress(const KadId &id,
                                                   const std::string &ip,
                                                   const boost::uint16_t &port,
                                                   const std::string &ext_ip) {
  if (ip.empty() || port == 0)
    return REMOTE;
  std::string str_id(id.String());
  int result = (*base::PublicRoutingTable::GetInstance())
               [boost::lexical_cast<std::string>(host_port_)]->ContactLocal(
                   str_id);
  ConnectionType conn_type(UNKNOWN);
  std::string ext_ip_dec;
  switch (result) {
    case LOCAL: conn_type = LOCAL;
                break;
    case REMOTE: conn_type = REMOTE;
                 break;
    case UNKNOWN: ext_ip_dec = base::IpBytesToAscii(ext_ip);
                  if (host_ip_ != ext_ip_dec) {
                    conn_type = REMOTE;
                  } else if (transport_handler_->CanConnect(ip, port,
                                                            transport_id_)) {
                    conn_type = LOCAL;
                    (*base::PublicRoutingTable::GetInstance())
                        [base::IntToString(host_port_)]->UpdateContactLocal(
                            str_id, ip, conn_type);
                  } else {
                    conn_type = REMOTE;
                    (*base::PublicRoutingTable::GetInstance())[
                        base::IntToString(host_port_)]->UpdateContactLocal(
                        str_id, ext_ip, conn_type);
                  }
                  break;
  }
  return conn_type;
}

void KNodeImpl::UPnPMap(boost::uint16_t host_port) {
  // Get a UPnP mapping port
  upnp_mapped_port_ = 0;
  DLOG(INFO) << "Initialising UPNP\n";
  // ignore result, in case it's already initialised
  upnp_.InitControlPoint();

  DLOG(INFO) << "Mapping local port " << host_port << std::endl;
  if (upnp_.AddPortMapping(host_port, upnp::kUdp)) {
    upnp_mapped_port_ = host_port;
    host_ip_ = upnp_.GetExternalIpAddress();
    host_port_ = upnp_mapped_port_;
    DLOG(INFO) << "Successfully mapped to " << host_ip_ << ":" <<
        upnp_mapped_port_ << std::endl;
  } else {
    DLOG(ERROR) << "UPnP port mappin failed" << std::endl;
  }
}

void KNodeImpl::UnMapUPnP() {
  DLOG(INFO) << "Deleting the UPnP mapped port\n";
  upnp_.DeletePortMapping(upnp_mapped_port_, upnp::kUdp);
  upnp_mapped_port_ = 0;
}

void KNodeImpl::UpdatePDRTContactToRemote(const KadId &node_id,
                                          const std::string &host_ip) {
  (*base::PublicRoutingTable::GetInstance())[base::IntToString(host_port_)]->
      UpdateContactLocal(node_id.String(), host_ip, REMOTE);
}

ContactInfo KNodeImpl::contact_info() const {
  ContactInfo info;
  if (host_ip_.size() > 4) {
    info.set_ip(base::IpAsciiToBytes(host_ip_));
  } else {
    info.set_ip(host_ip_);
  }
  if (local_host_ip_.size() > 4) {
    info.set_local_ip(base::IpAsciiToBytes(local_host_ip_));
  } else {
    info.set_local_ip(local_host_ip_);
  }
  if (rv_ip_.size() > 4) {
    info.set_rendezvous_ip(base::IpAsciiToBytes(rv_ip_));
  } else {
    info.set_rendezvous_ip(rv_ip_);
  }
  if (type_ == CLIENT || type_ == CLIENT_PORT_MAPPED) {
    info.set_node_id(fake_kClientId_.String());
  } else {
    info.set_node_id(node_id_.String());
  }
  info.set_port(host_port_);
  info.set_local_port(local_host_port_);
  info.set_rendezvous_port(rv_port_);
  return info;
}

void KNodeImpl::CheckToInsert(const Contact &new_contact) {
  if (!is_joined_)
    return;
  int index = prouting_table_->KBucketIndex(new_contact.node_id());
  Contact last_seen;
  last_seen = prouting_table_->GetLastSeenContact(index);
  DLOG(INFO) << "Pinging last seen node in routing table to try to insert " <<
    "to try to insert contact\n" << new_contact.DebugString();
  Ping(last_seen,
       boost::bind(&KNodeImpl::CheckToInsert_Callback, this, _1,
                   new_contact.node_id(), new_contact));
}

void KNodeImpl::CheckToInsert_Callback(const std::string &result, KadId id,
                                       Contact new_contact) {
  if (!is_joined_)
    return;
  PingResponse result_msg;
  if (!result_msg.ParseFromString(result) ||
      result_msg.result() != kRpcResultSuccess) {
    boost::mutex::scoped_lock gaurd(routingtable_mutex_);
    prouting_table_->RemoveContact(id, true);
    prouting_table_->AddContact(new_contact);
  }
}

void KNodeImpl::CheckAddContacts() {
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

void KNodeImpl::StartSearchIteration(const KadId &key,
                                     const RemoteFindMethod &method,
                                     VoidFunctorOneString callback) {
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
  boost::shared_ptr<IterativeLookUpData> data(new IterativeLookUpData(method,
      key, callback));
  for (unsigned int i = 0; i < close_nodes.size(); ++i) {
    struct LookupContact ctc;
    ctc.kad_contact = close_nodes[i];
    data->short_list.push_back(ctc);
  }
  SearchIteration(data);
}

void KNodeImpl::SendFindRpc(Contact remote,
                            boost::shared_ptr<IterativeLookUpData> data,
                            const ConnectionType &conn_type) {
  if (!is_joined_ && data->method != BOOTSTRAP)
    return;
  FindResponse *resp = new FindResponse;
  FindCallbackArgs callback_args(data);
  callback_args.remote_ctc = remote;
  callback_args.rpc_ctrler = new rpcprotocol::Controller;
  std::string contact_ip, rendezvous_ip("");
  boost::uint16_t contact_port, rendezvous_port(0);
  if (conn_type == LOCAL) {
    callback_args.retry = true;
    contact_ip = remote.local_ip();
    contact_port = remote.local_port();
  } else {
    contact_ip = remote.host_ip();
    contact_port = remote.host_port();
    rendezvous_ip = remote.rendezvous_ip();
    rendezvous_port = remote.rendezvous_port();
  }
  google::protobuf::Closure *done = google::protobuf::NewCallback
      <KNodeImpl, const FindResponse*, FindCallbackArgs>
      (this, &KNodeImpl::SearchIteration_ExtendShortList, resp, callback_args);
  if (data->method == FIND_NODE || data->method == BOOTSTRAP) {
    if (data->method == BOOTSTRAP) {
      kad::Contact tmp_contact(node_id(), host_ip_, host_port_, local_host_ip_,
          local_host_port_, rv_ip_, rv_port_);
      std::string contact_str;
      tmp_contact.SerialiseToString(&contact_str);
      resp->set_requester_ext_addr(contact_str);
    }
    if (data->key == remote.node_id())
      data->wait_for_key = true;
    kadrpcs_.FindNode(data->key, contact_ip, contact_port, rendezvous_ip,
                      rendezvous_port, resp, callback_args.rpc_ctrler, done);
  } else if (data->method == FIND_VALUE) {
    kadrpcs_.FindValue(data->key, contact_ip, contact_port, rendezvous_ip,
                       rendezvous_port, resp, callback_args.rpc_ctrler, done);
  } else {
    delete done;
    delete resp;
    delete callback_args.rpc_ctrler;
  }
}

void KNodeImpl::SearchIteration(boost::shared_ptr<IterativeLookUpData> data) {
  if ((data->is_callbacked)||(!is_joined_ && data->method != BOOTSTRAP))
    return;
  // Found an alternative value holder or the actual value
  if (data->method == FIND_VALUE && (!data->values_found.empty() ||
      !data->sig_values_found.empty() ||
      !data->alternative_value_holder.node_id().empty()))
    SearchIteration_Callback(data);

  // sort the active contacts
  SortContactList(&data->active_contacts, data->key);
  // sort the short_list
  SortLookupContact(&data->short_list, data->key);
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
            pending_to_contact[i].host_ip());
        SendFindRpc(pending_to_contact[i], data, conn_type);
      }
    }
  }
}

void KNodeImpl::SearchIteration_ExtendShortList(
    const FindResponse *response,
    FindCallbackArgs callback_data) {
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
                                  callback_data.remote_ctc.host_ip());
        SendFindRpc(callback_data.remote_ctc, callback_data.data, REMOTE);
        return;
      }
    }
  }

  if (!is_valid || response->result() == kRpcResultFailure) {
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
    std::list<kad::SignedValue>::iterator it_svals;
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
        Contact self_node(node_id_, host_ip_, host_port_, local_host_ip_,
                          local_host_port_);
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

void KNodeImpl::SendFinalIteration(
    boost::shared_ptr<IterativeLookUpData> data) {
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
          pending_to_contact[i].local_port(), pending_to_contact[i].host_ip());
      SendFindRpc(pending_to_contact[i], data, conn_type);
    }
  }
}

void KNodeImpl::FinalIteration(boost::shared_ptr<IterativeLookUpData> data) {
  if ((data->is_callbacked)||(!is_joined_ && data->method != BOOTSTRAP))
    return;

  activeprobes_mutex_.lock();
  if (!data->active_probes.empty()) {
    activeprobes_mutex_.unlock();
    return;
  }
  activeprobes_mutex_.unlock();

  // sort the active contacts
  SortContactList(&data->active_contacts, data->key);
  // check whether thare are any closer nodes
  SortLookupContact(&data->short_list, data->key);

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
                                                            remote.host_ip());
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

void KNodeImpl::SearchIteration_CancelActiveProbe(
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

void KNodeImpl::SearchIteration_Callback(
    boost::shared_ptr<IterativeLookUpData> data) {
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
      result.set_result(kRpcResultFailure);
      is_joined_ = false;
    } else {
      result.set_result(kRpcResultSuccess);
      if (!is_joined_) {
        is_joined_ = true;
        premote_service_->set_node_joined(true);
        premote_service_->set_node_info(contact_info());
        addcontacts_routine_.reset(new boost::thread(
            &KNodeImpl::CheckAddContacts, this));
        // start a schedule to delete expired key/value pairs only once
        if (!refresh_routine_started_) {
          ptimer_->AddCallLater(kRefreshTime * 1000,
                                boost::bind(&KNodeImpl::RefreshRoutine, this));
          ptimer_->AddCallLater(2000,
                                boost::bind(&KNodeImpl::RefreshValuesRoutine,
                                            this));
          refresh_routine_started_ = true;
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
      result.set_result(kRpcResultSuccess);
      *result.mutable_alternative_value_holder() =
          data->alternative_value_holder;
    } else if (data->method == FIND_VALUE && (!data->values_found.empty() ||
               !data->sig_values_found.empty())) {
      result.set_result(kRpcResultSuccess);
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
        result.set_result(kRpcResultSuccess);
      else
        result.set_result(kRpcResultFailure);
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

void KNodeImpl::SendDownlist(boost::shared_ptr<IterativeLookUpData> data) {
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
          it1->giver.local_ip(), it1->giver.local_port(), it1->giver.host_ip());
      std::string contact_ip, rendezvous_ip("");
      boost::uint16_t contact_port, rendezvous_port(0);
      if (conn_type == LOCAL) {
        contact_ip = it1->giver.local_ip();
        contact_port = it1->giver.local_port();
      } else {
        contact_ip = it1->giver.host_ip();
        contact_port = it1->giver.host_port();
        rendezvous_ip = it1->giver.rendezvous_ip();
        rendezvous_port = it1->giver.rendezvous_port();
      }
      DownlistResponse *resp = new DownlistResponse;
      rpcprotocol::Controller *ctrl = new rpcprotocol::Controller;
      google::protobuf::Closure *done = google::protobuf::NewCallback
          <DownlistResponse*, rpcprotocol::Controller*>
          (&dummy_downlist_callback, resp, ctrl);
      kadrpcs_.Downlist(downlist, contact_ip, contact_port, rendezvous_ip,
                        rendezvous_port, resp, ctrl, done);
    }
  }
  data->downlist_sent = true;
  // End of downlist
}

boost::uint32_t KNodeImpl::KeyLastRefreshTime(const KadId &key,
                                              const std::string &value) {
  return pdata_store_->LastRefreshTime(key.String(), value);
}

boost::uint32_t KNodeImpl::KeyExpireTime(const KadId &key,
                                         const std::string &value) {
  return pdata_store_->ExpireTime(key.String(), value);
}

bool KNodeImpl::HasRSAKeys() {
  if (private_key_.empty() || public_key_.empty())
    return false;
  return true;
}

boost::int32_t KNodeImpl::KeyValueTTL(const KadId &key,
                                      const std::string &value) const {
  return pdata_store_->TimeToLive(key.String(), value);
}

void KNodeImpl::RefreshValue(const KadId &key, const std::string &value,
                             const boost::int32_t &ttl,
                             VoidFunctorOneString callback) {
  if (!is_joined_ || !refresh_routine_started_  || stopping_)
    return;
  SignedRequest sreq;
  SignedValue svalue;
  if (HasRSAKeys()) {
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
    FindKClosestNodes(key, boost::bind(&KNodeImpl::StoreValue_ExecuteStoreRPCs,
                                       this, _1, key, "", svalue, sreq, false,
                                       ttl, callback));
  } else {
    FindKClosestNodes(key, boost::bind(&KNodeImpl::StoreValue_ExecuteStoreRPCs,
                                       this, _1, key, value, svalue, sreq,
                                       false, ttl, callback));
  }
}

void KNodeImpl::RefreshValueCallback(
    const std::string &result, const KadId &key, const std::string &value,
    const boost::int32_t &ttl,
    boost::shared_ptr<boost::uint32_t> refreshes_done,
    const boost::uint32_t &total_refreshes) {
  if (!is_joined_ || !refresh_routine_started_  || stopping_)
    return;
  StoreResponse refresh_result;
  if (!refresh_result.ParseFromString(result) ||
      refresh_result.result() == kRpcResultSuccess ||
      !refresh_result.has_signed_request())
    RefreshValueLocal(key, value, ttl);
  ++(*refreshes_done);
  if (total_refreshes == *refreshes_done) {
    ptimer_->AddCallLater(2000, boost::bind(&KNodeImpl::RefreshValuesRoutine,
                                            this));
  }
}

void KNodeImpl::RefreshValuesRoutine() {
  if (is_joined_ && refresh_routine_started_  && !stopping_) {
    std::vector<refresh_value> values = pdata_store_->ValuesToRefresh();
    if (values.empty()) {
      ptimer_->AddCallLater(2000, boost::bind(&KNodeImpl::RefreshValuesRoutine,
                                              this));
    } else  {
      boost::shared_ptr<boost::uint32_t> refreshes_done(new boost::uint32_t(0));
      // *refreshes_done = 0;
      for (size_t i = 0; i < values.size(); ++i) {
        KadId id_key;
        switch (values[i].del_status_) {
          case NOT_DELETED: id_key = KadId(values[i].key_);
                            RefreshValue(
                                id_key, values[i].value_, values[i].ttl_,
                                boost::bind(&KNodeImpl::RefreshValueCallback,
                                            this, _1, id_key, values[i].value_,
                                            values[i].ttl_, refreshes_done,
                                            values.size()));
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

void KNodeImpl::DeleteValue(const KadId &key, const SignedValue &signed_value,
                            const SignedRequest &signed_request,
                            VoidFunctorOneString callback) {
  if (!signed_value.IsInitialized() || !signed_request.IsInitialized()) {
    DeleteResponse resp;
    resp.set_result(kad::kRpcResultFailure);
    std::string ser_resp(resp.SerializeAsString());
    callback(ser_resp);
    return;
  }
  FindKClosestNodes(key, boost::bind(&KNodeImpl::DelValue_ExecuteDeleteRPCs,
                                     this, _1, key, signed_value,
                                     signed_request, callback));
}

void KNodeImpl::DelValue_ExecuteDeleteRPCs(const std::string &result,
                                           const KadId &key,
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
  if ((is_valid) || (result_msg.result() == kRpcResultSuccess)) {
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
    local_result.set_result(kRpcResultFailure);
    std::string local_result_str(local_result.SerializeAsString());
    callback(local_result_str);
  } else {
    DeleteResponse local_result;
    local_result.set_result(kRpcResultFailure);
    std::string local_result_str(local_result.SerializeAsString());
    callback(local_result_str);
  }
}

bool KNodeImpl::DelValueLocal(const KadId &key, const SignedValue &value,
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

void KNodeImpl::DelValue_IterativeDeleteValue(
    const DeleteResponse *response,
    DeleteCallbackArgs callback_data) {
  if (!is_joined_)
    return;
  if (callback_data.data->is_callbacked)
    // Only call back once
    return;

  if (response != NULL) {
    if (response->IsInitialized() && response->has_node_id() &&
        response->node_id() !=
          callback_data.remote_ctc.node_id().String()) {
      if (callback_data.retry) {
        delete response;
        DeleteResponse *resp = new DeleteResponse;
        UpdatePDRTContactToRemote(callback_data.remote_ctc.node_id(),
            callback_data.remote_ctc.host_ip());
        callback_data.retry = false;
      // send RPC to this contact's remote address because local failed
        google::protobuf::Closure *done1 = google::protobuf::NewCallback
            <KNodeImpl, const DeleteResponse*, DeleteCallbackArgs>
            (this, &KNodeImpl::DelValue_IterativeDeleteValue, resp,
             callback_data);
        kadrpcs_.Delete(callback_data.data->key, callback_data.data->value,
                        callback_data.data->sig_request,
                        callback_data.remote_ctc.host_ip(),
                        callback_data.remote_ctc.host_port(),
                        callback_data.remote_ctc.rendezvous_ip(),
                        callback_data.remote_ctc.rendezvous_port(), resp,
                        callback_data.rpc_ctrler, done1);
        return;
      }
    }
    if (response->IsInitialized() && !callback_data.rpc_ctrler->Failed()) {
      if (response->result() == kRpcResultSuccess) {
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
      del_value_result.set_result(kRpcResultSuccess);
    } else {
      del_value_result.set_result(kRpcResultFailure);
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
                                                        next_node.host_ip());
    std::string contact_ip, rendezvous_ip;
    boost::uint16_t contact_port, rendezvous_port(0);
    if (conn_type == LOCAL) {
      callback_args.retry = true;
      contact_ip = next_node.local_ip();
      contact_port = next_node.local_port();
    } else {
      contact_ip = next_node.host_ip();
      contact_port = next_node.host_port();
      rendezvous_ip = next_node.rendezvous_ip();
      rendezvous_port = next_node.rendezvous_port();
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback
        <KNodeImpl, const DeleteResponse*, DeleteCallbackArgs >
        (this, &KNodeImpl::DelValue_IterativeDeleteValue, resp, callback_args);

    kadrpcs_.Delete(callback_data.data->key, callback_data.data->value,
                    callback_data.data->sig_request, contact_ip, contact_port,
                    rendezvous_ip, rendezvous_port, resp,
                    callback_args.rpc_ctrler, done);
  }
}

void KNodeImpl::UpdateValue(const KadId &key,
                            const SignedValue &old_value,
                            const SignedValue &new_value,
                            const SignedRequest &signed_request,
                            boost::uint32_t ttl,
                            VoidFunctorOneString callback) {
  if (!old_value.IsInitialized() || !new_value.IsInitialized() ||
      !signed_request.IsInitialized()) {
    DeleteResponse resp;
    resp.set_result(kad::kRpcResultFailure);
    std::string ser_resp(resp.SerializeAsString());
    callback(ser_resp);
    DLOG(WARNING) << "KNodeImpl::UpdateValue - uninitialised values or request"
                  << std::endl;
    return;
  }
  FindKClosestNodes(key, boost::bind(&KNodeImpl::ExecuteUpdateRPCs,
                                     this, _1, key, old_value, new_value,
                                     signed_request, ttl, callback));
}

void KNodeImpl::ExecuteUpdateRPCs(const std::string &result,
                                  const KadId &key,
                                  const SignedValue &old_value,
                                  const SignedValue &new_value,
                                  const SignedRequest &sig_req,
                                  boost::uint32_t ttl,
                                  VoidFunctorOneString callback) {
  if (!is_joined_)
    return;

  FindResponse result_msg;
  if (!result_msg.ParseFromString(result) ||
      result_msg.closest_nodes_size() == 0 ||
      result_msg.result() != kRpcResultSuccess) {
    DeleteResponse resp;
    resp.set_result(kad::kRpcResultFailure);
    std::string ser_resp(resp.SerializeAsString());
    callback(ser_resp);
    DLOG(WARNING) << "KNodeImpl::ExecuteUpdateRPCs - failed find nodes"
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
    resp.set_result(kad::kRpcResultFailure);
    std::string ser_resp(resp.SerializeAsString());
    callback(ser_resp);
    DLOG(WARNING) << "KNodeImpl::ExecuteUpdateRPCs - Not enough nodes"
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
                              closest_nodes[n].host_ip());
    uca->controller = new rpcprotocol::Controller;
    google::protobuf::Closure *done = google::protobuf::NewCallback
                                      <KNodeImpl,
                                       boost::shared_ptr<UpdateCallbackArgs> >
                                      (this, &KNodeImpl::UpdateValueResponses,
                                       uca);
    ConnectionType conn_type = CheckContactLocalAddress(
                                   closest_nodes[n].node_id(),
                                   closest_nodes[n].local_ip(),
                                   closest_nodes[n].local_port(),
                                   closest_nodes[n].host_ip());
    std::string contact_ip, rendezvous_ip;
    boost::uint16_t contact_port(0), rendezvous_port(0);
    uca->ct = conn_type;
    if (conn_type == LOCAL) {
      uca->uvd->retries = 1;
      contact_ip = closest_nodes[n].local_ip();
      contact_port = closest_nodes[n].local_port();
    } else {
      contact_ip = closest_nodes[n].host_ip();
      contact_port = closest_nodes[n].host_port();
      rendezvous_ip = closest_nodes[n].rendezvous_ip();
      rendezvous_port = closest_nodes[n].rendezvous_port();
    }
    kadrpcs_.Update(key, new_value, old_value, ttl, sig_req, contact_ip,
                    contact_port, rendezvous_ip, rendezvous_port,
                    uca->response, uca->controller, done);
  }
}

void KNodeImpl::UpdateValueResponses(
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
               <KNodeImpl, boost::shared_ptr<UpdateCallbackArgs> >
               (this, &KNodeImpl::UpdateValueResponses, uca);
        kadrpcs_.Update(uca->uvd->uvd_key, uca->uvd->uvd_new_value,
                        uca->uvd->uvd_old_value, uca->uvd->ttl,
                        uca->uvd->uvd_request_signature, uca->contact.host_ip(),
                        uca->contact.host_port(),
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
      update_result.set_result(kRpcResultFailure);

      DLOG(WARNING) << "KNodeImpl::ExecuteUpdateRPCs - Not enough succ in RPCs"
                    << std::endl;

    } else {
      update_result.set_result(kRpcResultSuccess);
    }
    std::string serialised_result(update_result.SerializeAsString());
    uca->uvd->uvd_callback(serialised_result);
  }
}

void KNodeImpl::RecheckNatRoutine() {
  if (!recheck_nat_type_)
    return;

  // Check routing table
  if (prouting_table_->Size() < size_t(2)) {
    ptimer_->AddCallLater(60 * 1000,
                          boost::bind(&KNodeImpl::RecheckNatRoutine, this));
    return;
  }

  std::vector<Contact> close_nodes;
  prouting_table_->GetFurthestContacts(node_id_, -1, exclude_bs_contacts_,
                                       &close_nodes);
  if (close_nodes.size() < size_t(1)) {
    ptimer_->AddCallLater(60 * 1000,
                          boost::bind(&KNodeImpl::RecheckNatRoutine, this));
    return;
  }

  Leave();
  Join(node_id_, kad_config_path_.string(),
       boost::bind(&KNodeImpl::RecheckNatRoutineJoinCallback, this, _1));
}

void KNodeImpl::RecheckNatRoutineJoinCallback(const std::string &result) {
  base::GeneralResponse gr;
  if (!gr.ParseFromString(result)) {
    ptimer_->AddCallLater(60 * 1000,
                          boost::bind(&KNodeImpl::RecheckNatRoutine, this));
    return;
  }

  if (gr.result() != kRpcResultSuccess) {
    ptimer_->AddCallLater(60 * 1000,
                          boost::bind(&KNodeImpl::RecheckNatRoutine, this));
    return;
  }

  if (recheck_nat_type_ == true) {
    ptimer_->AddCallLater(60 * 1000,
                          boost::bind(&KNodeImpl::RecheckNatRoutine, this));
    return;
  }
}

}  // namespace kad
