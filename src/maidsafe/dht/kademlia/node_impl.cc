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

#include <algorithm>
#include <functional>
#include <map>

#include "maidsafe/common/alternative_store.h"

#include "maidsafe/dht/log.h"
#include "maidsafe/dht/kademlia/node_impl.h"
#include "maidsafe/dht/kademlia/data_store.h"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/dht/kademlia/kademlia.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "maidsafe/dht/kademlia/node_id.h"
#include "maidsafe/dht/kademlia/rpcs.h"
#include "maidsafe/dht/kademlia/return_codes.h"
#include "maidsafe/dht/kademlia/routing_table.h"
#include "maidsafe/dht/kademlia/securifier.h"
#include "maidsafe/dht/kademlia/service.h"
#include "maidsafe/dht/kademlia/utils.h"
#include "maidsafe/dht/transport/tcp_transport.h"

namespace arg = std::placeholders;

namespace maidsafe {
namespace dht {
namespace kademlia {

namespace {
bool FindResultError(int result) {
  return (result != kSuccess &&
          result != kFoundAlternativeStoreHolder &&
          result != kFailedToFindValue);
}
}  // unnamed namespace

NodeImpl::NodeImpl(AsioService &asio_service,                 // NOLINT (Fraser)
                   TransportPtr listening_transport,
                   MessageHandlerPtr message_handler,
                   SecurifierPtr default_securifier,
                   AlternativeStorePtr alternative_store,
                   bool client_only_node,
                   const uint16_t &k,
                   const uint16_t &alpha,
                   const uint16_t &beta,
                   const bptime::time_duration &mean_refresh_interval)
    : asio_service_(asio_service),
      listening_transport_(listening_transport),
      message_handler_(message_handler),
      default_securifier_(default_securifier),
      alternative_store_(alternative_store),
      on_online_status_change_(new OnOnlineStatusChangePtr::element_type),
      client_only_node_(client_only_node),
      k_(k),
      kAlpha_(alpha),
      kBeta_(beta),
      kMeanRefreshInterval_(mean_refresh_interval.is_special() ? 3600 :
                            mean_refresh_interval.total_seconds()),
      kDataStoreCheckInterval_(bptime::seconds(1)),
      data_store_(),
      service_(),
      routing_table_(),
      rpcs_(),
      contact_(),
      joined_(false),
      ping_oldest_contact_(),
      validate_contact_(),
      ping_down_contact_(),
      refresh_data_store_timer_(asio_service_) {}

NodeImpl::~NodeImpl() {
  if (joined_)
    Leave(NULL);
}

void NodeImpl::Join(const NodeId &node_id,
                    std::vector<Contact> bootstrap_contacts,
                    JoinFunctor callback) {
  if (joined_) {
    asio_service_.post(std::bind(&NodeImpl::JoinSucceeded, this, callback));
    return;
  }

  // Remove our own Contact if present
  bootstrap_contacts.erase(
      std::remove_if(bootstrap_contacts.begin(), bootstrap_contacts.end(),
          std::bind(&HasId, arg::_1, node_id)), bootstrap_contacts.end());

  if (!client_only_node_ && listening_transport_->listening_port() == 0) {
    return asio_service_.post(std::bind(&NodeImpl::JoinFailed, this, callback,
                                        kNotListening));
  }

  if (!default_securifier_) {
    crypto::RsaKeyPair key_pair;
    key_pair.GenerateKeys(4096);
    default_securifier_ =
        SecurifierPtr(new Securifier(node_id.String(), key_pair.public_key(),
                                     key_pair.private_key()));
  }

  if (!rpcs_) {
    rpcs_.reset(new Rpcs<transport::TcpTransport>(asio_service_,
                                                  default_securifier_));
  }

  // TODO(Fraser#5#): 2011-07-08 - Need to update code for local endpoints.
  if (!client_only_node_) {
    std::vector<transport::Endpoint> local_endpoints;
    // Create contact_ information for node and set contact for Rpcs
    transport::Endpoint endpoint;
    endpoint.ip = listening_transport_->transport_details().endpoint.ip;
    endpoint.port = listening_transport_->transport_details().endpoint.port;
    local_endpoints.push_back(endpoint);
    contact_ =
        Contact(node_id, endpoint, local_endpoints,
                listening_transport_->transport_details().rendezvous_endpoint,
                false, false, default_securifier_->kSigningKeyId(),
                default_securifier_->kSigningPublicKey(), "");
    rpcs_->set_contact(contact_);
  } else {
    contact_ = Contact(node_id, transport::Endpoint(),
                       std::vector<transport::Endpoint>(),
                       transport::Endpoint(), false, false,
                       default_securifier_->kSigningKeyId(),
                       default_securifier_->kSigningPublicKey(), "");
    protobuf::Contact proto_contact(ToProtobuf(contact_));
    proto_contact.set_node_id(NodeId().String());
    rpcs_->set_contact(FromProtobuf(proto_contact));
  }

  routing_table_.reset(new RoutingTable(node_id, k_));
  // Connect the slots to the routing table signals.
  ConnectPingOldestContact();
  ConnectValidateContact();
  ConnectPingDownContact();

  if (bootstrap_contacts.empty()) {
    // This is the first node on the network.
    asio_service_.post(std::bind(&NodeImpl::JoinSucceeded, this, callback));
    return;
  }

  // Ensure bootstrap contacts are valid
  bootstrap_contacts.erase(std::remove(bootstrap_contacts.begin(),
                                       bootstrap_contacts.end(), Contact()),
                           bootstrap_contacts.end());
  if (bootstrap_contacts.empty()) {
    return asio_service_.post(std::bind(&NodeImpl::JoinFailed, this, callback,
                                        kInvalidBootstrapContacts));
  }

  OrderedContacts search_contacts(CreateOrderedContacts(node_id));
  search_contacts.insert(bootstrap_contacts.front());
  bootstrap_contacts.erase(bootstrap_contacts.begin());
  FindValueArgsPtr find_value_args(
      new FindValueArgs(node_id, k_, search_contacts, true, default_securifier_,
          std::bind(&NodeImpl::JoinFindValueCallback, this, arg::_1,
                    bootstrap_contacts, node_id, callback, true)));
  StartLookup(find_value_args);
}

void NodeImpl::JoinFindValueCallback(FindValueReturns find_value_returns,
                                     std::vector<Contact> bootstrap_contacts,
                                     const NodeId &node_id,
                                     JoinFunctor callback,
                                     bool none_reached) {
  if (!find_value_returns.values_and_signatures.empty()) {
    JoinFailed(callback, kValueAlreadyExists);
    return;
  }
  if (none_reached && !NodeContacted(find_value_returns.return_code) &&
      bootstrap_contacts.empty()) {
    JoinFailed(callback, kContactFailedToRespond);
  } else if ((find_value_returns.return_code != kFailedToFindValue) &&
             !bootstrap_contacts.empty()) {
    if (NodeContacted(find_value_returns.return_code))
      none_reached = false;
    OrderedContacts search_contacts(CreateOrderedContacts(node_id));
    search_contacts.insert(bootstrap_contacts.front());
    bootstrap_contacts.erase(bootstrap_contacts.begin());
    FindValueArgsPtr find_value_args(
        new FindValueArgs(node_id, k_, search_contacts, true,
            default_securifier_, std::bind(&NodeImpl::JoinFindValueCallback,
                                           this, arg::_1, bootstrap_contacts,
                                           node_id, callback, none_reached)));
    StartLookup(find_value_args);
  } else {
    JoinSucceeded(callback);
  }
}

void NodeImpl::JoinSucceeded(JoinFunctor callback) {
  joined_ = true;
  if (!client_only_node_) {
    data_store_.reset(new DataStore(kMeanRefreshInterval_));
    service_.reset(new Service(routing_table_, data_store_,
                               alternative_store_, default_securifier_, k_));
    service_->set_node_joined(true);
    service_->set_node_contact(contact_);
    service_->ConnectToSignals(message_handler_);
    refresh_data_store_timer_.expires_from_now(kDataStoreCheckInterval_);
    refresh_data_store_timer_.async_wait(
        std::bind(&NodeImpl::RefreshDataStore, this, arg::_1));
    data_store_->set_debug_id(DebugId(contact_));
  }
  callback(kSuccess);
}

void NodeImpl::JoinFailed(JoinFunctor callback, int result) {
  callback(result);
}

void NodeImpl::Leave(std::vector<Contact> *bootstrap_contacts) {
  joined_ = false;
  refresh_data_store_timer_.cancel();
  ping_oldest_contact_.disconnect();
  validate_contact_.disconnect();
  ping_down_contact_.disconnect();
  if (!client_only_node_)
    service_.reset();
  GetBootstrapContacts(bootstrap_contacts);
}

template <typename T>
void NodeImpl::NotJoined(T callback) {
  callback(kNotJoined);
}

template <>
void NodeImpl::NotJoined<FindValueFunctor> (FindValueFunctor callback) {
  callback(FindValueReturns(kNotJoined, std::vector<ValueAndSignature>(),
                            std::vector<Contact>(), Contact(), Contact()));
}

template <>
void NodeImpl::NotJoined<FindNodesFunctor> (FindNodesFunctor callback) {
  callback(kNotJoined, std::vector<Contact>());
}

template <>
void NodeImpl::NotJoined<GetContactFunctor> (GetContactFunctor callback) {
  callback(kNotJoined, Contact());
}

template <typename T>
void NodeImpl::FailedValidation(T callback) {
  callback(kFailedValidation);
}

OrderedContacts NodeImpl::GetClosestContactsLocally(
    const Key &key,
    const uint16_t &total_contacts) {
  std::vector<Contact> close_nodes, excludes;
  routing_table_->GetCloseContacts(key, total_contacts, excludes, &close_nodes);
  OrderedContacts close_contacts(CreateOrderedContacts(close_nodes.begin(),
                                                       close_nodes.end(), key));
  // This node's ID will not be held in the routing table, so add it now.  The
  // iterative lookup will take care of the (likely) case that it's not within
  // the requested number of closest contacts.
  if (!client_only_node_)
    close_contacts.insert(contact_);
  return close_contacts;
}

bool NodeImpl::ValidateOrSign(const std::string &value,
                              SecurifierPtr securifier,
                              std::string *signature) {
  if (signature->empty()) {
    *signature = securifier->Sign(value);
    return true;
  } else {
    return securifier->Validate(value, *signature, "",
                                securifier->kSigningPublicKey(), "", "");
  }
}

void NodeImpl::Store(const Key &key,
                     const std::string &value,
                     const std::string &signature,
                     const bptime::time_duration &ttl,
                     SecurifierPtr securifier,
                     StoreFunctor callback) {
  if (!joined_) {
    return asio_service_.post(std::bind(&NodeImpl::NotJoined<StoreFunctor>,
                                        this, callback));
  }

  if (!securifier)
    securifier = default_securifier_;

  std::string sig(signature);
  if (!ValidateOrSign(value, securifier, &sig)) {
    return asio_service_.post(
        std::bind(&NodeImpl::FailedValidation<StoreFunctor>, this, callback));
  }

  OrderedContacts close_contacts(GetClosestContactsLocally(key, k_));
  StoreArgsPtr store_args(new StoreArgs(key, k_, close_contacts,
      static_cast<int>(k_ * kMinSuccessfulPecentageStore), value, sig, ttl,
      securifier, callback));
  StartLookup(store_args);
}

void NodeImpl::Delete(const Key &key,
                      const std::string &value,
                      const std::string &signature,
                      SecurifierPtr securifier,
                      DeleteFunctor callback) {
  if (!joined_) {
    return asio_service_.post(std::bind(&NodeImpl::NotJoined<DeleteFunctor>,
                                        this, callback));
  }

  if (!securifier)
    securifier = default_securifier_;

  std::string sig(signature);
  if (!ValidateOrSign(value, securifier, &sig)) {
    return asio_service_.post(
        std::bind(&NodeImpl::FailedValidation<DeleteFunctor>, this, callback));
  }

  OrderedContacts close_contacts(GetClosestContactsLocally(key, k_));
  DeleteArgsPtr delete_args(new DeleteArgs(key, k_, close_contacts,
      static_cast<int>(k_ * kMinSuccessfulPecentageDelete), value, sig,
      securifier, callback));
  StartLookup(delete_args);
}

void NodeImpl::Update(const Key &key,
                      const std::string &new_value,
                      const std::string &new_signature,
                      const std::string &old_value,
                      const std::string &old_signature,
                      const bptime::time_duration &ttl,
                      SecurifierPtr securifier,
                      UpdateFunctor callback) {
  if (!joined_) {
    return asio_service_.post(std::bind(&NodeImpl::NotJoined<UpdateFunctor>,
                                        this, callback));
  }

  if (!securifier)
    securifier = default_securifier_;

  std::string new_sig(new_signature), old_sig(old_signature);
  if (!ValidateOrSign(old_value, securifier, &old_sig) ||
      !ValidateOrSign(new_value, securifier, &new_sig)) {
    return asio_service_.post(
        std::bind(&NodeImpl::FailedValidation<UpdateFunctor>, this, callback));
  }

  OrderedContacts close_contacts(GetClosestContactsLocally(key, k_));
  UpdateArgsPtr update_args(new UpdateArgs(key, k_, close_contacts,
      static_cast<int>(k_ * kMinSuccessfulPecentageUpdate), old_value,
      old_sig, new_value, new_sig, ttl, securifier, callback));
  StartLookup(update_args);
}

void NodeImpl::FindValue(const Key &key,
                         SecurifierPtr securifier,
                         FindValueFunctor callback,
                         const uint16_t &extra_contacts,
                         bool cache) {
  if (!joined_) {
    return asio_service_.post(std::bind(&NodeImpl::NotJoined<FindValueFunctor>,
                                        this, callback));
  }
  if (!securifier)
    securifier = default_securifier_;
  OrderedContacts close_contacts(
      GetClosestContactsLocally(key, k_ + extra_contacts));

  // If this node is not client-only & is within the k_ closest do a local find.
  if (!client_only_node_) {
    uint16_t closest_count(0);
    auto itr(close_contacts.begin());
    while (itr != close_contacts.end() && closest_count != k_) {
      if (*itr == contact_) {
        std::vector<ValueAndSignature> values_and_sigs;
        std::vector<Contact> contacts;
        if (alternative_store_ && alternative_store_->Has(key.String())) {
          FindValueReturns find_value_returns(kFoundAlternativeStoreHolder,
                                              values_and_sigs, contacts,
                                              contact_, Contact());
          asio_service_.post(std::bind(&NodeImpl::FoundValueLocally, this,
                                       find_value_returns, callback));
          return;
        }
        if (data_store_->GetValues(key.String(), &values_and_sigs)) {
          FindValueReturns find_value_returns(kSuccess, values_and_sigs,
                                              contacts, Contact(), Contact());
          asio_service_.post(std::bind(&NodeImpl::FoundValueLocally, this,
                                       find_value_returns, callback));
          return;
        }
      }
      ++itr;
      ++closest_count;
    }
  }

  FindValueArgsPtr find_value_args(new FindValueArgs(key, k_ + extra_contacts,
      close_contacts, cache, securifier, callback));
  StartLookup(find_value_args);
}

void NodeImpl::FoundValueLocally(const FindValueReturns &find_value_returns,
                                 FindValueFunctor callback) {
  callback(find_value_returns);
}

void NodeImpl::FindNodes(const Key &key,
                         FindNodesFunctor callback,
                         const uint16_t &extra_contacts) {
  if (!joined_) {
    return asio_service_.post(std::bind(&NodeImpl::NotJoined<FindNodesFunctor>,
                                        this, callback));
  }
  OrderedContacts close_contacts(
      GetClosestContactsLocally(key, k_ + extra_contacts));
  FindNodesArgsPtr find_nodes_args(new FindNodesArgs(key, k_ + extra_contacts,
      close_contacts, default_securifier_, callback));
  StartLookup(find_nodes_args);
}

void NodeImpl::GetContact(const NodeId &node_id, GetContactFunctor callback) {
  if (node_id == contact_.node_id()) {
    asio_service_.post(std::bind(&NodeImpl::GetOwnContact, this, callback));
    return;
  }

  if (!joined_) {
    return asio_service_.post(std::bind(&NodeImpl::NotJoined<GetContactFunctor>,
                                        this, callback));
  }

  std::vector<Contact> close_nodes, excludes;
  routing_table_->GetCloseContacts(node_id, k_, excludes, &close_nodes);
  OrderedContacts close_contacts(CreateOrderedContacts(close_nodes.begin(),
                                                       close_nodes.end(),
                                                       node_id));
  // If we have the contact in our own routing table, ping it, otherwise start
  // a lookup for it.
  if ((*close_contacts.begin()).node_id() == node_id) {
    rpcs_->Ping(SecurifierPtr(), *close_contacts.begin(),
                std::bind(&NodeImpl::GetContactPingCallback, this, arg::_1,
                          arg::_2, *close_contacts.begin(), callback));
  } else {
    GetContactArgsPtr get_contact_args(
        new GetContactArgs(node_id, k_, close_contacts, default_securifier_,
                           callback));
    StartLookup(get_contact_args);
  }
}

void NodeImpl::GetOwnContact(GetContactFunctor callback) {
  callback(kSuccess, contact_);
}

void NodeImpl::GetContactPingCallback(RankInfoPtr rank_info,
                                      int result,
                                      Contact peer,
                                      GetContactFunctor callback) {
  AsyncHandleRpcCallback(peer, rank_info, result);
  if (result == kSuccess)
    callback(kSuccess, peer);
  else
    callback(kFailedToGetContact, Contact());
}

void NodeImpl::Ping(const Contact &contact, PingFunctor callback) {
  if (!joined_) {
    return asio_service_.post(std::bind(&NodeImpl::NotJoined<PingFunctor>,
                                        this, callback));
  }
  rpcs_->Ping(SecurifierPtr(), contact,
              std::bind(&NodeImpl::PingCallback, this, arg::_1, arg::_2,
                        contact, callback));
}

void NodeImpl::PingCallback(RankInfoPtr rank_info,
                            int result,
                            Contact peer,
                            PingFunctor callback) {
  AsyncHandleRpcCallback(peer, rank_info, result);
  callback(result);
}

void NodeImpl::SetLastSeenToNow(const Contact &contact) {
  Contact result;
  if (routing_table_->GetContact(contact.node_id(), &result) != kSuccess)
    return;
  // If the contact exists in the routing table, adding it again will set its
  // last_seen to now.
  routing_table_->AddContact(contact, RankInfoPtr());
}

void NodeImpl::IncrementFailedRpcs(const Contact &contact) {
  routing_table_->IncrementFailedRpcCount(contact.node_id());
}

void NodeImpl::UpdateRankInfo(const Contact &contact, RankInfoPtr rank_info) {
  routing_table_->UpdateRankInfo(contact.node_id(), rank_info);
}

RankInfoPtr NodeImpl::GetLocalRankInfo(const Contact &contact) const {
  return routing_table_->GetLocalRankInfo(contact);
}

void NodeImpl::GetAllContacts(std::vector<Contact> *contacts) {
  routing_table_->GetAllContacts(contacts);
}

void NodeImpl::GetBootstrapContacts(std::vector<Contact> *contacts) {
  if (!contacts)
    return;
  routing_table_->GetBootstrapContacts(contacts);

  // Allow time to validate and add the first node on the network in the case
  // where this node is the second.
  int attempts(0);
  const int kMaxAttempts(50);
  while (attempts != kMaxAttempts && contacts->empty()) {
    Sleep(bptime::milliseconds(100));
    routing_table_->GetBootstrapContacts(contacts);
    ++attempts;
  }

  if (contacts->empty())
    contacts->push_back(contact_);
}

void NodeImpl::StartLookup(LookupArgsPtr lookup_args) {
  BOOST_ASSERT(lookup_args->kNumContactsRequested >= k_);
  boost::mutex::scoped_lock lock(lookup_args->mutex);
  DoLookupIteration(lookup_args);
}

void NodeImpl::DoLookupIteration(LookupArgsPtr lookup_args) {
  lookup_args->rpcs_in_flight_for_current_iteration = 0;
  lookup_args->lookup_phase_complete = false;
  size_t good_contact_count(0), pending_result_count(0);
  bool wait_for_in_flight_rpcs(false);
  auto itr(lookup_args->lookup_contacts.begin());
  while (itr != lookup_args->lookup_contacts.end() &&
         !wait_for_in_flight_rpcs) {
    switch ((*itr).second.rpc_state) {
      case ContactInfo::kNotSent: {
        if (!client_only_node_ && (*itr).first == contact_) {
          // If this node isn't a client and is the current contact, we've
          // already added the closest it knows of at the start of the op.
          (*itr).second.rpc_state = ContactInfo::kRepliedOK;
        } else {
          if (lookup_args->kOperationType == LookupArgs::kFindValue) {
            rpcs_->FindValue(lookup_args->kTarget,
                             lookup_args->kNumContactsRequested,
                             lookup_args->securifier,
                             (*itr).first,
                             std::bind(&NodeImpl::IterativeFindCallback,
                                       this, arg::_1, arg::_2, arg::_3, arg::_4,
                                       arg::_5, (*itr).first, lookup_args));
          } else {
            rpcs_->FindNodes(lookup_args->kTarget,
                             lookup_args->kNumContactsRequested,
                             default_securifier_,
                             (*itr).first,
                             std::bind(&NodeImpl::IterativeFindCallback,
                                       this, arg::_1, arg::_2,
                                       std::vector<ValueAndSignature>(),
                                       arg::_3, Contact(), (*itr).first,
                                       lookup_args));
          }
          ++lookup_args->total_lookup_rpcs_in_flight;
          ++lookup_args->rpcs_in_flight_for_current_iteration;
          (*itr).second.rpc_state = ContactInfo::kSent;
        }
        break;
      }
      case ContactInfo::kSent: {
        ++pending_result_count;
        (*itr).second.rpc_state = ContactInfo::kDelayed;
        break;
      }
      case ContactInfo::kDelayed: {
        ++pending_result_count;
        break;
      }
      case ContactInfo::kRepliedOK: {
        ++good_contact_count;
        break;
      }
      default: break;
    }
    wait_for_in_flight_rpcs =
        (lookup_args->rpcs_in_flight_for_current_iteration == kAlpha_) ||
        ((lookup_args->rpcs_in_flight_for_current_iteration +
            pending_result_count + good_contact_count) ==
            lookup_args->kNumContactsRequested);
    ++itr;
  }
}

void NodeImpl::IterativeFindCallback(
    RankInfoPtr rank_info,
    int result,
    const std::vector<ValueAndSignature> &values_and_signatures,
    const std::vector<Contact> &contacts,
    const Contact &alternative_store,
    Contact peer,
    LookupArgsPtr lookup_args) {
  // It is only OK for a node to return no meaningful information if this is
  // the second to join the network (peer being the first)
  boost::mutex::scoped_lock lock(lookup_args->mutex);
  bool second_node(false);
  if (result == kIterativeLookupFailed &&
      lookup_args->lookup_contacts.size() == 1) {
    result = kSuccess;
    second_node = true;
  }

  AsyncHandleRpcCallback(peer, rank_info, result);
  auto this_peer(lookup_args->lookup_contacts.find(peer));
  --lookup_args->total_lookup_rpcs_in_flight;
  BOOST_ASSERT(lookup_args->total_lookup_rpcs_in_flight >= 0);
  if (this_peer == lookup_args->lookup_contacts.end()) {
    DLOG(ERROR) << DebugId(contact_) << ": Can't find " << DebugId(peer)
                << " in lookup args.";
    return;
  }

  // Note - if the RPC isn't from this iteration, it will be marked as kDelayed.
  if ((*this_peer).second.rpc_state == ContactInfo::kSent)
    --lookup_args->rpcs_in_flight_for_current_iteration;

  // If the RPC returned an error, move peer to the downlist.
  if (FindResultError(result)) {
    lookup_args->downlist.insert(*this_peer);
    lookup_args->lookup_contacts.erase(this_peer);
  }

  // If the lookup has already been completed, do nothing unless this is also
  // the last callback, in which case, send the downlist notifications out.
  if (lookup_args->lookup_phase_complete) {
    if (lookup_args->total_lookup_rpcs_in_flight == 0)
      SendDownlist(lookup_args->downlist);
    return;
  }

  // If DoLookupIteration didn't send any RPCs, this will hit -1.
  BOOST_ASSERT(lookup_args->rpcs_in_flight_for_current_iteration >= -1);

  // If we should stop early (found value, or found single contact), do so.
  if (AbortLookup(result, values_and_signatures, contacts, alternative_store,
                  peer, second_node, lookup_args))
    return;

  // Handle result if RPC was successful.
  auto shortlist_upper_bound(lookup_args->lookup_contacts.begin());
  if (FindResultError(result)) {
    shortlist_upper_bound = GetShortlistUpperBound(lookup_args);
  } else {
    (*this_peer).second.rpc_state = ContactInfo::kRepliedOK;
    OrderedContacts close_contacts(CreateOrderedContacts(contacts.begin(),
        contacts.end(), lookup_args->kTarget));
    RemoveDownlistedContacts(lookup_args, this_peer, &close_contacts);
    shortlist_upper_bound = InsertCloseContacts(close_contacts, lookup_args,
                                                this_peer);
  }

  // Check to see if the lookup phase and/or iteration is now finished.
  bool iteration_complete(false);
  int shortlist_ok_count(0);
  AssessLookupState(lookup_args, shortlist_upper_bound, &iteration_complete,
                    &shortlist_ok_count);

  // If the lookup phase is marked complete, but we still have <
  // kNumContactsRequested then try to get more contacts from the local routing
  // table.
  if (lookup_args->lookup_phase_complete &&
      shortlist_ok_count != lookup_args->kNumContactsRequested) {
    std::vector<Contact> close_nodes, excludes;
    excludes.reserve(shortlist_ok_count + lookup_args->downlist.size());
    auto shortlist_itr(lookup_args->lookup_contacts.begin());
    while (shortlist_itr != lookup_args->lookup_contacts.end())
      excludes.push_back((*shortlist_itr++).first);
    auto downlist_itr(lookup_args->downlist.begin());
    while (downlist_itr != lookup_args->downlist.end())
      excludes.push_back((*downlist_itr++).first);
    routing_table_->GetCloseContacts(lookup_args->kTarget, k_, excludes,
                                     &close_nodes);
    if (!close_nodes.empty()) {
      OrderedContacts close_contacts(
          CreateOrderedContacts(close_nodes.begin(), close_nodes.end(),
                                lookup_args->kTarget));
      shortlist_upper_bound =
          InsertCloseContacts(close_contacts, lookup_args,
                              lookup_args->lookup_contacts.end());
      lookup_args->lookup_phase_complete = false;
    } else {
      DLOG(WARNING) << DebugId(contact_) << ": Lookup is returning only "
                    << shortlist_ok_count << " contacts (k is " << k_ << ").";
    }
  }

  // If the lookup phase is still not finished, set cache candidate and start
  // next iteration if due.
  if (!lookup_args->lookup_phase_complete) {
    if (!FindResultError(result))
      lookup_args->cache_candidate = (*this_peer).first;
    if (iteration_complete)
      DoLookupIteration(lookup_args);
    return;
  }

  HandleCompletedLookup(lookup_args, shortlist_upper_bound, shortlist_ok_count);

  // If this is the last lookup callback, send the downlist notifications out.
  if (lookup_args->total_lookup_rpcs_in_flight == 0)
    SendDownlist(lookup_args->downlist);
}

bool NodeImpl::AbortLookup(
    int result,
    const std::vector<ValueAndSignature> &values_and_signatures,
    const std::vector<Contact> &contacts,
    const Contact &alternative_store,
    const Contact &peer,
    bool second_node,
    LookupArgsPtr lookup_args) {
  if (lookup_args->kOperationType == LookupArgs::kFindValue) {
    // If the value was returned, or the peer claimed to have the value in its
    // alternative store, we're finished with the lookup.
    if (result == kSuccess || result == kFoundAlternativeStoreHolder ||
        second_node) {
#ifdef DEBUG
      if (second_node) {
        BOOST_ASSERT(values_and_signatures.empty() && contacts.empty() &&
                     alternative_store == Contact());
      } else {
        BOOST_ASSERT(!values_and_signatures.empty() ||
                     alternative_store == peer);
      }
#endif
      FindValueReturns find_value_returns(result, values_and_signatures,
                                          contacts, alternative_store,
                                          lookup_args->cache_candidate);
      lookup_args->lookup_phase_complete = true;
      std::static_pointer_cast<FindValueArgs>(lookup_args)->callback(
          find_value_returns);
      // TODO(Fraser#5#): 2011-08-16 - Send value to cache_candidate here.
//      if (std::static_pointer_cast<FindValueArgs>(lookup_args)->cache)
    }
    return lookup_args->lookup_phase_complete;
  } else if (lookup_args->kOperationType == LookupArgs::kGetContact) {
    // If the peer is the target, we're finished with the lookup, whether the
    // RPC timed out or not.
    if (peer.node_id() == lookup_args->kTarget) {
      lookup_args->lookup_phase_complete = true;
      if (result == kSuccess) {
        std::static_pointer_cast<GetContactArgs>(lookup_args)->callback(
            kSuccess, peer);
      } else {
        std::static_pointer_cast<GetContactArgs>(lookup_args)->callback(
            kFailedToGetContact, Contact());
      }
    }
    return lookup_args->lookup_phase_complete;
  }
  return false;
}

LookupContacts::iterator NodeImpl::GetShortlistUpperBound(
    LookupArgsPtr lookup_args) {
  uint16_t count(0);
  auto shortlist_upper_bound(lookup_args->lookup_contacts.begin());
  while (count != lookup_args->kNumContactsRequested &&
         shortlist_upper_bound != lookup_args->lookup_contacts.end()) {
    ++shortlist_upper_bound;
    ++count;
  }
  return shortlist_upper_bound;
}

void NodeImpl::RemoveDownlistedContacts(LookupArgsPtr lookup_args,
                                        LookupContacts::iterator this_peer,
                                        OrderedContacts *contacts) {
  auto downlist_itr(lookup_args->downlist.begin());
  auto contacts_itr(contacts->begin());
  while (downlist_itr != lookup_args->downlist.end() &&
         contacts_itr != contacts->end()) {
    if ((*downlist_itr).first < *contacts_itr) {
      ++downlist_itr;
    } else if (*contacts_itr < (*downlist_itr).first) {
      ++contacts_itr;
    } else {
      (*downlist_itr++).second.providers.push_back((*this_peer).first);
      contacts->erase(contacts_itr++);
    }
  }
}

LookupContacts::iterator NodeImpl::InsertCloseContacts(
    const OrderedContacts &contacts,
    LookupArgsPtr lookup_args,
    LookupContacts::iterator this_peer) {
  auto existing_contacts_itr(lookup_args->lookup_contacts.begin());
  if (!contacts.empty()) {
    auto new_contacts_itr(contacts.begin());
    auto insertion_point(lookup_args->lookup_contacts.end());
    ContactInfo contact_info;
    if (this_peer != lookup_args->lookup_contacts.end())
      contact_info = ContactInfo((*this_peer).first);
    for (;;) {
      if (existing_contacts_itr == lookup_args->lookup_contacts.end()) {
        while (new_contacts_itr != contacts.end()) {
          insertion_point = lookup_args->lookup_contacts.insert(
              insertion_point, std::make_pair(*new_contacts_itr++,
                                              contact_info));
        }
        break;
      }

      if ((*existing_contacts_itr).first < *new_contacts_itr) {
        insertion_point = existing_contacts_itr++;
      } else if (*new_contacts_itr < (*existing_contacts_itr).first) {
        insertion_point = lookup_args->lookup_contacts.insert(
            insertion_point, std::make_pair(*new_contacts_itr++, contact_info));
      } else {
        insertion_point = existing_contacts_itr;
        if (this_peer != lookup_args->lookup_contacts.end()) {
          (*existing_contacts_itr++).second.providers.push_back(
              (*this_peer).first);
        }
        ++new_contacts_itr;
      }

      if (new_contacts_itr == contacts.end())
        break;
    }
  }
  return GetShortlistUpperBound(lookup_args);
}

void NodeImpl::AssessLookupState(LookupArgsPtr lookup_args,
                                 LookupContacts::iterator shortlist_upper_bound,
                                 bool *iteration_complete,
                                 int *shortlist_ok_count) {
  *iteration_complete =
      (lookup_args->rpcs_in_flight_for_current_iteration <= kAlpha_ - kBeta_);

  lookup_args->lookup_phase_complete = true;
  auto itr(lookup_args->lookup_contacts.begin());
  while (itr != shortlist_upper_bound && lookup_args->lookup_phase_complete) {
    switch ((*itr).second.rpc_state) {
      case ContactInfo::kRepliedOK:
        ++(*shortlist_ok_count);
        break;
      case ContactInfo::kNotSent:
      case ContactInfo::kSent:
      case ContactInfo::kDelayed:
      default:
        lookup_args->lookup_phase_complete = false;
        break;
    }
    ++itr;
  }
}

void NodeImpl::HandleCompletedLookup(
    LookupArgsPtr lookup_args,
    LookupContacts::iterator closest_upper_bound,
    const int &closest_count) {
  switch (lookup_args->kOperationType) {
    case LookupArgs::kFindNodes:
    case LookupArgs::kFindValue: {
      auto itr(lookup_args->lookup_contacts.begin());
      std::vector<Contact> contacts;
      contacts.reserve(lookup_args->kNumContactsRequested);
      while (itr != closest_upper_bound) {
        BOOST_ASSERT((*itr).second.rpc_state == ContactInfo::kRepliedOK);
        contacts.push_back((*itr++).first);
      }
      if (lookup_args->kOperationType == LookupArgs::kFindNodes) {
        int result(contacts.empty() ? kFindNodesFailed : kSuccess);
        std::static_pointer_cast<FindNodesArgs>(lookup_args)->callback(result,
            contacts);
      } else {
        // We've already handled the case where the value or an alternative
        // store holder was found (in AbortLookup).
        int result(contacts.empty() ? kIterativeLookupFailed :
                   kFailedToFindValue);
        FindValueReturns find_value_returns(result,
                                            std::vector<ValueAndSignature>(),
                                            contacts, Contact(),
                                            lookup_args->cache_candidate);
        std::static_pointer_cast<FindValueArgs>(lookup_args)->callback(
            find_value_returns);
      }
      break;
    }
    case LookupArgs::kStore: {
      InitiateStorePhase(std::static_pointer_cast<StoreArgs>(lookup_args),
                         closest_upper_bound, closest_count);
      break;
    }
    case LookupArgs::kDelete: {
      InitiateDeletePhase(std::static_pointer_cast<DeleteArgs>(lookup_args),
                          closest_upper_bound, closest_count);
      break;
    }
    case LookupArgs::kUpdate: {
      InitiateUpdatePhase(std::static_pointer_cast<UpdateArgs>(lookup_args),
                          closest_upper_bound, closest_count);
      break;
    }
    case LookupArgs::kGetContact: {
      // We've already handled the case where the target contact was found (in
      // AbortLookup).
      std::static_pointer_cast<GetContactArgs>(lookup_args)->callback(
            kFailedToGetContact, Contact());
      break;
    }
    case LookupArgs::kStoreRefresh:
    case LookupArgs::kDeleteRefresh: {
      InitiateRefreshPhase(std::static_pointer_cast<RefreshArgs>(lookup_args),
                           closest_upper_bound, closest_count);
      break;
    }
    default: break;
  }
}

void NodeImpl::InitiateStorePhase(StoreArgsPtr store_args,
                                  LookupContacts::iterator closest_upper_bound,
                                  const int &closest_count) {
  if (closest_count < store_args->kSuccessThreshold) {
    if (closest_count == 0) {
      DLOG(ERROR) << DebugId(contact_) << ": Failed to get any contacts "
                  << "before store phase.";
      store_args->callback(kIterativeLookupFailed);
    } else {
      DLOG(ERROR) << DebugId(contact_) << ": Failed to get enough contacts "
                  << "to initiate store.";
      store_args->callback(kFoundTooFewNodes);
    }
    return;
  }
  auto itr(store_args->lookup_contacts.begin());
  while (itr != closest_upper_bound) {
    if (!client_only_node_ && ((*itr).first == contact_)) {
      HandleStoreToSelf(store_args);
    } else {
      rpcs_->Store(store_args->kTarget,
                   store_args->kValue,
                   store_args->kSignature,
                   store_args->kSecondsToLive,
                   store_args->securifier,
                   (*itr).first,
                   std::bind(&NodeImpl::StoreCallback, this, arg::_1, arg::_2,
                             (*itr).first, store_args));
      ++store_args->second_phase_rpcs_in_flight;
    }
    ++itr;
  }
}

void NodeImpl::InitiateDeletePhase(DeleteArgsPtr delete_args,
                                   LookupContacts::iterator closest_upper_bound,
                                   const int &closest_count) {
  if (closest_count < delete_args->kSuccessThreshold) {
    if (closest_count == 0) {
      DLOG(ERROR) << DebugId(contact_) << ": Failed to get any contacts "
                  << "before delete phase.";
      delete_args->callback(kIterativeLookupFailed);
    } else {
      DLOG(ERROR) << DebugId(contact_) << ": Failed to get enough contacts "
                  << "to initiate delete.";
      delete_args->callback(kFoundTooFewNodes);
    }
    return;
  }
  auto itr(delete_args->lookup_contacts.begin());
  while (itr != closest_upper_bound) {
    if (!client_only_node_ && ((*itr).first == contact_)) {
      HandleDeleteToSelf(delete_args);
    } else {
      rpcs_->Delete(delete_args->kTarget,
                    delete_args->kValue,
                    delete_args->kSignature,
                    delete_args->securifier,
                    (*itr).first,
                    std::bind(&NodeImpl::DeleteCallback, this, arg::_1, arg::_2,
                              (*itr).first, delete_args));
      ++delete_args->second_phase_rpcs_in_flight;
    }
    ++itr;
  }
}

void NodeImpl::InitiateUpdatePhase(UpdateArgsPtr update_args,
                                   LookupContacts::iterator closest_upper_bound,
                                   const int &closest_count) {
  if (closest_count < update_args->kSuccessThreshold) {
    if (closest_count == 0) {
      DLOG(ERROR) << DebugId(contact_) << ": Failed to get any contacts "
                  << "before update phase.";
      update_args->callback(kIterativeLookupFailed);
    } else {
      DLOG(ERROR) << DebugId(contact_) << ": Failed to get enough contacts "
                  << "to initiate update.";
      update_args->callback(kFoundTooFewNodes);
    }
    return;
  }
  auto itr(update_args->lookup_contacts.begin());
  while (itr != closest_upper_bound) {
    if (!client_only_node_ && ((*itr).first == contact_)) {
      HandleUpdateToSelf(update_args);
    } else {
      rpcs_->Store(update_args->kTarget,
                   update_args->kNewValue,
                   update_args->kNewSignature,
                   update_args->kSecondsToLive,
                   update_args->securifier,
                   (*itr).first,
                   std::bind(&NodeImpl::UpdateCallback, this, arg::_1, arg::_2,
                             (*itr).first, update_args));
      ++update_args->store_rpcs_in_flight;
      // Increment second_phase_rpcs_in_flight (representing the subsequent
      // Delete RPC) to avoid the DeleteCallback finishing early.  This assumes
      // the Store RPC will succeed - if it fails, we need to decrement
      // second_phase_rpcs_in_flight.
      ++update_args->second_phase_rpcs_in_flight;
    }
    ++itr;
  }
}

void NodeImpl::InitiateRefreshPhase(
    RefreshArgsPtr refresh_args,
    LookupContacts::iterator closest_upper_bound,
    const int &closest_count) {
  if (closest_count == 0) {
    DLOG(ERROR) << DebugId(contact_) << ": Failed to get any contacts "
                << "before refresh phase.";
    return;
  }
  auto itr(refresh_args->lookup_contacts.begin());
  bool this_node_within_closest(false);
  while (itr != closest_upper_bound) {
    if (!client_only_node_ && ((*itr).first == contact_)) {
      this_node_within_closest = true;
    } else {
      if (refresh_args->kOperationType == LookupArgs::kStoreRefresh) {
        rpcs_->StoreRefresh(refresh_args->kSerialisedRequest,
                            refresh_args->kSerialisedRequestSignature,
                            refresh_args->securifier, (*itr).first,
                            std::bind(&NodeImpl::HandleRpcCallback, this,
                                      (*itr).first, arg::_1, arg::_2));
      } else {
        rpcs_->DeleteRefresh(refresh_args->kSerialisedRequest,
                             refresh_args->kSerialisedRequestSignature,
                             refresh_args->securifier, (*itr).first,
                             std::bind(&NodeImpl::HandleRpcCallback, this,
                                       (*itr).first, arg::_1, arg::_2));
      }
    }
    ++itr;
  }
  if (!this_node_within_closest) {
    // TODO(Fraser#5#): 2011-09-02 - Remove k,v from data_store_, or move it to
    //                               a cache store.
  }
}

void NodeImpl::HandleStoreToSelf(StoreArgsPtr store_args) {
  // Check this node signed other values under same key in datastore
  ++store_args->second_phase_rpcs_in_flight;
  KeyValueSignature key_value_signature(store_args->kTarget.String(),
                                        store_args->kValue,
                                        store_args->kSignature);
  if (data_store_->DifferentSigner(key_value_signature, contact_.public_key(),
                                   default_securifier_)) {
    DLOG(WARNING) << DebugId(contact_) << ": Can't store to self - different "
                  << "signing key used to store under Kad key.";
    HandleSecondPhaseCallback<StoreArgsPtr>(kValueAlreadyExists, store_args);
    return;
  }

  // Check the signature validates with this node's public key
  if (!default_securifier_->Validate(store_args->kValue, store_args->kSignature,
                                     "", contact_.public_key(), "", "")) {
    DLOG(ERROR) << DebugId(contact_) << ": Failed to validate Store request "
                << "for kademlia value";
    HandleSecondPhaseCallback<StoreArgsPtr>(kGeneralError, store_args);
    return;
  }

  // Store the value
  RequestAndSignature store_request_and_signature(
      rpcs_->MakeStoreRequestAndSignature(store_args->kTarget,
                                          store_args->kValue,
                                          store_args->kSignature,
                                          store_args->kSecondsToLive,
                                          store_args->securifier));
  int result(data_store_->StoreValue(key_value_signature,
                                     store_args->kSecondsToLive,
                                     store_request_and_signature,
                                     false));
  if (result == kSuccess) {
    HandleSecondPhaseCallback<StoreArgsPtr>(kSuccess, store_args);
  } else {
    DLOG(ERROR) << DebugId(contact_) << ": Failed to store value: " << result;
    HandleSecondPhaseCallback<StoreArgsPtr>(kGeneralError, store_args);
  }
}

void NodeImpl::HandleDeleteToSelf(DeleteArgsPtr delete_args) {
  if (!data_store_->HasKey(delete_args->kTarget.String())) {
    HandleSecondPhaseCallback<DeleteArgsPtr>(kSuccess, delete_args);
    return;
  }

  ++delete_args->second_phase_rpcs_in_flight;

  // Check this node signed other values under same key in datastore
  KeyValueSignature key_value_signature(delete_args->kTarget.String(),
                                        delete_args->kValue,
                                        delete_args->kSignature);
  if (data_store_->DifferentSigner(key_value_signature, contact_.public_key(),
                                   default_securifier_)) {
    DLOG(WARNING) << DebugId(contact_) << ": Can't delete to self - different "
                  << "signing key used to store under Kad key.";
    HandleSecondPhaseCallback<DeleteArgsPtr>(kGeneralError, delete_args);
    return;
  }

  // Check the signature validates with this node's public key
  if (!default_securifier_->Validate(delete_args->kValue,
                                     delete_args->kSignature, "",
                                     contact_.public_key(), "", "")) {
    DLOG(ERROR) << DebugId(contact_) << ": Failed to validate Delete request "
                << "for kademlia value";
    HandleSecondPhaseCallback<DeleteArgsPtr>(kGeneralError, delete_args);
    return;
  }

  // Delete the value
  RequestAndSignature delete_request_and_signature(
      rpcs_->MakeDeleteRequestAndSignature(delete_args->kTarget,
                                           delete_args->kValue,
                                           delete_args->kSignature,
                                           delete_args->securifier));
  bool result(data_store_->DeleteValue(key_value_signature,
                                       delete_request_and_signature, false));
  if (result) {
    HandleSecondPhaseCallback<DeleteArgsPtr>(kSuccess, delete_args);
  } else {
    DLOG(ERROR) << DebugId(contact_) << ": Failed to delete value";
    HandleSecondPhaseCallback<DeleteArgsPtr>(kGeneralError, delete_args);
  }
}

void NodeImpl::HandleUpdateToSelf(UpdateArgsPtr update_args) {
  // Check this node signed other values under same key in datastore
  ++update_args->second_phase_rpcs_in_flight;
  KeyValueSignature new_key_value_signature(update_args->kTarget.String(),
                                            update_args->kNewValue,
                                            update_args->kNewSignature);
  if (data_store_->DifferentSigner(new_key_value_signature,
                                   contact_.public_key(),
                                   default_securifier_)) {
    DLOG(WARNING) << DebugId(contact_) << ": Can't update to self - different "
                  << "signing key used to store under Kad key.";
    HandleSecondPhaseCallback<UpdateArgsPtr>(kGeneralError, update_args);
    return;
  }

  // Check the new signature validates with this node's public key
  if (!default_securifier_->Validate(update_args->kNewValue,
                                     update_args->kNewSignature,
                                     "", contact_.public_key(), "", "")) {
    DLOG(ERROR) << DebugId(contact_) << ": Failed to validate Update new "
                << "request for kademlia value";
    HandleSecondPhaseCallback<UpdateArgsPtr>(kGeneralError, update_args);
    return;
  }

  // Store the value
  RequestAndSignature store_request_and_signature(
      rpcs_->MakeStoreRequestAndSignature(update_args->kTarget,
                                          update_args->kNewValue,
                                          update_args->kNewSignature,
                                          update_args->kSecondsToLive,
                                          update_args->securifier));
  int result(data_store_->StoreValue(new_key_value_signature,
                                     update_args->kSecondsToLive,
                                     store_request_and_signature,
                                     false));
  if (result != kSuccess) {
    DLOG(ERROR) << DebugId(contact_) << ": Failed to store value: " << result;
    HandleSecondPhaseCallback<UpdateArgsPtr>(kGeneralError, update_args);
    return;
  }
  ++update_args->store_successes;

  if (update_args->kOldValue == update_args->kNewValue) {
    HandleSecondPhaseCallback<UpdateArgsPtr>(kSuccess, update_args);
    return;
  }

  // Check the old signature validates with this node's public key
  if (!default_securifier_->Validate(update_args->kOldValue,
                                     update_args->kOldSignature, "",
                                     contact_.public_key(), "", "")) {
    DLOG(ERROR) << DebugId(contact_) << ": Failed to validate Update old "
                << "request for kademlia value";
    HandleSecondPhaseCallback<UpdateArgsPtr>(kGeneralError, update_args);
    return;
  }

  // Delete the value
  KeyValueSignature old_key_value_signature(update_args->kTarget.String(),
                                            update_args->kOldValue,
                                            update_args->kOldSignature);
  RequestAndSignature delete_request_and_signature(
      rpcs_->MakeDeleteRequestAndSignature(update_args->kTarget,
                                           update_args->kOldValue,
                                           update_args->kOldSignature,
                                           update_args->securifier));
  if (data_store_->DeleteValue(old_key_value_signature,
                               delete_request_and_signature, false)) {
    HandleSecondPhaseCallback<UpdateArgsPtr>(kSuccess, update_args);
  } else {
    DLOG(ERROR) << DebugId(contact_) << ": Failed to delete value";
    HandleSecondPhaseCallback<UpdateArgsPtr>(kGeneralError, update_args);
  }
}

void NodeImpl::StoreCallback(RankInfoPtr rank_info,
                             int result,
                             Contact peer,
                             StoreArgsPtr store_args) {
  AsyncHandleRpcCallback(peer, rank_info, result);
  boost::mutex::scoped_lock lock(store_args->mutex);
  HandleSecondPhaseCallback<StoreArgsPtr>(result, store_args);
  // If this is the last RPC, and the overall store failed, delete the value
  if (store_args->second_phase_rpcs_in_flight == 0 &&
      store_args->successes < store_args->kSuccessThreshold) {
    auto itr(store_args->lookup_contacts.begin());
    uint16_t count(0);
    while (itr != store_args->lookup_contacts.end() &&
           count != store_args->kNumContactsRequested) {
      if (!client_only_node_ && ((*itr).first == contact_)) {
        // Handle deleting from self
        KeyValueSignature key_value_signature(store_args->kTarget.String(),
                                              store_args->kValue,
                                              store_args->kSignature);
        RequestAndSignature delete_request_and_signature(
            rpcs_->MakeDeleteRequestAndSignature(store_args->kTarget,
                                                 store_args->kValue,
                                                 store_args->kSignature,
                                                 store_args->securifier));
        if (!data_store_->DeleteValue(key_value_signature,
                                      delete_request_and_signature, false)) {
          DLOG(WARNING) << DebugId(contact_) << ": Failed to delete value "
                        << "from self after bad store.";
        }
      } else {
        rpcs_->Delete(store_args->kTarget,
                      store_args->kValue,
                      store_args->kSignature,
                      store_args->securifier,
                      (*itr).first,
                      std::bind(&NodeImpl::HandleRpcCallback, this,
                                (*itr).first, arg::_1, arg::_2));
      }
      ++itr;
      ++count;
    }
  }
}

void NodeImpl::DeleteCallback(RankInfoPtr rank_info,
                              int result,
                              Contact peer,
                              LookupArgsPtr args) {
  AsyncHandleRpcCallback(peer, rank_info, result);
  boost::mutex::scoped_lock lock(args->mutex);
  if (args->kOperationType == LookupArgs::kDelete) {
    HandleSecondPhaseCallback<DeleteArgsPtr>(result,
        std::static_pointer_cast<DeleteArgs>(args));
  } else {
    HandleSecondPhaseCallback<UpdateArgsPtr>(result,
        std::static_pointer_cast<UpdateArgs>(args));
  }
  // TODO(Fraser#5#): 2011-08-16 - Decide if we want to try to re-store the
  //                  if the delete operation failed.  The problem is that we
  //                  don't have the outstanding TTL available here.
}

void NodeImpl::UpdateCallback(RankInfoPtr rank_info,
                              int result,
                              Contact peer,
                              UpdateArgsPtr update_args) {
  AsyncHandleRpcCallback(peer, rank_info, result);
  boost::mutex::scoped_lock lock(update_args->mutex);
  --update_args->store_rpcs_in_flight;
  BOOST_ASSERT(update_args->store_rpcs_in_flight >= 0);

  if (result == kSuccess && update_args->kSuccessThreshold <=
      update_args->store_successes + update_args->store_rpcs_in_flight) {
    ++update_args->store_successes;
    if (update_args->kOldValue != update_args->kNewValue)
      rpcs_->Delete(update_args->kTarget,
                    update_args->kOldValue,
                    update_args->kOldSignature,
                    update_args->securifier,
                    peer,
                    std::bind(&NodeImpl::DeleteCallback, this, arg::_1, arg::_2,
                              peer, update_args));
    else
      HandleSecondPhaseCallback<UpdateArgsPtr>(result,
          std::static_pointer_cast<UpdateArgs>(update_args));
  } else {
    // Decrement second_phase_rpcs_in_flight (representing the subsequent Delete
    // RPC) to avoid the DeleteCallback finishing early.
    --update_args->second_phase_rpcs_in_flight;
    BOOST_ASSERT(update_args->second_phase_rpcs_in_flight >= 0);
    if (update_args->kSuccessThreshold ==
        update_args->store_successes + update_args->store_rpcs_in_flight + 1) {
      update_args->callback(kUpdateTooFewNodes);
    }
  }
}

template <typename T>
void NodeImpl::HandleSecondPhaseCallback(int result, T args) {
  --args->second_phase_rpcs_in_flight;
  BOOST_ASSERT(args->second_phase_rpcs_in_flight >= 0);
  if (result == kSuccess) {
    ++args->successes;
    if (args->successes == args->kSuccessThreshold)
      args->callback(kSuccess);
  } else {
    if (args->kSuccessThreshold ==
        args->successes + args->second_phase_rpcs_in_flight + 1) {
      switch (args->kOperationType) {
        case LookupArgs::kStore:
          args->callback(kStoreTooFewNodes);
          break;
        case LookupArgs::kDelete:
          args->callback(kDeleteTooFewNodes);
          break;
        case LookupArgs::kUpdate:
          args->callback(kUpdateTooFewNodes);
          break;
        default:
          break;
      }
    }
  }
}

void NodeImpl::SendDownlist(const Downlist &downlist) {
  // Convert map of <down_contact, vector<providers>> to
  // map<provider, vector<down_ids>>.
  std::map<Contact, std::vector<NodeId>> downlist_by_provider;
  auto downlist_itr(downlist.begin());
  while (downlist_itr != downlist.end()) {
    auto provider_itr((*downlist_itr).second.providers.begin());
    while (provider_itr != (*downlist_itr).second.providers.end()) {
      auto insert_result(downlist_by_provider.insert(std::make_pair(
          *provider_itr,
          std::vector<NodeId>(1, (*downlist_itr).first.node_id()))));
      if (!insert_result.second) {
        (insert_result.first)->second.push_back(
            (*downlist_itr).first.node_id());
      }
      ++provider_itr;
    }
    ++downlist_itr;
  }
  // Send RPCs
  auto itr(downlist_by_provider.begin());
  while (itr != downlist_by_provider.end()) {
    rpcs_->Downlist((*itr).second, default_securifier_, (*itr).first);
    ++itr;
  }
}

void NodeImpl::RefreshDataStore(const boost::system::error_code &error_code) {
  if (error_code) {
    if (error_code != boost::asio::error::operation_aborted) {
      DLOG(ERROR) << DebugId(contact_) << ": DataStore refresh timer error: "
                  << error_code.message();
    } else {
      return;
    }
  }
  if (!joined_)
    return;
  std::vector<KeyValueTuple> key_value_tuples;
  data_store_->Refresh(&key_value_tuples);
  std::for_each(key_value_tuples.begin(), key_value_tuples.end(),
                std::bind(&NodeImpl::RefreshData, this, arg::_1));
  refresh_data_store_timer_.expires_at(refresh_data_store_timer_.expires_at() +
                                       kDataStoreCheckInterval_);
  refresh_data_store_timer_.async_wait(std::bind(&NodeImpl::RefreshDataStore,
                                                 this, arg::_1));
}

void NodeImpl::RefreshData(const KeyValueTuple &key_value_tuple) {
  OrderedContacts close_contacts(
      GetClosestContactsLocally(Key(key_value_tuple.key()), k_));
  LookupArgs::OperationType op_type(key_value_tuple.deleted ?
                                    LookupArgs::kDeleteRefresh :
                                    LookupArgs::kStoreRefresh);
  RefreshArgsPtr refresh_args(new RefreshArgs(op_type,
      NodeId(key_value_tuple.key()), k_, close_contacts, default_securifier_,
      key_value_tuple.request_and_signature.first,
      key_value_tuple.request_and_signature.second));
  StartLookup(refresh_args);
}

bool NodeImpl::NodeContacted(const int &code) {
  switch (code) {
    case transport::kError:
    case transport::kSendFailure:
    case transport::kSendTimeout:
    case transport::kSendStalled:
    case kIterativeLookupFailed:
      return false;
    default:
      return true;
  }
}

void NodeImpl::PingOldestContact(const Contact &oldest_contact,
                                 const Contact &replacement_contact,
                                 RankInfoPtr replacement_rank_info) {
  rpcs_->Ping(SecurifierPtr(), oldest_contact,
              std::bind(&NodeImpl::PingOldestContactCallback, this,
                        oldest_contact, arg::_1, arg::_2, replacement_contact,
                        replacement_rank_info));
}

void NodeImpl::PingOldestContactCallback(Contact oldest_contact,
                                         RankInfoPtr oldest_rank_info,
                                         const int &result,
                                         Contact replacement_contact,
                                         RankInfoPtr replacement_rank_info) {
  HandleRpcCallback(oldest_contact, oldest_rank_info, result);
  if (result != kSuccess) {
    // Try to add the new contact again in case the oldest was removed
    routing_table_->AddContact(replacement_contact, replacement_rank_info);
    routing_table_->SetValidated(replacement_contact.node_id(), true);
  }
}

void NodeImpl::ConnectPingOldestContact() {
  if (ping_oldest_contact_ == boost::signals2::connection()) {
    ping_oldest_contact_ =
        routing_table_->ping_oldest_contact()->connect(
            std::bind(&NodeImpl::PingOldestContact, this, arg::_1, arg::_2,
                      arg::_3));
  }
}

void NodeImpl::ValidateContact(const Contact &contact) {
  GetPublicKeyAndValidationCallback callback(
      std::bind(&NodeImpl::ValidateContactCallback, this, contact, arg::_1,
                arg::_2));
  default_securifier_->GetPublicKeyAndValidation(contact.public_key_id(),
                                                 callback);
}

void NodeImpl::ValidateContactCallback(Contact contact,
                                       std::string public_key,
                                       std::string public_key_validation) {
  bool valid = default_securifier_->Validate("", "", contact.public_key_id(),
                                             public_key, public_key_validation,
                                             contact.node_id().String());
  routing_table_->SetValidated(contact.node_id(), valid);
}

void NodeImpl::ConnectValidateContact() {
  if (validate_contact_ == boost::signals2::connection()) {
    validate_contact_ = routing_table_->validate_contact()->connect(
        std::bind(&NodeImpl::ValidateContact, this, arg::_1));
  }
}

void NodeImpl::PingDownContact(const Contact &down_contact) {
  rpcs_->Ping(SecurifierPtr(), down_contact,
              std::bind(&NodeImpl::PingDownContactCallback, this,
                        down_contact, arg::_1, arg::_2));
}

void NodeImpl::PingDownContactCallback(Contact down_contact,
                                       RankInfoPtr rank_info,
                                       const int &result) {
  if (result != kSuccess) {
    // Increment failed RPC count by two: one for us and one for the reporter.
    routing_table_->IncrementFailedRpcCount(down_contact.node_id());
    routing_table_->IncrementFailedRpcCount(down_contact.node_id());
  } else {
    // Add the contact again to update its last_seen to now
    routing_table_->AddContact(down_contact, rank_info);
  }
}

void NodeImpl::ConnectPingDownContact() {
  if (ping_down_contact_ == boost::signals2::connection()) {
    ping_down_contact_ = routing_table_->ping_down_contact()->connect(
        std::bind(&NodeImpl::PingDownContact, this, arg::_1));
  }
}

void NodeImpl::HandleRpcCallback(const Contact &contact,
                                 RankInfoPtr rank_info,
                                 const int &result) {
  int routing_table_result(kSuccess);
  if (!FindResultError(result)) {
    // Add the contact to update its last_seen to now
    routing_table_result = routing_table_->AddContact(contact, rank_info);
  } else {
    routing_table_result =
        routing_table_->IncrementFailedRpcCount(contact.node_id());
  }
#ifdef DEBUG
  if (routing_table_result != kSuccess)
    DLOG(INFO) << DebugId(contact_) << ": Failed to update routing table for "
               << "contact " << DebugId(contact) << ".  RPC result: " << result
               << "  Update result: " << routing_table_result;
#endif
}

void NodeImpl::AsyncHandleRpcCallback(const Contact &contact,
                                      RankInfoPtr rank_info,
                                      const int &result) {
  asio_service_.post(std::bind(&NodeImpl::HandleRpcCallback, this, contact,
                               rank_info, result));
}

}  // namespace kademlia
}  // namespace dht
}  // namespace maidsafe
