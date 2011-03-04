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

#ifndef MAIDSAFE_DHT_KADEMLIA_NODE_IMPL_STRUCTS_H_
#define MAIDSAFE_DHT_KADEMLIA_NODE_IMPL_STRUCTS_H_

// #include <list>
// #include <map>
// #include <set>
// #include <string>
// #include <vector>

#include "boost/thread/mutex.hpp"
#include "boost/multi_index_container.hpp"
#include "boost/multi_index/composite_key.hpp"
#include "boost/multi_index/ordered_index.hpp"
#include "boost/multi_index/identity.hpp"
#include "boost/multi_index/member.hpp"

#include "maidsafe-dht/kademlia/config.h"
#include "maidsafe-dht/kademlia/contact.h"
#include "maidsafe-dht/kademlia/node_id.h"
#include "maidsafe-dht/kademlia/rpcs.h"
#include "maidsafe-dht/kademlia/utils.h"

namespace maidsafe {

namespace kademlia {

class Signature;
class SignedValue;

enum RemoteFindMethod { kFindNode, kFindValue, kBootstrap };

enum NodeSearchState { kNew, kContacted, kDown, kSelectedAlpha };

struct NodeContainerTuple {
  explicit NodeContainerTuple(const Contact &cont, const NodeId &target_id)
      : contact(cont),
        contact_id(cont.node_id()),
        state(kNew),
        distance_to_target(contact_id ^ target_id),
        round(-1) {}
  NodeContainerTuple(const Contact &cont, const NodeId &target_id, int rnd)
      : contact(cont),
        contact_id(cont.node_id()),
        state(kNew),
        distance_to_target(contact_id ^ target_id),
        round(rnd) {}
  Contact contact;
  NodeId contact_id;
  NodeSearchState state;
  NodeId distance_to_target;
  int round;
};

// Modifiers
struct ChangeState {
  explicit ChangeState(NodeSearchState new_state)
      : new_state(new_state) {}
  void operator()(NodeContainerTuple &node_container_tuple) {  // NOLINT
    node_container_tuple.state = new_state;
  }
  NodeSearchState new_state;
};

struct ChangeRound {
  explicit ChangeRound(int new_round)
      : new_round(new_round) {}
  void operator()(NodeContainerTuple &node_container_tuple) {  // NOLINT
    node_container_tuple.round = new_round;
  }
  int new_round;
};

// Tags
struct nc_id;
struct nc_state;
struct nc_distance;
struct nc_round;
struct nc_state_round;
struct nc_state_distance;

typedef boost::multi_index_container<
  NodeContainerTuple,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<nc_id>,
      BOOST_MULTI_INDEX_MEMBER(NodeContainerTuple, NodeId, contact_id)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<nc_state>,
      BOOST_MULTI_INDEX_MEMBER(NodeContainerTuple, NodeSearchState, state)
    >,
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<nc_distance>,
      BOOST_MULTI_INDEX_MEMBER(NodeContainerTuple, NodeId, distance_to_target)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<nc_round>,
      BOOST_MULTI_INDEX_MEMBER(NodeContainerTuple, int, round)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<nc_state_round>,
      boost::multi_index::composite_key<
        NodeContainerTuple,
        BOOST_MULTI_INDEX_MEMBER(NodeContainerTuple, NodeSearchState, state),
        BOOST_MULTI_INDEX_MEMBER(NodeContainerTuple, int, round)
      >
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<nc_state_distance>,
      boost::multi_index::composite_key<
        NodeContainerTuple,
        BOOST_MULTI_INDEX_MEMBER(NodeContainerTuple, NodeSearchState, state),        
        BOOST_MULTI_INDEX_MEMBER(NodeContainerTuple, NodeId, distance_to_target)
      >
    >    
  >
> NodeContainer;

typedef NodeContainer::index<nc_id>::type& NodeContainerByNodeId;

typedef NodeContainer::index<nc_state>::type& NodeContainerByState;

typedef NodeContainer::index<nc_distance>::type& NodeContainerByDistance;

typedef NodeContainer::index<nc_round>::type& NodeContainerByRound;

typedef NodeContainer::index<nc_state_round>::type& NodeContainerByStateRound;

typedef NodeContainer::index<nc_state_distance>::type&
            NodeContainerByStateDistance;

struct FindNodesArgs {
  FindNodesArgs(const NodeId &fna_key, FindNodesFunctor fna_callback)
      : key(fna_key),
        nc(),
        mutex(),
        callback(fna_callback),
        calledback(false),
        round(0) {}
  NodeId key;
  NodeContainer nc;
  boost::mutex mutex;
  FindNodesFunctor callback;
  bool calledback;
  int round;
};

struct FindNodesRpcArgs {
  FindNodesRpcArgs(const Contact &c, std::shared_ptr<FindNodesArgs> fna)
      : contact(c), rpc_fna(fna) {}
        
  Contact contact;
  std::shared_ptr<FindNodesArgs> rpc_fna;
};

/*
struct ContactAndTargetKey {
  ContactAndTargetKey() : contact(), target_key(), contacted(false) {}
  Contact contact;
  NodeId target_key;
  bool contacted;
};

struct DownListCandidate {
  DownListCandidate() : node(), is_down(false) {}
  Contact node;
  bool is_down;  // flag to mark whether this node is down
};

// mapping of giver and suggested list of entires
struct DownListData {
  DownListData() : giver(), candidate_list() {}
  Contact giver;
  std::list<struct DownListCandidate> candidate_list;
};

// define data structures for callbacks
struct LookupContact {
  LookupContact() : kad_contact(), contacted(false) {}
  Contact kad_contact;
  bool contacted;
};

struct IterativeLookUpData {
  IterativeLookUpData(const RemoteFindMethod &method, const NodeId &key,
                      VoidFunctorOneString callback)
      : method(method), key(key), short_list(), current_alpha(),
        active_contacts(), active_probes(), values_found(), dead_ids(),
        downlist(), downlist_sent(false), in_final_iteration(false),
        is_callbacked(false), wait_for_key(false), callback(callback),
        alternative_value_holder(), sig_values_found() {}
  RemoteFindMethod method;
  NodeId key;
  std::list<LookupContact> short_list;
  std::list<Contact> current_alpha, active_contacts, active_probes;
  std::list<std::string> values_found, dead_ids;
  std::list<struct DownListData> downlist;
  bool downlist_sent, in_final_iteration, is_callbacked, wait_for_key;
  VoidFunctorOneString callback;
  Contact alternative_value_holder;
  std::list<kademlia::SignedValue> sig_values_found;
};

struct IterativeStoreValueData {
  IterativeStoreValueData(const std::vector<Contact> &close_nodes,
                          const NodeId &key, const std::string &value,
                          VoidFunctorOneString callback,
                          const bool &publish_val,
                          const boost::int32_t &timetolive,
                          const SignedValue &svalue,
                          const Signature &sreq)
      : closest_nodes(close_nodes), key(key), value(value), save_nodes(0),
        contacted_nodes(0), index(-1), callback(callback), is_callbacked(false),
        data_type(0), publish(publish_val), ttl(timetolive), sig_value(svalue),
        sig_request(sreq) {}
  IterativeStoreValueData(const std::vector<Contact> &close_nodes,
                          const NodeId &key, const std::string &value,
                          VoidFunctorOneString callback,
                          const bool &publish_val,
                          const boost::uint32_t &timetolive)
      : closest_nodes(close_nodes),
        key(key),
        value(value),
        save_nodes(0),
        contacted_nodes(0),
        index(-1),
        callback(callback),
        is_callbacked(false),
        data_type(0),
        publish(publish_val),
        ttl(timetolive),
        sig_value(),
        sig_request() {}
  std::vector<Contact> closest_nodes;
  NodeId key;
  std::string value;
  boost::uint32_t save_nodes, contacted_nodes, index;
  VoidFunctorOneString callback;
  bool is_callbacked;
  int data_type;
  bool publish;
  boost::int32_t ttl;
  SignedValue sig_value;
  Signature sig_request;
};

struct IterativeDelValueData {
  IterativeDelValueData(const std::vector<Contact> &close_nodes,
      const NodeId &key, const SignedValue &svalue,
      const Signature &sreq, VoidFunctorOneString callback)
      : closest_nodes(close_nodes),
        key(key),
        del_nodes(0),
        contacted_nodes(0),
        index(-1),
        callback(callback),
        is_callbacked(false),
        value(svalue),
        sig_request(sreq) {}
  std::vector<Contact> closest_nodes;
  NodeId key;
  boost::uint32_t del_nodes, contacted_nodes, index;
  VoidFunctorOneString callback;
  bool is_callbacked;
  SignedValue value;
  Signature sig_request;
};

struct UpdateValueData {
  UpdateValueData(const NodeId &key, const SignedValue &old_value,
                  const SignedValue &new_value, const Signature &sreq,
                  VoidFunctorOneString callback, boost::uint8_t foundnodes)
      : uvd_key(key),
        uvd_old_value(old_value),
        uvd_new_value(new_value),
        uvd_request_signature(sreq),
        uvd_callback(callback),
        uvd_calledback(0),
        uvd_succeeded(0),
        retries(0),
        found_nodes(foundnodes),
        ttl(0),
        mutex() {}
  NodeId uvd_key;
  SignedValue uvd_old_value;
  SignedValue uvd_new_value;
  Signature uvd_request_signature;
  VoidFunctorOneString uvd_callback;
  boost::uint8_t uvd_calledback;
  boost::uint8_t uvd_succeeded;
  boost::uint8_t retries;
  boost::uint8_t found_nodes;
  boost::uint32_t ttl;
  boost::mutex mutex;
};

struct FindCallbackArgs {
 public:
  explicit FindCallbackArgs(boost::shared_ptr<IterativeLookUpData> data)
      : remote_ctc(), data(data), retry(false) {}
  FindCallbackArgs(const FindCallbackArgs &findcbargs)
      : remote_ctc(findcbargs.remote_ctc),
        data(findcbargs.data),
        retry(findcbargs.retry) {}
  FindCallbackArgs &operator=(const FindCallbackArgs &findcbargs) {
    if (this != &findcbargs) {
      remote_ctc = findcbargs.remote_ctc;
      data = findcbargs.data;
      retry = findcbargs.retry;
//      delete rpc_ctrler;
//      rpc_ctrler = findcbargs.rpc_ctrler;
    }
    return *this;
  }
  Contact remote_ctc;
  boost::shared_ptr<IterativeLookUpData> data;
  bool retry;
//  rpcprotocol::Controller *rpc_ctrler;
};

struct StoreCallbackArgs {
  explicit StoreCallbackArgs(boost::shared_ptr<IterativeStoreValueData> data)
      : remote_ctc(), data(data), retry(false) {}
  StoreCallbackArgs(const StoreCallbackArgs &storecbargs)
      : remote_ctc(storecbargs.remote_ctc),
        data(storecbargs.data),
        retry(storecbargs.retry) {}
  StoreCallbackArgs &operator=(const StoreCallbackArgs &storecbargs) {
    if (this != &storecbargs) {
      remote_ctc = storecbargs.remote_ctc;
      data = storecbargs.data;
      retry = storecbargs.retry;
//      delete rpc_ctrler;
//      rpc_ctrler = storecbargs.rpc_ctrler;
    }
    return *this;
  }
  Contact remote_ctc;
  boost::shared_ptr<IterativeStoreValueData> data;
  bool retry;
//  rpcprotocol::Controller *rpc_ctrler;
};

struct PingCallbackArgs {
  explicit PingCallbackArgs(VoidFunctorOneString callback)
      : remote_ctc(), callback(callback), retry(false) {}
  PingCallbackArgs(const PingCallbackArgs &pingcbargs)
      : remote_ctc(pingcbargs.remote_ctc),
        callback(pingcbargs.callback),
        retry(pingcbargs.retry) {}
  PingCallbackArgs &operator=(const PingCallbackArgs &pingcbargs) {
    if (this != &pingcbargs) {
      remote_ctc = pingcbargs.remote_ctc;
      callback = pingcbargs.callback;
      retry = pingcbargs.retry;
//      delete rpc_ctrler;
//      rpc_ctrler = pingcbargs.rpc_ctrler;
    }
    return *this;
  }
  Contact remote_ctc;
  VoidFunctorOneString callback;
  bool retry;
//  rpcprotocol::Controller *rpc_ctrler;
};

struct DeleteCallbackArgs {
  explicit DeleteCallbackArgs(boost::shared_ptr<IterativeDelValueData> data)
      : remote_ctc(), data(data), retry(false) {}
  DeleteCallbackArgs(const DeleteCallbackArgs &delcbargs)
      : remote_ctc(delcbargs.remote_ctc),
        data(delcbargs.data),
        retry(delcbargs.retry) {}
  DeleteCallbackArgs &operator=(const DeleteCallbackArgs &delcbargs) {
    if (this != &delcbargs) {
      remote_ctc = delcbargs.remote_ctc;
      data = delcbargs.data;
      retry = delcbargs.retry;
//      delete rpc_ctrler;
//      rpc_ctrler = delcbargs.rpc_ctrler;
    }
    return *this;
  }
  Contact remote_ctc;
  boost::shared_ptr<IterativeDelValueData> data;
  bool retry;
//  rpcprotocol::Controller *rpc_ctrler;
};

struct UpdateCallbackArgs {
  UpdateCallbackArgs()
      : uvd(), retries(0), ct(), contact() {}
  UpdateCallbackArgs(const UpdateCallbackArgs &updatecbargs)
      : uvd(updatecbargs.uvd),
        retries(updatecbargs.retries),
//        response(updatecbargs.response),
        ct(updatecbargs.ct),
        contact(updatecbargs.contact) {}
  UpdateCallbackArgs &operator=(const UpdateCallbackArgs &updatecbargs) {
    if (this != &updatecbargs) {
      uvd = updatecbargs.uvd;
      retries = updatecbargs.retries;
      ct = updatecbargs.ct;
      contact = updatecbargs.contact;
//      delete response;
//      delete controller;
//      response = updatecbargs.response;
//      controller = updatecbargs.controller;
    }
    return *this;
  }
  boost::shared_ptr<UpdateValueData> uvd;
  boost::uint8_t retries;
//  UpdateResponse *response;
//  rpcprotocol::Controller *controller;
  ConnectionType ct;
  Contact contact;
};

struct FindNodesParams {
  FindNodesParams()
      : key(),
        start_nodes(),
        exclude_nodes(),
        use_routingtable(true),
        callback() {}
  NodeId key;
  std::vector<Contact> start_nodes;
  std::vector<Contact> exclude_nodes;
  bool use_routingtable;
  FindNodesFunctor callback;
};
*/
}  // namespace kademlia

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_NODE_IMPL_STRUCTS_H_
