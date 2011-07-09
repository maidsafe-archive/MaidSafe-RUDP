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

#include <memory>
#include <string>

#include "boost/thread/mutex.hpp"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4244)
#endif
#include "boost/multi_index_container.hpp"
#include "boost/multi_index/composite_key.hpp"
#include "boost/multi_index/ordered_index.hpp"
#include "boost/multi_index/identity.hpp"
#include "boost/multi_index/member.hpp"
#ifdef __MSVC__
#  pragma warning(pop)
#endif

#include "maidsafe/dht/kademlia/config.h"
#include "maidsafe/dht/kademlia/contact.h"
#include "maidsafe/dht/kademlia/node_id.h"
#include "maidsafe/dht/kademlia/rpcs.h"
#include "maidsafe/dht/kademlia/utils.h"

namespace maidsafe {

namespace dht {

namespace kademlia {

class Signature;
class SignedValue;

enum RemoteFindMethod { kFindNode, kFindValue, kBootstrap };

enum NodeSearchState { kNew, kContacted, kDown, kSelectedAlpha };

enum OperationMethod { kOpDelete, kOpStore, kOpUpdate,
                       kOpFindNode, kOpFindValue };

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

struct Args {
  explicit Args(OperationMethod operation_type)
      : nc(),
        mutex(),
        calledback(false),
        operation_type(operation_type) {}
  virtual ~Args() {}
  NodeContainer nc;
  boost::mutex mutex;
  bool calledback;
  OperationMethod operation_type;
};

struct RpcArgs {
  RpcArgs(const Contact &c, std::shared_ptr<Args> a)
      : contact(c),
        rpc_a(a) {}
  Contact contact;
  std::shared_ptr<Args> rpc_a;
};

struct FindNodesArgs : Args {
  FindNodesArgs(const NodeId &fna_key, FindNodesFunctor fna_callback)
      : Args(kOpFindNode),
        key(fna_key),
        callback(fna_callback),
        round(0) {}
  NodeId key;
  FindNodesFunctor callback;
  int round;
};

struct FindValueArgs : Args {
  FindValueArgs(const NodeId &fva_key, SecurifierPtr securifier,
                FindValueFunctor fva_callback)
      : Args(kOpFindValue), key(fva_key), securifier(securifier),
        callback(fva_callback), round(0) {}
  NodeId key;
  SecurifierPtr securifier;
  FindValueFunctor callback;
  int round;
};

struct StoreArgs : Args {
  explicit StoreArgs(StoreFunctor sa_callback)
      : Args(kOpStore),
        callback(sa_callback) {}
  StoreFunctor callback;
};

struct DeleteArgs : Args {
  explicit DeleteArgs(DeleteFunctor da_callback)
    : Args(kOpDelete),
      callback(da_callback) {}
  DeleteFunctor callback;
};

struct UpdateArgs : Args {
  UpdateArgs(const std::string &new_value, const std::string &new_signature,
             const std::string &old_value, const std::string &old_signature,
             UpdateFunctor ua_callback)
      : Args(kOpUpdate),
        callback(ua_callback),
        new_value(new_value),
        new_signature(new_signature),
        old_value(old_value),
        old_signature(old_signature) {}
  UpdateFunctor callback;
  std::string new_value;
  std::string new_signature;
  std::string old_value;
  std::string old_signature;
};

typedef std::shared_ptr<Args> ArgsPtr;
typedef std::shared_ptr<RpcArgs> RpcArgsPtr;
typedef std::shared_ptr<FindNodesArgs> FindNodesArgsPtr;
typedef std::shared_ptr<FindValueArgs> FindValueArgsPtr;
typedef std::shared_ptr<StoreArgs> StoreArgsPtr;
typedef std::shared_ptr<DeleteArgs> DeleteArgsPtr;
typedef std::shared_ptr<UpdateArgs> UpdateArgsPtr;

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_NODE_IMPL_STRUCTS_H_
