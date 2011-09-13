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

/*******************************************************************************
 * NOTE: This API is unlikely to have any breaking changes applied.  However,  *
 *       it should not be regarded as a final API until this notice is removed.*
 ******************************************************************************/

#ifndef MAIDSAFE_DHT_KADEMLIA_NODE_API_H_
#define MAIDSAFE_DHT_KADEMLIA_NODE_API_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "boost/asio/io_service.hpp"
#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "boost/scoped_ptr.hpp"
#include "maidsafe/common/version.h"

#include "maidsafe/dht/kademlia/contact.h"
#include "maidsafe/dht/kademlia/config.h"
#include "maidsafe/dht/version.h"

#if MAIDSAFE_DHT_VERSION != 3104
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-dht library.
#endif


namespace maidsafe {

namespace dht {

namespace kademlia {

class NodeImpl;

// This class represents a kademlia node providing the API to join the network,
// find nodes and values, store, delete and update values, as well as the
// methods to access the local storage of the node and its routing table.
class Node {
 public:

  // asio_service is a reference to a boost::asio::io_service instance which
  // should have at least 1 thread running io_service::run().
  //
  // listening_transport is responsible for listening only, not sending.  It
  // need not be listening before it is passed, it will be started in Join.
  //
  // default_securifier is responsible for signing, verification, encrypting and
  // decrypting messages and values.  If it is an invalid pointers, a basic
  // instantiation will be made.  For all other member functions where a
  // securifer is passed, if it is invalid, this default_securifier will be used
  // instead.
  //
  // alternative_store can be used to augment / complement the native Kademlia
  // datastore of <key,values>.  If alternative_store is an invalid pointer, no
  // default is instantiated, and all values are held in memory in datastore.
  //
  // client_only_node specifies whether the node should be treated as a client
  // on the network rather than a full peer.  In client mode, the node does not
  // accept store requests and is not added to other nodes' routing tables.
  //
  // k, alpha and beta are as defined for standard Kademlia, i.e. number of
  // contacts returned from a Find RPC, parallel level of Find RPCs, and number
  // of returned Find RPCs required to start a subsequent iteration
  // respectively.
  //
  // mean_refresh_interval indicates the average interval between calls to
  // refresh values.
  Node(AsioService &asio_service,                             // NOLINT (Fraser)
       TransportPtr listening_transport,
       MessageHandlerPtr message_handler,
       SecurifierPtr default_securifier,
       AlternativeStorePtr alternative_store,
       bool client_only_node,
       const uint16_t &k,
       const uint16_t &alpha,
       const uint16_t &beta,
       const boost::posix_time::time_duration &mean_refresh_interval);

  ~Node();

  // Join the network.  If the listening_transport cannot be started (or is not
  // already started) on the desired port, the callback indicates failure.
  // bootstrap_contacts should be directly-connected peers to allow successful
  // NAT detection.
  void Join(const NodeId &node_id,
            std::vector<Contact> bootstrap_contacts,
            JoinFunctor callback);

  // Leave the kademlia network.  All values stored in the node are erased and
  // all directly-connected nodes from the routing table are passed into
  // bootstrap_contacts.
  void Leave(std::vector<Contact> *bootstrap_contacts);

  // Store <key,value,signature> for ttl.  Infinite ttl is indicated by
  // boost::posix_time::pos_infin.  If signature is empty, the value is signed
  // using securifier, unless it is invalid, in which case the node's
  // default_securifier signs value.  If signature is not empty, it is
  // validated by securifier or default_securifer.
  void Store(const Key &key,
             const std::string &value,
             const std::string &signature,
             const boost::posix_time::time_duration &ttl,
             SecurifierPtr securifier,
             StoreFunctor callback);

  // Delete <key,value,signature> from network.  If signature is empty, the
  // value is signed using securifier, unless it is invalid, in which case
  // the node's default_securifier signs value.  If signature is not empty, it
  // is validated by securifier or default_securifer.  The securifier must sign
  // and encrypt with the same cryptographic keys as were used when the
  // <key,value,signature> was stored.
  void Delete(const Key &key,
              const std::string &value,
              const std::string &signature,
              SecurifierPtr securifier,
              DeleteFunctor callback);

  // Replace <key,old_value,old_signature> with <key,new_value,new_signature>
  // on the network.  If either signature is empty, the corresponding value is
  // signed using securifier, unless it is invalid, in which case the node's
  // default_securifier signs the value.  If a signature is not empty, it is
  // validated by securifier or default_securifer.  The securifier must sign
  // and encrypt with the same cryptographic keys as were used when the
  // <key,old_value,old_signature> was stored.  Infinite ttl is indicated by
  // boost::posix_time::pos_infin.
  void Update(const Key &key,
              const std::string &new_value,
              const std::string &new_signature,
              const std::string &old_value,
              const std::string &old_signature,
              const boost::posix_time::time_duration &ttl,
              SecurifierPtr securifier,
              UpdateFunctor callback);

  // Find value(s) on the network.  The callback will always have passed to it
  // the contact details of the node needing a cache copy of the value(s) (i.e.
  // the last node during the search to not hold the value(s)).  This could be
  // an empty contact (e.g. if the lookup failed, or was completed by the first
  // RPC's callback).  If cache is true for this lookup, the cache contact is
  // not empty, and the value(s) are found, then the cache contact is sent the
  // value(s) for caching.
  //
  // Other than this, the callback parameters are populated as follows:
  // * If any queried peer holds the value(s) in its alternative_store, its
  //   details are passed in the callback and no other callback parameters are
  //   completed.  In this case, the return code is kFoundAlternativeStoreHolder
  // * If any queried peer holds the value(s) in its kademlia datastore, the
  //   value(s) and signature(s) are passed in the callback and no other
  //   callback parameters are completed.  In this case, the return code is
  //   kSuccess.
  // * Otherwise, iff no value exists under key, the (k + extra) closest nodes'
  //   details are passed in callback, ordered by kademlia closeness to key,
  //   closest first.  In this case, the return code is kFailedToFindValue.
  //
  // These return codes are all >= 0.  Any other return code indicates an error
  // in the lookup process and will be < 0.  N.B. This node could be returned as
  // the alternative_store holder or as one of the closest contacts.
  void FindValue(const Key &key,
                 SecurifierPtr securifier,
                 FindValueFunctor callback,
                 const uint16_t &extra_contacts = 0,
                 bool cache = true);

  // Find details of (k + extra) nodes closest to key.  The details are passed
  // in callback, ordered by kademlia closeness to key, closest first.
  // N.B. This node could be returned as one of the closest contacts.
  void FindNodes(const Key &key,
                 FindNodesFunctor callback,
                 const uint16_t &extra_contacts = 0);

  // Find the contact details of a node.  If the target node is not in this
  // node's routing table (and is not this node), a FindNode will be executed.
  // If the node is offline, a default-constructed Contact will be passed back
  // in the callback.
  void GetContact(const NodeId &node_id, GetContactFunctor callback);

  // Mark contact in routing table as having just been seen (i.e. contacted).
  void SetLastSeenToNow(const Contact &contact);

  // Mark contact in routing table as having failed to respond correctly to an
  // RPC request.
  void IncrementFailedRpcs(const Contact &contact);

  // Update contact in routing table with revised rank info.
  void UpdateRankInfo(const Contact &contact, RankInfoPtr rank_info);

  // Retrieve rank info from contact in routing table.  No network operation is
  // executed.
  RankInfoPtr GetLocalRankInfo(const Contact &contact);

  // Retrieve all contacts from the routing table.  No network operation is
  // executed.
  void GetAllContacts(std::vector<Contact> *contacts);

  // Retrieve all directly-connected contacts from the routing table.  No
  // network operation is executed.
  void GetBootstrapContacts(std::vector<Contact> *contacts);

  // Checks whether the contact is online or not
  void Ping(const Contact &contact, PingFunctor callback);

  // This node's contact details
  Contact contact() const;

  // Whether node is currently joined to the network.
  bool joined() const;

  // Getters
  AlternativeStorePtr alternative_store();
  OnOnlineStatusChangePtr on_online_status_change();
  bool client_only_node() const;
  uint16_t k() const;

 private:
  boost::scoped_ptr<NodeImpl> pimpl_;
};


struct FindValueReturns {
  FindValueReturns() : return_code(kPendingResult),
                       values_and_signatures(),
                       closest_nodes(),
                       alternative_store_holder(),
                       needs_cache_copy() {}
  FindValueReturns(
      int return_code_in,
      const std::vector<ValueAndSignature> &values_and_signatures_in,
      const std::vector<Contact> &closest_nodes_in,
      const Contact &alternative_store_holder_in,
      const Contact &needs_cache_copy_in)
          : return_code(return_code_in),
            values_and_signatures(values_and_signatures_in),
            closest_nodes(closest_nodes_in),
            alternative_store_holder(alternative_store_holder_in),
            needs_cache_copy(needs_cache_copy_in) {}
  int return_code;
  std::vector<ValueAndSignature> values_and_signatures;
  std::vector<Contact> closest_nodes;
  Contact alternative_store_holder;
  Contact needs_cache_copy;
};

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_NODE_API_H_
