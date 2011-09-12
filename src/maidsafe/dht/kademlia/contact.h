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

#ifndef MAIDSAFE_DHT_KADEMLIA_CONTACT_H_
#define MAIDSAFE_DHT_KADEMLIA_CONTACT_H_

#include <functional>
#include <set>
#include <string>
#include <vector>
#include "boost/scoped_ptr.hpp"
#include "boost/serialization/nvp.hpp"
#include "boost/serialization/vector.hpp"
#include "maidsafe/common/utils.h"
#include "maidsafe/dht/transport/transport.h"
#include "maidsafe/dht/kademlia/node_id.h"
#include "maidsafe/dht/version.h"

#if MAIDSAFE_DHT_VERSION != 3104
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-dht library.
#endif

namespace arg = std::placeholders;


namespace maidsafe {

namespace dht {

namespace kademlia {


/** Object containing a Node's Kademlia ID and details of its endpoint(s).
 *  @class Contact */
class Contact {
 public:

  /** Default constructor. */
  Contact();

  /** Copy constructor. */
  Contact(const Contact &other);

  /** Constructor.  To create a valid Contact, in all cases the node ID and
   *  endpoint must be valid, and there must be at least one valid local
   *  endpoint.  Furthermore, for a direct-connected node, there must be no
   *  rendezvous endpoint, but either of tcp443 or tcp80 may be true.  For a
   *  non-direct-connected node, both of tcp443 and tcp80 must be false, but it
   *  may have a rendezvous endpoint set.  A contact is deemed to be direct-
   *  connected if the endpoint equals the first local endpoint.
   *  @param[in] node_id The contact's Kademlia ID.
   *  @param[in] endpoint The contact's external endpoint.
   *  @param[in] local_endpoints The contact's local endpoints.  They must all
   *             have the same port, or local_endpoints_ will be set empty.
   *  @param[in] tcp443 Whether the contact is listening on TCP port 443 or not.
   *  @param[in] tcp443 Whether the contact is listening on TCP port 80 or not.
   *  @param[in] public_key_id ID of the public key which should be used to
   *             encrypt messages for this contact.
   *  @param[in] public_key Public key which should be used to encrypt messages
   *             for this contact.
   *  @param[in] other_info Any extra information to be held. */
  Contact(const NodeId &node_id,
          const transport::Endpoint &endpoint,
          const std::vector<transport::Endpoint> &local_endpoints,
          const transport::Endpoint &rendezvous_endpoint,
          bool tcp443,
          bool tcp80,
          const std::string &public_key_id,
          const std::string &public_key,
          const std::string &other_info);

  /** Destructor. */
  ~Contact();

  /** Getter.
   *  @return The contact's Kademlia ID. */
  NodeId node_id() const;

  /** Getter.
   *  @return The contact's external endpoint. */
  transport::Endpoint endpoint() const;

  /** Getter.
   *  @return The contact's local endpoints. */
  std::vector<transport::Endpoint> local_endpoints() const;

  /** Getter.
   *  @return The contact's rendezous endpoint. */
  transport::Endpoint rendezvous_endpoint() const;

  /** Getter.
   *  @return The contact's external endpoint which is on TCP port 443. */
  transport::Endpoint tcp443endpoint() const;

  /** Getter.
   *  @return The contact's external endpoint which is on TCP port 80. */
  transport::Endpoint tcp80endpoint() const;

  /** Getter.
   *  @return ID of the public key which should be used to encrypt messages for
   *          this contact. */
  std::string public_key_id() const;

  /** Getter.
   *  @return Public key which should be used to encrypt messages for this
   *          contact. */
  std::string public_key() const;

  /** Getter.
   *  @return Any extra information held for this contact. */
  std::string other_info() const;

  /** Setter to mark which of the contact's endpoints should be preferred.
   *  @param ip IP of preferred endpoint.
   *  @return Success of operation. */
  bool SetPreferredEndpoint(const transport::IP &ip);

  /** Getter.
   *  @return The contact's preferred endpoint. */
  transport::Endpoint PreferredEndpoint() const;

  /** Indicate whether the contact is directly-connected or not.
   *  @return True if directly-connected, else false. */
  bool IsDirectlyConnected() const;

  /** Assignment operator. */
  Contact& operator=(const Contact &other);

  // @{
  /** Equality and inequality operators.
   *  Equality is based on node ID.  However if both node IDs are kZeroId,
   *  equality is then based on endpoint IPs.  Note that this means that
   *  equality is not the same as equivalence for Contacts, where equivalence is
   *  defined as neither of two Contacts comparing < than the other, since
   *  operator< only considers node IDs. */
  bool operator==(const Contact &other) const;
  bool operator!=(const Contact &other) const;
  // @}

  // @{
  /** Comparison operators.
   *  Comparisons are based on node ID (lexicographical comparison) */
  bool operator<(const Contact &other) const;
  bool operator>(const Contact &other) const;
  bool operator<=(const Contact &other) const;
  bool operator>=(const Contact &other) const;
  // @}

 private:
  class Impl;
  boost::scoped_ptr<Impl> pimpl_;
};


/** Returns an abbreviated hex representation of contact's NodeId */
std::string DebugId(const Contact &contact);

/** Returns true if node_id is closer to target than contact. */
bool CloserToTarget(const NodeId &node_id,
                    const Contact &contact,
                    const NodeId &target);

/** Returns true if contact1 is closer to target than contact2. */
bool CloserToTarget(const Contact &contact1,
                    const Contact &contact2,
                    const NodeId &target);

/** Returns true if node_id is closer to target than any of closest_contacts. */
bool NodeWithinClosest(const NodeId &node_id,
                       const std::vector<Contact> &closest_contacts,
                       const NodeId &target);

/** Erases all contacts from vector which have the given node_id and returns
 *  true if any were erased. */
bool RemoveContact(const NodeId &node_id, std::vector<Contact> *contacts);

/** Can be used to hold a set of Contacts ordered by closeness to a target. */
typedef std::set<Contact, std::function<bool(const Contact&,  // NOLINT (Fraser)
                                             const Contact&)>> OrderedContacts;

/** Creates an new empty set of Contacts ordered by closeness to target. */
inline OrderedContacts CreateOrderedContacts(const NodeId &target) {
  return OrderedContacts(
      std::bind(static_cast<bool(*)(const Contact&,           // NOLINT (Fraser)
                                    const Contact&,
                                    const NodeId&)>(&CloserToTarget),
                arg::_1, arg::_2, target));
}

/** Creates an new set of Contacts ordered by closeness to target, initialised
 *  with a copy of elements between first (inclusive) and last (exclusive). */
template <typename InputIterator>
OrderedContacts CreateOrderedContacts(InputIterator first,
                                      InputIterator last,
                                      const NodeId &target) {
  return OrderedContacts(first, last,
      std::bind(static_cast<bool(*)(const Contact&,           // NOLINT (Fraser)
                                    const Contact&,
                                    const NodeId&)>(&CloserToTarget),
                arg::_1, arg::_2, target));
}


}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe



namespace mk = maidsafe::dht::kademlia;
namespace mt = maidsafe::dht::transport;

namespace boost {

namespace serialization {

#ifdef __MSVC__
#  pragma warning(disable: 4127)
#endif
template <typename Archive>
void serialize(Archive &archive,                              // NOLINT (Fraser)
               mk::Contact &contact,
               const unsigned int& /*version*/) {
  mk::NodeId node_id;
  mt::Endpoint endpoint;
  std::vector<mt::Endpoint> local_endpoints;
  mt::Endpoint rendezvous_endpoint;
  bool tcp443, tcp80;
  std::string public_key_id, public_key, other_info;

  if (Archive::is_saving::value) {
    node_id = contact.node_id();
    endpoint = contact.endpoint();
    local_endpoints = contact.local_endpoints();
    rendezvous_endpoint = contact.rendezvous_endpoint();
    tcp443 = contact.tcp443endpoint().port == 443;
    tcp80 = contact.tcp80endpoint().port == 80;
    public_key_id = maidsafe::EncodeToBase64(contact.public_key_id());
    public_key = maidsafe::EncodeToBase64(contact.public_key());
    other_info = contact.other_info();
  }

  archive& make_nvp("node_id", node_id);
  archive& make_nvp("endpoint", endpoint);
  archive& make_nvp("local_endpoints", local_endpoints);
  archive& make_nvp("rendezvous_endpoint", rendezvous_endpoint);
  archive& make_nvp("tcp443", tcp443);
  archive& make_nvp("tcp80", tcp80);
  archive& make_nvp("public_key_id", public_key_id);
  archive& make_nvp("public_key", public_key);
  archive& make_nvp("other_info", other_info);

  if (Archive::is_loading::value) {
    public_key_id = maidsafe::DecodeFromBase64(public_key_id);
    public_key = maidsafe::DecodeFromBase64(public_key);
    contact = mk::Contact(node_id, endpoint, local_endpoints,
                          rendezvous_endpoint, tcp443, tcp80, public_key_id,
                          public_key, other_info);
  }
#ifdef __MSVC__
#  pragma warning(default: 4127)
#endif
}

}  // namespace serialization

}  // namespace boost

#endif  // MAIDSAFE_DHT_KADEMLIA_CONTACT_H_
