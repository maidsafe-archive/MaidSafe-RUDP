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

#include <vector>
#include "boost/cstdint.hpp"
#include "boost/scoped_ptr.hpp"
#include "maidsafe-dht/transport/transport.h"

namespace maidsafe {

namespace kademlia {

class NodeId;

/** Object containing a Node's Kademlia ID and details of its endpoint(s).
 *  @class Contact */
class Contact {
 public:

  /** Default constructor. */
  Contact();

  /** Copy constructor. */
  Contact(const Contact &other);

  /** Constructor.
   *  @param node_id The contact's Kademlia ID.
   *  @param endpoint The contact's external endpoint. */
  Contact(const NodeId &node_id, const transport::Endpoint &endpoint);

  /** Constructor.
   *  @param node_id The contact's Kademlia ID.
   *  @param endpoint The contact's external endpoint.
   *  @param rendezvous_endpoint The contact's rendezous endpoint.
   *  @param local_endpoints The contact's local endpoints.  They must all have
   *  the same port, or local_endpoints_ will be set to an empty vector. */
  Contact(const NodeId &node_id,
          const transport::Endpoint &endpoint,
          const transport::Endpoint &rendezvous_endpoint,
          std::vector<transport::Endpoint> &local_endpoints);

  /** Destructor. */
  ~Contact();

  /** Getter.
   *  @return The contact's Kademlia ID. */
  NodeId node_id() const;

  /** Getter.
   *  @return The contact's external endpoint. */
  transport::Endpoint endpoint() const;

  /** Getter.
   *  @return The contact's rendezous endpoint. */
  transport::Endpoint rendezvous_endpoint() const;

  /** Getter.
   *  @return The contact's local endpoints. */
  std::vector<transport::Endpoint> local_endpoints() const;

  /** Setter to mark which of the contact's endpoints should be preferred.
   *  @param ip IP of preferred endpoint.
   *  @return Success of operation. */
  bool SetPreferredEndpoint(const transport::IP &ip);

  /** Getter.
   *  @return The contact's preferred endpoint. */
  transport::Endpoint GetPreferredEndpoint() const;

  /** Assignment operator. */
  Contact& operator=(const Contact &other);

  //@{
  /** Equality and inequality operators.
   *  Equality is based on node ID or (IP and port) if dummy */
  bool operator==(const Contact &other) const;
  bool operator!=(const Contact &other) const;
  //@}

  //@{
  /** Comparison operators.
   *  Comparisons are based on node ID (lexicographical comparison) */
  bool operator<(const Contact &other) const;
  bool operator>(const Contact &other) const;
  bool operator<=(const Contact &other) const;
  bool operator>=(const Contact &other) const;
  //@}

 private:
  class Impl;
  boost::scoped_ptr<Impl> pimpl_;
};

// Retuns true if contact1 is closer to target than contact2.
bool CloserToTarget(const Contact &contact1,
                    const Contact &contact2,
                    const NodeId &target);

// Returns true if contact is closer to target than any one of closest_contacts.
bool ContactWithinClosest(const Contact &contact,
                          const std::vector<Contact> &closest_contacts,
                          const NodeId &target);

// Erases all contacts from vector which have the given node_id and returns true
// if any were erased.
bool RemoveContact(const NodeId &node_id, std::vector<Contact> *contacts);

}  // namespace kademlia

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_CONTACT_H_
