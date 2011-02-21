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
 * NOTE: This header is unlikely to have any breaking changes applied.         *
 *       However, it should not be regarded as finalised until this notice is  *
 *       removed.                                                              *
 ******************************************************************************/

#ifndef MAIDSAFE_DHT_KADEMLIA_CONTACT_IMPL_H_
#define MAIDSAFE_DHT_KADEMLIA_CONTACT_IMPL_H_

#include <vector>
#include "boost/cstdint.hpp"
#include "maidsafe-dht/kademlia/contact.h"
#include "maidsafe-dht/kademlia/node_id.h"
#include "maidsafe-dht/transport/transport.h"

namespace maidsafe {

namespace kademlia {

class Contact::Impl {
 public:
  Impl();
  explicit Impl(const Contact &other);
  Impl(const NodeId &node_id,
       const transport::Endpoint &endpoint,
       const std::vector<transport::Endpoint> &local_endpoints,
       const transport::Endpoint &rendezvous_endpoint,
       bool tcp443,
       bool tcp80);
  NodeId node_id() const { return node_id_; }
  transport::Endpoint endpoint() const { return endpoint_; }
  std::vector<transport::Endpoint> local_endpoints() const {
    return local_endpoints_;
  }
  transport::Endpoint rendezvous_endpoint() const {
    return rendezvous_endpoint_;
  }
  transport::Endpoint tcp443endpoint() const;
  transport::Endpoint tcp80endpoint() const;
  bool SetPreferredEndpoint(const transport::IP &ip);
  transport::Endpoint PreferredEndpoint() const;
  bool IsDirectlyConnected() const;
  Impl& operator=(const Impl &other);
  bool operator==(const Impl &other) const;
  bool operator!=(const Impl &other) const;
  bool operator<(const Impl &other) const;
  bool operator>(const Impl &other) const;
  bool operator<=(const Impl &other) const;
  bool operator>=(const Impl &other) const;
 private:
  void Init();
  void Clear();
  bool MoveLocalEndpointToFirst(const transport::IP &ip);
  bool IpMatchesEndpoint(const transport::IP &ip,
                         const transport::Endpoint &endpoint);
  NodeId node_id_;
  transport::Endpoint endpoint_, rendezvous_endpoint_;
  std::vector<transport::Endpoint> local_endpoints_;
  bool tcp443_, tcp80_, prefer_local_;
};

}  // namespace kademlia

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_CONTACT_IMPL_H_
