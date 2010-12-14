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

#ifndef MAIDSAFE_KADEMLIA_CONTACT_H_
#define MAIDSAFE_KADEMLIA_CONTACT_H_

#include <boost/cstdint.hpp>
#include <maidsafe/kademlia/nodeid.h>
#include <maidsafe/kademlia/config.h>
#include <string>


namespace kademlia {

class ContactInfo;

class Contact {
// This class contains information on a single remote contact
 public:
  Contact();
  Contact(const std::string &node_id,
          const Endpoint ep,
          const Endpoint &local_ip);
  explicit Contact(const ContactInfo &contact_info);
  Contact(const Contact &other);
  // Equality is based on node id or (IP and port) if dummy
  bool Equals(const Contact &other) const;
  Contact& operator=(const Contact &other);
  bool SerialiseToString(std::string *serialised_output);
  std::string SerialiseAsString();
  bool ParseFromString(const std::string &data);
  std::string DebugString() const;
  inline const NodeId &node_id() const { return node_id_; }
  inline const Endpoint &ep() const { return ep_; }
  inline boost::uint16_t failed_rpc() const { return failed_rpc_; }
  inline void IncreaseFailed_RPC() { ++failed_rpc_; }
  const Endpoint &rendezvous_ip() const { return rv_ep_; }
 // Port rendezvous_port() const { return rendezvous_port_; }
  inline boost::uint64_t last_seen() const { return last_seen_; }
  inline void set_last_seen(boost::uint64_t last_seen) {
    last_seen_ = last_seen;
  }
  inline const Endpoint &local_eps() const { return local_eps_; }
  bool operator<(const Contact &rhs) const;
  bool operator==(const Contact &rhs) const { return Equals(rhs); }

 private:
  NodeId node_id_;
  Endpoint ep_;
  boost::uint16_t failed_rpc_;
  Endpoint rv_ep_;
  Endpoint local_eps_;
  boost::uint64_t last_seen_;
};

}  // namespace kademlia

#endif  // MAIDSAFE_KADEMLIA_CONTACT_H_
