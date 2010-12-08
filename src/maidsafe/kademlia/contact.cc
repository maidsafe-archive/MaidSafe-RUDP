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

#include "maidsafe/kademlia/contact.h"
#include <boost/lexical_cast.hpp>
#include "maidsafe/base/utils.h"
#include "maidsafe/protobuf/contact_info.pb.h"

namespace kad {

Contact::Contact()
    : node_id_(),
      ip_(),
      port_(0),
      failed_rpc_(0),
      rendezvous_ip_(),
      rendezvous_port_(0),
      last_seen_(base::GetEpochMilliseconds()),
      local_ip_(),
      local_port_(0) {}

Contact::Contact(const std::string &node_id, const IP &ip,
                 const Port &port, const IP &local_ip,
                 const Port &local_port,
                 const IP &rendezvous_ip,
                 const Port &rendezvous_port)
    : node_id_(node_id), ip_(ip), port_(port),
      failed_rpc_(0), rendezvous_ip_(rendezvous_ip),
      rendezvous_port_(rendezvous_port),
      last_seen_(base::GetEpochMilliseconds()), local_ip_(local_ip),
      local_port_(local_port) {
  if (ip.size() > 4)
      ip_ = base::IpAsciiToBytes(ip);
  if (local_ip.size() > 4)
      local_ip_ = base::IpAsciiToBytes(local_ip);
  if (rendezvous_ip.size() > 4)
      rendezvous_ip_ = base::IpAsciiToBytes(rendezvous_ip);
}

Contact::Contact(const std::string &node_id, const IP &ip,
                 const Port &port)
    : node_id_(node_id), ip_(ip), port_(port),
      failed_rpc_(0), rendezvous_ip_(), rendezvous_port_(0),
      last_seen_(base::GetEpochMilliseconds()), local_ip_(), local_port_(0) {
  if (ip.size() > 4)
      ip_ = base::IpAsciiToBytes(ip);
}

Contact::Contact(const std::string &node_id, const IP &ip,
                 const Port &port, const IP &local_ip,
                 const Port &local_port)
    : node_id_(node_id), ip_(ip), port_(port),
      failed_rpc_(0), rendezvous_ip_(), rendezvous_port_(0),
      last_seen_(base::GetEpochMilliseconds()), local_ip_(local_ip),
      local_port_(local_port) {
  if (ip.size() > 4)
      ip_ = base::IpAsciiToBytes(ip);
  if (local_ip.size() > 4)
      local_ip_ = base::IpAsciiToBytes(local_ip);
}

Contact::Contact(const KadId &node_id, const IP &ip,
                 const Port &port, const IP &local_ip,
                 const Port &local_port, const IP &rendezvous_ip,
                 const Port &rendezvous_port)
    : node_id_(node_id), ip_(ip), port_(port),
      failed_rpc_(0), rendezvous_ip_(rendezvous_ip),
      rendezvous_port_(rendezvous_port),
      last_seen_(base::GetEpochMilliseconds()), local_ip_(local_ip),
      local_port_(local_port) {
  if (ip.size() > 4)
      ip_ = base::IpAsciiToBytes(ip);
  if (local_ip.size() > 4)
      local_ip_ = base::IpAsciiToBytes(local_ip);
  if (rendezvous_ip.size() > 4)
      rendezvous_ip_ = base::IpAsciiToBytes(rendezvous_ip);
}

Contact::Contact(const KadId &node_id, const IP &ip,
                 const Port &port)
    : node_id_(node_id), ip_(ip), port_(port),
      failed_rpc_(0), rendezvous_ip_(), rendezvous_port_(0),
      last_seen_(base::GetEpochMilliseconds()), local_ip_(), local_port_(0) {
  if (ip.size() > 4)
      ip_ = base::IpAsciiToBytes(ip);
}

Contact::Contact(const KadId &node_id, const IP &ip,
                 const Port &port, const IP &local_ip,
                 const Port &local_port)
    : node_id_(node_id), ip_(ip), port_(port),
      failed_rpc_(0), rendezvous_ip_(), rendezvous_port_(0),
      last_seen_(base::GetEpochMilliseconds()), local_ip_(local_ip),
      local_port_(local_port) {
  if (ip.size() > 4)
      ip_ = base::IpAsciiToBytes(ip);
  if (local_ip.size() > 4)
      local_ip_ = base::IpAsciiToBytes(local_ip);
}

Contact::Contact(const ContactInfo &contact_info)
    : node_id_(contact_info.node_id()), ip_(contact_info.ip()),
      port_(contact_info.port()), failed_rpc_(0),
      rendezvous_ip_(contact_info.rendezvous_ip()),
      rendezvous_port_(contact_info.rendezvous_port()),
      last_seen_(base::GetEpochMilliseconds()),
      local_ip_(contact_info.local_ips()),
      local_port_(contact_info.local_port()) {
  if (contact_info.ip().size() > 4)
      ip_ = base::IpAsciiToBytes(contact_info.ip());
  if (contact_info.local_ips().size() > 4)
      local_ip_ = base::IpAsciiToBytes(contact_info.local_ips());
  if (contact_info.rendezvous_ip().size() > 4)
      rendezvous_ip_ = base::IpAsciiToBytes(contact_info.rendezvous_ip());
}

Contact::Contact(const Contact &other)
    : node_id_(other.node_id_), ip_(other.ip_),
      port_(other.port_), failed_rpc_(other.failed_rpc_),
      rendezvous_ip_(other.rendezvous_ip_),
      rendezvous_port_(other.rendezvous_port_),
      last_seen_(other.last_seen_), local_ip_(other.local_ip_),
      local_port_(other.local_port_) {}

bool Contact::Equals(const Contact &other) const {
  if (node_id_ == other.node_id_)
    return (node_id_.String() != kClientId) ||
           (ip_ == other.ip_ && port_ == other.port_);
  return false;
}

Contact& Contact::operator=(const Contact &other) {
  this->node_id_ = other.node_id_;
  this->ip_ = other.ip_;
  this->port_ = other.port_;
  this->failed_rpc_ = other.failed_rpc_;
  this->rendezvous_ip_ = other.rendezvous_ip_;
  this->rendezvous_port_ = other.rendezvous_port_;
  this->last_seen_ = other.last_seen_;
  this->local_ip_ = other.local_ip_;
  this->local_port_ = other.local_port_;
  return *this;
}

bool Contact::SerialiseToString(std::string *serialised_output) {
  ContactInfo info;
  info.set_node_id(node_id_.String());
  info.set_ip(ip_);
  info.set_port(port_);
  info.set_rendezvous_ip(rendezvous_ip_);
  info.set_rendezvous_port(rendezvous_port_);
  info.set_local_ips(local_ip_);
  info.set_local_port(local_port_);
  return info.SerializeToString(serialised_output);
}

std::string Contact::SerialiseAsString() {
  // do not serialise empty contacts
  if (port_ == 0 && ip_.empty()) {
    return "";
  }
  ContactInfo info;
  info.set_node_id(node_id_.String());
  info.set_ip(ip_);
  info.set_port(port_);
  info.set_rendezvous_ip(rendezvous_ip_);
  info.set_rendezvous_port(rendezvous_port_);
//  info.set_local_ip(local_ip_);
  info.set_local_port(local_port_);

  return info.SerializeAsString();
}

bool Contact::ParseFromString(const std::string &data) {
  kad::ContactInfo info;
  if (!info.ParseFromString(data))
    return false;
  node_id_ = KadId(info.node_id());
  if (!node_id_.IsValid())
    return false;
  if (info.ip().size() > 4)
    ip_ = base::IpAsciiToBytes(info.ip());
  else
    ip_ = info.ip();
  port_ = static_cast<Port>(info.port());
  if (info.has_rendezvous_ip()) {
    if (info.rendezvous_ip().size() > 4)
      rendezvous_ip_ = base::IpAsciiToBytes(info.rendezvous_ip());
    else
      rendezvous_ip_ = info.rendezvous_ip();
    rendezvous_port_ = static_cast<Port>(info.rendezvous_port());
  } else {
    rendezvous_ip_.clear();
    rendezvous_port_ = 0;
  }
  if (info.has_local_ips()) {
    if (info.local_ips().size() > 4)
      local_ip_ = base::IpAsciiToBytes(info.local_ips());
    else
      local_ip_ = info.local_ips();
    local_port_ = static_cast<Port>(info.local_port());
  } else {
    local_ip_.clear();
    local_port_ = 0;
  }
  last_seen_ = base::GetEpochMilliseconds();
  return true;
}

std::string Contact::DebugString() const {
  if (port_ == 0 && ip_.empty()) {
    return "Empty contact.\n";
  }
  std::string port(boost::lexical_cast<std::string>(port_));
  std::string debug_string = "Node_id: " + node_id_.ToStringEncoded(KadId::kHex)
                             + "\n";
  std::string dec_ip(base::IpBytesToAscii(ip_));
  debug_string += ("IP address: " + dec_ip + ":" + port + "\n");

  if (!local_ip_.empty()) {
    std::string dec_lip(base::IpBytesToAscii(local_ip_));
    std::string lport(boost::lexical_cast<std::string>(local_port_));
    debug_string += ("Local IP address: " + dec_lip + ":" + lport + "\n");
  }

  if (!rendezvous_ip_.empty()) {
    std::string dec_rip(base::IpBytesToAscii(rendezvous_ip_));
    std::string rport(boost::lexical_cast<std::string>(rendezvous_port_));
    debug_string += ("RV IP address: " + dec_rip + ":" + rport + "\n");
  }
  return debug_string;
}

bool Contact::operator<(const Contact &rhs) const {
  return this->node_id().String() < rhs.node_id().String();
}

}  // namespace kad
