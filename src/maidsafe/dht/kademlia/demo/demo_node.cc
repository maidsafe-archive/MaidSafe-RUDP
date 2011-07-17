/* Copyright (c) 2011 maidsafe.net limited
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

#include "maidsafe/dht/kademlia/demo/demo_node.h"
#include <iostream>  //  NOLINT
#include <functional>
#include <string>
#include "boost/format.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/dht/log.h"
#include "maidsafe/dht/kademlia/contact.h"
#include "maidsafe/dht/kademlia/node_id.h"
#include "maidsafe/dht/kademlia/node-api.h"
#include "maidsafe/dht/kademlia/securifier.h"
#include "maidsafe/dht/kademlia/rpcs.h"  // for TransportType enum
#include "maidsafe/dht/transport/transport.h"
#include "maidsafe/dht/transport/tcp_transport.h"
#include "maidsafe/dht/transport/udp_transport.h"

namespace arg = std::placeholders;
namespace bptime = boost::posix_time;


namespace maidsafe {

namespace dht {

namespace kademlia {

void PrintNodeInfo(const Contact &contact) {
  ULOG(INFO)
      << boost::format("Node ID:   %1%")
                       % contact.node_id().ToStringEncoded(NodeId::kHex);
  ULOG(INFO)
      << boost::format("Node IP:   %1%") % contact.endpoint().ip.to_string();
  ULOG(INFO)
      << boost::format("Node port: %1%") % contact.endpoint().port;
}

DemoNode::DemoNode() : asio_service_(),
                       work_(new boost::asio::io_service::work(asio_service_)),
                       thread_group_(),
                       listening_transport_(),
                       securifier_(new Securifier("", "", "")),
                       kademlia_node_(),
                       bootstrap_contacts_() {}

int DemoNode::Init(const size_t &thread_count,
                   bool client_only_node,
                   const int &transport_type,
                   const transport::Endpoint &endpoint,
                   const uint16_t &k,
                   const uint16_t &alpha,
                   const uint16_t &beta,
                   const bptime::seconds &mean_refresh_interval,
                   bool secure) {
  // Create worker threads for asynchronous operations.
  for (size_t i(0); i != thread_count; ++i) {
    thread_group_.create_thread(
        std::bind(static_cast<size_t(boost::asio::io_service::*)()>(
            &boost::asio::io_service::run), &asio_service_));
  }

  // If we want a secure network, reset the securifier with cryptographic keys.
  if (secure) {
    crypto::RsaKeyPair rsa_key_pair;
    rsa_key_pair.GenerateKeys(4096);
    std::string public_key_id(RandomString(64));
    securifier_.reset(new Securifier(public_key_id, rsa_key_pair.public_key(),
                                     rsa_key_pair.private_key()));
  }

  // Create an incoming message handler and start a listening transport if this
  // is not a client node.
  MessageHandlerPtr message_handler;
  if (!client_only_node) {
    message_handler = MessageHandlerPtr(new MessageHandler(securifier_));
    switch (transport_type) {
      case kTcp:
        listening_transport_.reset(new transport::TcpTransport(asio_service_));
        break;
      case kUdp:
        listening_transport_.reset(new transport::UdpTransport(asio_service_));
        break;
      default:
        return transport::kError;
    }

    transport::TransportCondition result =
        listening_transport_->StartListening(endpoint);

    if (result != transport::kSuccess)
      return result;
  }

  kademlia_node_.reset(new Node(asio_service_,
                                listening_transport_,
                                message_handler,
                                securifier_,
                                AlternativeStorePtr(),
                                client_only_node,
                                k,
                                alpha,
                                beta,
                                mean_refresh_interval));
  return 0;
}

int DemoNode::JoinNode(const NodeId &node_id,
                       const std::vector<Contact> &bootstrap_contacts) {
  const int kWaiting(1234567);
  int response(kWaiting);
  boost::mutex mutex;
  boost::condition_variable cond_var;
  {
    boost::mutex::scoped_lock lock(mutex);
    kademlia_node_->Join(node_id, bootstrap_contacts,
                         std::bind(&DemoNode::JoinCallback, this, arg::_1,
                                   &response, &mutex, &cond_var));
    while (response == kWaiting)
      cond_var.wait(lock);
  }
  return response;
}

void DemoNode::JoinCallback(const int &result,
                            int *response_code,
                            boost::mutex *mutex,
                            boost::condition_variable *cond_var) {
  boost::mutex::scoped_lock lock(*mutex);
  *response_code = result;
  cond_var->notify_one();
}

void DemoNode::LeaveNode(std::vector<Contact> *bootstrap_contacts) {
  kademlia_node_->Leave(bootstrap_contacts);
}

void DemoNode::StopListeningTransport() {
  listening_transport_->StopListening();
}

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe
