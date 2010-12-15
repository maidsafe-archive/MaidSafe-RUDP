/* Copyright (c) 2010 maidsafe.net limited
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

#ifndef MAIDSAFE_TRANSPORT_MESSAGEHANDLER_H_
#define MAIDSAFE_TRANSPORT_MESSAGEHANDLER_H_

#include <boost/cstdint.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/function.hpp>
#include <boost/signals2/signal.hpp>

#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/transport.pb.h"

#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>


namespace transport {

enum MessageHandlerCondition {
  kSuccess = 0,
  kError = -1,
  kListenError = -2
};

enum MessageType {
  kRaw = 0,
  kManagedEndpointMessage = 1,
  kNatDetectionRequest = 2,
  kNatDetectionResponse = 3,
  kProxyConnectRequest = 4,
  kProxyConnectResponse = 5,
  kRendezvousRequest = 6
};
const int kMessageTypeExt = 7;  // offset for extensions

typedef boost::function<void(protobuf::ManagedEndpointMessage,
                             ConversationId)> ManagedEndpointRspFunc;
typedef boost::signals2::signal<void(protobuf::ManagedEndpointMessage,
                                     ConversationId)> ManagedEndpointReqSig;
                             
typedef boost::function<void(protobuf::NatDetectionResponse,
                             ConversationId)> NatDetectionRspFunc;
typedef boost::signals2::signal<void(protobuf::NatDetectionRequest,
                                     ConversationId)> NatDetectionReqSig;
                           
typedef boost::function<void(protobuf::ProxyConnectResponse,
                             ConversationId)> ProxyConnectRspFunc;
typedef boost::signals2::signal<void(protobuf::ProxyConnectRequest,
                                     ConversationId)> ProxyConnectReqSig;

typedef boost::signals2::signal<void(protobuf::RendezvousRequest,
                                     ConversationId)> RendezvousReqSig;

class MessageHandler {
 public:
  MessageHandler()
    : transport_(),
      transport_condition_(kError),
      mutex_(),
      on_managed_endpoint_(),
      on_nat_detection_(),
      on_proxy_connect_(),
      on_rendezvous_() {}
  virtual ~MessageHandler() {}
  MessageHandlerCondition ManagedEndpoint(
      const protobuf::ManagedEndpointMessage &request,
      ManagedEndpointRspFunc response_cb);
  MessageHandlerCondition NatDetection(
      const protobuf::NatDetectionRequest &request,
      NatDetectionRspFunc response_cb);
  MessageHandlerCondition ProxyConnect(
      const protobuf::ProxyConnectRequest &request,
      ProxyConnectRspFunc response_cb);
  MessageHandlerCondition Rendezvous(
      const protobuf::RendezvousRequest &request);
  ManagedEndpointReqSig on_managed_endpoint() { return on_managed_endpoint_; }
  NatDetectionReqSig on_nat_detection() { return on_nat_detection_; }
  ProxyConnectReqSig on_proxy_connect() { return on_proxy_connect_; }
  RendezvousReqSig on_rendezvous() { return on_rendezvous_; }
  MessageHandlerCondition StartListening(const Endpoint &endpoint);
  void StopListening();
 protected:
  Transport transport_;
  TransportCondition transport_condition_;
  boost::mutex mutex_;
  ManagedEndpointReqSig on_managed_endpoint_;
  NatDetectionReqSig on_nat_detection_;
  ProxyConnectReqSig on_proxy_connect_;
  RendezvousReqSig on_rendezvous_;
 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_MESSAGEHANDLER_H_
