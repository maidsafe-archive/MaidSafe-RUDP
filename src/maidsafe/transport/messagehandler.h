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

#include <boost/shared_ptr.hpp>
#include <boost/function.hpp>
#include <boost/signals2/signal.hpp>
#include <boost/thread/mutex.hpp>

#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/transport.pb.h"

#include <string>

namespace bs2 = boost::signals2;

namespace transport {

enum MessageHandlerCondition {
  kSuccess = 0,
  kError = -1,
  kListenError = -2
};

class MessageHandler {
 public:
  const int kMessageTypeExt = 7;  // Offset for type extensions.
  typedef boost::function<void(protobuf::ManagedEndpointMessage)>
      ManagedEndpointRspFunc;
  typedef boost::shared_ptr<bs2::signal<void(protobuf::ManagedEndpointMessage,
      ConversationId)> > ManagedEndpointReqSigPtr;
  typedef boost::function<void(protobuf::NatDetectionResponse)>
      NatDetectionRspFunc;
  typedef boost::shared_ptr<bs2::signal<void(protobuf::NatDetectionRequest,
      ConversationId)> > NatDetectionReqSigPtr;
  typedef boost::function<void(protobuf::ProxyConnectResponse)>
      ProxyConnectRspFunc;
  typedef boost::shared_ptr<bs2::signal<void(protobuf::ProxyConnectRequest,
      ConversationId)> > ProxyConnectReqSigPtr;
  typedef boost::shared_ptr<bs2::signal<void(protobuf::RendezvousRequest)> >
      RendezvousReqSigPtr;

  MessageHandler();
  virtual ~MessageHandler() {}
  MessageHandlerCondition StartListening(const Endpoint &endpoint);
  void StopListening();
  
  MessageHandlerCondition RequestManagedEndpoint(
      const protobuf::ManagedEndpointMessage &request,
      const Endpoint &recipient,
      ManagedEndpointRspFunc response_cb);
  MessageHandlerCondition RespondToManagedEndpoint(
      const protobuf::ManagedEndpointMessage &response,
      const ConversationId &conversation_id);
  
  MessageHandlerCondition RequestNatDetection(
      const protobuf::NatDetectionRequest &request,
      const Endpoint &recipient,
      NatDetectionRspFunc response_cb);
  MessageHandlerCondition RespondToNatDetection(
      const protobuf::NatDetectionResponse &response,
      const ConversationId &conversation_id);
  
  MessageHandlerCondition RequestProxyConnect(
      const protobuf::ProxyConnectRequest &request,
      const Endpoint &recipient,
      ProxyConnectRspFunc response_cb);
  MessageHandlerCondition RespondToProxyConnect(
      const protobuf::ProxyConnectResponse &response,
      const ConversationId &conversation_id);
  
  MessageHandlerCondition RequestRendezvous(
      const protobuf::RendezvousRequest &request,
      const Endpoint &recipient);
  
  ManagedEndpointReqSigPtr on_managed_endpoint() {
    return on_managed_endpoint_;
  }
  NatDetectionReqSigPtr on_nat_detection() { return on_nat_detection_; }
  ProxyConnectReqSigPtr on_proxy_connect() { return on_proxy_connect_; }
  RendezvousReqSigPtr on_rendezvous() { return on_rendezvous_; }
 protected:
  Transport transport_;
  TransportCondition transport_condition_;
  boost::mutex mutex_;
 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);
  void OnMessageReceived(const ConversationId &conversation_id,
                         const std::string &data,
                         const Info &info);
  ManagedEndpointReqSigPtr on_managed_endpoint_;
  NatDetectionReqSigPtr on_nat_detection_;
  ProxyConnectReqSigPtr on_proxy_connect_;
  RendezvousReqSigPtr on_rendezvous_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_MESSAGEHANDLER_H_
