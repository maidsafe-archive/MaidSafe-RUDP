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

#ifndef MAIDSAFE_TRANSPORT_RUDP_MESSAGE_HANDLER_H_
#define MAIDSAFE_TRANSPORT_RUDP_MESSAGE_HANDLER_H_

#include <memory>
#include <string>

#include "boost/signals2/signal.hpp"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/message_handler.h"
#include "maidsafe/transport/version.h"

#if MAIDSAFE_TRANSPORT_VERSION != 300
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-transport library.
#endif


namespace bs2 = boost::signals2;

namespace maidsafe {

namespace transport {

namespace protobuf {
class ManagedEndpointMessage;
class NatDetectionRequest;
class NatDetectionResponse;
class ProxyConnectRequest;
class ProxyConnectResponse;
class ForwardRendezvousRequest;
class ForwardRendezvousResponse;
class RendezvousRequest;
class RendezvousAcknowledgement;
}  // namespace protobuf

namespace test {
class RudpMessageHandlerTest_BEH_WrapMessageNatDetectionResponse_Test;
class RudpMessageHandlerTest_BEH_WrapMessageProxyConnectResponse_Test;
class RudpMessageHandlerTest_BEH_WrapMessageForwardRendezvousResponse_Test;
class RudpMessageHandlerTest_BEH_WrapMessageRendezvousAcknowledgement_Test;
class RudpMessageHandlerTest_BEH_MakeSerialisedWrapperMessage_Test;
}  // namespace test

class RudpMessageHandler : public MessageHandler {
 public:
  typedef std::shared_ptr<
      bs2::signal<void(const protobuf::ManagedEndpointMessage&,
                       protobuf::ManagedEndpointMessage*,
                       transport::Timeout*)>> ManagedEndpointMsgSigPtr;
  typedef std::shared_ptr<
      bs2::signal<void(const transport::Info&,
                       const protobuf::NatDetectionRequest&,
                       protobuf::NatDetectionResponse*,
                       transport::Timeout*)>> NatDetectionReqSigPtr;
  typedef std::shared_ptr<
      bs2::signal<void(const protobuf::NatDetectionResponse&)>>
          NatDetectionRspSigPtr;
  typedef std::shared_ptr<
      bs2::signal<void(const transport::Info&,
                       const protobuf::ProxyConnectRequest&,
                       protobuf::ProxyConnectResponse*,
                       transport::Timeout*)>> ProxyConnectReqSigPtr;
  typedef std::shared_ptr<
      bs2::signal<void(const protobuf::ProxyConnectResponse&)>>
          ProxyConnectRspSigPtr;
  typedef std::shared_ptr<
      bs2::signal<void(const Info&, const protobuf::ForwardRendezvousRequest&,
          protobuf::ForwardRendezvousResponse*)>>  ForwardRendezvousReqSigPtr;
  typedef std::shared_ptr<
      bs2::signal<void(const protobuf::ForwardRendezvousResponse&)>>
          ForwardRendezvousRspSigPtr;
  typedef std::shared_ptr<
      bs2::signal<void(const Info&, const protobuf::RendezvousRequest&,
          protobuf::RendezvousAcknowledgement*)>> RendezvousReqSigPtr;
  typedef std::shared_ptr<
      bs2::signal<void(const protobuf::RendezvousAcknowledgement&)>>
          RendezvousAckSigPtr;

  explicit RudpMessageHandler(PrivateKeyPtr private_key)
    : transport::MessageHandler(private_key),
      on_managed_endpoint_message_(new ManagedEndpointMsgSigPtr::element_type),
      on_nat_detection_request_(new NatDetectionReqSigPtr::element_type),
      on_nat_detection_response_(new NatDetectionRspSigPtr::element_type),
      on_proxy_connect_request_(new ProxyConnectReqSigPtr::element_type),
      on_proxy_connect_response_(new ProxyConnectRspSigPtr::element_type),
      on_forward_rendezvous_request_(
          new ForwardRendezvousReqSigPtr::element_type),
      on_forward_rendezvous_response_(
          new ForwardRendezvousRspSigPtr::element_type),
      on_rendezvous_request_(new RendezvousReqSigPtr::element_type),
      on_rendezvous_acknowledgement_(new RendezvousAckSigPtr::element_type) {}
  virtual ~RudpMessageHandler() {}

  std::string WrapMessage(const protobuf::ManagedEndpointMessage &msg);
  std::string WrapMessage(const protobuf::NatDetectionRequest &msg);
  std::string WrapMessage(const protobuf::ProxyConnectRequest &msg);
  std::string WrapMessage(const protobuf::ForwardRendezvousRequest &msg);
  std::string WrapMessage(const protobuf::RendezvousRequest &msg);
  std::string WrapMessage(const protobuf::NatDetectionResponse &msg);
  std::string WrapMessage(const protobuf::ForwardRendezvousResponse &msg);


  ManagedEndpointMsgSigPtr on_managed_endpoint_message() {
    return on_managed_endpoint_message_;
  }
  NatDetectionReqSigPtr on_nat_detection_request() {
    return on_nat_detection_request_;
  }
  NatDetectionRspSigPtr on_nat_detection_response() {
    return on_nat_detection_response_;
  }
  ProxyConnectReqSigPtr on_proxy_connect_request() {
    return on_proxy_connect_request_;
  }
  ProxyConnectRspSigPtr on_proxy_connect_response() {
    return on_proxy_connect_response_;
  }
  ForwardRendezvousReqSigPtr on_forward_rendezvous_request() {
    return on_forward_rendezvous_request_;
  }
  ForwardRendezvousRspSigPtr on_forward_rendezvous_response() {
    return on_forward_rendezvous_response_;
  }
  RendezvousReqSigPtr on_rendezvous_request() {
    return on_rendezvous_request_;
  }
  RendezvousAckSigPtr on_rendezvous_acknowledgement() {
    return on_rendezvous_acknowledgement_;
  }

  std::string CreateForwardRendezvousRequest(const Endpoint &endpoint);

 protected:
  void ProcessSerialisedMessage(const int &message_type,
                                const std::string &payload,
                                const SecurityType &security_type,
                                const std::string &message_signature,
                                const Info &info,
                                std::string *message_response,
                                Timeout *timeout);
//   bool UnwrapWrapperMessage(const std::string& serialised_message,
//                             int* msg_type,
//                             std::string* payload,
//                             std::string* message_signature);
//   std::string WrapWrapperMessage(const int& msg_type,
//                                  const std::string& payload,
//                                  const std::string& message_signature);
 private:
  friend class test::RudpMessageHandlerTest_BEH_WrapMessageNatDetectionResponse_Test;  // NOLINT
  friend class test::RudpMessageHandlerTest_BEH_WrapMessageProxyConnectResponse_Test;  // NOLINT
  friend class test::RudpMessageHandlerTest_BEH_WrapMessageForwardRendezvousResponse_Test;  // NOLINT
  friend class test::RudpMessageHandlerTest_BEH_WrapMessageRendezvousAcknowledgement_Test;  // NOLINT
  friend class test::RudpMessageHandlerTest_BEH_MakeSerialisedWrapperMessage_Test;  // NOLINT
  RudpMessageHandler(const RudpMessageHandler&);
  RudpMessageHandler& operator=(const RudpMessageHandler&);

  std::string WrapMessage(const protobuf::ProxyConnectResponse &msg);
  std::string WrapMessage(const protobuf::RendezvousAcknowledgement &msg);

  ManagedEndpointMsgSigPtr on_managed_endpoint_message_;
  NatDetectionReqSigPtr on_nat_detection_request_;
  NatDetectionRspSigPtr on_nat_detection_response_;
  ProxyConnectReqSigPtr on_proxy_connect_request_;
  ProxyConnectRspSigPtr on_proxy_connect_response_;
  ForwardRendezvousReqSigPtr on_forward_rendezvous_request_;
  ForwardRendezvousRspSigPtr on_forward_rendezvous_response_;
  RendezvousReqSigPtr on_rendezvous_request_;
  RendezvousAckSigPtr on_rendezvous_acknowledgement_;
};

typedef std::shared_ptr<RudpMessageHandler> RudpMessageHandlerPtr;

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_MESSAGE_HANDLER_H_
