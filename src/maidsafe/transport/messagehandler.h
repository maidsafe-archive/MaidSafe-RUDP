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

#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/transport.pb.h"

#include <string>

namespace bs2 = boost::signals2;

namespace transport {

class MessageHandler {
 public:
  const int kMessageTypeExt;  // Offset for type extensions.
  typedef boost::shared_ptr<bs2::signal<void(protobuf::ManagedEndpointMessage,
      protobuf::ManagedEndpointMessage*)> > ManagedEndpointMsgSigPtr;
  typedef boost::shared_ptr<bs2::signal<void(protobuf::NatDetectionRequest,
      protobuf::NatDetectionResponse*)> > NatDetectionReqSigPtr;
  typedef boost::shared_ptr<bs2::signal<void(protobuf::NatDetectionResponse)> >
      NatDetectionRspSigPtr;
  typedef boost::shared_ptr<bs2::signal<void(protobuf::ProxyConnectRequest,
      protobuf::ProxyConnectResponse*)> > ProxyConnectReqSigPtr;
  typedef boost::shared_ptr<bs2::signal<void(protobuf::ProxyConnectResponse)> >
      ProxyConnectRspSigPtr;
  typedef boost::shared_ptr<bs2::signal<void(protobuf::RendezvousRequest)> >
      RendezvousReqSigPtr;
  typedef boost::shared_ptr<bs2::signal<void(int, Info)> >MsgInfoSigPtr;

  MessageHandler()
    : kMessageTypeExt(7),
      on_managed_endpoint_message_(new ManagedEndpointMsgSigPtr::element_type),
      on_nat_detection_request_(new NatDetectionReqSigPtr::element_type),
      on_nat_detection_response_(new NatDetectionRspSigPtr::element_type),
      on_proxy_connect_request_(new ProxyConnectReqSigPtr::element_type),
      on_proxy_connect_response_(new ProxyConnectRspSigPtr::element_type),
      on_rendezvous_request_(new RendezvousReqSigPtr::element_type),
      on_info_(new MsgInfoSigPtr::element_type) {}
  virtual ~MessageHandler() {}
  void OnMessageReceived(const std::string &request,
                         const Info &info,
                         std::string *response,
                         Timeout *timout);
  void OnError(const TransportCondition &transport_condition);

  std::string WrapMessage(const protobuf::ManagedEndpointMessage &msg);
  std::string WrapMessage(const protobuf::NatDetectionRequest &msg);
  std::string WrapMessage(const protobuf::NatDetectionResponse &msg);
  std::string WrapMessage(const protobuf::ProxyConnectRequest &msg);
  std::string WrapMessage(const protobuf::ProxyConnectResponse &msg);
  std::string WrapMessage(const protobuf::RendezvousRequest &msg);
  
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
  RendezvousReqSigPtr on_rendezvous_request() {
    return on_rendezvous_request_;
  }
  MsgInfoSigPtr on_info() {
    return on_info_;
  }
 protected:
  virtual void ProcessSerialisedMessage(const int &message_type,
                                        const std::string &payload,
                                        std::string *response,
                                        Timeout *timeout);
  std::string MakeSerialisedWrapperMessage(const int &message_type,
                                           const std::string &payload);
 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);
  ManagedEndpointMsgSigPtr on_managed_endpoint_message_;
  NatDetectionReqSigPtr on_nat_detection_request_;
  NatDetectionRspSigPtr on_nat_detection_response_;
  ProxyConnectReqSigPtr on_proxy_connect_request_;
  ProxyConnectRspSigPtr on_proxy_connect_response_;
  RendezvousReqSigPtr on_rendezvous_request_;
  MsgInfoSigPtr on_info_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_MESSAGEHANDLER_H_
