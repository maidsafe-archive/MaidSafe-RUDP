///*******************************************************************************
// *  Copyright 2012 MaidSafe.net limited                                        *
// *                                                                             *
// *  The following source code is property of MaidSafe.net limited and is not   *
// *  meant for external use.  The use of this code is governed by the licence   *
// *  file licence.txt found in the root of this directory and also on           *
// *  www.maidsafe.net.                                                          *
// *                                                                             *
// *  You are not free to copy, amend or otherwise use this source code without  *
// *  the explicit written permission of the board of directors of MaidSafe.net. *
// ******************************************************************************/
//
//#ifndef MAIDSAFE_RUDP_CORE_MESSAGE_HANDLER_H_
//#define MAIDSAFE_RUDP_CORE_MESSAGE_HANDLER_H_
//
//#include <memory>
//#include <string>
//
//#include "boost/signals2/signal.hpp"
//#include "maidsafe/common/crypto.h"
//#include "maidsafe/common/utils.h"
//#include "maidsafe/common/rsa.h"
//#include "maidsafe/rudp/core/message_handler.h"
//
//
//namespace bs2 = boost::signals2;
//
//namespace maidsafe {
//
//namespace rudp {
//
//namespace detail {
//
//namespace protobuf {
//class ManagedEndpointMessage;
//class NatDetectionRequest;
//class NatDetectionResponse;
//class ProxyConnectRequest;
//class ProxyConnectResponse;
//class ForwardRendezvousRequest;
//class ForwardRendezvousResponse;
//class RendezvousRequest;
//class RendezvousAcknowledgement;
//}  // namespace protobuf
//
//namespace test {
//class MessageHandlerTest_BEH_WrapMessageNatDetectionResponse_Test;
//class MessageHandlerTest_BEH_WrapMessageProxyConnectResponse_Test;
//class MessageHandlerTest_BEH_WrapMessageForwardRendezvousResponse_Test;
//class MessageHandlerTest_BEH_WrapMessageRendezvousAcknowledgement_Test;
//class MessageHandlerTest_BEH_MakeSerialisedWrapperMessage_Test;
//}  // namespace test
//
//class MessageHandler : public MessageHandler {
// public:
//  typedef std::shared_ptr<
//      bs2::signal<void(const protobuf::ManagedEndpointMessage&,
//                       protobuf::ManagedEndpointMessage*,
//                       transport::Timeout*)>> ManagedEndpointMsgSigPtr;
//  typedef std::shared_ptr<
//      bs2::signal<void(const transport::Info&,
//                       const protobuf::NatDetectionRequest&,
//                       protobuf::NatDetectionResponse*,
//                       transport::Timeout*)>> NatDetectionReqSigPtr;
//  typedef std::shared_ptr<
//      bs2::signal<void(const protobuf::NatDetectionResponse&)>>
//          NatDetectionRspSigPtr;
//  typedef std::shared_ptr<
//      bs2::signal<void(const transport::Info&,
//                       const protobuf::ProxyConnectRequest&,
//                       protobuf::ProxyConnectResponse*,
//                       transport::Timeout*)>> ProxyConnectReqSigPtr;
//  typedef std::shared_ptr<
//      bs2::signal<void(const protobuf::ProxyConnectResponse&)>>
//          ProxyConnectRspSigPtr;
//  typedef std::shared_ptr<
//      bs2::signal<void(const Info&, const protobuf::ForwardRendezvousRequest&,
//          protobuf::ForwardRendezvousResponse*)>>  ForwardRendezvousReqSigPtr;
//  typedef std::shared_ptr<
//      bs2::signal<void(const protobuf::ForwardRendezvousResponse&)>>
//          ForwardRendezvousRspSigPtr;
//  typedef std::shared_ptr<
//      bs2::signal<void(const Info&, const protobuf::RendezvousRequest&,
//          protobuf::RendezvousAcknowledgement*)>> RendezvousReqSigPtr;
//  typedef std::shared_ptr<
//      bs2::signal<void(const protobuf::RendezvousAcknowledgement&)>>
//          RendezvousAckSigPtr;
//
//  explicit MessageHandler(PrivateKeyPtr private_key)
//    : transport::MessageHandler(private_key),
//      on_managed_endpoint_message_(new ManagedEndpointMsgSigPtr::element_type),
//      on_nat_detection_request_(new NatDetectionReqSigPtr::element_type),
//      on_nat_detection_response_(new NatDetectionRspSigPtr::element_type),
//      on_proxy_connect_request_(new ProxyConnectReqSigPtr::element_type),
//      on_proxy_connect_response_(new ProxyConnectRspSigPtr::element_type),
//      on_forward_rendezvous_request_(
//          new ForwardRendezvousReqSigPtr::element_type),
//      on_forward_rendezvous_response_(
//          new ForwardRendezvousRspSigPtr::element_type),
//      on_rendezvous_request_(new RendezvousReqSigPtr::element_type),
//      on_rendezvous_acknowledgement_(new RendezvousAckSigPtr::element_type) {}
//  virtual ~MessageHandler() {}
//
//  std::string WrapMessage(const protobuf::ManagedEndpointMessage &msg);
//  std::string WrapMessage(const protobuf::NatDetectionRequest &msg);
//  std::string WrapMessage(const protobuf::ProxyConnectRequest &msg);
//  std::string WrapMessage(const protobuf::ForwardRendezvousRequest &msg);
//  std::string WrapMessage(const protobuf::RendezvousRequest &msg);
//  std::string WrapMessage(const protobuf::NatDetectionResponse &msg);
//  std::string WrapMessage(const protobuf::ForwardRendezvousResponse &msg);
//
//
//  ManagedEndpointMsgSigPtr on_managed_endpoint_message() {
//    return on_managed_endpoint_message_;
//  }
//  NatDetectionReqSigPtr on_nat_detection_request() {
//    return on_nat_detection_request_;
//  }
//  NatDetectionRspSigPtr on_nat_detection_response() {
//    return on_nat_detection_response_;
//  }
//  ProxyConnectReqSigPtr on_proxy_connect_request() {
//    return on_proxy_connect_request_;
//  }
//  ProxyConnectRspSigPtr on_proxy_connect_response() {
//    return on_proxy_connect_response_;
//  }
//  ForwardRendezvousReqSigPtr on_forward_rendezvous_request() {
//    return on_forward_rendezvous_request_;
//  }
//  ForwardRendezvousRspSigPtr on_forward_rendezvous_response() {
//    return on_forward_rendezvous_response_;
//  }
//  RendezvousReqSigPtr on_rendezvous_request() {
//    return on_rendezvous_request_;
//  }
//  RendezvousAckSigPtr on_rendezvous_acknowledgement() {
//    return on_rendezvous_acknowledgement_;
//  }
//
//  std::string CreateForwardRendezvousRequest(const Endpoint &endpoint);
//
// protected:
//  void ProcessSerialisedMessage(const int &message_type,
//                                const std::string &payload,
//                                const SecurityType &security_type,
//                                const std::string &message_signature,
//                                const Info &info,
//                                std::string *message_response,
//                                Timeout *timeout);
////   bool UnwrapWrapperMessage(const std::string& serialised_message,
////                             int* msg_type,
////                             std::string* payload,
////                             std::string* message_signature);
////   std::string WrapWrapperMessage(const int& msg_type,
////                                  const std::string& payload,
////                                  const std::string& message_signature);
// private:
//  friend class test::MessageHandlerTest_BEH_WrapMessageNatDetectionResponse_Test;  // NOLINT
//  friend class test::MessageHandlerTest_BEH_WrapMessageProxyConnectResponse_Test;  // NOLINT
//  friend class test::MessageHandlerTest_BEH_WrapMessageForwardRendezvousResponse_Test;  // NOLINT
//  friend class test::MessageHandlerTest_BEH_WrapMessageRendezvousAcknowledgement_Test;  // NOLINT
//  friend class test::MessageHandlerTest_BEH_MakeSerialisedWrapperMessage_Test;  // NOLINT
//  MessageHandler(const MessageHandler&);
//  MessageHandler& operator=(const MessageHandler&);
//
//  std::string WrapMessage(const protobuf::ProxyConnectResponse &msg);
//  std::string WrapMessage(const protobuf::RendezvousAcknowledgement &msg);
//
//  ManagedEndpointMsgSigPtr on_managed_endpoint_message_;
//  NatDetectionReqSigPtr on_nat_detection_request_;
//  NatDetectionRspSigPtr on_nat_detection_response_;
//  ProxyConnectReqSigPtr on_proxy_connect_request_;
//  ProxyConnectRspSigPtr on_proxy_connect_response_;
//  ForwardRendezvousReqSigPtr on_forward_rendezvous_request_;
//  ForwardRendezvousRspSigPtr on_forward_rendezvous_response_;
//  RendezvousReqSigPtr on_rendezvous_request_;
//  RendezvousAckSigPtr on_rendezvous_acknowledgement_;
//};
//
//typedef std::shared_ptr<MessageHandler> MessageHandlerPtr;
//
//}  // namespace detail
//
//}  // namespace rudp
//
//}  // namespace maidsafe
//
//#endif  // MAIDSAFE_RUDP_CORE_MESSAGE_HANDLER_H_
