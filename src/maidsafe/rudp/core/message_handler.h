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
//}  // namespace protobuf
//
//namespace test {
//class MessageHandlerTest_BEH_MakeSerialisedWrapperMessage_Test;
//}  // namespace test
//
//class MessageHandler : public MessageHandler {
// public:
//  typedef std::shared_ptr<
//      bs2::signal<void(const protobuf::ManagedEndpointMessage&,
//                       protobuf::ManagedEndpointMessage*,
//                       transport::Timeout*)>> ManagedEndpointMsgSigPtr;
//
//  explicit MessageHandler(PrivateKeyPtr private_key)
//    : transport::MessageHandler(private_key),
//      on_managed_endpoint_message_(new ManagedEndpointMsgSigPtr::element_type) {}
//  virtual ~MessageHandler() {}
//
//  std::string WrapMessage(const protobuf::ManagedEndpointMessage &msg);
//
//  ManagedEndpointMsgSigPtr on_managed_endpoint_message() {
//    return on_managed_endpoint_message_;
//  }
//
// protected:
//  void ProcessSerialisedMessage(const int &message_type,
//                                const std::string &payload,
//                                const SecurityType &security_type,
//                                const std::string &message_signature,
//                                const Info &info,
//                                std::string *message_response,
//                                Timeout *timeout);
// private:
//  friend class test::MessageHandlerTest_BEH_MakeSerialisedWrapperMessage_Test;  // NOLINT
//  MessageHandler(const MessageHandler&);
//  MessageHandler& operator=(const MessageHandler&);
//
//  ManagedEndpointMsgSigPtr on_managed_endpoint_message_;
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
