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

#include "gtest/gtest.h"
#include "boost/lexical_cast.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-dht/kademlia/securifier.h"
#include "maidsafe-dht/transport/message_handler.h"
#include "maidsafe-dht/transport/transport.pb.h"
#include "maidsafe-dht/transport/transport.pb.h"

namespace maidsafe {

namespace transport {

namespace test {

class TestSecurifier : public Securifier {
 public:
  TestSecurifier(const std::string &public_key_id,
                          const std::string &public_key,
                          const std::string &private_key) :
      Securifier(public_key_id, public_key, private_key) {}

  bool Validate(const std::string&, const std::string&,
                const std::string&, const std::string&,
                const std::string&, const std::string&) const { return true; }
};

class TransportMessageHandlerTest : public testing::Test {
 public:
  TransportMessageHandlerTest() : sec_ptr_(new TestSecurifier("", "", "")),
                                 msg_hndlr_(sec_ptr_),
                                 securifier_null_(),
                                 msg_hndlr_no_securifier_(securifier_null_) {  }
  virtual void SetUp() { }
  virtual void TearDown() { }

  template<class T>
  T GetWrapper(std::string encrypted, std::string key) {
    std::string amended(encrypted, 1, encrypted.size() - 1);
    std::string decrypted = crypto::AsymDecrypt(amended, key);
    transport::protobuf::WrapperMessage decrypted_msg;
    decrypted_msg.ParseFromString(decrypted);
    T result;
    result.ParseFromString(decrypted_msg.payload());
    return result;
  }

  template<class T>
  std::string EncryptMessage(T request,
                             maidsafe::transport::MessageType request_type) {
    transport::protobuf::WrapperMessage message;
    message.set_msg_type(request_type);
    message.set_payload(request.SerializeAsString());
    std::string result(1, kNone);
    result += message.SerializeAsString();
    return result;
  }

 protected:
  std::shared_ptr<Securifier> sec_ptr_;
  MessageHandler msg_hndlr_;
  std::shared_ptr<Securifier> securifier_null_;
  MessageHandler msg_hndlr_no_securifier_;
};

TEST_F(TransportMessageHandlerTest, BEH_KAD_WrapMessageManagedEndpointMessage) {
//  protobuf::NatDetectionRequest nat_detection_rqst;
//  nat_detection_rqst.add_local_ips(std::string("192.168.1.1"));
//  nat_detection_rqst.set_local_port(12345);
//  ASSERT_TRUE(nat_detection_rqst.IsInitialized());
////  crypto::RsaKeyPair kp;
////  kp.GenerateKeys(4096);
//  std::string result_no_securifier =
//      msg_hndlr_no_securifier_.WrapMessage(nat_detection_rqst);
//  ASSERT_EQ("", result_no_securifier);
//
//  std::string function_encrypt = msg_hndlr_.WrapMessage(nat_detection_rqst);
//  std::string manual_encrypt =
//      EncryptMessage<protobuf::NatDetectionRequest>(nat_detection_rqst,
//                                                   "", kNatDetectionRequest);
//  EXPECT_NE(manual_encrypt, function_encrypt);
//
//  // decrypt for comparison test
//  protobuf::NatDetectionRequest decrypted_function_nat_detection =
//      GetWrapper<protobuf::NatDetectionRequest>(function_encrypt, "");
//  protobuf::NatDetectionRequest decrypted_manual_nat_detection =
//      GetWrapper<protobuf::NatDetectionRequest>(manual_encrypt, "");
//  ASSERT_EQ(decrypted_manual_nat_detection.ping(), decrypted_function_nat_detection.ping());
//  ASSERT_EQ(decrypted_manual_nat_detection.sender().node_id(),
//            decrypted_function_nat_detection.sender().node_id());
}

TEST_F(TransportMessageHandlerTest, BEH_KAD_WrapMessageNatDetectionRequest) {
  protobuf::NatDetectionRequest nat_detection_rqst;
  nat_detection_rqst.add_local_ips(std::string("192.168.1.1"));
  nat_detection_rqst.set_local_port(12345);
  ASSERT_TRUE(nat_detection_rqst.IsInitialized());

  std::string function_encrypt = msg_hndlr_.WrapMessage(nat_detection_rqst);
  std::string manual_encrypt =
      EncryptMessage<protobuf::NatDetectionRequest>(nat_detection_rqst,
                                                    kNatDetectionRequest);
  EXPECT_EQ(manual_encrypt, function_encrypt);
}

TEST_F(TransportMessageHandlerTest, BEH_KAD_WrapMessageProxyConnectRequest) {
//  protobuf::FindNodesRequest nodes_rqst;
//  nodes_rqst.set_key("node_request_key");
//  protobuf::Contact contact;
//  contact.set_node_id("node_id_test");
//  nodes_rqst.mutable_sender()->CopyFrom(contact);
//  ASSERT_TRUE(nodes_rqst.IsInitialized());
//  crypto::RsaKeyPair kp;
//  kp.GenerateKeys(4096);
//  std::string result_no_securifier =
//      msg_hndlr_no_securifier_.WrapMessage(nodes_rqst, kp.public_key());
//  ASSERT_EQ("", result_no_securifier);
//
//  std::string function_encrypt = msg_hndlr_.WrapMessage(nodes_rqst,
//                                                        kp.public_key());
//  std::string manual_encrypt =
//              EncryptMessage<protobuf::FindNodesRequest>(nodes_rqst, kp.public_key(),
//                                                  kFindNodesRequest);
//  EXPECT_NE(manual_encrypt, function_encrypt);
//
//  // decrypt for comparison test
//  protobuf::FindNodesRequest decrypted_function_value =
//                     GetWrapper<protobuf::FindNodesRequest>(function_encrypt,
//                                                             kp.private_key());
//  protobuf::FindNodesRequest decrypted_manual_value =
//                     GetWrapper<protobuf::FindNodesRequest>(manual_encrypt,
//                                                             kp.private_key());
//  ASSERT_EQ(decrypted_manual_value.key(), decrypted_function_value.key());
//  ASSERT_EQ(decrypted_manual_value.sender().node_id(),
//            decrypted_function_value.sender().node_id());
}

TEST_F(TransportMessageHandlerTest, BEH_KAD_WrapMessageForwardRendezvousRequest) {  // NOLINT
//  protobuf::StoreRequest store_rqst;
//  store_rqst.set_key("store_request_key");
//  protobuf::Contact contact;
//  contact.set_node_id("node_id_test");
//  store_rqst.mutable_sender()->CopyFrom(contact);
//  protobuf::SignedValue s_val;
//  s_val.set_value("signed_value");
//  s_val.set_signature("store_signature");
//  store_rqst.mutable_signed_value()->CopyFrom(s_val);
//  store_rqst.set_ttl(1234);
//  ASSERT_TRUE(store_rqst.IsInitialized());
//  crypto::RsaKeyPair kp;
//  kp.GenerateKeys(4096);
//  std::string result_no_securifier =
//      msg_hndlr_no_securifier_.WrapMessage(store_rqst, kp.public_key());
//  ASSERT_EQ("", result_no_securifier);
//
//  std::string function_encrypt = msg_hndlr_.WrapMessage(store_rqst,
//                                                        kp.public_key());
//  std::string manual_encrypt =
//                   EncryptMessage<protobuf::StoreRequest>(store_rqst, kp.public_key(),
//                                                   kStoreRequest);
//  EXPECT_NE(manual_encrypt, function_encrypt);
//
//  protobuf::StoreRequest decrypted_function_value =
//       GetWrapper<protobuf::StoreRequest>(function_encrypt, kp.private_key());
//  protobuf::StoreRequest decrypted_manual_value =
//        GetWrapper<protobuf::StoreRequest>(manual_encrypt, kp.private_key());
//  ASSERT_EQ(decrypted_manual_value.key(), decrypted_function_value.key());
//  ASSERT_EQ(decrypted_manual_value.sender().node_id(),
//            decrypted_function_value.sender().node_id());
//  ASSERT_EQ(decrypted_manual_value.signed_value().value(),
//            decrypted_function_value.signed_value().value());
//  ASSERT_EQ(decrypted_manual_value.signed_value().signature(),
//            decrypted_function_value.signed_value().signature());
//  ASSERT_EQ(decrypted_manual_value.ttl(), decrypted_function_value.ttl());
}

TEST_F(TransportMessageHandlerTest, BEH_KAD_WrapMessageRendezvousRequest) {
//  protobuf::StoreRefreshRequest refresh_rqst;
//  protobuf::Contact contact;
//  contact.set_node_id("node_id_test");
//  refresh_rqst.mutable_sender()->CopyFrom(contact);
//  ASSERT_TRUE(refresh_rqst.IsInitialized());
//  crypto::RsaKeyPair kp;
//  kp.GenerateKeys(4096);
//  std::string result_no_securifier =
//      msg_hndlr_no_securifier_.WrapMessage(refresh_rqst, kp.public_key());
//  ASSERT_EQ("", result_no_securifier);
//  std::string function_encrypt = msg_hndlr_.WrapMessage(refresh_rqst,
//                                                        kp.public_key());
//  std::string manual_encrypt =
//          EncryptMessage<protobuf::StoreRefreshRequest>(refresh_rqst, kp.public_key(),
//                                                 kStoreRefreshRequest);
//  EXPECT_NE(manual_encrypt, function_encrypt);
//  protobuf::StoreRefreshRequest decrypted_function_value =
//          GetWrapper<protobuf::StoreRefreshRequest>(function_encrypt,
//                                                     kp.private_key());
//  protobuf::StoreRefreshRequest decrypted_manual_value =
//          GetWrapper<protobuf::StoreRefreshRequest>(manual_encrypt,
//                                                     kp.private_key());
//  ASSERT_EQ(decrypted_manual_value.sender().node_id(),
//            decrypted_function_value.sender().node_id());
}

TEST_F(TransportMessageHandlerTest, BEH_KAD_WrapMessageNatDetectionResponse) {
//  protobuf::PingResponse response;
//  response.set_echo("ping response echo");
//  ASSERT_TRUE(response.IsInitialized());
//  crypto::RsaKeyPair kp;
//  kp.GenerateKeys(4096);
//  std::string result_no_securifier =
//      msg_hndlr_no_securifier_.WrapMessage(response, kp.public_key());
//  ASSERT_EQ("", result_no_securifier);
//  std::string function_encrypt = msg_hndlr_.WrapMessage(response,
//                                                        kp.public_key());
//  std::string manual_encrypt =
//               EncryptMessage<protobuf::PingResponse>(response, kp.public_key(),
//                                               kPingResponse);
//  EXPECT_NE(manual_encrypt, function_encrypt);
//  protobuf::PingResponse decrypted_function_value =
//                         GetWrapper<protobuf::PingResponse>(function_encrypt,
//                                                             kp.private_key());
//  protobuf::PingResponse decrypted_manual_value =
//                         GetWrapper<protobuf::PingResponse>(manual_encrypt,
//                                                             kp.private_key());
//  ASSERT_EQ(decrypted_manual_value.echo(),
//            decrypted_function_value.echo());
}

TEST_F(TransportMessageHandlerTest, BEH_KAD_WrapMessageProxyConnectResponse) {
//  protobuf::FindValueResponse response;
//  response.set_result(1);
//  ASSERT_TRUE(response.IsInitialized());
//  crypto::RsaKeyPair kp;
//  kp.GenerateKeys(4096);
//  std::string result_no_securifier =
//      msg_hndlr_no_securifier_.WrapMessage(response, kp.public_key());
//  ASSERT_EQ("", result_no_securifier);
//  std::string function_encrypt = msg_hndlr_.WrapMessage(response,
//                                                        kp.public_key());
//  std::string manual_encrypt =
//               EncryptMessage<protobuf::FindValueResponse>(response, kp.public_key(),
//                                                    kFindValueResponse);
//  EXPECT_NE(manual_encrypt, function_encrypt);
//  protobuf::FindValueResponse decrypted_function_value =
//                     GetWrapper<protobuf::FindValueResponse>(function_encrypt,
//                                                             kp.private_key());
//  protobuf::FindValueResponse decrypted_manual_value =
//                       GetWrapper<protobuf::FindValueResponse>(manual_encrypt,
//                                                             kp.private_key());
//  ASSERT_TRUE(decrypted_manual_value.result());
//  ASSERT_TRUE(decrypted_function_value.result());
}

TEST_F(TransportMessageHandlerTest, BEH_KAD_WrapMessageForwardRendezvousResponse) {  // NOLINT
//  protobuf::FindNodesResponse response;
//  response.set_result(1);
//  ASSERT_TRUE(response.IsInitialized());
//  crypto::RsaKeyPair kp;
//  kp.GenerateKeys(4096);
//  std::string result_no_securifier =
//      msg_hndlr_no_securifier_.WrapMessage(response, kp.public_key());
//  ASSERT_EQ("", result_no_securifier);
//  std::string function_encrypt = msg_hndlr_.WrapMessage(response,
//                                                        kp.public_key());
//  std::string manual_encrypt =
//               EncryptMessage<protobuf::FindNodesResponse>(response, kp.public_key(),
//                                                    kFindNodesResponse);
//  EXPECT_NE(manual_encrypt, function_encrypt);
//  protobuf::FindNodesResponse decrypted_function_value =
//                     GetWrapper<protobuf::FindNodesResponse>(function_encrypt,
//                                                             kp.private_key());
//  protobuf::FindNodesResponse decrypted_manual_value =
//                       GetWrapper<protobuf::FindNodesResponse>(manual_encrypt,
//                                                             kp.private_key());
//  ASSERT_TRUE(decrypted_manual_value.result());
//  ASSERT_TRUE(decrypted_function_value.result());
}

TEST_F(TransportMessageHandlerTest, BEH_KAD_WrapMessageRendezvousAcknowledgement) {  // NOLINT
//  protobuf::StoreResponse response;
//  response.set_result(1);
//  ASSERT_TRUE(response.IsInitialized());
//  crypto::RsaKeyPair kp;
//  kp.GenerateKeys(4096);
//  std::string result_no_securifier =
//      msg_hndlr_no_securifier_.WrapMessage(response, kp.public_key());
//  ASSERT_EQ("", result_no_securifier);
//  std::string function_encrypt = msg_hndlr_.WrapMessage(response,
//                                                        kp.public_key());
//  std::string manual_encrypt =
//               EncryptMessage<protobuf::StoreResponse>(response, kp.public_key(),
//                                                kStoreResponse);
//  EXPECT_NE(manual_encrypt, function_encrypt);
//  protobuf::StoreResponse decrypted_function_value =
//                     GetWrapper<protobuf::StoreResponse>(function_encrypt,
//                                                          kp.private_key());
//  protobuf::StoreResponse decrypted_manual_value =
//                       GetWrapper<protobuf::StoreResponse>(manual_encrypt,
//                                                            kp.private_key());
//  ASSERT_TRUE(decrypted_manual_value.result());
//  ASSERT_TRUE(decrypted_function_value.result());
}

}  // namespace test

}  // namespace transport

}  // namespace maidsafe
