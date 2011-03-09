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

#include "maidsafe-dht/kademlia/securifier.h"
#include "maidsafe-dht/kademlia/message_handler.h"
#include "maidsafe-dht/kademlia/config.h"
#include "maidsafe-dht/kademlia/rpcs.pb.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe-dht/kademlia/utils.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-dht/transport/transport.pb.h"
#include "maidsafe-dht/kademlia/message_handler.cc"

namespace maidsafe {

namespace kademlia {

namespace test {

class SecurifierValidateFalse: public Securifier {
 public:
  SecurifierValidateFalse(const std::string &public_key_id,
                          const std::string &public_key,
                          const std::string &private_key) :
      Securifier(public_key_id, public_key, private_key) {}

  bool Validate(const std::string &,
                const std::string &,
                const std::string &,
                const std::string &,
                const std::string &,
                const std::string &) const {
    return false;
  }
};

class KademliaMessageHandlerTest: public testing::Test {
 public:
  KademliaMessageHandlerTest() : sec_ptr_(
                                   new SecurifierValidateFalse("", "", "")),
                                 msg_hndlr_(sec_ptr_),
                                 securifier_null_(),
                                 message_(securifier_null_) {  }
  virtual void SetUp() { }
  virtual void TearDown() { }

  template<class T>
  T get_wrapper(std::string encrypted, std::string key) {
    std::string amended(encrypted, 1, encrypted.size()-1);
    std::string decrypted = crypto::AsymDecrypt(amended, key);
    transport::protobuf::WrapperMessage decrypted_msg;
    decrypted_msg.ParseFromString(decrypted);
    T result;
    result.ParseFromString(decrypted_msg.payload());
    return result;
  }

  template<class T>
  std::string encrypt(T request, std::string key,
                      maidsafe::kademlia::MessageType request_type) {
    transport::protobuf::WrapperMessage message;
    message.set_msg_type(request_type);
    message.set_payload(request.SerializeAsString());
    std::string result(1, kAsymmetricEncrypt);
    result += crypto::AsymEncrypt(message.SerializeAsString(),
                                  key);
    return result;
  }

 protected:
  std::shared_ptr<Securifier> sec_ptr_;
  MessageHandler msg_hndlr_;
  std::shared_ptr<Securifier> securifier_null_;
  MessageHandler message_;
};

TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForPingRequest) {
  protobuf::PingRequest ping_rqst;
  ping_rqst.set_ping("ping");
  protobuf::Contact contact;
  contact.set_node_id("test");
  ping_rqst.mutable_sender()->CopyFrom(contact);
  ASSERT_TRUE(ping_rqst.IsInitialized());
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  std::string result_no_securifier = message_.WrapMessage(ping_rqst,
                                                          kp.public_key());
  ASSERT_EQ("", result_no_securifier);

  std::string function_encrypt = msg_hndlr_.WrapMessage(ping_rqst,
                                                        kp.public_key());
  std::string manual_encrypt = encrypt<protobuf::PingRequest>(ping_rqst,
                                                              kp.public_key(),
                                                              kPingRequest);
  EXPECT_NE(manual_encrypt, function_encrypt);

  // decrypt for comparison test
  protobuf::PingRequest decrypted_function_ping =
        get_wrapper<protobuf::PingRequest>(function_encrypt, kp.private_key());
  protobuf::PingRequest decrypted_manual_ping =
        get_wrapper<protobuf::PingRequest>(manual_encrypt, kp.private_key());
  ASSERT_EQ(decrypted_manual_ping.ping(), decrypted_function_ping.ping());
  ASSERT_EQ(decrypted_manual_ping.sender().node_id(),
            decrypted_function_ping.sender().node_id());
}


TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForFindValueRequest) {
  protobuf::FindValueRequest value_rqst;
  value_rqst.set_key("request_key");
  protobuf::Contact contact;
  contact.set_node_id("node_id_test");
  value_rqst.mutable_sender()->CopyFrom(contact);
  ASSERT_TRUE(value_rqst.IsInitialized());
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  std::string pub_key = kp.public_key();
  std::string priv_key = kp.private_key();
  std::string result_no_securifier = message_.WrapMessage(value_rqst,
                                                          kp.public_key());
  ASSERT_EQ("", result_no_securifier);

  std::string function_encrypt = msg_hndlr_.WrapMessage(value_rqst,
                                                        kp.public_key());
  std::string manual_encrypt =
               encrypt<protobuf::FindValueRequest>(value_rqst, kp.public_key(),
                                                   kFindValueRequest);
  EXPECT_NE(manual_encrypt, function_encrypt);

  // decrypt for comparison test
  protobuf::FindValueRequest decrypted_function_value =
          get_wrapper<protobuf::FindValueRequest>(function_encrypt,
                                                  kp.private_key());
  protobuf::FindValueRequest decrypted_manual_value =
          get_wrapper<protobuf::FindValueRequest>(manual_encrypt,
                                                  kp.private_key());
  ASSERT_EQ(decrypted_manual_value.key(), decrypted_function_value.key());
  ASSERT_EQ(decrypted_manual_value.sender().node_id(),
            decrypted_function_value.sender().node_id());
}

TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForFindNodesRequest) {
  protobuf::FindNodesRequest nodes_rqst;
  nodes_rqst.set_key("node_request_key");
  protobuf::Contact contact;
  contact.set_node_id("node_id_test");
  nodes_rqst.mutable_sender()->CopyFrom(contact);
  ASSERT_TRUE(nodes_rqst.IsInitialized());
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  std::string result_no_securifier = message_.WrapMessage(nodes_rqst,
                                                          kp.public_key());
  ASSERT_EQ("", result_no_securifier);

  std::string function_encrypt = msg_hndlr_.WrapMessage(nodes_rqst,
                                                        kp.public_key());
  std::string manual_encrypt =
              encrypt<protobuf::FindNodesRequest>(nodes_rqst, kp.public_key(),
                                                  kFindNodesRequest);
  EXPECT_NE(manual_encrypt, function_encrypt);

  // decrypt for comparison test
  protobuf::FindNodesRequest decrypted_function_value =
                     get_wrapper<protobuf::FindNodesRequest>(function_encrypt,
                                                             kp.private_key());
  protobuf::FindNodesRequest decrypted_manual_value =
                     get_wrapper<protobuf::FindNodesRequest>(manual_encrypt,
                                                             kp.private_key());
  ASSERT_EQ(decrypted_manual_value.key(), decrypted_function_value.key());
  ASSERT_EQ(decrypted_manual_value.sender().node_id(),
            decrypted_function_value.sender().node_id());
}

TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForStoreRequest) {
  protobuf::StoreRequest store_rqst;
  store_rqst.set_key("store_request_key");
  protobuf::Contact contact;
  contact.set_node_id("node_id_test");
  store_rqst.mutable_sender()->CopyFrom(contact);
  protobuf::SignedValue s_val;
  s_val.set_value("signed_value");
  s_val.set_signature("store_signature");
  store_rqst.mutable_signed_value()->CopyFrom(s_val);
  store_rqst.set_ttl(1234);
  ASSERT_TRUE(store_rqst.IsInitialized());
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  std::string result_no_securifier = message_.WrapMessage(store_rqst,
                                                          kp.public_key());
  ASSERT_EQ("", result_no_securifier);

  std::string function_encrypt = msg_hndlr_.WrapMessage(store_rqst,
                                                        kp.public_key());
  std::string manual_encrypt =
                   encrypt<protobuf::StoreRequest>(store_rqst, kp.public_key(),
                                                   kStoreRequest);
  EXPECT_NE(manual_encrypt, function_encrypt);

  protobuf::StoreRequest decrypted_function_value =
       get_wrapper<protobuf::StoreRequest>(function_encrypt, kp.private_key());
  protobuf::StoreRequest decrypted_manual_value =
        get_wrapper<protobuf::StoreRequest>(manual_encrypt, kp.private_key());
  ASSERT_EQ(decrypted_manual_value.key(), decrypted_function_value.key());
  ASSERT_EQ(decrypted_manual_value.sender().node_id(),
            decrypted_function_value.sender().node_id());
  ASSERT_EQ(decrypted_manual_value.signed_value().value(),
            decrypted_function_value.signed_value().value());
  ASSERT_EQ(decrypted_manual_value.signed_value().signature(),
            decrypted_function_value.signed_value().signature());
  ASSERT_EQ(decrypted_manual_value.ttl(), decrypted_function_value.ttl());
}

TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForStoreRefreshRequest) {
  protobuf::StoreRefreshRequest refresh_rqst;
  protobuf::Contact contact;
  contact.set_node_id("node_id_test");
  refresh_rqst.mutable_sender()->CopyFrom(contact);
  ASSERT_TRUE(refresh_rqst.IsInitialized());
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  std::string result_no_securifier = message_.WrapMessage(refresh_rqst,
                                                          kp.public_key());
  ASSERT_EQ("", result_no_securifier);
  std::string function_encrypt = msg_hndlr_.WrapMessage(refresh_rqst,
                                                        kp.public_key());
  std::string manual_encrypt =
          encrypt<protobuf::StoreRefreshRequest>(refresh_rqst, kp.public_key(),
                                                 kStoreRefreshRequest);
  EXPECT_NE(manual_encrypt, function_encrypt);
  protobuf::StoreRefreshRequest decrypted_function_value =
          get_wrapper<protobuf::StoreRefreshRequest>(function_encrypt,
                                                     kp.private_key());
  protobuf::StoreRefreshRequest decrypted_manual_value =
          get_wrapper<protobuf::StoreRefreshRequest>(manual_encrypt,
                                                     kp.private_key());
  ASSERT_EQ(decrypted_manual_value.sender().node_id(),
            decrypted_function_value.sender().node_id());
}

TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForDeleteRequest) {
  protobuf::DeleteRequest delete_rqst;
  protobuf::Contact contact;
  contact.set_node_id("node_id_test");
  delete_rqst.mutable_sender()->CopyFrom(contact);
  delete_rqst.set_key("delete_request_key");
  protobuf::SignedValue s_val;
  s_val.set_value("signed_value");
  s_val.set_signature("delete_signature");
  delete_rqst.mutable_signed_value()->CopyFrom(s_val);
  ASSERT_TRUE(delete_rqst.IsInitialized());
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  std::string result_no_securifier = message_.WrapMessage(delete_rqst,
                                                          kp.public_key());
  ASSERT_EQ("", result_no_securifier);
  std::string function_encrypt = msg_hndlr_.WrapMessage(delete_rqst,
                                                        kp.public_key());
  std::string manual_encrypt =
                 encrypt<protobuf::DeleteRequest>(delete_rqst, kp.public_key(),
                                                  kDeleteRequest);
  EXPECT_NE(manual_encrypt, function_encrypt);
  protobuf::DeleteRequest decrypted_function_value =
          get_wrapper<protobuf::DeleteRequest>(function_encrypt,
                                               kp.private_key());
  protobuf::DeleteRequest decrypted_manual_value =
          get_wrapper<protobuf::DeleteRequest>(manual_encrypt,
                                               kp.private_key());
  ASSERT_EQ(decrypted_manual_value.key(), decrypted_function_value.key());
  ASSERT_EQ(decrypted_manual_value.sender().node_id(),
            decrypted_function_value.sender().node_id());
  ASSERT_EQ(decrypted_manual_value.signed_value().value(),
            decrypted_function_value.signed_value().value());
  ASSERT_EQ(decrypted_manual_value.signed_value().signature(),
            decrypted_function_value.signed_value().signature());
}

TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForDeleteRefreshRequest) {
  protobuf::DeleteRefreshRequest delrefresh_rqst;
  protobuf::Contact contact;
  contact.set_node_id("node_id_test");
  delrefresh_rqst.mutable_sender()->CopyFrom(contact);
  ASSERT_TRUE(delrefresh_rqst.IsInitialized());
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  std::string result_no_securifier = message_.WrapMessage(delrefresh_rqst,
                                                          kp.public_key());
  ASSERT_EQ("", result_no_securifier);
  std::string function_encrypt = msg_hndlr_.WrapMessage(delrefresh_rqst,
                                                        kp.public_key());
  std::string manual_encrypt =
               encrypt<protobuf::DeleteRefreshRequest>(delrefresh_rqst,
                                                       kp.public_key(),
                                                       kDeleteRefreshRequest);
  EXPECT_NE(manual_encrypt, function_encrypt);
  protobuf::DeleteRefreshRequest decrypted_function_value =
          get_wrapper<protobuf::DeleteRefreshRequest>(function_encrypt,
                                                      kp.private_key());
  protobuf::DeleteRefreshRequest decrypted_manual_value =
          get_wrapper<protobuf::DeleteRefreshRequest>(manual_encrypt,
                                                      kp.private_key());
  ASSERT_EQ(decrypted_manual_value.sender().node_id(),
            decrypted_function_value.sender().node_id());
}

TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForDownlistNotification) {
  protobuf::DownlistNotification downlist;
  protobuf::Contact contact;
  contact.set_node_id("node_id_test");
  downlist.mutable_sender()->CopyFrom(contact);
  ASSERT_TRUE(downlist.IsInitialized());
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  std::string result_no_securifier = message_.WrapMessage(downlist,
                                                          kp.public_key());
  ASSERT_EQ("", result_no_securifier);
  std::string function_encrypt = msg_hndlr_.WrapMessage(downlist,
                                                        kp.public_key());
  std::string manual_encrypt =
               encrypt<protobuf::DownlistNotification>(downlist,
                                                       kp.public_key(),
                                                       kDownlistNotification);
  EXPECT_NE(manual_encrypt, function_encrypt);
  protobuf::DownlistNotification decrypted_function_value =
                 get_wrapper<protobuf::DownlistNotification>(function_encrypt,
                                                             kp.private_key());
  protobuf::DownlistNotification decrypted_manual_value =
                 get_wrapper<protobuf::DownlistNotification>(manual_encrypt,
                                                             kp.private_key());
  ASSERT_EQ(decrypted_manual_value.sender().node_id(),
            decrypted_function_value.sender().node_id());
}


TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForPingResponse) {
  protobuf::PingResponse response;
  response.set_echo("ping response echo");
  ASSERT_TRUE(response.IsInitialized());
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  std::string result_no_securifier = message_.WrapMessage(response,
                                                          kp.public_key());
  ASSERT_EQ("", result_no_securifier);
  std::string function_encrypt = msg_hndlr_.WrapMessage(response,
                                                        kp.public_key());
  std::string manual_encrypt =
               encrypt<protobuf::PingResponse>(response, kp.public_key(),
                                               kPingResponse);
  EXPECT_NE(manual_encrypt, function_encrypt);
  protobuf::PingResponse decrypted_function_value =
                         get_wrapper<protobuf::PingResponse>(function_encrypt,
                                                             kp.private_key());
  protobuf::PingResponse decrypted_manual_value =
                         get_wrapper<protobuf::PingResponse>(manual_encrypt,
                                                             kp.private_key());
  ASSERT_EQ(decrypted_manual_value.echo(),
            decrypted_function_value.echo());
}

TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForFindValueResponse) {
  protobuf::FindValueResponse response;
  response.set_result(1);
  ASSERT_TRUE(response.IsInitialized());
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  std::string result_no_securifier = message_.WrapMessage(response,
                                                          kp.public_key());
  ASSERT_EQ("", result_no_securifier);
  std::string function_encrypt = msg_hndlr_.WrapMessage(response,
                                                        kp.public_key());
  std::string manual_encrypt =
               encrypt<protobuf::FindValueResponse>(response, kp.public_key(),
                                                    kFindValueResponse);
  EXPECT_NE(manual_encrypt, function_encrypt);
  protobuf::FindValueResponse decrypted_function_value =
                     get_wrapper<protobuf::FindValueResponse>(function_encrypt,
                                                             kp.private_key());
  protobuf::FindValueResponse decrypted_manual_value =
                       get_wrapper<protobuf::FindValueResponse>(manual_encrypt,
                                                             kp.private_key());
  ASSERT_TRUE(decrypted_manual_value.result());
  ASSERT_TRUE(decrypted_function_value.result());
}

TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForFindNodesResponse) {
  protobuf::FindNodesResponse response;
  response.set_result(1);
  ASSERT_TRUE(response.IsInitialized());
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  std::string result_no_securifier = message_.WrapMessage(response,
                                                          kp.public_key());
  ASSERT_EQ("", result_no_securifier);
  std::string function_encrypt = msg_hndlr_.WrapMessage(response,
                                                        kp.public_key());
  std::string manual_encrypt =
               encrypt<protobuf::FindNodesResponse>(response, kp.public_key(),
                                                    kFindNodesResponse);
  EXPECT_NE(manual_encrypt, function_encrypt);
  protobuf::FindNodesResponse decrypted_function_value =
                     get_wrapper<protobuf::FindNodesResponse>(function_encrypt,
                                                             kp.private_key());
  protobuf::FindNodesResponse decrypted_manual_value =
                       get_wrapper<protobuf::FindNodesResponse>(manual_encrypt,
                                                             kp.private_key());
  ASSERT_TRUE(decrypted_manual_value.result());
  ASSERT_TRUE(decrypted_function_value.result());
}

TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForStoreResponse) {
  protobuf::StoreResponse response;
  response.set_result(1);
  ASSERT_TRUE(response.IsInitialized());
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  std::string result_no_securifier = message_.WrapMessage(response,
                                                          kp.public_key());
  ASSERT_EQ("", result_no_securifier);
  std::string function_encrypt = msg_hndlr_.WrapMessage(response,
                                                        kp.public_key());
  std::string manual_encrypt =
               encrypt<protobuf::StoreResponse>(response, kp.public_key(),
                                                kStoreResponse);
  EXPECT_NE(manual_encrypt, function_encrypt);
  protobuf::StoreResponse decrypted_function_value =
                     get_wrapper<protobuf::StoreResponse>(function_encrypt,
                                                          kp.private_key());
  protobuf::StoreResponse decrypted_manual_value =
                       get_wrapper<protobuf::StoreResponse>(manual_encrypt,
                                                            kp.private_key());
  ASSERT_TRUE(decrypted_manual_value.result());
  ASSERT_TRUE(decrypted_function_value.result());
}

TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForStoreRefreshResponse) {
  protobuf::StoreRefreshResponse response;
  response.set_result(1);
  ASSERT_TRUE(response.IsInitialized());
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  std::string result_no_securifier = message_.WrapMessage(response,
                                                          kp.public_key());
  ASSERT_EQ("", result_no_securifier);
  std::string function_encrypt = msg_hndlr_.WrapMessage(response,
                                                        kp.public_key());
  std::string manual_encrypt =
             encrypt<protobuf::StoreRefreshResponse>(response, kp.public_key(),
                                                     kStoreRefreshResponse);
  EXPECT_NE(manual_encrypt, function_encrypt);
  protobuf::StoreRefreshResponse decrypted_function_value =
                 get_wrapper<protobuf::StoreRefreshResponse>(function_encrypt,
                                                             kp.private_key());
  protobuf::StoreRefreshResponse decrypted_manual_value =
                 get_wrapper<protobuf::StoreRefreshResponse>(manual_encrypt,
                                                             kp.private_key());
  ASSERT_TRUE(decrypted_manual_value.result());
  ASSERT_TRUE(decrypted_function_value.result());
}

TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForDeleteResponse) {
  protobuf::DeleteResponse response;
  response.set_result(1);
  ASSERT_TRUE(response.IsInitialized());
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  std::string result_no_securifier = message_.WrapMessage(response,
                                                          kp.public_key());
  ASSERT_EQ("", result_no_securifier);
  std::string function_encrypt = msg_hndlr_.WrapMessage(response,
                                                        kp.public_key());
  std::string manual_encrypt =
             encrypt<protobuf::DeleteResponse>(response, kp.public_key(),
                                               kDeleteResponse);
  EXPECT_NE(manual_encrypt, function_encrypt);
  protobuf::DeleteResponse decrypted_function_value =
                 get_wrapper<protobuf::DeleteResponse>(function_encrypt,
                                                       kp.private_key());
  protobuf::DeleteResponse decrypted_manual_value =
                 get_wrapper<protobuf::DeleteResponse>(manual_encrypt,
                                                       kp.private_key());
  ASSERT_TRUE(decrypted_manual_value.result());
  ASSERT_TRUE(decrypted_function_value.result());
}

TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForDeleteRefreshResponse) { // NOLINT
  protobuf::DeleteRefreshResponse response;
  response.set_result(1);
  ASSERT_TRUE(response.IsInitialized());
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  std::string result_no_securifier = message_.WrapMessage(response,
                                                          kp.public_key());
  ASSERT_EQ("", result_no_securifier);
  std::string function_encrypt = msg_hndlr_.WrapMessage(response,
                                                        kp.public_key());
  std::string manual_encrypt =
            encrypt<protobuf::DeleteRefreshResponse>(response, kp.public_key(),
                                                     kDeleteRefreshResponse);
  EXPECT_NE(manual_encrypt, function_encrypt);
  protobuf::DeleteRefreshResponse decrypted_function_value =
                get_wrapper<protobuf::DeleteRefreshResponse>(function_encrypt,
                                                             kp.private_key());
  protobuf::DeleteRefreshResponse decrypted_manual_value =
                get_wrapper<protobuf::DeleteRefreshResponse>(manual_encrypt,
                                                             kp.private_key());
  ASSERT_TRUE(decrypted_manual_value.result());
  ASSERT_TRUE(decrypted_function_value.result());
}
}  // namespace test_service

}  // namespace kademlia

}  // namespace maidsafe
