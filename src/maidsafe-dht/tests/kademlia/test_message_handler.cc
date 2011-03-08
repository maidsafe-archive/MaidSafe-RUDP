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

  KademliaMessageHandlerTest() : sec_ptr_(new SecurifierValidateFalse("","","")),
                                 msg_hndlr_(sec_ptr_),
                                 securifier_null_(),
                                 message_(securifier_null_) {  }
  
  virtual void SetUp() { }
 
  virtual void TearDown() {}
  
  template<class T>
  T get_wrapper(std::string encrypted, std::string key){
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
                      maidsafe::kademlia::MessageType request_type){
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
  std::string pub_key = kp.public_key();
  std::string priv_key = kp.private_key();
 
  std::string result_no_securifier = message_.WrapMessage(ping_rqst, pub_key);
  ASSERT_EQ("", result_no_securifier);
  
  std::string function_encrypt = msg_hndlr_.WrapMessage(ping_rqst, pub_key);  
  std::string manual_encrypt = encrypt<protobuf::PingRequest>(ping_rqst,
							      pub_key,
							      kPingRequest);
  EXPECT_NE(manual_encrypt, function_encrypt);

  // decrypt for comparison test
  protobuf::PingRequest decrypted_function_ping =
                get_wrapper<protobuf::PingRequest>(function_encrypt, priv_key);
  protobuf::PingRequest decrypted_manual_ping =
                get_wrapper<protobuf::PingRequest>(manual_encrypt, priv_key);
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
							  pub_key);
  ASSERT_EQ("", result_no_securifier);
  
  std::string function_encrypt = msg_hndlr_.WrapMessage(value_rqst, pub_key);  
  std::string manual_encrypt = encrypt<protobuf::FindValueRequest>(value_rqst,
							      pub_key,
							      kFindValueRequest);
  EXPECT_NE(manual_encrypt, function_encrypt);

  // decrypt for comparison test
  protobuf::FindValueRequest decrypted_function_value =
          get_wrapper<protobuf::FindValueRequest>(function_encrypt, priv_key);
  protobuf::FindValueRequest decrypted_manual_value =
          get_wrapper<protobuf::FindValueRequest>(manual_encrypt, priv_key);
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
  std::string pub_key = kp.public_key();
  std::string priv_key = kp.private_key();
 
  std::string result_no_securifier = message_.WrapMessage(nodes_rqst,
							  pub_key);
  ASSERT_EQ("", result_no_securifier);
  
  std::string function_encrypt = msg_hndlr_.WrapMessage(nodes_rqst, pub_key);  
  std::string manual_encrypt = encrypt<protobuf::FindNodesRequest>(nodes_rqst,
							      pub_key,
							      kFindNodesRequest);
  EXPECT_NE(manual_encrypt, function_encrypt);

  // decrypt for comparison test
  protobuf::FindNodesRequest decrypted_function_value =
          get_wrapper<protobuf::FindNodesRequest>(function_encrypt, priv_key);
  protobuf::FindNodesRequest decrypted_manual_value =
          get_wrapper<protobuf::FindNodesRequest>(manual_encrypt, priv_key);
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
  
  ASSERT_TRUE(store_rqst.IsInitialized());
}
  


TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForStoreRefreshRequest) { }
TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForDeleteRequest) { }
TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForDeleteRefreshRequest) { }
TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForPingResponse) {}
TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForFindValueResponse) { }
TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForFindNodesResponse) { }
TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForStoreResponse) { }
TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForStoreRefreshResponse) { }
TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForDeleteResponse) { }
TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForDeleteRefreshResponse) { }
TEST_F(KademliaMessageHandlerTest, BEH_KAD_WrapMessageForDownlistNotification) { }
}  // namespace test_service

}  // namespace kademlia

}  // namespace maidsafe
