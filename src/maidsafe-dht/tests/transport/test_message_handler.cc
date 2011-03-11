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
                                  msg_hndlr_no_securifier_(securifier_null_),
                                  invoked_slots_() {}
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

  void ManagedEndpointSlot(const protobuf::ManagedEndpointMessage&,
                           protobuf::ManagedEndpointMessage*,
                           transport::Timeout*) {
    auto it = invoked_slots_->find(kManagedEndpointMessage);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }
  void NatDetectionReqSlot(const protobuf::NatDetectionRequest&,
                           protobuf::NatDetectionResponse*,
                           transport::Timeout*) {
    auto it = invoked_slots_->find(kNatDetectionRequest);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }
  void NatDetectionRspSlot(const protobuf::NatDetectionResponse&) {
    auto it = invoked_slots_->find(kNatDetectionResponse);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }
  void  ProxyConnectReqSlot(const protobuf::ProxyConnectRequest&,
                            protobuf::ProxyConnectResponse*,
                            transport::Timeout*) {
    auto it = invoked_slots_->find(kProxyConnectRequest);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }
  void ProxyConnectRspSlot(const protobuf::ProxyConnectResponse&) {
    auto it = invoked_slots_->find(kProxyConnectResponse);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }
  void ForwardRendezvousReqSlot(const protobuf::ForwardRendezvousRequest&,
                               protobuf::ForwardRendezvousResponse*,
                               transport::Timeout*) {
    auto it = invoked_slots_->find(kForwardRendezvousRequest);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }
  void ForwardRendezvousRspSlot(const protobuf::ForwardRendezvousResponse&) {
    auto it = invoked_slots_->find(kForwardRendezvousResponse);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }
  void RendezvousReqSlot(const protobuf::RendezvousRequest&) {
    auto it = invoked_slots_->find(kRendezvousRequest);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }
  void RendezvousAckSlot(const protobuf::RendezvousAcknowledgement&) {
    auto it = invoked_slots_->find(kRendezvousAcknowledgement);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }
  void ErrorSlot(const TransportCondition&) {}

  void ConnectToHandlerSignals() {
    msg_hndlr_.on_managed_endpoint_message()->connect(boost::bind(
        &TransportMessageHandlerTest::ManagedEndpointSlot, this, _1, _2, _3));
    msg_hndlr_.on_nat_detection_request()->connect(boost::bind(
        &TransportMessageHandlerTest::NatDetectionReqSlot, this, _1, _2, _3));
    msg_hndlr_.on_nat_detection_response()->connect(boost::bind(
        &TransportMessageHandlerTest::NatDetectionRspSlot, this, _1));
    msg_hndlr_.on_proxy_connect_request()->connect(boost::bind(
        &TransportMessageHandlerTest::ProxyConnectReqSlot, this, _1, _2, _3));
    msg_hndlr_.on_proxy_connect_response()->connect(boost::bind(
        &TransportMessageHandlerTest::ProxyConnectRspSlot, this, _1));
    msg_hndlr_.on_forward_rendezvous_request()->connect(boost::bind(
        &TransportMessageHandlerTest::ForwardRendezvousReqSlot,
        this, _1, _2, _3));
    msg_hndlr_.on_forward_rendezvous_response()->connect(boost::bind(
        &TransportMessageHandlerTest::ForwardRendezvousRspSlot, this, _1));
    msg_hndlr_.on_rendezvous_request()->connect(boost::bind(
        &TransportMessageHandlerTest::RendezvousReqSlot, this, _1));
    msg_hndlr_.on_rendezvous_acknowledgement()->connect(boost::bind(
        &TransportMessageHandlerTest::RendezvousAckSlot, this, _1));
    msg_hndlr_.on_error()->connect(boost::bind(
        &TransportMessageHandlerTest::ErrorSlot, this, _1));
  }
  void InitialiseMap() {
    invoked_slots_.reset(new std::map<MessageType, boost::uint8_t>);
    for (int n = kManagedEndpointMessage; n != kRendezvousAcknowledgement; ++n)
      invoked_slots_->insert(std::pair<MessageType, boost::uint8_t>(
                                       MessageType(n), 0));
  }
  void CreateMesages() {
    ManagedEndpointMessage me_msg;
    NatDetectionRequest nd_req;
    ProxyConnectRequest pc_req;
    ForwardRendezvousRequest fr_req;
    RendezvousRequest r_req;
    NatDetectionResponse nd_res;
    ProxyConnectResponse pc_res;
    ForwardRendezvousResponse fr_res;
    RendezvousAcknowledgement ra_msg;
  }
 protected:
  std::shared_ptr<Securifier> sec_ptr_;
  MessageHandler msg_hndlr_;
  std::shared_ptr<Securifier> securifier_null_;
  MessageHandler msg_hndlr_no_securifier_;
  std::shared_ptr<std::map<MessageType, boost::uint8_t>> invoked_slots_;
};

TEST_F(TransportMessageHandlerTest, BEH_TRANS_WrapMessageManagedEndpointMessage) {  // NOLINT
  protobuf::ManagedEndpointMessage managed_endpoint_message;
  ASSERT_TRUE(managed_endpoint_message.IsInitialized());

  std::string function(msg_hndlr_.WrapMessage(managed_endpoint_message));
  std::string manual(EncryptMessage<protobuf::ManagedEndpointMessage>(
                         managed_endpoint_message, kManagedEndpointMessage));
  EXPECT_EQ(manual, function);
}

TEST_F(TransportMessageHandlerTest, BEH_TRANS_WrapMessageNatDetectionRequest) {
  protobuf::NatDetectionRequest nat_detection_rqst;
  nat_detection_rqst.add_local_ips(std::string("192.168.1.1"));
  nat_detection_rqst.set_local_port(12345);
  ASSERT_TRUE(nat_detection_rqst.IsInitialized());

  std::string function_encrypt(msg_hndlr_.WrapMessage(nat_detection_rqst));
  std::string manual_encrypt(
      EncryptMessage<protobuf::NatDetectionRequest>(nat_detection_rqst,
                                                    kNatDetectionRequest));
  EXPECT_EQ(manual_encrypt, function_encrypt);
}

TEST_F(TransportMessageHandlerTest, BEH_TRANS_WrapMessageProxyConnectRequest) {
  protobuf::ProxyConnectRequest proxy_connect_rqst;
  protobuf::Endpoint *ep = proxy_connect_rqst.mutable_endpoint();
  ep->set_ip(std::string("192.168.1.1"));
  ep->set_port(12345);
  proxy_connect_rqst.set_rendezvous_connect(true);
  ASSERT_TRUE(proxy_connect_rqst.IsInitialized());

  std::string function_encrypt(msg_hndlr_.WrapMessage(proxy_connect_rqst));
  std::string manual_encrypt(
      EncryptMessage<protobuf::ProxyConnectRequest>(proxy_connect_rqst,
                                                    kProxyConnectRequest));
  EXPECT_EQ(manual_encrypt, function_encrypt);
}

TEST_F(TransportMessageHandlerTest, BEH_TRANS_WrapMessageForwardRendezvousRequest) {  // NOLINT
  protobuf::ForwardRendezvousRequest forward_rdvz_rqst;
  protobuf::Endpoint *ep = forward_rdvz_rqst.mutable_receiver_endpoint();
  ep->set_ip(std::string("192.168.1.1"));
  ep->set_port(12345);
  ASSERT_TRUE(forward_rdvz_rqst.IsInitialized());

  std::string function_encrypt(msg_hndlr_.WrapMessage(forward_rdvz_rqst));
  std::string manual_encrypt(EncryptMessage<protobuf::ForwardRendezvousRequest>(
                                 forward_rdvz_rqst, kForwardRendezvousRequest));
  EXPECT_EQ(manual_encrypt, function_encrypt);
}

TEST_F(TransportMessageHandlerTest, BEH_TRANS_WrapMessageRendezvousRequest) {
  protobuf::RendezvousRequest rdvz_rqst;
  protobuf::Endpoint *ep = rdvz_rqst.mutable_originator_endpoint();
  ep->set_ip(std::string("192.168.1.1"));
  ep->set_port(12345);
  ASSERT_TRUE(rdvz_rqst.IsInitialized());

  std::string function_encrypt(msg_hndlr_.WrapMessage(rdvz_rqst));
  std::string manual_encrypt(EncryptMessage<protobuf::RendezvousRequest>(
                                 rdvz_rqst, kRendezvousRequest));
  EXPECT_EQ(manual_encrypt, function_encrypt);
}

TEST_F(TransportMessageHandlerTest, BEH_TRANS_WrapMessageNatDetectionResponse) {
  protobuf::NatDetectionResponse nat_detection_resp;
  nat_detection_resp.set_nat_type(12345);
  ASSERT_TRUE(nat_detection_resp.IsInitialized());

  std::string function_encrypt(msg_hndlr_.WrapMessage(nat_detection_resp));
  std::string manual_encrypt(
      EncryptMessage<protobuf::NatDetectionResponse>(nat_detection_resp,
                                                    kNatDetectionResponse));
  EXPECT_EQ(manual_encrypt, function_encrypt);
}

TEST_F(TransportMessageHandlerTest, BEH_TRANS_WrapMessageProxyConnectResponse) {
  protobuf::ProxyConnectResponse proxy_connect_resp;
  proxy_connect_resp.set_result(true);
  ASSERT_TRUE(proxy_connect_resp.IsInitialized());

  std::string function_encrypt(msg_hndlr_.WrapMessage(proxy_connect_resp));
  std::string manual_encrypt(
      EncryptMessage<protobuf::ProxyConnectResponse>(proxy_connect_resp,
                                                     kProxyConnectResponse));
  EXPECT_EQ(manual_encrypt, function_encrypt);
}

TEST_F(TransportMessageHandlerTest, BEH_TRANS_WrapMessageForwardRendezvousResponse) {  // NOLINT
  protobuf::ForwardRendezvousResponse forward_rdvz_resp;
  protobuf::Endpoint *ep =
      forward_rdvz_resp.mutable_receiver_rendezvous_endpoint();
  ep->set_ip(std::string("192.168.1.1"));
  ep->set_port(12345);
  ASSERT_TRUE(forward_rdvz_resp.IsInitialized());

  std::string function_encrypt(msg_hndlr_.WrapMessage(forward_rdvz_resp));
  std::string manual_encrypt(
      EncryptMessage<protobuf::ForwardRendezvousResponse>(
          forward_rdvz_resp, kForwardRendezvousResponse));
  EXPECT_EQ(manual_encrypt, function_encrypt);
}

TEST_F(TransportMessageHandlerTest, BEH_TRANS_WrapMessageRendezvousAcknowledgement) {  // NOLINT
  protobuf::RendezvousAcknowledgement rdvz_ack_message;
  protobuf::Endpoint *ep =
      rdvz_ack_message.mutable_originator_endpoint();
  ep->set_ip(std::string("192.168.1.1"));
  ep->set_port(12345);
  ASSERT_TRUE(rdvz_ack_message.IsInitialized());

  std::string function(msg_hndlr_.WrapMessage(rdvz_ack_message));
  std::string manual(EncryptMessage<protobuf::RendezvousAcknowledgement>(
                         rdvz_ack_message, kRendezvousAcknowledgement));
  EXPECT_EQ(manual, function);
}

TEST_F(TransportMessageHandlerTest, BEH_TRANS_OnMessageReceived) {
  ConnectToHandlerSignals();
  InitialiseMap();
  CreateMessages();
}

}  // namespace test

}  // namespace transport

}  // namespace maidsafe
