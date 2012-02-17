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

#include "boost/lexical_cast.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/thread/thread.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/transport/rudp_message_handler.h"
#include "maidsafe/transport/transport_pb.h"

namespace maidsafe {

namespace transport {

namespace test {

class RudpMessageHandlerTest : public testing::Test {
 public:
  RudpMessageHandlerTest() : private_key_(),
                             msg_hndlr_(),
                             asym_null_private_key_(),
                             msg_hndlr_no_securifier_(
                                 asym_null_private_key_),
                             invoked_slots_(),
                             slots_mutex_(),
                             error_count_(0) {}
  static void SetUpTestCase() {
    Asym::GenerateKeyPair(&crypto_key_pair_);
  }

  virtual void SetUp() {
    private_key_.reset(new Asym::PrivateKey(crypto_key_pair_.private_key));
    msg_hndlr_.reset(new RudpMessageHandler(private_key_));
  }
  virtual void TearDown() {}

  template<class T>
  std::string EncryptMessage(T request,
                            MessageType request_type) {
    protobuf::WrapperMessage message;
    message.set_msg_type(request_type);
    message.set_payload(request.SerializeAsString());
    std::string result(1, kNone);
    result += message.SerializeAsString();
    return result;
  }

  void ManagedEndpointSlot(const protobuf::ManagedEndpointMessage&,
                          protobuf::ManagedEndpointMessage*,
                          transport::Timeout*) {
    boost::mutex::scoped_lock lock(slots_mutex_);
    auto it = invoked_slots_->find(kManagedEndpointMessage);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }
  void NatDetectionReqSlot(const Info &/*info*/,
      const protobuf::NatDetectionRequest&,
      protobuf::NatDetectionResponse* response,
      transport::Timeout*) {
    boost::mutex::scoped_lock lock(slots_mutex_);
    response->set_nat_type(0);
    auto it = invoked_slots_->find(kNatDetectionRequest);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }
  void NatDetectionRspSlot(const protobuf::NatDetectionResponse&) {
    boost::mutex::scoped_lock lock(slots_mutex_);
    auto it = invoked_slots_->find(kNatDetectionResponse);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }
  void ProxyConnectReqSlot(const Info &/*info*/,
                          const protobuf::ProxyConnectRequest&,
                          protobuf::ProxyConnectResponse* response,
                          transport::Timeout*) {
    boost::mutex::scoped_lock lock(slots_mutex_);
    response->set_result(true);
    auto it = invoked_slots_->find(kProxyConnectRequest);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }
  void ProxyConnectRspSlot(const protobuf::ProxyConnectResponse&) {
    boost::mutex::scoped_lock lock(slots_mutex_);
    auto it = invoked_slots_->find(kProxyConnectResponse);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }
  void ForwardRendezvousReqSlot(const Info&,
                                const protobuf::ForwardRendezvousRequest&,
                                protobuf::ForwardRendezvousResponse* response) {
    boost::mutex::scoped_lock lock(slots_mutex_);
    protobuf::Endpoint *rv_endpoint =
        response->mutable_receiver_rendezvous_endpoint();
    rv_endpoint->set_ip("127.0.0.1");
    rv_endpoint->set_port(9999);
    auto it = invoked_slots_->find(kForwardRendezvousRequest);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }
  void ForwardRendezvousRspSlot(const protobuf::ForwardRendezvousResponse&) {
    boost::mutex::scoped_lock lock(slots_mutex_);
    auto it = invoked_slots_->find(kForwardRendezvousResponse);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }
  void RendezvousReqSlot(const Info&,
                        const protobuf::RendezvousRequest&,
                        protobuf::RendezvousAcknowledgement*) {
    boost::mutex::scoped_lock lock(slots_mutex_);
    auto it = invoked_slots_->find(kRendezvousRequest);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }
  void RendezvousAckSlot(const protobuf::RendezvousAcknowledgement&) {
    boost::mutex::scoped_lock lock(slots_mutex_);
    auto it = invoked_slots_->find(kRendezvousAcknowledgement);
    if (it != invoked_slots_->end())
      ++((*it).second);
  }
  void ErrorSlot(const TransportCondition &tc) { error_count_ += tc; }

  void ConnectToHandlerSignals() {
    msg_hndlr_->on_managed_endpoint_message()->connect(boost::bind(
        &RudpMessageHandlerTest::ManagedEndpointSlot, this, _1, _2, _3));
    msg_hndlr_->on_nat_detection_request()->connect(boost::bind(
        &RudpMessageHandlerTest::NatDetectionReqSlot, this, _1, _2, _3,
            _4));
    msg_hndlr_->on_nat_detection_response()->connect(boost::bind(
        &RudpMessageHandlerTest::NatDetectionRspSlot, this, _1));
    msg_hndlr_->on_proxy_connect_request()->connect(boost::bind(
        &RudpMessageHandlerTest::ProxyConnectReqSlot, this, _1, _2, _3,
            _4));
    msg_hndlr_->on_proxy_connect_response()->connect(boost::bind(
        &RudpMessageHandlerTest::ProxyConnectRspSlot, this, _1));
    msg_hndlr_->on_forward_rendezvous_request()->connect(boost::bind(
        &RudpMessageHandlerTest::ForwardRendezvousReqSlot,
        this, _1, _2, _3));
    msg_hndlr_->on_forward_rendezvous_response()->connect(boost::bind(
        &RudpMessageHandlerTest::ForwardRendezvousRspSlot, this, _1));
    msg_hndlr_->on_rendezvous_request()->connect(boost::bind(
        &RudpMessageHandlerTest::RendezvousReqSlot, this, _1, _2, _3));
    msg_hndlr_->on_rendezvous_acknowledgement()->connect(boost::bind(
        &RudpMessageHandlerTest::RendezvousAckSlot, this, _1));
    msg_hndlr_->on_error()->connect(boost::bind(
        &RudpMessageHandlerTest::ErrorSlot, this, _1));
  }
  void InitialiseMap() {
    invoked_slots_.reset(new std::map<MessageType, uint16_t>);
    for (int n = kManagedEndpointMessage; n != kRendezvousAcknowledgement; ++n)
      invoked_slots_->insert(std::pair<MessageType, uint16_t>(
                                      MessageType(n), 0));
  }
  std::vector<std::string> CreateMessages() {
    protobuf::ManagedEndpointMessage me_msg;
    protobuf::NatDetectionRequest nd_req;
    protobuf::ProxyConnectRequest pc_req;
    protobuf::ForwardRendezvousRequest fr_req;
    protobuf::RendezvousRequest r_req;
    protobuf::NatDetectionResponse nd_res;
    protobuf::ProxyConnectResponse pc_res;
    protobuf::ForwardRendezvousResponse fr_res;
    protobuf::RendezvousAcknowledgement ra_msg;

    protobuf::Endpoint ep, ep_proxy;
    ep.set_ip(std::string("192.168.1.1"));
    ep_proxy.set_ip(std::string("192.168.0.9"));
    ep.set_port(12345);
    ep_proxy.set_port(12349);
    me_msg.mutable_endpoint()->CopyFrom(ep);
    pc_req.mutable_endpoint()->CopyFrom(ep);
    fr_req.mutable_receiver_endpoint()->CopyFrom(ep);
    r_req.mutable_proxy_endpoint()->CopyFrom(ep_proxy);
    nd_res.mutable_endpoint()->CopyFrom(ep);
    fr_res.mutable_receiver_rendezvous_endpoint()->CopyFrom(ep);
    ra_msg.mutable_originator_endpoint()->CopyFrom(ep);

    nd_req.set_local_port(12021);
    nd_req.add_local_ips(std::string("192.168.1.1"));
    nd_req.add_local_ips(std::string("192.168.1.2"));
    nd_res.set_nat_type(0);
    pc_req.set_rendezvous_connect(true);
    pc_res.set_result(true);

    EXPECT_TRUE(me_msg.IsInitialized());
    EXPECT_TRUE(nd_req.IsInitialized());
    EXPECT_TRUE(pc_req.IsInitialized());
    EXPECT_TRUE(fr_req.IsInitialized());
    EXPECT_TRUE(r_req.IsInitialized());
    EXPECT_TRUE(nd_res.IsInitialized());
    EXPECT_TRUE(pc_res.IsInitialized());
    EXPECT_TRUE(fr_res.IsInitialized());
    EXPECT_TRUE(ra_msg.IsInitialized());

    std::vector<std::string> messages;
    transport::protobuf::WrapperMessage wrap;
    wrap.set_msg_type(kManagedEndpointMessage);
    wrap.set_payload(me_msg.SerializeAsString());
    messages.push_back(std::string(1, kNone) + wrap.SerializeAsString());

    wrap.Clear();
    wrap.set_msg_type(kNatDetectionRequest);
    wrap.set_payload(nd_req.SerializeAsString());
    messages.push_back(std::string(1, kNone) + wrap.SerializeAsString());

    wrap.Clear();
    wrap.set_msg_type(kProxyConnectRequest);
    wrap.set_payload(pc_req.SerializeAsString());
    messages.push_back(std::string(1, kNone) + wrap.SerializeAsString());

    wrap.Clear();
    wrap.set_msg_type(kForwardRendezvousRequest);
    wrap.set_payload(fr_req.SerializeAsString());
    messages.push_back(std::string(1, kNone) + wrap.SerializeAsString());

    wrap.Clear();
    wrap.set_msg_type(kRendezvousRequest);
    wrap.set_payload(r_req.SerializeAsString());
    messages.push_back(std::string(1, kNone) + wrap.SerializeAsString());

    wrap.Clear();
    wrap.set_msg_type(kNatDetectionResponse);
    wrap.set_payload(nd_res.SerializeAsString());
    messages.push_back(std::string(1, kNone) + wrap.SerializeAsString());

    wrap.Clear();
    wrap.set_msg_type(kProxyConnectResponse);
    wrap.set_payload(pc_res.SerializeAsString());
    messages.push_back(std::string(1, kNone) + wrap.SerializeAsString());

    wrap.Clear();
    wrap.set_msg_type(kForwardRendezvousResponse);
    wrap.set_payload(fr_res.SerializeAsString());
    messages.push_back(std::string(1, kNone) + wrap.SerializeAsString());

    wrap.Clear();
    wrap.set_msg_type(kRendezvousAcknowledgement);
    wrap.set_payload(ra_msg.SerializeAsString());
    messages.push_back(std::string(1, kNone) + wrap.SerializeAsString());
    return messages;
  }
  void ExecuteThread(std::vector<std::string> messages_copy, int rounds) {
    Info info;
    std::string response;
    Timeout timeout;

    uint32_t random_sleep((RandomUint32() % 100) + 100);
    for (int a = 0; a < rounds; ++a) {
      Sleep(boost::posix_time::milliseconds(random_sleep));
      for (size_t n = 0; n < messages_copy.size(); ++n)
        msg_hndlr_->OnMessageReceived(messages_copy[n], info, &response,
                                      &timeout);
    }
  }

  std::shared_ptr<std::map<MessageType, uint16_t>> invoked_slots() {
    return invoked_slots_;
  }
  int error_count() { return error_count_; }

 protected:
  static Asym::Keys crypto_key_pair_;
  std::shared_ptr<Asym::PrivateKey> private_key_;
  std::shared_ptr<RudpMessageHandler> msg_hndlr_;
  std::shared_ptr<Asym::PrivateKey> asym_null_private_key_;
  MessageHandler msg_hndlr_no_securifier_;
  std::shared_ptr<std::map<MessageType, uint16_t>> invoked_slots_;
  boost::mutex slots_mutex_;
  int error_count_;
};

Asym::Keys RudpMessageHandlerTest::crypto_key_pair_;

TEST_F(RudpMessageHandlerTest, BEH_OnError) {
  ConnectToHandlerSignals();

  int errors(0);
  for (int tc = transport::kError;
      tc != transport::kMessageSizeTooLarge; --tc) {
    errors += tc;
    msg_hndlr_->OnError(transport::TransportCondition(tc), Endpoint());
  }

  ASSERT_EQ(errors, error_count());
}

TEST_F(RudpMessageHandlerTest, BEH_OnMessageNullSecurifier) {
  ConnectToHandlerSignals();
  InitialiseMap();
  std::vector<std::string> messages(CreateMessages());

  Info info;
  std::string response;
  Timeout timeout;
  for (size_t n = 0; n < messages.size(); ++n)
    msg_hndlr_->OnMessageReceived(
        std::string(1, kAsymmetricEncrypt) + messages[n],
        info, &response, &timeout);
  std::shared_ptr<std::map<MessageType,
                  uint16_t>> slots = invoked_slots();
  for (auto it = slots->begin(); it != slots->end(); ++it)
    ASSERT_EQ(uint16_t(0), (*it).second);

  slots->clear();
  InitialiseMap();
  for (size_t n = 0; n < messages.size(); ++n)
    msg_hndlr_->OnMessageReceived(
        std::string(1, kAsymmetricEncrypt) + messages[n],
        info, &response, &timeout);
  for (auto it = slots->begin(); it != slots->end(); ++it)
    ASSERT_EQ(uint16_t(0), (*it).second);

  slots->clear();
  InitialiseMap();
  for (size_t n = 0; n < messages.size(); ++n)
    msg_hndlr_->OnMessageReceived("", info, &response, &timeout);
  for (auto it = slots->begin(); it != slots->end(); ++it)
    ASSERT_EQ(uint16_t(0), (*it).second);
}

TEST_F(RudpMessageHandlerTest, BEH_WrapMessageManagedEndpointMessage) {  // NOLINT
  protobuf::ManagedEndpointMessage managed_endpoint_message;
  ASSERT_TRUE(managed_endpoint_message.IsInitialized());

  std::string function(msg_hndlr_->WrapMessage(managed_endpoint_message));
  std::string manual(EncryptMessage<protobuf::ManagedEndpointMessage>(
                        managed_endpoint_message, kManagedEndpointMessage));
  EXPECT_EQ(manual, function);
}

TEST_F(RudpMessageHandlerTest, BEH_WrapMessageNatDetectionRequest) {
  protobuf::NatDetectionRequest nat_detection_rqst;
  nat_detection_rqst.add_local_ips(std::string("192.168.1.1"));
  nat_detection_rqst.set_local_port(12345);
  nat_detection_rqst.set_full_detection(true);
  ASSERT_TRUE(nat_detection_rqst.IsInitialized());

  std::string function_encrypt(msg_hndlr_->WrapMessage(nat_detection_rqst));
  std::string manual_encrypt(
      EncryptMessage<protobuf::NatDetectionRequest>(nat_detection_rqst,
                                                    kNatDetectionRequest));
  EXPECT_EQ(manual_encrypt, function_encrypt);
}

TEST_F(RudpMessageHandlerTest, BEH_WrapMessageProxyConnectRequest) {
  protobuf::ProxyConnectRequest proxy_connect_rqst;
  protobuf::Endpoint *ep = proxy_connect_rqst.mutable_endpoint();
  ep->set_ip(std::string("192.168.1.1"));
  ep->set_port(12345);
  proxy_connect_rqst.set_rendezvous_connect(true);
  ASSERT_TRUE(proxy_connect_rqst.IsInitialized());

  std::string function_encrypt(msg_hndlr_->WrapMessage(proxy_connect_rqst));
  std::string manual_encrypt(
      EncryptMessage<protobuf::ProxyConnectRequest>(proxy_connect_rqst,
                                                    kProxyConnectRequest));
  EXPECT_EQ(manual_encrypt, function_encrypt);
}

TEST_F(RudpMessageHandlerTest, BEH_WrapMessageForwardRendezvousRequest) {  // NOLINT
  protobuf::ForwardRendezvousRequest forward_rdvz_rqst;
  protobuf::Endpoint *ep = forward_rdvz_rqst.mutable_receiver_endpoint();
  ep->set_ip(std::string("192.168.1.1"));
  ep->set_port(12345);
  ASSERT_TRUE(forward_rdvz_rqst.IsInitialized());

  std::string function_encrypt(msg_hndlr_->WrapMessage(forward_rdvz_rqst));
  std::string manual_encrypt(EncryptMessage<protobuf::ForwardRendezvousRequest>(
                                forward_rdvz_rqst, kForwardRendezvousRequest));
  EXPECT_EQ(manual_encrypt, function_encrypt);
}

TEST_F(RudpMessageHandlerTest, BEH_WrapMessageRendezvousRequest) {
  protobuf::RendezvousRequest rdvz_rqst;

  protobuf::Endpoint *proxy_endpoint = rdvz_rqst.mutable_proxy_endpoint();
  proxy_endpoint->set_ip(std::string("192.168.0.9"));
  proxy_endpoint->set_port(12349);

  ASSERT_TRUE(rdvz_rqst.IsInitialized());

  std::string function_encrypt(msg_hndlr_->WrapMessage(rdvz_rqst));
  std::string manual_encrypt(EncryptMessage<protobuf::RendezvousRequest>(
                                 rdvz_rqst, kRendezvousRequest));
  EXPECT_EQ(manual_encrypt, function_encrypt);
}

TEST_F(RudpMessageHandlerTest, BEH_WrapMessageNatDetectionResponse) {
  protobuf::NatDetectionResponse nat_detection_resp;
  protobuf::Endpoint *endpoint = nat_detection_resp.mutable_endpoint();
  endpoint->set_ip(std::string("192.168.0.9"));
  endpoint->set_port(12349);
  nat_detection_resp.set_nat_type(12345);
  ASSERT_TRUE(nat_detection_resp.IsInitialized());

  std::string function_encrypt(msg_hndlr_->WrapMessage(nat_detection_resp));
  std::string manual_encrypt(
      EncryptMessage<protobuf::NatDetectionResponse>(nat_detection_resp,
                                                    kNatDetectionResponse));
  EXPECT_EQ(manual_encrypt, function_encrypt);
}

TEST_F(RudpMessageHandlerTest, BEH_WrapMessageProxyConnectResponse) {
  protobuf::ProxyConnectResponse proxy_connect_resp;
  proxy_connect_resp.set_result(true);
  ASSERT_TRUE(proxy_connect_resp.IsInitialized());

  std::string function_encrypt(msg_hndlr_->WrapMessage(proxy_connect_resp));
  std::string manual_encrypt(
      EncryptMessage<protobuf::ProxyConnectResponse>(proxy_connect_resp,
                                                    kProxyConnectResponse));
  EXPECT_EQ(manual_encrypt, function_encrypt);
}

TEST_F(RudpMessageHandlerTest, BEH_WrapMessageForwardRendezvousResponse) {  // NOLINT
  protobuf::ForwardRendezvousResponse forward_rdvz_resp;
  protobuf::Endpoint *ep =
      forward_rdvz_resp.mutable_receiver_rendezvous_endpoint();
  ep->set_ip(std::string("192.168.1.1"));
  ep->set_port(12345);
  ASSERT_TRUE(forward_rdvz_resp.IsInitialized());

  std::string function_encrypt(msg_hndlr_->WrapMessage(forward_rdvz_resp));
  std::string manual_encrypt(
      EncryptMessage<protobuf::ForwardRendezvousResponse>(
          forward_rdvz_resp, kForwardRendezvousResponse));
  EXPECT_EQ(manual_encrypt, function_encrypt);
}

TEST_F(RudpMessageHandlerTest, BEH_WrapMessageRendezvousAcknowledgement) {  // NOLINT
  protobuf::RendezvousAcknowledgement rdvz_ack_message;
  protobuf::Endpoint *ep =
      rdvz_ack_message.mutable_originator_endpoint();
  ep->set_ip(std::string("192.168.1.1"));
  ep->set_port(12345);
  ASSERT_TRUE(rdvz_ack_message.IsInitialized());

  std::string function(msg_hndlr_->WrapMessage(rdvz_ack_message));
  std::string manual(EncryptMessage<protobuf::RendezvousAcknowledgement>(
                        rdvz_ack_message, kRendezvousAcknowledgement));
  EXPECT_EQ(manual, function);
}

TEST_F(RudpMessageHandlerTest, BEH_OnMessageReceived) {
  ConnectToHandlerSignals();
  InitialiseMap();
  std::vector<std::string> messages(CreateMessages());

  Info info;
  std::string response;
  Timeout timeout;
  for (size_t n = 0; n < messages.size(); ++n)
    msg_hndlr_->OnMessageReceived(messages[n], info, &response, &timeout);

  std::shared_ptr<std::map<MessageType, uint16_t>> slots = invoked_slots();
  for (auto it = slots->begin(); it != slots->end(); ++it)
    ASSERT_EQ(uint16_t(1), (*it).second);
}

TEST_F(RudpMessageHandlerTest, BEH_ThreadedMessageHandling) {
  ConnectToHandlerSignals();
  InitialiseMap();
  std::vector<std::string> messages(CreateMessages());

  uint8_t thread_count((RandomUint32() % 5) + 4);
  uint16_t total_messages(0);
  boost::thread_group thg;
  for (uint8_t n = 0; n < thread_count; ++n) {
    uint16_t rounds((RandomUint32() % 5) + 4);
    thg.create_thread(std::bind(&RudpMessageHandlerTest::ExecuteThread,
                                this, messages, rounds));
    total_messages += rounds;
  }

  thg.join_all();
  std::shared_ptr<std::map<MessageType,
                  uint16_t>> slots = invoked_slots();
  for (auto it = slots->begin(); it != slots->end(); ++it)
    ASSERT_EQ(uint16_t(total_messages), (*it).second);
}

TEST_F(RudpMessageHandlerTest, BEH_MakeSerialisedWrapperMessage) {
  std::string payload(RandomString(5 * 1024));
  ASSERT_TRUE(msg_hndlr_no_securifier_.MakeSerialisedWrapperMessage(0, payload,
              kAsymmetricEncrypt, crypto_key_pair_.public_key).empty());
  ASSERT_TRUE(msg_hndlr_no_securifier_.MakeSerialisedWrapperMessage(0, payload,
              kSignAndAsymEncrypt, crypto_key_pair_.public_key).empty());

  ASSERT_EQ("", msg_hndlr_->MakeSerialisedWrapperMessage(0,
                                                         payload,
                                                         kAsymmetricEncrypt,
                                                         Asym::PublicKey()));
  ASSERT_EQ("", msg_hndlr_->MakeSerialisedWrapperMessage(0,
                                                         payload,
                                                         kSignAndAsymEncrypt,
                                                         Asym::PublicKey()));

  ASSERT_FALSE(msg_hndlr_->MakeSerialisedWrapperMessage(0, payload,
               kAsymmetricEncrypt, crypto_key_pair_.public_key).empty());
  ASSERT_FALSE(msg_hndlr_->MakeSerialisedWrapperMessage(0, payload,
               kSignAndAsymEncrypt, crypto_key_pair_.public_key).empty());
}

}  // namespace test

}  // namespace transport

}  // namespace maidsafe
