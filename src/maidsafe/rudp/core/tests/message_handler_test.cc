/*******************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of MaidSafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the licence   *
 *  file licence.txt found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of MaidSafe.net. *
 ******************************************************************************/

#include "boost/lexical_cast.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/thread/thread.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/rudp/core/message_handler.h"
#include "maidsafe/rudp/transport_pb.h"
#include "maidsafe/rudp/return_codes.h"

namespace maidsafe {

namespace rudp {

namespace detail {

namespace test {

class MessageHandlerTest : public testing::Test {
 public:
  MessageHandlerTest() : private_key_(),
                         msg_hndlr_(),
                         asym_null_private_key_(),
                         msg_hndlr_no_securifier_(asym_null_private_key_),
                         invoked_slots_(),
                         slots_mutex_(),
                         error_count_(0) {}
  static void SetUpTestCase() {
    asymm::GenerateKeyPair(&crypto_key_pair_);
  }

  virtual void SetUp() {
    private_key_.reset(new asymm::PrivateKey(crypto_key_pair_.private_key));
    msg_hndlr_.reset(new MessageHandler(private_key_));
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
  void ErrorSlot(const ReturnCode &tc) { error_count_ += tc; }

  void ConnectToHandlerSignals() {
    msg_hndlr_->on_managed_endpoint_message()->connect(boost::bind(
        &MessageHandlerTest::ManagedEndpointSlot, this, _1, _2, _3));
    msg_hndlr_->on_error()->connect(boost::bind(
        &MessageHandlerTest::ErrorSlot, this, _1));
  }
  void InitialiseMap() {
    invoked_slots_.reset(new std::map<MessageType, uint16_t>);
    // TODO(Prakash) : Update this with updated MessageType.
    for (int n = kManagedEndpointMessage; n != kManagedEndpointMessage; ++n)
      invoked_slots_->insert(std::pair<MessageType, uint16_t>(
                                      MessageType(n), 0));
  }
  std::vector<std::string> CreateMessages() {
    protobuf::ManagedEndpointMessage me_msg;

    protobuf::Endpoint ep, ep_proxy;
    ep.set_ip(std::string("192.168.1.1"));
    ep_proxy.set_ip(std::string("192.168.0.9"));
    ep.set_port(12345);
    ep_proxy.set_port(12349);
    me_msg.mutable_endpoint()->CopyFrom(ep);

    EXPECT_TRUE(me_msg.IsInitialized());

    std::vector<std::string> messages;
    transport::protobuf::WrapperMessage wrap;
    wrap.set_msg_type(kManagedEndpointMessage);
    wrap.set_payload(me_msg.SerializeAsString());
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
  static asymm::Keys crypto_key_pair_;
  std::shared_ptr<asymm::PrivateKey> private_key_;
  std::shared_ptr<MessageHandler> msg_hndlr_;
  std::shared_ptr<asymm::PrivateKey> asym_null_private_key_;
  MessageHandler msg_hndlr_no_securifier_;
  std::shared_ptr<std::map<MessageType, uint16_t>> invoked_slots_;
  boost::mutex slots_mutex_;
  int error_count_;
};

asymm::Keys MessageHandlerTest::crypto_key_pair_;

TEST_F(MessageHandlerTest, BEH_OnError) {
  ConnectToHandlerSignals();

  int errors(0);
  for (int tc = transport::kError;
      tc != transport::kMessageSizeTooLarge; --tc) {
    errors += tc;
    msg_hndlr_->OnError(transport::ReturnCode(tc), Endpoint());
  }

  ASSERT_EQ(errors, error_count());
}

TEST_F(MessageHandlerTest, BEH_OnMessageNullSecurifier) {
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

TEST_F(MessageHandlerTest, BEH_WrapMessageManagedEndpointMessage) {  // NOLINT
  protobuf::ManagedEndpointMessage managed_endpoint_message;
  ASSERT_TRUE(managed_endpoint_message.IsInitialized());

  std::string function(msg_hndlr_->WrapMessage(managed_endpoint_message));
  std::string manual(EncryptMessage<protobuf::ManagedEndpointMessage>(
                        managed_endpoint_message, kManagedEndpointMessage));
  EXPECT_EQ(manual, function);
}

TEST_F(MessageHandlerTest, BEH_OnMessageReceived) {
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
    EXPECT_EQ(uint16_t(1), (*it).second) << "Type: " << (*it).first;
}

TEST_F(MessageHandlerTest, BEH_ThreadedMessageHandling) {
  ConnectToHandlerSignals();
  InitialiseMap();
  std::vector<std::string> messages(CreateMessages());

  uint8_t thread_count((RandomUint32() % 5) + 4);
  uint16_t total_messages(0);
  boost::thread_group thg;
  for (uint8_t n = 0; n < thread_count; ++n) {
    uint16_t rounds((RandomUint32() % 5) + 4);
    thg.create_thread(std::bind(&MessageHandlerTest::ExecuteThread,
                                this, messages, rounds));
    total_messages += rounds;
  }

  thg.join_all();
  std::shared_ptr<std::map<MessageType,
                  uint16_t>> slots = invoked_slots();
  for (auto it = slots->begin(); it != slots->end(); ++it)
    ASSERT_EQ(uint16_t(total_messages), (*it).second);
}

TEST_F(MessageHandlerTest, BEH_MakeSerialisedWrapperMessage) {
  std::string payload(RandomString(5 * 1024));
  ASSERT_TRUE(msg_hndlr_no_securifier_.MakeSerialisedWrapperMessage(0, payload,
              kAsymmetricEncrypt, crypto_key_pair_.public_key).empty());
  ASSERT_TRUE(msg_hndlr_no_securifier_.MakeSerialisedWrapperMessage(0, payload,
              kSignAndAsymEncrypt, crypto_key_pair_.public_key).empty());

  ASSERT_EQ("", msg_hndlr_->MakeSerialisedWrapperMessage(0,
                                                         payload,
                                                         kAsymmetricEncrypt,
                                                         asymm::PublicKey()));
  ASSERT_EQ("", msg_hndlr_->MakeSerialisedWrapperMessage(0,
                                                         payload,
                                                         kSignAndAsymEncrypt,
                                                         asymm::PublicKey()));

  ASSERT_FALSE(msg_hndlr_->MakeSerialisedWrapperMessage(0, payload,
               kAsymmetricEncrypt, crypto_key_pair_.public_key).empty());
  ASSERT_FALSE(msg_hndlr_->MakeSerialisedWrapperMessage(0, payload,
               kSignAndAsymEncrypt, crypto_key_pair_.public_key).empty());
}

}  // namespace test

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
