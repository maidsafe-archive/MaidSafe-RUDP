/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.
File Created: 2011/03/16
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

#include "boost/thread.hpp"
#include "boost/thread/mutex.hpp"
#include "maidsafe/common/test.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/dht/kademlia/message_handler.h"
#include "maidsafe/dht/transport/message_handler.h"
#include "maidsafe/dht/kademlia/message_handler.cc"
#include "maidsafe/dht/kademlia/utils.h"
#include "maidsafe/dht/kademlia/rpcs.h"
#include "maidsafe/dht/kademlia/securifier.h"
#include "maidsafe/dht/kademlia/node_id.h"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/dht/transport/transport.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "maidsafe/dht/transport/tcp_transport.h"


namespace arg = std::placeholders;

namespace maidsafe {
namespace dht {
namespace kademlia {
namespace test {
namespace {

// Mock the TcpTransport class
class RpcsMockTransport : public transport::Transport {
 public:
  RpcsMockTransport(boost::asio::io_service &asio_service,  // NOLINT
                    const uint16_t &repeat_factor,
                    uint16_t failure_tolerance)
      : Transport(asio_service),
        repeat_factor_(repeat_factor),
        failure_tolerance_(failure_tolerance) {}
  ~RpcsMockTransport() {}
  virtual transport::TransportCondition StartListening(
      const transport::Endpoint &/*endpoint*/) {
    return transport::kSuccess;
  }
  virtual transport::TransportCondition Bootstrap(
      const std::vector<transport::Endpoint> &/*endpoints*/) {
    return transport::kSuccess;
  }
  virtual void StopListening() {}
  virtual void Send(const std::string &data,
                    const transport::Endpoint &/*endpoint*/,
                    const transport::Timeout &/*timeout*/) {
    if (repeat_factor_ < failure_tolerance_) {
      boost::thread(&RpcsMockTransport::SignalError, this);
    } else {
      boost::thread(&RpcsMockTransport::SignalMessageReceived, this, data);
    }
  }
  void SignalError() {
    Sleep(boost::posix_time::milliseconds(500));
    ++repeat_factor_;
    (*on_error())(transport::kError, transport::Endpoint());
  }
  void SignalMessageReceived(std::string data) {
    Sleep(boost::posix_time::milliseconds(500));
    transport::Info info;
    transport::Timeout response_timeout(transport::kImmediateTimeout);
    std::string response("response");
    (*on_message_received())(data, info, &response, &response_timeout);
  }
 protected:
  uint16_t repeat_factor_;
  uint16_t failure_tolerance_;
};

class MockMessageHandler : public MessageHandler {
 public:
  MockMessageHandler(SecurifierPtr securifier,
                     const int &request_type,
                     const int &result_type)
    : MessageHandler(securifier),
      securifier_(securifier),
      request_type_(request_type),
      result_type_(result_type) {}

  void OnMessageReceived(const std::string &request,
                         const transport::Info &info,
                         std::string *response,
                         transport::Timeout *timeout) {
    ProcessSerialisedMessage(request_type_, request, kNone, "",
                             info, response, timeout);
  }

  void ProcessSerialisedMessage(
    const int &message_type,
    const std::string &payload,
    const SecurityType &/*security_type*/,
    const std::string &/*message_signature*/,
    const transport::Info &info,
    std::string *message_response,
    transport::Timeout* timeout) {
  message_response->clear();
  *timeout = transport::kImmediateTimeout;

  switch (message_type) {
    case kademlia::kPingRequest: {
      protobuf::PingRequest request;
      request.ParseFromString(payload);
      protobuf::PingResponse response;
      switch (result_type_) {
        case 1: {
          response.set_echo(request.ping());
          break;
        }
        case 2: {
          response.set_echo("");
          break;
        }
        default:
          break;
      }
      (*on_ping_response())(info, response);
      break;
    }
    case kFindValueRequest: {
      protobuf::FindValueResponse response;
      switch (result_type_) {
        case 1: {
          protobuf::SignedValue value;
          value.set_value("value");
          value.set_signature("signature");
          Contact contact, alternative_value_holder;
          response.set_result(true);
          *response.add_closest_nodes() = ToProtobuf(contact);
          *response.add_signed_values() = value;
          *response.mutable_alternative_value_holder() =
              ToProtobuf(alternative_value_holder);
          break;
        }
        case 2: {
          response.set_result(false);
          break;
        }
        default:
          break;
      }
      (*on_find_value_response())(info, response);
      break;
    }
    case kFindNodesRequest: {
      protobuf::FindNodesResponse response;
      switch (result_type_) {
        case 1: {
          Contact contact;
          response.set_result(true);
          *response.add_closest_nodes() = ToProtobuf(contact);
          break;
        }
        case 2: {
          response.set_result(false);
          break;
        }
        default:
          break;
      }
      (*on_find_nodes_response())(info, response);
      break;
    }
    case kStoreRequest: {
      protobuf::StoreResponse response;
      switch (result_type_) {
        case 1: {
          response.set_result(true);
          break;
        }
        case 2: {
          response.set_result(false);
          break;
        }
        default:
          break;
      }
      (*on_store_response())(info, response);
      break;
    }
    case kStoreRefreshRequest: {
      protobuf::StoreRefreshResponse response;
      switch (result_type_) {
        case 1: {
          response.set_result(true);
          break;
        }
        case 2: {
          response.set_result(false);
          break;
        }
        default:
          break;
      }
      (*on_store_refresh_response())(info, response);
      break;
    }
    case kDeleteRequest: {
      protobuf::DeleteResponse response;
      switch (result_type_) {
        case 1: {
          response.set_result(true);
          break;
        }
        case 2: {
          response.set_result(false);
          break;
        }
        default:
          break;
      }
      (*on_delete_response())(info, response);
      break;
    }
    case kDeleteRefreshRequest: {
      protobuf::DeleteRefreshResponse response;
      switch (result_type_) {
        case 1: {
          response.set_result(true);
          break;
        }
        case 2: {
          response.set_result(false);
          break;
        }
        default:
          break;
      }
      (*on_delete_refresh_response())(info, response);
      break;
    }
    case kDownlistNotification: {
      protobuf::DownlistNotification request;
      EXPECT_TRUE(request.ParseFromString(payload));
      EXPECT_EQ(size_t(1), request.node_ids_size());
      ops_completion_flag = true;
      break;
    }
    default:
      break;
  }
}
  static volatile bool ops_completion_flag;
 protected:
  SecurifierPtr securifier_;
  int request_type_;
  int result_type_;
};

typedef std::shared_ptr<MockMessageHandler> MockMessageHandlerPtr;
volatile bool MockMessageHandler::ops_completion_flag = false;


template <typename TransportType>
class MockRpcs : public Rpcs<TransportType> {
 public:
  MockRpcs(AsioService &asio_service,                     // NOLINT (Fraser)
           SecurifierPtr securifier,
           const int &request_type,
           const uint16_t &repeat_factor,
           const int &result_type)
      : Rpcs<TransportType>(asio_service, securifier),
        local_t_(),
        local_mh_(),
        request_type_(request_type),
        repeat_factor_(repeat_factor),
        result_type_(result_type) {}
  MOCK_METHOD3_T(Prepare, void(SecurifierPtr securifier,
                               TransportPtr &transport,
                               MessageHandlerPtr &message_handler));
  void MockPrepare(SecurifierPtr securifier,
                   TransportPtr &transport,
                   MessageHandlerPtr &message_handler) {
    transport.reset(new RpcsMockTransport(this->asio_service_, repeat_factor_,
                                          this->kFailureTolerance_));
    message_handler.reset(new MockMessageHandler(securifier,
                                                 request_type_,
                                                 result_type_));
    transport->on_message_received()->connect(
        transport::OnMessageReceived::element_type::slot_type(
            &MessageHandler::OnMessageReceived, message_handler.get(),
            _1, _2, _3, _4).track_foreign(message_handler));
    transport->on_error()->connect(
        transport::OnError::element_type::slot_type(
            &MessageHandler::OnError, message_handler.get(),
            _1, _2).track_foreign(message_handler));
    if (request_type_ == kDownlistNotification) {
      local_t_ = transport;
      local_mh_ = message_handler;
    }
  }

  uint16_t kFailureTolerance() const { return this->kFailureTolerance_; }

 protected:
  TransportPtr local_t_;
  MessageHandlerPtr local_mh_;
  int request_type_;
  uint16_t repeat_factor_;
  int result_type_;

 private:
  MockRpcs(const MockRpcs&);
  MockRpcs& operator=(const MockRpcs&);
};

}  // unnamed namespace

class MockRpcsTest : public testing::Test {
 public:
  MockRpcsTest() : asio_service_(),
                   securifier_(),
                   peer_(ComposeContact(NodeId(NodeId::kRandomId), 6789)) {}

  ~MockRpcsTest() {}

  static void SetUpTestCase() {
    crypto_key_pair_.GenerateKeys(4096);
  }

  virtual void SetUp() {
    securifier_.reset(
        new Securifier(RandomString(64), crypto_key_pair_.public_key(),
                        crypto_key_pair_.private_key()));
  }

  Contact ComposeContact(const NodeId& node_id, uint16_t port) {
    std::string ip("127.0.0.1");
    std::vector<transport::Endpoint> local_endpoints;
    transport::Endpoint end_point(ip, port);
    local_endpoints.push_back(end_point);
    Contact contact(node_id, end_point, local_endpoints, end_point, false,
                    false, "", crypto_key_pair_.public_key(), "");
    return contact;
  }

  void Callback(RankInfoPtr /*rank_info*/,
                const int &result,
                bool *b,
                boost::mutex *m,
                int *query_result) {
    boost::mutex::scoped_lock lock(*m);
    *b = true;
    *query_result = result;
  }
  void FindNodesCallback(RankInfoPtr rank_info,
                         const int &result,
                         std::vector<Contact> /*contacts*/,
                         bool *b,
                         boost::mutex *m,
                         int *query_result) {
    Callback(rank_info, result, b, m, query_result);
  }
  void FindValueCallback(RankInfoPtr rank_info,
                         const int &result,
                         const std::vector<ValueAndSignature> &/*values*/,
                         const std::vector<Contact> &/*contacts*/,
                         const Contact &/*contact*/,
                         bool *b,
                         boost::mutex *m,
                         int *query_result) {
    Callback(rank_info, result, b, m, query_result);
  }
  protected:
  static crypto::RsaKeyPair crypto_key_pair_;
  AsioService asio_service_;
  SecurifierPtr securifier_;
  Contact peer_;
};

crypto::RsaKeyPair MockRpcsTest::crypto_key_pair_;

TEST_F(MockRpcsTest, BEH_Ping) {
  uint16_t repeat_factor(1);
  int result_type(1);
  for (int i = 0; i < 5; ++i) {
    std::shared_ptr<MockRpcs<transport::TcpTransport>> rpcs(
        new MockRpcs<transport::TcpTransport>(asio_service_,
                                              securifier_,
                                              kPingRequest,
                                              repeat_factor,
                                              result_type));
    bool b(false), b2(false);
    int result(999);
    boost::mutex m;
    EXPECT_CALL(*rpcs, Prepare(testing::_, testing::_, testing::_))
        .WillOnce(testing::WithArgs<0, 1, 2>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::MockPrepare,
                      rpcs.get(), arg::_1, arg::_2, arg::_3))));

    RpcPingFunctor pf = std::bind(&MockRpcsTest::Callback, this, arg::_1,
                                  arg::_2, &b, &m, &result);
    rpcs->Ping(securifier_, peer_, pf);
    while (!b2) {
      Sleep(boost::posix_time::milliseconds(10));
      {
        boost::mutex::scoped_lock lock(m);
        b2 = b;
      }
    }
    switch (i) {
      case 0: {
        ASSERT_EQ(transport::kSuccess, result);
        result_type = 2;
        break;
      }
      case 1: {
        ASSERT_EQ(transport::kError, result);
        result_type = 1;
        repeat_factor = rpcs->kFailureTolerance();
        break;
      }
      case 2: {
        ASSERT_EQ(transport::kSuccess, result);
        repeat_factor = 0;
        break;
      }
      case 3: {
        ASSERT_EQ(transport::kError, result);
        repeat_factor = rpcs->kFailureTolerance() - 1;
        break;
      }
      case 4: {
        ASSERT_EQ(transport::kSuccess, result);
        break;
      }
      default:
        break;
    }
  }
}

TEST_F(MockRpcsTest, BEH_Store) {
  uint16_t repeat_factor(1);
  int result_type(1);
  for (int i = 0; i < 5; ++i) {
    std::shared_ptr<MockRpcs<transport::TcpTransport>> rpcs(
        new MockRpcs<transport::TcpTransport>(asio_service_,
                                              securifier_,
                                              kStoreRequest,
                                              repeat_factor,
                                              result_type));
    bool b(false), b2(false);
    int result(999);
    boost::mutex m;
    EXPECT_CALL(*rpcs, Prepare(testing::_, testing::_, testing::_))
        .WillOnce(testing::WithArgs<0, 1, 2>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::MockPrepare,
                      rpcs.get(), arg::_1, arg::_2, arg::_3))));

    RpcStoreFunctor sf = std::bind(&MockRpcsTest::Callback, this, arg::_1,
                                   arg::_2, &b, &m, &result);
    rpcs->Store(NodeId(NodeId::kRandomId), "", "",
                boost::posix_time::seconds(1), securifier_, peer_, sf);
    while (!b2) {
      Sleep(boost::posix_time::milliseconds(10));
      {
        boost::mutex::scoped_lock lock(m);
        b2 = b;
      }
    }
    switch (i) {
      case 0: {
        ASSERT_EQ(transport::kSuccess, result);
        result_type = 2;
        break;
      }
      case 1: {
        ASSERT_EQ(transport::kError, result);
        result_type = 1;
        repeat_factor = rpcs->kFailureTolerance();
        break;
      }
      case 2: {
        ASSERT_EQ(transport::kSuccess, result);
        repeat_factor = 0;
        break;
      }
      case 3: {
        ASSERT_EQ(transport::kError, result);
        repeat_factor = rpcs->kFailureTolerance() - 1;
        break;
      }
      case 4: {
        ASSERT_EQ(transport::kSuccess, result);
        break;
      }
      default:
        break;
    }
  }
}

TEST_F(MockRpcsTest, BEH_StoreRefresh) {
  uint16_t repeat_factor(1);
  int result_type(1);
  for (int i = 0; i < 5; ++i) {
    std::shared_ptr<MockRpcs<transport::TcpTransport>> rpcs(
        new MockRpcs<transport::TcpTransport>(asio_service_,
                                              securifier_,
                                              kStoreRefreshRequest,
                                              repeat_factor,
                                              result_type));
    bool b(false), b2(false);
    int result(999);
    boost::mutex m;
    EXPECT_CALL(*rpcs, Prepare(testing::_, testing::_, testing::_))
        .WillOnce(testing::WithArgs<0, 1, 2>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::MockPrepare,
                      rpcs.get(), arg::_1, arg::_2, arg::_3))));

    RpcStoreRefreshFunctor srf = std::bind(&MockRpcsTest::Callback, this,
                                           arg::_1, arg::_2, &b, &m, &result);
    rpcs->StoreRefresh("", "", securifier_, peer_, srf);
    while (!b2) {
      Sleep(boost::posix_time::milliseconds(10));
      boost::mutex::scoped_lock lock(m);
      b2 = b;
    }
    switch (i) {
      case 0: {
        ASSERT_EQ(transport::kSuccess, result);
        result_type = 2;
        break;
      }
      case 1: {
        ASSERT_EQ(transport::kError, result);
        result_type = 1;
        repeat_factor = rpcs->kFailureTolerance();
        break;
      }
      case 2: {
        ASSERT_EQ(transport::kSuccess, result);
        repeat_factor = 0;
        break;
      }
      case 3: {
        ASSERT_EQ(transport::kError, result);
        repeat_factor = rpcs->kFailureTolerance() - 1;
        break;
      }
      case 4: {
        ASSERT_EQ(transport::kSuccess, result);
        break;
      }
      default:
        break;
    }
  }
}

TEST_F(MockRpcsTest, BEH_Delete) {
  uint16_t repeat_factor(1);
  int result_type(1);
  for (int i = 0; i < 5; ++i) {
    std::shared_ptr<MockRpcs<transport::TcpTransport>> rpcs(
        new MockRpcs<transport::TcpTransport>(asio_service_,
                                              securifier_,
                                              kDeleteRequest,
                                              repeat_factor,
                                              result_type));
    bool b(false), b2(false);
    int result(999);
    boost::mutex m;
    EXPECT_CALL(*rpcs, Prepare(testing::_, testing::_, testing::_))
        .WillOnce(testing::WithArgs<0, 1, 2>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::MockPrepare,
                      rpcs.get(), arg::_1, arg::_2, arg::_3))));

    RpcDeleteFunctor df = std::bind(&MockRpcsTest::Callback, this, arg::_1,
                                    arg::_2, &b, &m, &result);
    rpcs->Delete(NodeId(NodeId::kRandomId), "", "", securifier_, peer_, df);
    while (!b2) {
      Sleep(boost::posix_time::milliseconds(10));
      boost::mutex::scoped_lock lock(m);
      b2 = b;
    }
    switch (i) {
      case 0: {
        ASSERT_EQ(transport::kSuccess, result);
        result_type = 2;
        break;
      }
      case 1: {
        ASSERT_EQ(transport::kError, result);
        result_type = 1;
        repeat_factor = rpcs->kFailureTolerance();
        break;
      }
      case 2: {
        ASSERT_EQ(transport::kSuccess, result);
        repeat_factor = 0;
        break;
      }
      case 3: {
        ASSERT_EQ(transport::kError, result);
        repeat_factor = rpcs->kFailureTolerance() - 1;
        break;
      }
      case 4: {
        ASSERT_EQ(transport::kSuccess, result);
        break;
      }
      default:
        break;
    }
  }
}

TEST_F(MockRpcsTest, BEH_DeleteRefresh) {
  uint16_t repeat_factor(1);
  int result_type(1);
  for (int i = 0; i < 5; ++i) {
    std::shared_ptr<MockRpcs<transport::TcpTransport>> rpcs(
        new MockRpcs<transport::TcpTransport>(asio_service_,
                                              securifier_,
                                              kDeleteRefreshRequest,
                                              repeat_factor,
                                              result_type));
    bool b(false), b2(false);
    int result(999);
    boost::mutex m;
    EXPECT_CALL(*rpcs, Prepare(testing::_, testing::_, testing::_))
        .WillOnce(testing::WithArgs<0, 1, 2>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::MockPrepare,
                      rpcs.get(), arg::_1, arg::_2, arg::_3))));

    RpcDeleteRefreshFunctor drf = std::bind(&MockRpcsTest::Callback, this,
                                            arg::_1, arg::_2, &b, &m, &result);
    rpcs->DeleteRefresh("", "", securifier_, peer_, drf);
    while (!b2) {
      Sleep(boost::posix_time::milliseconds(10));
      boost::mutex::scoped_lock lock(m);
      b2 = b;
    }
    switch (i) {
      case 0: {
        ASSERT_EQ(transport::kSuccess, result);
        result_type = 2;
        break;
      }
      case 1: {
        ASSERT_EQ(transport::kError, result);
        result_type = 1;
        repeat_factor = rpcs->kFailureTolerance();
        break;
      }
      case 2: {
        ASSERT_EQ(transport::kSuccess, result);
        repeat_factor = 0;
        break;
      }
      case 3: {
        ASSERT_EQ(transport::kError, result);
        repeat_factor = rpcs->kFailureTolerance() - 1;
        break;
      }
      case 4: {
        ASSERT_EQ(transport::kSuccess, result);
        break;
      }
      default:
        break;
    }
  }
}

TEST_F(MockRpcsTest, BEH_FindNodes) {
  uint16_t repeat_factor(1);
  int result_type(1);
  for (int i = 0; i < 5; ++i) {
    std::shared_ptr<MockRpcs<transport::TcpTransport>> rpcs(
        new MockRpcs<transport::TcpTransport>(asio_service_,
                                              securifier_,
                                              kFindNodesRequest,
                                              repeat_factor,
                                              result_type));
    bool b(false), b2(false);
    int result(999);
    boost::mutex m;
    EXPECT_CALL(*rpcs, Prepare(testing::_, testing::_, testing::_))
        .WillOnce(testing::WithArgs<0, 1, 2>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::MockPrepare,
                      rpcs.get(), arg::_1, arg::_2, arg::_3))));

    RpcFindNodesFunctor fnf = std::bind(&MockRpcsTest::FindNodesCallback, this,
                                        arg::_1, arg::_2, arg::_3, &b, &m,
                                        &result);

    rpcs->FindNodes(NodeId(NodeId::kRandomId), 1, securifier_, peer_, fnf);
    while (!b2) {
      Sleep(boost::posix_time::milliseconds(10));
      boost::mutex::scoped_lock lock(m);
      b2 = b;
    }
    switch (i) {
      case 0: {
        ASSERT_EQ(transport::kSuccess, result);
        result_type = 2;
        break;
      }
      case 1: {
        ASSERT_EQ(transport::kError, result);
        result_type = 1;
        repeat_factor = rpcs->kFailureTolerance();
        break;
      }
      case 2: {
        ASSERT_EQ(transport::kSuccess, result);
        repeat_factor = 0;
        break;
      }
      case 3: {
        ASSERT_EQ(transport::kError, result);
        repeat_factor = rpcs->kFailureTolerance() - 1;
        break;
      }
      case 4: {
        ASSERT_EQ(transport::kSuccess, result);
        break;
      }
      default:
        break;
    }
  }
}

TEST_F(MockRpcsTest, BEH_FindValue) {
  uint16_t repeat_factor(1);
  int result_type(1);
  for (int i = 0; i < 5; ++i) {
    std::shared_ptr<MockRpcs<transport::TcpTransport>> rpcs(
        new MockRpcs<transport::TcpTransport>(asio_service_,
                                              securifier_,
                                              kFindValueRequest,
                                              repeat_factor,
                                              result_type));
    bool b(false), b2(false);
    int result(999);
    boost::mutex m;
    EXPECT_CALL(*rpcs, Prepare(testing::_, testing::_, testing::_))
        .WillOnce(testing::WithArgs<0, 1, 2>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::MockPrepare,
                      rpcs.get(), arg::_1, arg::_2, arg::_3))));

    RpcFindValueFunctor fvf = std::bind(&MockRpcsTest::FindValueCallback, this,
                                        arg::_1, arg::_2, arg::_3, arg::_4,
                                        arg::_5, &b, &m, &result);

    rpcs->FindValue(NodeId(NodeId::kRandomId), 1, securifier_, peer_, fvf);
    while (!b2) {
      Sleep(boost::posix_time::milliseconds(10));
      boost::mutex::scoped_lock lock(m);
      b2 = b;
    }
    switch (i) {
      case 0: {
        EXPECT_EQ(kFoundAlternativeStoreHolder, result) << i;
        result_type = 2;
        break;
      }
      case 1: {
        EXPECT_EQ(transport::kError, result);
        result_type = 1;
        repeat_factor = rpcs->kFailureTolerance();
        break;
      }
      case 2: {
        EXPECT_EQ(kFoundAlternativeStoreHolder, result);
        repeat_factor = 0;
        break;
      }
      case 3: {
        EXPECT_EQ(transport::kError, result);
        repeat_factor = rpcs->kFailureTolerance() - 1;
        break;
      }
      case 4: {
        EXPECT_EQ(kFoundAlternativeStoreHolder, result);
        break;
      }
      default:
        break;
    }
  }
}

TEST_F(MockRpcsTest, BEH_Downlist) {
  boost::mutex m;
  std::vector<NodeId> node_ids;
  NodeId node_id(NodeId::kRandomId);
  node_ids.push_back(node_id);
  std::shared_ptr<MockRpcs<transport::TcpTransport>> rpcs(
      new MockRpcs<transport::TcpTransport>(asio_service_,
                                            securifier_,
                                            kDownlistNotification,
                                            2,
                                            1));

  EXPECT_CALL(*rpcs, Prepare(testing::_, testing::_, testing::_))
      .WillOnce(testing::WithArgs<0, 1, 2>(testing::Invoke(
          std::bind(&MockRpcs<transport::TcpTransport>::MockPrepare,
                    rpcs.get(), arg::_1, arg::_2, arg::_3))));

  rpcs->Downlist(node_ids, securifier_, peer_);
  while (!MockMessageHandler::ops_completion_flag) {
    Sleep(boost::posix_time::milliseconds(10));
  }
  MockMessageHandler::ops_completion_flag = false;
}

}   // namespace maidsafe

}   // namespace kademlia

}   // namespace dht

}   // namespace test
