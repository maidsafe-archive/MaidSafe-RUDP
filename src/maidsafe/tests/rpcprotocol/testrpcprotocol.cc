/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

#include <gtest/gtest.h>
#include <google/protobuf/descriptor.h>
#include <algorithm>
#include "maidsafe/base/log.h"
#include "maidsafe/base/calllatertimer.h"
#include "maidsafe/maidsafe-dht.h"
#include "maidsafe/protobuf/rpcmessage.pb.h"
#include "maidsafe/rpcprotocol/channel-api.h"
#include "maidsafe/rpcprotocol/channelmanager-api.h"
#include "maidsafe/transport/transport-api.h"
#include "maidsafe/transport/transportudt.h"
#include "maidsafe/tests/rpcprotocol/testservices.pb.h"

class PingTestService : public tests::PingTest {
 public:
  void Ping(google::protobuf::RpcController *controller,
            const tests::PingRequest *request,
            tests::PingResponse *response,
            google::protobuf::Closure *done) {
    rpcprotocol::Controller *ctrler =
        static_cast<rpcprotocol::Controller*>(controller);
    if (request->IsInitialized()) {
      if (request->ping() == "ping") {
        response->set_result("S");
        response->set_pong("pong");
        LOG(INFO) << "Got ping request, returning response." << std::endl;
      } else {
        response->set_result("F");
        response->set_pong("");
      }
    }
    LOG(INFO) << "PingRpc request rtt " << ctrler->rtt() << std::endl;
    done->Run();
  }
};

class TestOpService : public tests::TestOp {
 public:
  void Add(google::protobuf::RpcController *controller,
           const tests::BinaryOpRequest *request,
           tests::BinaryOpResponse *response,
           google::protobuf::Closure *done) {
    if (request->IsInitialized())
      response->set_result(request->first() + request->second());
    rpcprotocol::Controller *ctrler =
        static_cast<rpcprotocol::Controller*>(controller);
    LOG(INFO) << "AddRpc request rtt " << ctrler->rtt() << std::endl;
    done->Run();
  }
  void Multiplyl(google::protobuf::RpcController *controller,
           const tests::BinaryOpRequest *request,
           tests::BinaryOpResponse *response,
           google::protobuf::Closure *done) {
    if (request->IsInitialized())
      response->set_result(request->first() * request->second());
    rpcprotocol::Controller *ctrler =
        static_cast<rpcprotocol::Controller*>(controller);
    LOG(INFO) << "MultiplyRpc request rtt " << ctrler->rtt() << std::endl;
    done->Run();
  }
};

class MirrorTestService : public tests::MirrorTest {
 public:
  void Mirror(google::protobuf::RpcController *controller,
              const tests::StringMirrorRequest *request,
              tests::StringMirrorResponse *response,
              google::protobuf::Closure *done) {
    if (request->IsInitialized()) {
      LOG(INFO) << "Before reversing the string" << std::endl;
      std::string message(request->message());
      std::reverse(message.begin(), message.end());
      response->set_mirrored_string(message);
      LOG(INFO) << "Done reversing the string" << std::endl;
    }
    rpcprotocol::Controller *ctrler =
        static_cast<rpcprotocol::Controller*>(controller);
    LOG(INFO) << "MirrorRpc request rtt " << ctrler->rtt() << std::endl;
    if (!request->has_not_pause() || !request->not_pause()) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(1500));
    }
    done->Run();
  }
};

class ResultHolder {
 public:
  ResultHolder() : ping_res(), op_res(), mirror_res() {
    ping_res.set_result("");
    op_res.set_result(-1);
    mirror_res.set_mirrored_string("-");
  }
  void GetPingRes(const tests::PingResponse *response,
      rpcprotocol::Controller *ctrl) {
    if (ctrl->Failed() && ctrl->ErrorText() == rpcprotocol::kCancelled) {
      LOG(INFO) << "Ping RPC canceled by the client" << std::endl;
      return;
    }
    LOG(INFO) << "Received result -- waiting for 1 second" << std::endl;
    boost::this_thread::sleep(boost::posix_time::seconds(1));
    if (response->IsInitialized()) {
      ping_res.set_result(response->result());
      ping_res.set_pong(response->pong());
    } else {
      ping_res.set_result("F");
    }
  }
  void GetOpResult(const tests::BinaryOpResponse *response,
      rpcprotocol::Controller *ctrl) {
    if (ctrl->Failed() && ctrl->ErrorText() == rpcprotocol::kCancelled) {
      LOG(INFO) << "BinaryOperation RPC canceled by the client" << std::endl;
      return;
    }
    if (response->IsInitialized()) {
      op_res.set_result(response->result());
    } else {
      op_res.set_result(-2);
    }
  }
  void GetMirrorResult(const tests::StringMirrorResponse *response,
      rpcprotocol::Controller *ctrl) {
    if (ctrl->Failed() && ctrl->ErrorText() == rpcprotocol::kCancelled) {
      LOG(INFO) << "Mirror RPC canceled by the client" << std::endl;
      return;
    }
    if (response->IsInitialized()) {
      if (response->has_mirrored_string())
        mirror_res.set_mirrored_string(response->mirrored_string());
      else
        mirror_res.set_mirrored_string("+");
    } else {
      mirror_res.set_mirrored_string("+");
    }
  }
  void Reset() {
    ping_res.Clear();
    ping_res.set_result("");
    op_res.Clear();
    op_res.set_result(-1);
    mirror_res.Clear();
    mirror_res.set_mirrored_string("-");
  }
  tests::PingResponse ping_res;
  tests::BinaryOpResponse op_res;
  tests::StringMirrorResponse mirror_res;
};

inline void HandleDeadServer(const bool &, const std::string &,
  const boost::uint16_t&) {}

class RpcProtocolTest : public testing::Test {
 protected:
  static void SetUpTestCase() {
    server_transport_handler = new transport::TransportHandler;
    server_udt_transport = new transport::TransportUDT;
    server_transport_handler->Register(server_udt_transport,
      &server_transport_id);
    server_chann_manager = new
      rpcprotocol::ChannelManager(server_transport_handler);
    client_transport_handler = new transport::TransportHandler;
    client_udt_transport = new transport::TransportUDT;
    client_transport_handler->Register(client_udt_transport,
      &client_transport_id);
    client_chann_manager = new
      rpcprotocol::ChannelManager(client_transport_handler);
  }
  static void TearDownTestCase() {
    delete client_chann_manager;
    delete server_chann_manager;
    transport::TransportUDT* trans_temp =
      static_cast<transport::TransportUDT*>(server_transport_handler->Get(0));
    trans_temp->CleanUp();
    delete server_transport_handler;
    delete client_transport_handler;
    delete client_udt_transport;
    delete server_udt_transport;
  }
  virtual void SetUp() {
    ASSERT_TRUE(server_chann_manager->RegisterNotifiersToTransport());
//     ASSERT_TRUE(server_transport_handler->RegisterOnServerDown(boost::bind(
//       &HandleDeadServer, _1, _2, _3)));
    ASSERT_EQ(0, server_transport_handler->Start(0, server_transport_id));
    server_transport_handler->StartPingRendezvous(true, "", 0,
      server_transport_id);
    ASSERT_TRUE(client_chann_manager->RegisterNotifiersToTransport());
//     ASSERT_TRUE(client_transport_handler->RegisterOnServerDown(boost::bind(
//       &HandleDeadServer, _1, _2, _3)));
    ASSERT_EQ(0, client_transport_handler->Start(0, client_transport_id));
    client_transport_handler->StartPingRendezvous(true, "", 0,
      client_transport_id);
    ASSERT_EQ(0, server_chann_manager->Start());
    ASSERT_EQ(0, client_chann_manager->Start());
  }
  virtual void TearDown() {
    client_transport_handler->StopAll();
    server_transport_handler->StopAll();
    client_chann_manager->Stop();
    server_chann_manager->Stop();
  }
  static rpcprotocol::ChannelManager *server_chann_manager,
      *client_chann_manager;
  static transport::TransportHandler *server_transport_handler,
    *client_transport_handler;
  static boost::int16_t server_transport_id, client_transport_id;
  static transport::Transport *client_udt_transport, *server_udt_transport;
};

rpcprotocol::ChannelManager* RpcProtocolTest::server_chann_manager = NULL;
rpcprotocol::ChannelManager* RpcProtocolTest::client_chann_manager = NULL;
transport::TransportHandler* RpcProtocolTest::server_transport_handler = NULL;
transport::TransportHandler* RpcProtocolTest::client_transport_handler = NULL;
boost::int16_t RpcProtocolTest::server_transport_id = 0;
boost::int16_t RpcProtocolTest::client_transport_id = 0;
transport::Transport* RpcProtocolTest::client_udt_transport = NULL;
transport::Transport* RpcProtocolTest::server_udt_transport = NULL;

TEST_F(RpcProtocolTest, BEH_RPC_RegisterAChannel) {
  PingTestService service;
  // creating a channel for the service
  rpcprotocol::Channel service_channel(server_chann_manager,
                                       server_transport_handler);
  service_channel.SetService(&service);
  server_chann_manager->RegisterChannel(service.GetDescriptor()->name(),
                                        &service_channel);
  // creating a channel for the client to send a request to the service
  rpcprotocol::Controller controller;
  controller.set_timeout(5);
  rpcprotocol::Channel out_channel(client_chann_manager,
      client_transport_handler, client_transport_id, "127.0.0.1",
      server_transport_handler->listening_port(server_transport_id), "", 0, "",
      0);
  tests::PingTest::Stub stubservice(&out_channel);
  tests::PingRequest req;
  tests::PingResponse resp;
  req.set_ping("ping");
  req.set_ip("127.0.0.1");
  req.set_port(client_transport_handler->listening_port(client_transport_id));
  ResultHolder resultholder;
  google::protobuf::Closure *done = google::protobuf::NewCallback<ResultHolder,
      const tests::PingResponse*, rpcprotocol::Controller*>(&resultholder,
      &ResultHolder::GetPingRes, &resp, &controller);
  stubservice.Ping(&controller, &req, &resp, done);
  while (resultholder.ping_res.result().empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));

  ASSERT_EQ("S", resultholder.ping_res.result());
  ASSERT_TRUE(resultholder.ping_res.has_pong());
  ASSERT_EQ("pong", resultholder.ping_res.pong());
  ASSERT_FALSE(controller.Failed());
  RpcProtocolTest::server_chann_manager->ClearCallLaters();
  RpcProtocolTest::client_chann_manager->ClearCallLaters();
}

TEST_F(RpcProtocolTest, FUNC_RPC_MultipleChannelsRegistered) {
  PingTestService service1;
  TestOpService service2;
  MirrorTestService service3;
  MirrorTestService service4;

  // creating a channel for the service
  rpcprotocol::Channel service_channel1(server_chann_manager,
                                        server_transport_handler);
  service_channel1.SetService(&service1);
  server_chann_manager->RegisterChannel(service1.GetDescriptor()->name(),
                                        &service_channel1);
  rpcprotocol::Channel service_channel2(server_chann_manager,
                                        server_transport_handler);
  service_channel2.SetService(&service2);
  server_chann_manager->RegisterChannel(service2.GetDescriptor()->name(),
                                        &service_channel2);
  rpcprotocol::Channel service_channel3(server_chann_manager,
                                        server_transport_handler);
  service_channel3.SetService(&service3);
  server_chann_manager->RegisterChannel(service3.GetDescriptor()->name(),
                                        &service_channel3);
  rpcprotocol::Channel service_channel4(server_chann_manager,
                                        server_transport_handler);
  service_channel4.SetService(&service4);
  server_chann_manager->RegisterChannel(service4.GetDescriptor()->name(),
                                        &service_channel4);

  // creating a channel for the client to send a request to the service
  rpcprotocol::Controller controller;
  controller.set_timeout(5);
  rpcprotocol::Channel out_channel(client_chann_manager,
      client_transport_handler, client_transport_id, "127.0.0.1",
      server_transport_handler->listening_port(server_transport_id), "", 0, "",
      0);
  tests::PingTest::Stub stubservice1(&out_channel);
  tests::PingRequest req1;
  tests::PingResponse resp1;
  req1.set_ping("ping");
  req1.set_ip("127.0.0.1");
  req1.set_port(client_transport_handler->listening_port(client_transport_id));
  ResultHolder resultholder;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<ResultHolder,
      const tests::PingResponse*, rpcprotocol::Controller*>(&resultholder,
      &ResultHolder::GetPingRes, &resp1, &controller);
  stubservice1.Ping(&controller, &req1, &resp1, done1);
  while (resultholder.ping_res.result().empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ("S", resultholder.ping_res.result());
  ASSERT_TRUE(resultholder.ping_res.has_pong());
  ASSERT_EQ("pong", resultholder.ping_res.pong());
  ASSERT_FALSE(controller.Failed());
  resultholder.Reset();
  controller.Reset();

  tests::TestOp::Stub stubservice2(&out_channel);
  tests::BinaryOpRequest req2;
  tests::BinaryOpResponse resp2;
  req2.set_first(3);
  req2.set_second(2);
  req2.set_ip("127.0.0.1");
  req2.set_port(client_transport_handler->listening_port(client_transport_id));
  rpcprotocol::Controller controller2;
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<ResultHolder,
      const tests::BinaryOpResponse*, rpcprotocol::Controller*>(&resultholder,
      &ResultHolder::GetOpResult, &resp2, &controller2);
  controller2.set_timeout(6);
  stubservice2.Add(&controller2, &req2, &resp2, done2);
  while (resultholder.op_res.result() == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(5, resultholder.op_res.result());
  ASSERT_FALSE(controller2.Failed());
  controller2.Reset();

  std::string test_string;
  test_string.reserve(5 * 1024 * 1024);
  std::string random_substring(base::RandomString(1024));
  for (int i = 0; i < 5 * 1024; ++i)
    test_string += random_substring;
  tests::MirrorTest::Stub stubservice3(&out_channel);
  tests::StringMirrorRequest req3;
  tests::StringMirrorResponse resp3;
  req3.set_message(test_string);
  req3.set_ip("127.0.0.1");
  req3.set_port(client_transport_handler->listening_port(client_transport_id));
  rpcprotocol::Controller controller3;
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<ResultHolder,
      const tests::StringMirrorResponse*, rpcprotocol::Controller*>(
      &resultholder, &ResultHolder::GetMirrorResult, &resp3, &controller3);
  controller3.set_timeout(1);
  stubservice3.Mirror(&controller3, &req3, &resp3, done3);
  while (resultholder.mirror_res.mirrored_string() == "-")
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  if ("+" != resultholder.mirror_res.mirrored_string()) {
    RpcProtocolTest::server_chann_manager->ClearCallLaters();
    RpcProtocolTest::client_chann_manager->ClearCallLaters();
    FAIL() << "Operation did not time out.";
  }
  ASSERT_TRUE(controller3.Failed());
  ASSERT_EQ(rpcprotocol::kTimeOut, controller3.ErrorText());
  resultholder.Reset();
  controller3.Reset();
  tests::MirrorTest::Stub stubservice4(&out_channel);
  tests::StringMirrorRequest req4;
  tests::StringMirrorResponse resp4;
  test_string.replace(test_string.size()-10, 10, "0123456789");
  req4.set_message(test_string);
  req4.set_ip("127.0.0.1");
  req4.set_port(client_transport_handler->listening_port(client_transport_id));
  rpcprotocol::Controller controller4;
  google::protobuf::Closure *done4 = google::protobuf::NewCallback<ResultHolder,
      const tests::StringMirrorResponse*, rpcprotocol::Controller*>(
      &resultholder, &ResultHolder::GetMirrorResult, &resp4, &controller4);
  controller4.set_timeout(70);
  stubservice4.Mirror(&controller4, &req4, &resp4, done4);

  while (resultholder.mirror_res.mirrored_string() == "-")
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  if ("+" == resultholder.mirror_res.mirrored_string()) {
    RpcProtocolTest::server_chann_manager->ClearCallLaters();
    RpcProtocolTest::client_chann_manager->ClearCallLaters();
    FAIL() << "Result of mirror RPC is incorrect.";
  }
  ASSERT_EQ("9876543210",
            resultholder.mirror_res.mirrored_string().substr(0, 10));
  ASSERT_FALSE(controller4.Failed());
  RpcProtocolTest::server_chann_manager->ClearCallLaters();
  RpcProtocolTest::client_chann_manager->ClearCallLaters();
}

TEST_F(RpcProtocolTest, BEH_RPC_ServerAndClientAtSameTime) {
  TestOpService service1;
  rpcprotocol::Channel service_channel1(server_chann_manager,
                                        server_transport_handler);
  service_channel1.SetService(&service1);
  server_chann_manager->RegisterChannel(service1.GetDescriptor()->name(),
                                        &service_channel1);
  TestOpService service2;
  rpcprotocol::Channel service_channel2(client_chann_manager,
                                        client_transport_handler);
  service_channel2.SetService(&service2);
  client_chann_manager->RegisterChannel(service2.GetDescriptor()->name(),
                                        &service_channel2);
  rpcprotocol::Controller controller1;
  controller1.set_timeout(5);
  rpcprotocol::Controller controller2;
  controller2.set_timeout(5);

  rpcprotocol::Channel out_channel1(server_chann_manager,
      server_transport_handler, server_transport_id, "127.0.0.1",
      client_transport_handler->listening_port(client_transport_id), "", 0, "",
      0);
  rpcprotocol::Channel out_channel2(client_chann_manager,
      client_transport_handler, client_transport_id, "127.0.0.1",
      server_transport_handler->listening_port(server_transport_id), "", 0, "",
      0);
  tests::TestOp::Stub stubservice1(&out_channel1);

  tests::BinaryOpRequest req1;
  tests::BinaryOpResponse resp1;
  req1.set_first(3);
  req1.set_second(2);
  req1.set_ip("127.0.0.1");
  req1.set_port(server_transport_handler->listening_port(server_transport_id));

  ResultHolder resultholder;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<ResultHolder,
      const tests::BinaryOpResponse*, rpcprotocol::Controller*>(&resultholder,
      &ResultHolder::GetOpResult, &resp1, &controller1);
  stubservice1.Add(&controller1, &req1, &resp1, done1);
  while (resultholder.op_res.result() == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(5, resultholder.op_res.result());
  ASSERT_FALSE(controller1.Failed());
  resultholder.Reset();

  tests::TestOp::Stub stubservice2(&out_channel2);
  tests::BinaryOpRequest req2;
  tests::BinaryOpResponse resp2;
  req2.set_first(4);
  req2.set_second(4);
  req2.set_ip("127.0.0.1");
  req2.set_port(client_transport_handler->listening_port(client_transport_id));
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<ResultHolder,
      const tests::BinaryOpResponse*, rpcprotocol::Controller*>(&resultholder,
      &ResultHolder::GetOpResult, &resp2, &controller2);
  stubservice2.Multiplyl(&controller2, &req2, &resp2, done2);
  while (resultholder.op_res.result() == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(16, resultholder.op_res.result());
  ASSERT_FALSE(controller2.Failed());
  RpcProtocolTest::server_chann_manager->ClearCallLaters();
  RpcProtocolTest::client_chann_manager->ClearCallLaters();
}

TEST_F(RpcProtocolTest, BEH_RPC_Timeout) {
  // creating a channel for the client to send a request to the service
  rpcprotocol::Controller controller;
  boost::uint32_t timeout = 3;
  controller.set_timeout(timeout);
  rpcprotocol::Channel out_channel(client_chann_manager,
      client_transport_handler, client_transport_id, "127.0.0.1",
      server_transport_handler->listening_port(server_transport_id) - 1, "", 0,
      "", 0);
  tests::PingTest::Stub stubservice(&out_channel);
  tests::PingRequest req;
  tests::PingResponse resp;
  req.set_ping("ping");
  req.set_ip("127.0.0.1");
  req.set_port(client_transport_handler->listening_port(client_transport_id));
  ResultHolder resultholder;
  google::protobuf::Closure *done = google::protobuf::NewCallback<ResultHolder,
      const tests::PingResponse*, rpcprotocol::Controller*>(&resultholder,
      &ResultHolder::GetPingRes, &resp, &controller);
  stubservice.Ping(&controller, &req, &resp, done);
  boost::this_thread::sleep(boost::posix_time::seconds(timeout + 1));
  ASSERT_EQ("F", resultholder.ping_res.result());
  ASSERT_FALSE(resultholder.ping_res.has_pong());
  ASSERT_TRUE(controller.Failed());
  ASSERT_EQ(rpcprotocol::kTimeOut, controller.ErrorText());
  RpcProtocolTest::server_chann_manager->ClearCallLaters();
  RpcProtocolTest::client_chann_manager->ClearCallLaters();
}

TEST_F(RpcProtocolTest, FUNC_RPC_DeletePendingRequest) {
  MirrorTestService mirrorservice;
  rpcprotocol::Channel service_channel(server_chann_manager,
                                       server_transport_handler);
  service_channel.SetService(&mirrorservice);
  server_chann_manager->RegisterChannel(mirrorservice.GetDescriptor()->name(),
                                        &service_channel);
  // Sending rpc to an existing server, but deleting it before response arrives
  rpcprotocol::Controller controller;
  controller.set_timeout(10);
  rpcprotocol::Channel out_channel1(client_chann_manager,
      client_transport_handler, client_transport_id, "127.0.0.1",
      server_transport_handler->listening_port(server_transport_id), "", 0, "",
      0);
  std::string test_string(base::RandomString(500 * 1024));
  tests::MirrorTest::Stub stubservice1(&out_channel1);
  tests::StringMirrorRequest req1, req2;
  tests::StringMirrorResponse resp1, resp2;
  req1.set_message(test_string);
  req1.set_ip("127.0.0.1");
  req1.set_port(client_transport_handler->listening_port(client_transport_id));
  ResultHolder resultholder;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<ResultHolder,
      const tests::StringMirrorResponse*, rpcprotocol::Controller*>(
      &resultholder, &ResultHolder::GetMirrorResult, &resp1, &controller);
  stubservice1.Mirror(&controller, &req1, &resp1, done1);
  ASSERT_TRUE(client_chann_manager->DeletePendingRequest(
      controller.rpc_id()));
  boost::this_thread::sleep(boost::posix_time::seconds(11));
  ASSERT_EQ(std::string("-"), resultholder.mirror_res.mirrored_string());
  ASSERT_EQ(rpcprotocol::kCancelled, controller.ErrorText());
  controller.Reset();
  ASSERT_TRUE(controller.ErrorText().empty());

  // Sending a request to a non-existent server and deleting before it
  // times out
  controller.set_timeout(3);
  rpcprotocol::Channel out_channel2(client_chann_manager,
      client_transport_handler, client_transport_id, "2.2.2.1", 5555, "", 0, "",
      0);
  req2.set_message(test_string);
  req2.set_ip("2.2.2.1");
  req2.set_port(5555);
  tests::MirrorTest::Stub stubservice2(&out_channel2);
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<ResultHolder,
      const tests::StringMirrorResponse*, rpcprotocol::Controller*>(
      &resultholder, &ResultHolder::GetMirrorResult, &resp2, &controller);
  stubservice2.Mirror(&controller, &req2, &resp2, done2);
  ASSERT_TRUE(client_chann_manager->DeletePendingRequest(
              controller.rpc_id()));
  boost::this_thread::sleep(boost::posix_time::seconds(4));
  ASSERT_EQ(std::string("-"), resultholder.mirror_res.mirrored_string());
  ASSERT_EQ(rpcprotocol::kCancelled, controller.ErrorText());
  ASSERT_FALSE(client_chann_manager->DeletePendingRequest(1));
}

TEST_F(RpcProtocolTest, BEH_RPC_CancelPendingRequest) {
  MirrorTestService mirrorservice;
  rpcprotocol::Channel service_channel(server_chann_manager,
    server_transport_handler);
  service_channel.SetService(&mirrorservice);
  server_chann_manager->RegisterChannel(mirrorservice.GetDescriptor()->name(),
      &service_channel);
  // Sending rpc to an existing server, but cancelin it before response arrives
  rpcprotocol::Controller controller;
  controller.set_timeout(10);
  rpcprotocol::Channel out_channel1(client_chann_manager,
    client_transport_handler, client_transport_id, "127.0.0.1",
    server_transport_handler->listening_port(server_transport_id), "", 0, "",
    0);
  std::string test_string(base::RandomString(500 * 1024));
  tests::MirrorTest::Stub stubservice1(&out_channel1);
  tests::StringMirrorRequest req1, req2;
  tests::StringMirrorResponse resp1, resp2;
  req1.set_message(test_string);
  req1.set_ip("127.0.0.1");
  req1.set_port(client_transport_handler->listening_port(client_transport_id));
  ResultHolder resultholder;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<ResultHolder,
      const tests::StringMirrorResponse*, rpcprotocol::Controller*>(
      &resultholder, &ResultHolder::GetMirrorResult, &resp1, &controller);
  stubservice1.Mirror(&controller, &req1, &resp1, done1);
  ASSERT_TRUE(client_chann_manager->CancelPendingRequest(
              controller.rpc_id()));
  ASSERT_FALSE(client_chann_manager->CancelPendingRequest(
               controller.rpc_id()));
//  boost::this_thread::sleep(boost::posix_time::milliseconds(100));
//  ASSERT_EQ(std::string("-"), resultholder.mirror_res.mirrored_string());
//  ASSERT_EQ(rpcprotocol::kCancelled, controller.ErrorText());
  controller.Reset();
  ASSERT_EQ(std::string(""), controller.ErrorText());

  // Sending a request to a non-existent server and cancelling before it
  // times out
  boost::shared_ptr<rpcprotocol::Controller>
      p_controller(new rpcprotocol::Controller);
  p_controller->set_timeout(11);
  rpcprotocol::Channel out_channel2(client_chann_manager,
    client_transport_handler, client_transport_id, "2.2.2.1", 5555, "", 0, "",
    0);
  req2.set_message(test_string);
  req2.set_ip("2.2.2.1");
  req2.set_port(5555);
  tests::MirrorTest::Stub stubservice2(&out_channel2);
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<ResultHolder,
      const tests::StringMirrorResponse*, rpcprotocol::Controller*>(
      &resultholder, &ResultHolder::GetMirrorResult, &resp2,
      p_controller.get());
  stubservice2.Mirror(&controller, &req2, &resp2, done2);
  ASSERT_TRUE(client_chann_manager->CancelPendingRequest(
              controller.rpc_id()));
  ASSERT_FALSE(client_chann_manager->CancelPendingRequest(
               controller.rpc_id()));
}

TEST_F(RpcProtocolTest, BEH_RPC_ResetTimeout) {
  MirrorTestService service;
  // creating a channel for the service
  rpcprotocol::Channel service_channel(server_chann_manager,
                                       server_transport_handler);
  service_channel.SetService(&service);
  server_chann_manager->RegisterChannel(service.GetDescriptor()->name(),
                                        &service_channel);
  // creating a channel for the client to send a request to the service
  rpcprotocol::Controller controller;
  controller.set_timeout(20);
  rpcprotocol::Channel out_channel(client_chann_manager,
      client_transport_handler, client_transport_id, "127.0.0.1",
      server_transport_handler->listening_port(server_transport_id), "", 0, "",
      0);
  tests::MirrorTest::Stub stubservice(&out_channel);
  tests::StringMirrorRequest req;
  tests::StringMirrorResponse resp;
  req.set_message(base::RandomString(1024 * 1024));
  req.set_ip("127.0.0.1");
  req.set_port(client_transport_handler->listening_port(client_transport_id));
  req.set_not_pause(true);
  ResultHolder resultholder;
  google::protobuf::Closure *done = google::protobuf::NewCallback<ResultHolder,
      const tests::StringMirrorResponse*, rpcprotocol::Controller*>(
      &resultholder, &ResultHolder::GetMirrorResult, &resp, &controller);
  stubservice.Mirror(&controller, &req, &resp, done);
  while (resultholder.mirror_res.mirrored_string() == "-")
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  if ("+" == resultholder.mirror_res.mirrored_string()) {
    RpcProtocolTest::server_chann_manager->ClearCallLaters();
    RpcProtocolTest::client_chann_manager->ClearCallLaters();
    FAIL() << "Result of mirror RPC is incorrect.";
  }
  ASSERT_FALSE(controller.Failed());
  RpcProtocolTest::server_chann_manager->ClearCallLaters();
  RpcProtocolTest::client_chann_manager->ClearCallLaters();
}

TEST_F(RpcProtocolTest, FUNC_RPC_ChannelManagerLocalTransport) {
  transport::TransportHandler local_transport_handler;
  transport::TransportUDT local_udt_transport;
  boost::int16_t local_transport_id;
  local_transport_handler.Register(&local_udt_transport, &local_transport_id);
  rpcprotocol::ChannelManager chman(&local_transport_handler);
  ASSERT_TRUE(chman.RegisterNotifiersToTransport());
  std::string local_ip;
  std::string loop_back("127.0.0.1");
  boost::asio::ip::address local_address;
  if (base::GetLocalAddress(&local_address)) {
    local_ip = local_address.to_string();
  } else {
    FAIL() << "Can not get local address.";
  }
  ASSERT_NE(loop_back, local_ip);
  ASSERT_EQ(1, chman.Start());
  ASSERT_EQ(0, local_transport_handler.StartLocal(0, local_transport_id));
  ASSERT_EQ(0, chman.Start());
  PingTestService service;
  // creating a channel for the service
  rpcprotocol::Channel service_channel(&chman, &local_transport_handler);
  service_channel.SetService(&service);
  chman.RegisterChannel(service.GetDescriptor()->name(), &service_channel);
  // creating a channel for the client to send a request to the service
  rpcprotocol::Controller controller;
  controller.set_timeout(5);
  rpcprotocol::Channel out_channel1(client_chann_manager,
      client_transport_handler, client_transport_id, loop_back,
      local_transport_handler.listening_port(local_transport_id), "", 0, "", 0);
  tests::PingTest::Stub stubservice1(&out_channel1);
  tests::PingRequest req;
  tests::PingResponse resp1;
  req.set_ping("ping");
  req.set_ip("127.0.0.1");
  req.set_port(local_transport_handler.listening_port(local_transport_id));
  ResultHolder resultholder;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<ResultHolder,
      const tests::PingResponse*, rpcprotocol::Controller*>(&resultholder,
      &ResultHolder::GetPingRes, &resp1, &controller);
  stubservice1.Ping(&controller, &req, &resp1, done1);
  while (resultholder.ping_res.result().empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));

  ASSERT_EQ("S", resultholder.ping_res.result());
  ASSERT_TRUE(resultholder.ping_res.has_pong());
  ASSERT_EQ("pong", resultholder.ping_res.pong());
  ASSERT_FALSE(controller.Failed());
  controller.Reset();
  resultholder.Reset();

  controller.set_timeout(5);
  rpcprotocol::Channel out_channel2(client_chann_manager,
      client_transport_handler, client_transport_id, local_ip,
      local_transport_handler.listening_port(local_transport_id), "", 0, "", 0);
  tests::PingTest::Stub stubservice2(&out_channel2);
  tests::PingResponse resp2;
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<ResultHolder,
      const tests::PingResponse*, rpcprotocol::Controller*>(&resultholder,
      &ResultHolder::GetPingRes, &resp2, &controller);
  stubservice2.Ping(&controller, &req, &resp2, done2);
  while (resultholder.ping_res.result().empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ("F", resultholder.ping_res.result());
  ASSERT_FALSE(resultholder.ping_res.has_pong());
  ASSERT_TRUE(controller.Failed());
  ASSERT_EQ(rpcprotocol::kTimeOut, controller.ErrorText());

  local_transport_handler.Stop(local_transport_id);
  chman.Stop();
  RpcProtocolTest::server_chann_manager->ClearCallLaters();
  RpcProtocolTest::client_chann_manager->ClearCallLaters();
}

TEST_F(RpcProtocolTest, FUNC_RPC_RestartLocalTransport) {
  transport::TransportHandler local_transport_handler;
  boost::int16_t local_transport_id;
  local_transport_handler.Register(new transport::TransportUDT,
                                   &local_transport_id);
  rpcprotocol::ChannelManager chman(&local_transport_handler);
  ASSERT_EQ(1, chman.Start());
  ASSERT_TRUE(chman.RegisterNotifiersToTransport());
  std::string local_ip;
  std::string loop_back("127.0.0.1");
  boost::asio::ip::address local_address;
  if (base::GetLocalAddress(&local_address)) {
    local_ip = local_address.to_string();
  } else {
    FAIL() << "Can not get local address.";
  }
  ASSERT_NE(loop_back, local_ip);
  ASSERT_EQ(1, chman.Start());
  ASSERT_EQ(0, local_transport_handler.StartLocal(0, local_transport_id));
  ASSERT_FALSE(chman.RegisterNotifiersToTransport());
  ASSERT_EQ(0, chman.Start());
  ASSERT_TRUE(chman.RegisterNotifiersToTransport());
  PingTestService service;
  // creating a channel for the service
  rpcprotocol::Channel service_channel(&chman, &local_transport_handler);
  service_channel.SetService(&service);
  chman.RegisterChannel(service.GetDescriptor()->name(), &service_channel);
  // creating a channel for the client to send a request to the service
  rpcprotocol::Controller controller;
  controller.set_timeout(5);
  rpcprotocol::Channel out_channel1(client_chann_manager,
      client_transport_handler, client_transport_id, loop_back,
      local_transport_handler.listening_port(local_transport_id), "", 0, "", 0);
  tests::PingTest::Stub stubservice1(&out_channel1);
  tests::PingRequest req;
  tests::PingResponse resp1;
  req.set_ping("ping");
  req.set_ip("127.0.0.1");
  req.set_port(local_transport_handler.listening_port(local_transport_id));
  ResultHolder resultholder;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<ResultHolder,
      const tests::PingResponse*, rpcprotocol::Controller*>(&resultholder,
      &ResultHolder::GetPingRes, &resp1, &controller);
  stubservice1.Ping(&controller, &req, &resp1, done1);
  while (resultholder.ping_res.result().empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));

  ASSERT_EQ("S", resultholder.ping_res.result());
  ASSERT_TRUE(resultholder.ping_res.has_pong());
  ASSERT_EQ("pong", resultholder.ping_res.pong());
  ASSERT_FALSE(controller.Failed());
  controller.Reset();
  resultholder.Reset();

  controller.set_timeout(5);
  rpcprotocol::Channel out_channel2(client_chann_manager,
      client_transport_handler, client_transport_id, local_ip,
      local_transport_handler.listening_port(local_transport_id), "", 0, "", 0);
  tests::PingTest::Stub stubservice2(&out_channel2);
  tests::PingResponse resp2;
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<ResultHolder,
      const tests::PingResponse*, rpcprotocol::Controller*>(&resultholder,
      &ResultHolder::GetPingRes, &resp2, &controller);
  stubservice2.Ping(&controller, &req, &resp2, done2);
  while (resultholder.ping_res.result().empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ("F", resultholder.ping_res.result());
  ASSERT_FALSE(resultholder.ping_res.has_pong());
  ASSERT_TRUE(controller.Failed());
  ASSERT_EQ(rpcprotocol::kTimeOut, controller.ErrorText());

  local_transport_handler.Stop(local_transport_id);
  chman.Stop();
  // starting transport
  ASSERT_TRUE(chman.RegisterNotifiersToTransport());
  chman.RegisterChannel(service.GetDescriptor()->name(), &service_channel);
//   ASSERT_TRUE(local_transport_handler.RegisterOnServerDown(boost::bind(
//       &HandleDeadServer, _1, _2, _3)));
  ASSERT_EQ(0, local_transport_handler.Start(0, local_transport_id));
  ASSERT_EQ(0, chman.Start());
  local_transport_handler.StartPingRendezvous(true, "", 0, local_transport_id);
  controller.Reset();
  resultholder.Reset();
  controller.set_timeout(5);
  rpcprotocol::Channel out_channel3(client_chann_manager,
      client_transport_handler, client_transport_id, loop_back,
      local_transport_handler.listening_port(local_transport_id), "", 0, "", 0);
  tests::PingTest::Stub stubservice3(&out_channel3);
  tests::PingResponse resp3;
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<ResultHolder,
      const tests::PingResponse*, rpcprotocol::Controller*>(&resultholder,
      &ResultHolder::GetPingRes, &resp3, &controller);
  stubservice3.Ping(&controller, &req, &resp3, done3);
  while (resultholder.ping_res.result().empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));

  ASSERT_EQ("S", resultholder.ping_res.result());
  ASSERT_TRUE(resultholder.ping_res.has_pong());
  ASSERT_EQ("pong", resultholder.ping_res.pong());
  ASSERT_FALSE(controller.Failed());
  controller.Reset();
  resultholder.Reset();

  controller.set_timeout(5);
  rpcprotocol::Channel out_channel4(client_chann_manager,
      client_transport_handler, client_transport_id, local_ip,
      local_transport_handler.listening_port(local_transport_id), "", 0, "", 0);
  tests::PingTest::Stub stubservice4(&out_channel4);
  tests::PingResponse resp4;
  google::protobuf::Closure *done4 = google::protobuf::NewCallback<ResultHolder,
      const tests::PingResponse*, rpcprotocol::Controller*>(&resultholder,
      &ResultHolder::GetPingRes, &resp4, &controller);
  stubservice4.Ping(&controller, &req, &resp4, done4);
  while (resultholder.ping_res.result().empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ("S", resultholder.ping_res.result());
  ASSERT_TRUE(resultholder.ping_res.has_pong());
  ASSERT_EQ("pong", resultholder.ping_res.pong());
  ASSERT_FALSE(controller.Failed());

  RpcProtocolTest::server_chann_manager->ClearCallLaters();
  RpcProtocolTest::client_chann_manager->ClearCallLaters();
}

TEST(RpcControllerTest, BEH_RPC_RpcController) {
  rpcprotocol::Controller controller;
  ASSERT_FALSE(controller.Failed());
  ASSERT_TRUE(controller.ErrorText().empty());
  ASSERT_EQ(0, controller.rpc_id());
  controller.SetFailed(rpcprotocol::kTimeOut);
  RpcId id = 1234;
  controller.set_rpc_id(id);
  ASSERT_EQ(id, controller.rpc_id());
  ASSERT_TRUE(controller.Failed());
  ASSERT_EQ(rpcprotocol::kTimeOut, controller.ErrorText());
  controller.StartCancel();
  ASSERT_FALSE(controller.IsCanceled());
  controller.Reset();
  ASSERT_FALSE(controller.Failed());
  ASSERT_TRUE(controller.ErrorText().empty());
  ASSERT_EQ(0, controller.rpc_id());
  ASSERT_EQ(0, controller.Duration());
  controller.StartRpcTimer();
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  controller.StopRpcTimer();
  ASSERT_LE(10, controller.Duration());
  ASSERT_TRUE(controller.method().empty());
  controller.set_method("abc");
  ASSERT_EQ("abc", controller.method());
}
