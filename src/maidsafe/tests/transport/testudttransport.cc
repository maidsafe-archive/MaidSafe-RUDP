/* Copyright (c) 2010 maidsafe.net limited
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

#include <boost/asio/ip/address.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/signals2/signal.hpp>
#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread/thread.hpp>
#include <gtest/gtest.h>
#include <list>
#include <set>
#include <string>
#include "maidsafe/protobuf/transport_message.pb.h"
#include "maidsafe/protobuf/kademlia_service_messages.pb.h"
#include "maidsafe/tests/transport/messagehandler.h"
#include "maidsafe/tests/transport/udttestshelpers.h"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/transportsignals.h"
#include "maidsafe/transport/udtconnection.h"
#include "maidsafe/transport/udttransport.h"
#include "maidsafe/base/log.h"
#include "maidsafe/base/routingtable.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/udt/api.h"


namespace transport {

namespace test {

TransportMessage MakeDummyTransportMessage(bool is_request,
                                           const size_t &message_size) {
  TransportMessage transport_message;
  if (is_request)
    transport_message.set_type(TransportMessage::kRequest);
  else
    transport_message.set_type(TransportMessage::kResponse);
  rpcprotocol::RpcMessage *rpc_message =
      transport_message.mutable_data()->mutable_rpc_message();
  rpc_message->set_rpc_id(base::RandomUint32());
  rpc_message->set_method("Method");
  rpcprotocol::RpcMessage::Detail *payload = rpc_message->mutable_detail();
  kad::NatDetectionPingRequest *request = payload->MutableExtension(
      kad::NatDetectionPingRequest::nat_detection_ping_request);
  request->set_ping(base::RandomString(message_size));
  rpc_message->set_service("Service");
  return transport_message;
}

class UdtTransportTest: public testing::Test {
 protected:
  UdtTransportTest() : listening_node_(),
                       listening_message_handler_(listening_node_.signals(),
                                                  "Listening", false),
                       listening_port_(0),
                       loopback_ip_("127.0.0.1"),
                       sockets_for_closing_() {}
  void SetUp() {
    listening_port_ = listening_node_.StartListening("", 0, NULL);
    ASSERT_TRUE(ValidPort(listening_port_));
  }
  void TearDown() {
    std::for_each(sockets_for_closing_.begin(), sockets_for_closing_.end(),
                  boost::bind(&UDT::close, _1));
  }
  UdtTransport listening_node_;
  MessageHandler listening_message_handler_;
  Port listening_port_;
  IP loopback_ip_;
  std::vector<SocketId> sockets_for_closing_;
};


class UdtTransportVPTest: public testing::TestWithParam<size_t> {
 protected:
  UdtTransportVPTest() : listening_node_(),
                         listening_message_handler_(listening_node_.signals(),
                                                    "Listening", false),
                         listening_port_(0),
                         loopback_ip_("127.0.0.1"),
                         sockets_for_closing_() {}
  void SetUp() {
    listening_port_ = listening_node_.StartListening("", 0, NULL);
    ASSERT_TRUE(ValidPort(listening_port_));
  }
  void TearDown() {
    std::for_each(sockets_for_closing_.begin(), sockets_for_closing_.end(),
                  boost::bind(&UDT::close, _1));
  }
  UdtTransport listening_node_;
  MessageHandler listening_message_handler_;
  Port listening_port_;
  IP loopback_ip_;
  std::vector<SocketId> sockets_for_closing_;
};

TEST_P(UdtTransportVPTest, FUNC_TRANS_UdtSendMessagesFromManyToOne) {
  // Set up sending connections and message
  const size_t kTestMessageSize(GetParam());
  const boost::uint16_t kRepeats(kTestMessageSize > 256 * 1024 ? 5 : 50);
  std::vector<UdtConnection> send_connections;
  std::vector< boost::shared_ptr<MessageHandler> > send_message_handlers;
  for (boost::uint16_t i = 0; i < kRepeats; ++i) {
    UdtConnection udt_connection(loopback_ip_, listening_port_, "", 0);
    ASSERT_GT(udt_connection.socket_id(), 0);
    sockets_for_closing_.push_back(udt_connection.socket_id());
    send_connections.push_back(udt_connection);
    boost::shared_ptr<MessageHandler> message_handler(new MessageHandler(
        udt_connection.signals(), boost::lexical_cast<std::string>(i), false));
    send_message_handlers.push_back(message_handler);
  }
  TransportMessage request(MakeDummyTransportMessage(true, kTestMessageSize));
  const std::string kSentRpcRequest =
    request.data().rpc_message().SerializeAsString();

  // Send messages
  const int kTimeout(kTestMessageSize > 256 * 1024 ?
                     rpcprotocol::kRpcTimeout * 10 : rpcprotocol::kRpcTimeout);
  for (boost::uint16_t i = 0; i < kRepeats; ++i)
    send_connections.at(i).Send(request, kTimeout);
  int count(0);
  while (count < kTimeout * 2 &&
         listening_message_handler_.rpc_requests().size() < kRepeats) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }

  // Assess results and get receiving sockets' IDs
  boost::tuple<SocketId, TransportCondition> signalled_sent_result;
  size_t send_success_count(0);
  for (boost::uint16_t i = 0; i < kRepeats; ++i) {
    // TODO (dirvine)
    // ASSERT_EQ(1U, send_message_handlers.at(i)->sent_results().size());
    signalled_sent_result = send_message_handlers.at(i)->sent_results().back();
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    EXPECT_EQ(sockets_for_closing_.at(i), signalled_sent_result.get<0>());
    if (signalled_sent_result.get<1>() == kSuccess)
      ++send_success_count;
  }
  if (kTestMessageSize > 256 * 1024)
    ASSERT_LT(0, send_success_count);
  else
    ASSERT_EQ(kRepeats, send_success_count);
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(send_success_count,
            listening_message_handler_.rpc_requests().size());
  std::vector<SocketId> receiving_socket_ids;
  boost::tuple<rpcprotocol::RpcMessage, SocketId, float> signalled_rpc_message;
  MessageHandler::RpcMessageList copy_of_signalled_messages =
      listening_message_handler_.rpc_requests();
  for (boost::uint16_t i = 0; i < send_success_count; ++i) {
    signalled_rpc_message = copy_of_signalled_messages.front();
    copy_of_signalled_messages.pop_front();
    EXPECT_EQ(kSentRpcRequest,
              signalled_rpc_message.get<0>().SerializeAsString());
    receiving_socket_ids.push_back(signalled_rpc_message.get<1>());
  }

  // Send reply
  request.Clear();
  TransportMessage response(MakeDummyTransportMessage(false, kTestMessageSize));
  const std::string kSentRpcResponse =
      response.data().rpc_message().SerializeAsString();
  std::for_each(receiving_socket_ids.begin(), receiving_socket_ids.end(),
      boost::bind(&UdtTransport::Send, &listening_node_, response, _1, 0));
  count = 0;
  while (count < kTimeout * 5 &&
         listening_message_handler_.sent_results().size() < kRepeats) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }

  // Assess results
  ASSERT_EQ(send_success_count,
            listening_message_handler_.sent_results().size());
  MessageHandler::MessageResultList copy_of_signalled_results =
      listening_message_handler_.sent_results();
  size_t reply_success_count = 0;
  for (boost::uint16_t i = 0; i < send_success_count; ++i) {
    signalled_sent_result = copy_of_signalled_results.front();
    copy_of_signalled_results.pop_front();
    if (signalled_sent_result.get<1>() == kSuccess)
      ++reply_success_count;
    count = 0;
    while (count < kTimeout &&
           send_message_handlers.at(i)->rpc_responses().empty()) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      count += 10;
    }
    if (!send_message_handlers.at(i)->rpc_responses().empty()) {
      ASSERT_EQ(1U, send_message_handlers.at(i)->rpc_responses().size());
      signalled_rpc_message =
          send_message_handlers.at(i)->rpc_responses().back();
      EXPECT_EQ(kSentRpcResponse,
                signalled_rpc_message.get<0>().SerializeAsString());
    }
  }
  if (kTestMessageSize > 256 * 1024)
    ASSERT_LT(0, reply_success_count);
  else
    ASSERT_EQ(kRepeats, reply_success_count);
}

INSTANTIATE_TEST_CASE_P(VPTest, UdtTransportVPTest,
                        testing::Values(100, 1024 * 256,
                                        kMaxTransportMessageSize / 2));

TEST_F(UdtTransportTest, BEH_TRANS_UdtAddRemoveManagedEndpoints) {
  UdtTransport node1, node2, node3, node4, node5;
  MessageHandler message_handler1(node1.signals(), "Node 1", false);
  MessageHandler message_handler3(node3.signals(), "Node 3", false);
  node1.StartListening("", 0, NULL);
  Port node2_port = node2.StartListening("", 0, NULL);
  Port node3_port = node3.StartListening("", 0, NULL);
  Port node4_port = node4.StartListening("", 0, NULL);
  Port node5_port = node5.StartListening("", 0, NULL);
  ManagedEndpointId node1_end1 =
    node1.AddManagedEndpoint(loopback_ip_, node2_port, "", 0, "Node1", 0, 0, 0);
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(1, node1.managed_endpoint_sockets_.size());
  ManagedEndpointId node1_end2 =
    node1.AddManagedEndpoint(loopback_ip_, node3_port, "", 0, "Node1", 0, 0, 0);
  boost::this_thread::sleep(boost::posix_time::milliseconds(20));
  EXPECT_EQ(2, node1.managed_endpoint_sockets_.size());
  EXPECT_TRUE(node1.RemoveManagedEndpoint(node1_end2));
  const int kTimeout(10000);
  int count(0);
  while (count < kTimeout &&
         message_handler3.lost_managed_endpoint_ids().empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(size_t(1), message_handler3.lost_managed_endpoint_ids().size());
  EXPECT_EQ(1, node1.managed_endpoint_sockets_.size());
  node1_end2 =
    node1.AddManagedEndpoint(loopback_ip_, node3_port, "", 0, "Node1", 0, 0, 0);
  boost::this_thread::sleep(boost::posix_time::milliseconds(20));
  EXPECT_EQ(2, node1.managed_endpoint_sockets_.size());
  ManagedEndpointId node1_end3 =
    node1.AddManagedEndpoint(loopback_ip_, node4_port, "", 0, "Node1", 0, 0, 0);
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(3, node1.managed_endpoint_sockets_.size());
  ManagedEndpointId node1_end4 =
    node1.AddManagedEndpoint(loopback_ip_, node5_port, "", 0, "Node1", 0, 0, 0);
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_EQ(4, node1.managed_endpoint_sockets_.size());
  EXPECT_TRUE(SocketAlive(node1_end1));
  node1.StopManagedConnections();
  ASSERT_TRUE(node1.stop_managed_connections_);
  EXPECT_FALSE(SocketAlive(node1_end1));
  EXPECT_FALSE(SocketAlive(node1_end2));
  EXPECT_FALSE(SocketAlive(node1_end3));
  EXPECT_FALSE(SocketAlive(node1_end4));
  count = 0;
  while (count < kTimeout && !node1.managed_endpoint_sockets_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }
  EXPECT_EQ(0, node1.managed_endpoint_sockets_.size());
}

TEST_F(UdtTransportTest, FUNC_TRANS_UdtCrashManagedEndpoints) {
  // Setup managed connections between three nodes.
  boost::shared_ptr<UdtTransport> node1_ptr(new UdtTransport());
  UdtTransport node2, node3;
  MessageHandler message_handler2(node2.signals(), "Node 2", false);
  MessageHandler message_handler3(node3.signals(), "Node 3", false);
  Port node1_port = node1_ptr->StartListening("", 0, NULL);
  Port node2_port = node2.StartListening("", 0, NULL);
  Port node3_port = node3.StartListening("", 0, NULL);
  ManagedEndpointId node1_to_node2 = node1_ptr->AddManagedEndpoint(loopback_ip_,
      node2_port, "", 0, "Node1", 0, 0, 0);
  ASSERT_LT(0, node1_to_node2);
  ManagedEndpointId node2_to_node3 = node2.AddManagedEndpoint(loopback_ip_,
      node3_port, "", 0, "Node2", 0, 0, 0);
  ASSERT_LT(0, node2_to_node3);
  ManagedEndpointId node3_to_node1 = node3.AddManagedEndpoint(loopback_ip_,
      node1_port, "", 0, "Node3", 0, 0, 0);
  ASSERT_LT(0, node3_to_node1);

  // Stop Node 1's managed connections - Nodes 2 & 3 should each detect a lost
  // connection.
  node1_ptr->StopManagedConnections();
  const int kTimeout(kAddManagedConnectionTimeout);
  int count(0);
  while (count < kTimeout &&
         message_handler2.lost_managed_endpoint_ids().empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }
  EXPECT_EQ(size_t(1), message_handler2.lost_managed_endpoint_ids().size());
  count = 0;
  while (count < kTimeout &&
         message_handler3.lost_managed_endpoint_ids().empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }
  ASSERT_GE(message_handler3.lost_managed_endpoint_ids().size(), size_t(0));

  // Stop Node 2's managed connections - Node 3 should detect a lost connection.
  node2.StopManagedConnections();
  count = 0;
  while (count < kTimeout &&
         message_handler3.lost_managed_endpoint_ids().size() != size_t(2)) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }
  EXPECT_EQ(size_t(1), message_handler2.lost_managed_endpoint_ids().size());
  EXPECT_EQ(size_t(2), message_handler3.lost_managed_endpoint_ids().size());

  // Try to reconnect to Node 2 - should fail.
  node1_to_node2 = node1_ptr->AddManagedEndpoint(loopback_ip_, node2_port, "",
                                                 0, "Node1", 0, 0, 0);
  ASSERT_GE(0, node1_to_node2);

  // Re-enable managed connections on Node 2 & try to reconnect - should pass.
  node2.ReAllowIncomingManagedConnections();
  node1_to_node2 = node1_ptr->AddManagedEndpoint(loopback_ip_, node2_port, "",
                                                 0, "Node1", 0, 0, 0);
  ASSERT_LT(0, node1_to_node2);

  // Destroy Node 1 - Node 2 should detect a lost connection.
  // node1_ptr->StopManagedConnections();
  node1_ptr.reset();
  // Need to wait on the lost packets happening though (5 * 2 secs)
  boost::this_thread::sleep(boost::posix_time::seconds(11));
  count = 0;
  while (count < kTimeout &&
         message_handler2.lost_managed_endpoint_ids().size() != size_t(2)) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }
  EXPECT_EQ(size_t(2), message_handler2.lost_managed_endpoint_ids().size());
}

}  // namespace test

}  // namespace transport
