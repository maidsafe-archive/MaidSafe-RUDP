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
#include <boost/progress.hpp>
#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread/thread.hpp>
#include <gtest/gtest.h>
#include <list>
#include <set>
#include <string>
#include "maidsafe/protobuf/transport_message.pb.h"
#include "maidsafe/protobuf/kademlia_service_messages.pb.h"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/transportsignals.h"
#include "maidsafe/transport/transportudt.h"
#include "maidsafe/base/log.h"
#include "maidsafe/base/routingtable.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/udt/api.h"
#include "maidsafe/base/network_interface.h"


namespace transport {

namespace test {

class TransportNode {
 public:
  TransportNode(TransportUDT *transport)
      : transport_(transport),
        successful_conn_(0),
        refused_conn_(0) {}
  TransportUDT *transportUDT() { return transport_; }
  int successful_conn() { return successful_conn_; }
  int refused_conn() { return refused_conn_; }
  void IncreaseSuccessfulConn() { ++successful_conn_; }
  void IncreaseRefusedConn() { ++refused_conn_; }
 private:
  TransportUDT *transport_;
  int successful_conn_, refused_conn_;

};


class MessageHandler {
 public:
  MessageHandler(TransportUDT *transport, bool display_stats)
      : messages_(),
        raw_messages_(),
        target_message_(),
        ids_(),
        raw_ids_(),
        managed_endpoint_ids_(),
        lost_managed_endpoint_ids_(),
        transport_(transport),
        messages_sent_(0),
        messages_received_(0),
        messages_confirmed_(0),
        messages_unsent_(0),
        keep_messages_(true),
        rpc_request_(),
        rpc_response_(),
        send_(),
        message_connection_(),
        managed_endpoint_received_connection_(),
        managed_endpoint_lost_connection_(),
        stats_connection_() {
    rpc_request_ = transport->signals().ConnectOnRpcRequestReceived(
        boost::bind(&MessageHandler::OnRPCMessage, this, _1, _2));
    rpc_response_ = transport->signals().ConnectOnRpcResponseReceived(
        boost::bind(&MessageHandler::OnRPCMessage, this, _1, _2));
    send_ = transport->signals().ConnectOnSend(
        boost::bind(&MessageHandler::OnSend, this, _1, _2));
    message_connection_ = transport->signals().ConnectOnMessageReceived(
        boost::bind(&MessageHandler::OnMessage, this, _1, _2, _3));
    managed_endpoint_received_connection_ =
        transport->signals().ConnectOnManagedEndpointReceived(boost::bind(
            &MessageHandler::OnManagedEndpointReceived, this, _1, _2));
    managed_endpoint_lost_connection_ =
        transport->signals().ConnectOnManagedEndpointLost(
            boost::bind(&MessageHandler::OnManagedEndpointLost, this, _1));
    if (display_stats) {
      stats_connection_ = transport->signals().ConnectOnStats(
          boost::bind(&MessageHandler::OnStats, this, _1));
    }
  }
  ~MessageHandler() {
    rpc_request_.disconnect();
    rpc_response_.disconnect();
    send_.disconnect();
    message_connection_.disconnect();
    managed_endpoint_lost_connection_.disconnect();
    stats_connection_.disconnect();
  }
  void OnRPCMessage(const rpcprotocol::RpcMessage &rpc_message,
                    const SocketId &socket_id) {
    std::string message;
    rpc_message.SerializeToString(&message);
    ++messages_received_;
    if (!target_message_.empty() && message == target_message_)
      ++messages_confirmed_;
    if (keep_messages_) {
      messages_.push_back(message);
      ids_.push_back(socket_id);
    }

  }
  void OnMessage(const std::string &message,
                 const SocketId &socket_id,
                 const float&) {
    raw_messages_.push_back(message);
    raw_ids_.push_back(socket_id);
  }
  void OnManagedEndpointReceived(const ManagedEndpointId &managed_endpoint_id,
                                 const ManagedEndpointMessage &message) {
std::cout << "CATCHING OnManagedEndpointReceived" << std::endl;
    managed_endpoint_ids_.insert(managed_endpoint_id);
  }
  void OnManagedEndpointLost(const ManagedEndpointId &managed_endpoint_id) {
std::cout << "CATCHING OnManagedEndpointLost" << std::endl;
    managed_endpoint_ids_.erase(managed_endpoint_id);
    lost_managed_endpoint_ids_.insert(managed_endpoint_id);
  }
  void OnSend(const SocketId &socket_id,
              const TransportCondition &result) {
  if (result == kSuccess)
      ++messages_sent_;
    else
      ++messages_unsent_;
  }
  void OnStats(boost::shared_ptr<SocketPerformanceStats> stats) {
    boost::shared_ptr<UdtStats> udt_stats =
        boost::static_pointer_cast<UdtStats>(stats);
    if (udt_stats->udt_socket_type_ == UdtStats::kSend) {
      DLOG(INFO) << "\tSocket ID:         " << udt_stats->udt_socket_id_ <<
          std::endl;
      DLOG(INFO) << "\tRTT:               " <<
          udt_stats->performance_monitor_.msRTT << " ms" << std::endl;
      DLOG(INFO) << "\tBandwidth:         " <<
          udt_stats->performance_monitor_.mbpsBandwidth << " Mbps" << std::endl;
      DLOG(INFO) << "\tTime elapsed:      " <<
          udt_stats->performance_monitor_.msTimeStamp << " ms" << std::endl;
      DLOG(INFO) << "\tSent:              " <<
          udt_stats->performance_monitor_.pktSentTotal << " packets" << std::endl;
      DLOG(INFO) << "\tLost:              " <<
          udt_stats->performance_monitor_.pktSndLoss << " packets" << std::endl;
      DLOG(INFO) << "\tRetransmitted:     " <<
          udt_stats->performance_monitor_.pktRetrans << " packets" << std::endl;
      DLOG(INFO) << "\tACKs received:     " <<
          udt_stats->performance_monitor_.pktRecvACK << " packets" << std::endl;
      DLOG(INFO) << "\tNACKs received:    " <<
          udt_stats->performance_monitor_.pktRecvNAK << " packets" << std::endl;
      DLOG(INFO) << "\tSend rate:         " <<
          udt_stats->performance_monitor_.mbpsSendRate << " Mbps" << std::endl;
      DLOG(INFO) << "\tBusy send time:    " <<
          udt_stats->performance_monitor_.usSndDuration << " us" << std::endl;
      DLOG(INFO) << "\tSend period:       " <<
          udt_stats->performance_monitor_.usPktSndPeriod << " us" << std::endl;
      DLOG(INFO) << "\tFlow window:       " <<
          udt_stats->performance_monitor_.pktFlowWindow << " packets" <<
          std::endl;
      DLOG(INFO) << "\tCongestion window: " <<
          udt_stats->performance_monitor_.pktCongestionWindow << " packets" <<
          std::endl;
      DLOG(INFO) << "\tAvail send buffer: " <<
          udt_stats->performance_monitor_.byteAvailSndBuf << " bytes" <<
          std::endl;
      DLOG(INFO) << "\tAvail recv buffer: " <<
          udt_stats->performance_monitor_.byteAvailRcvBuf << " bytes" <<
          std::endl;
    } else {
      DLOG(INFO) << "\t\tSocket ID:         " << udt_stats->udt_socket_id_ <<
          std::endl;
      DLOG(INFO) << "\t\tRTT:               " <<
          udt_stats->performance_monitor_.msRTT << " ms" << std::endl;
      DLOG(INFO) << "\t\tBandwidth:         " <<
          udt_stats->performance_monitor_.mbpsBandwidth << " Mbps" << std::endl;
      DLOG(INFO) << "\t\tTime elapsed:      " <<
          udt_stats->performance_monitor_.msTimeStamp << " ms" << std::endl;
      DLOG(INFO) << "\t\tReceived:          " <<
          udt_stats->performance_monitor_.pktRecv << " packets" << std::endl;
      DLOG(INFO) << "\t\tLost:              " <<
          udt_stats->performance_monitor_.pktRcvLoss << " packets" << std::endl;
      DLOG(INFO) << "\t\tACKs sent:         " <<
          udt_stats->performance_monitor_.pktSentACK << " packets" << std::endl;
      DLOG(INFO) << "\t\tNACKs sent:        " <<
          udt_stats->performance_monitor_.pktSentNAK << " packets" << std::endl;
      DLOG(INFO) << "\t\tReceive rate:      " <<
          udt_stats->performance_monitor_.mbpsRecvRate << " Mbps" << std::endl;
      DLOG(INFO) << "\t\tFlow window:       " <<
          udt_stats->performance_monitor_.pktFlowWindow << " packets" <<
          std::endl;
      DLOG(INFO) << "\t\tCongestion window: " <<
          udt_stats->performance_monitor_.pktCongestionWindow << " packets" <<
          std::endl;
      DLOG(INFO) << "\t\tAvail send buffer: " <<
          udt_stats->performance_monitor_.byteAvailSndBuf << " bytes" <<
          std::endl;
      DLOG(INFO) << "\t\tAvail recv buffer: " <<
          udt_stats->performance_monitor_.byteAvailRcvBuf << " bytes" <<
          std::endl;
    }
  }
  std::list<std::string> messages_, raw_messages_;
  std::string target_message_;
  std::list<SocketId> ids_, raw_ids_;
  std::set<ManagedEndpointId> managed_endpoint_ids_;
  std::set<ManagedEndpointId> lost_managed_endpoint_ids_;
  TransportUDT *transport_;
  int messages_sent_, messages_received_, messages_confirmed_, messages_unsent_;
  bool keep_messages_;
 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);
  bs2::connection rpc_request_, rpc_response_;
  bs2::connection send_;
  bs2::connection message_connection_;
  bs2::connection managed_endpoint_received_connection_;
  bs2::connection managed_endpoint_lost_connection_;
  bs2::connection stats_connection_;
};

bool CheckSocketAlive(const UdtSocketId &udt_socket_id) {
  int result;
  std::vector<UdtSocketId> socket_to_check(1, udt_socket_id);
  std::vector<UdtSocketId> sockets_bad;
  return (UDT::selectEx(socket_to_check, NULL, NULL, &sockets_bad, 1000) == 0);
}



class TransportUdtTest: public testing::Test {
 protected:
  virtual ~TransportUdtTest() {
  //  UDT::cleanup();
  }
};


TEST_F(TransportUdtTest, BEH_TRANS_MultipleListeningPorts) {
  boost::uint16_t num_listening_ports = 12;
  TransportUDT node;
  MessageHandler message_handler1(&node, false);
  Port lp_node[100];
  TransportMessage transport_message;
  transport_message.set_type(TransportMessage::kRequest);
  rpcprotocol::RpcMessage *rpc_message =
      transport_message.mutable_data()->mutable_rpc_message();
  rpc_message->set_rpc_id(2000);
  rpc_message->set_method("Test");
  rpcprotocol::RpcMessage::Detail *payload = rpc_message->mutable_detail();
  kad::NatDetectionPingRequest *request = payload->MutableExtension(
      kad::NatDetectionPingRequest::nat_detection_ping_request);
  const std::string args = base::RandomString(256 * 1024);
  request->set_ping(args);
  std::string sent_message;
  rpc_message->SerializeToString(&sent_message);
  IP ip("127.0.0.1");
  EXPECT_FALSE(ValidPort(0));
  EXPECT_FALSE(ValidPort(1));
  EXPECT_FALSE(ValidPort(4999));
  EXPECT_FALSE(ValidPort(5000));
  EXPECT_TRUE(ValidPort(5001));
  for (int i = 0; i < num_listening_ports ; ++i) {
    lp_node[i] = node.StartListening("", 0, NULL);
    EXPECT_TRUE(ValidPort(lp_node[i]));
    node.Send(transport_message, ip, lp_node[i], 0);
  }
  EXPECT_EQ(num_listening_ports, node.listening_ports().size());
  const int kTimeout(10000);
  int count(0);
  while (count < kTimeout &&
         message_handler1.messages_received_ != num_listening_ports) {
//    LOG(INFO) << "Sent: " << message_handler1.messages_sent_ << std::endl;
//    LOG(INFO) << "Recd: " << message_handler1.messages_received_ << std::endl;
    boost::this_thread::sleep(boost::posix_time::milliseconds(30));
    count += 30;
  }
//  LOG(INFO) << "Sent: " << message_handler1.messages_sent_ << std::endl;
//  LOG(INFO) << "Recd: " << message_handler1.messages_received_ << std::endl;
  EXPECT_EQ(num_listening_ports, message_handler1.messages_received_);
  EXPECT_EQ(message_handler1.messages_sent_,
            message_handler1.messages_received_);
  EXPECT_TRUE(node.StopAllListening());
}

TEST_F(TransportUdtTest, BEH_TRANS_SendOneMessageFromOneToAnother) {
  const std::string args = base::RandomString(256 * 1024);
  const size_t kRepeats = 1;
  TransportUDT node1_transudt, node2_transudt;
  MessageHandler message_handler1(&node1_transudt, false);
  MessageHandler message_handler2(&node2_transudt, false);
  Port lp_node1 = node1_transudt.StartListening("", 0, NULL);
  Port lp_node2 = node2_transudt.StartListening("", 0, NULL);
  EXPECT_TRUE(ValidPort(lp_node1));
  EXPECT_TRUE(ValidPort(lp_node2));
  TransportMessage transport_message;
  transport_message.set_type(TransportMessage::kRequest);
  rpcprotocol::RpcMessage *rpc_message =
      transport_message.mutable_data()->mutable_rpc_message();
  rpc_message->set_rpc_id(2000);
  rpc_message->set_method("Test");
  rpcprotocol::RpcMessage::Detail *payload = rpc_message->mutable_detail();
  kad::NatDetectionPingRequest *request = payload->MutableExtension(
      kad::NatDetectionPingRequest::nat_detection_ping_request);
  request->set_ping(args);
  std::string sent_message;
  rpc_message->SerializeToString(&sent_message);
  IP ip("127.0.0.1");

  for (size_t i = 0; i < kRepeats; ++i) {
    node1_transudt.Send(transport_message, ip, lp_node2, 600);
  }

  node1_transudt.SendResponse(transport_message, UDT::INVALID_SOCK);
  const int kTimeout(10000);
  int count(0);
  while (count < kTimeout && message_handler1.messages_unsent_ == 0) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }
  EXPECT_EQ(1, message_handler1.messages_unsent_);

  count = 0;
  while (count < kTimeout && message_handler2.messages_.size() < kRepeats) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }
  node1_transudt.StopAllListening();
  node2_transudt.StopAllListening();
  for (size_t i = 0; i < kRepeats; ++i) {
    EXPECT_EQ(sent_message, message_handler2.messages_.front());
    message_handler2.messages_.pop_front();
  }
  EXPECT_EQ(static_cast<int>(kRepeats), message_handler1.messages_sent_);
                      //boost::this_thread::sleep(boost::posix_time::milliseconds(10000));
}

TEST_F(TransportUdtTest, BEH_TRANS_SendMessagesFromManyToOne) {
  TransportUDT node4;
  TransportUDT node[20];
  MessageHandler message_handler4(&node4, false);
  Port lp_node4 = node4.StartListening("", 0, NULL);
  TransportMessage transport_message;
  transport_message.set_type(TransportMessage::kRequest);
  rpcprotocol::RpcMessage *rpc_message =
  transport_message.mutable_data()->mutable_rpc_message();
  rpc_message->set_rpc_id(2000);
  rpc_message->set_method("Test");
  rpcprotocol::RpcMessage::Detail *payload = rpc_message->mutable_detail();
  kad::NatDetectionPingRequest *request = payload->MutableExtension(
      kad::NatDetectionPingRequest::nat_detection_ping_request);
  const std::string args = base::RandomString(256 * 1024);
  request->set_ping(args);
  std::string sent_message;
  rpc_message->SerializeToString(&sent_message);
  IP ip("127.0.0.1");
//  sent_messages.push_back(sent_message);
  for (int i =0; i < 20 ; ++i) {
    node[i].Send(transport_message, "127.0.0.1", lp_node4, 0);
  }
  node4.StopAllListening();
  for (int i =0; i < 20 ; ++i) {
    node[i].StopAllListening();
  }
}

TEST_F(TransportUdtTest, BEH_TRANS_AddRemoveManagedEndpoints) {
  TransportUDT node1, node2, node3, node4, node5;
  MessageHandler message_handler1(&node1, false);
  MessageHandler message_handler3(&node3, false);
  Port node1_port = node1.StartListening("", 0, NULL);
  Port node2_port = node2.StartListening("", 0, NULL);
  Port node3_port = node3.StartListening("", 0, NULL);
  Port node4_port = node4.StartListening("", 0, NULL);
  Port node5_port = node5.StartListening("", 0, NULL);
  ManagedEndpointId node1_end1 =
    node1.AddManagedEndpoint("127.0.0.1", node2_port, "", 0, "Node1", 0 ,0 ,0);
  EXPECT_EQ(1, node1.managed_endpoint_sockets_.size());
  ManagedEndpointId node1_end2 =
    node1.AddManagedEndpoint("127.0.0.1", node3_port, "", 0, "Node1", 0 ,0 ,0);
  EXPECT_EQ(2, node1.managed_endpoint_sockets_.size());
  EXPECT_TRUE(node1.RemoveManagedEndpoint(node1_end2));
  EXPECT_EQ(size_t(1), message_handler3.lost_managed_endpoint_ids_.size());
  EXPECT_EQ(1, node1.managed_endpoint_sockets_.size());
  node1_end2 =
    node1.AddManagedEndpoint("127.0.0.1", node3_port, "", 0, "Node1", 0 ,0 ,0);
  EXPECT_EQ(2, node1.managed_endpoint_sockets_.size());
  ManagedEndpointId node1_end3 =
    node1.AddManagedEndpoint("127.0.0.1", node4_port, "", 0, "Node1", 0 ,0 ,0);
  EXPECT_EQ(3, node1.managed_endpoint_sockets_.size());
  ManagedEndpointId node1_end4 =
    node1.AddManagedEndpoint("127.0.0.1", node5_port, "", 0, "Node1", 0 ,0 ,0);
  EXPECT_EQ(4, node1.managed_endpoint_sockets_.size());
 // EXPECT_TRUE(CheckSocketAlive(node1_end1));
  node1.StopManagedConnections();
  ASSERT_TRUE(node1.stop_managed_connections_);
  boost::this_thread::sleep(boost::posix_time::milliseconds(90));
  EXPECT_FALSE(CheckSocketAlive(node1_end1));
  EXPECT_FALSE(CheckSocketAlive(node1_end2));
  EXPECT_FALSE(CheckSocketAlive(node1_end3));
  EXPECT_FALSE(CheckSocketAlive(node1_end4));
  EXPECT_EQ(0, node1.managed_endpoint_sockets_.size());
}

TEST_F(TransportUdtTest, BEH_TRANS_CrashManagedEndpoints) {
  TransportUDT node2, node3, node4;
  boost::shared_ptr<TransportUDT> node1_ptr;
  MessageHandler message_handler2(&node2, false);
  MessageHandler message_handler3(&node3, false);
  MessageHandler message_handler4(&node4, false);
  Port node1_port = node1_ptr->StartListening("", 0, NULL);
  Port node2_port = node2.StartListening("", 0, NULL);
  Port node3_port = node3.StartListening("", 0, NULL);
  Port node4_port = node4.StartListening("", 0, NULL);
  ManagedEndpointId node1_end1 =
    node1_ptr->AddManagedEndpoint("127.0.0.1", node2_port, "", 0, "Node1", 0 ,0 ,0);
  ManagedEndpointId node1_end2 =
    node2.AddManagedEndpoint("127.0.0.1", node3_port, "", 0, "Node2", 0 ,0 ,0);
  ManagedEndpointId node1_end3 =
    node3.AddManagedEndpoint("127.0.0.1", node1_port, "", 0, "Node3", 0 ,0 ,0);
  // Kill node1
  node1_ptr.reset();
  EXPECT_EQ(size_t(1), message_handler2.lost_managed_endpoint_ids_.size());
LOG(INFO) << "HERE !!!" <<std::endl;
  node1_ptr->StopManagedConnections();
  node2.StopManagedConnections();
  node3.StopManagedConnections();
  node4.StopManagedConnections();
}

}  // namespace test

}  // namespace transport
