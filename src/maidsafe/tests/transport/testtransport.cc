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
#include <string>
#include "maidsafe/protobuf/transport_message.pb.h"
#include "maidsafe/protobuf/kademlia_service_messages.pb.h"
#include "maidsafe/transport/transportudt.h"
#include "maidsafe/base/log.h"
#include "maidsafe/base/routingtable.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/udt/api.h"
#include "maidsafe/base/network_interface.h"


class TransportNode {
 public:
  TransportNode(transport::TransportUDT *transport)
      : transport_(transport),
        successful_conn_(0),
        refused_conn_(0) {}
  transport::TransportUDT *transportUDT() { return transport_; }
  int successful_conn() { return successful_conn_; }
  int refused_conn() { return refused_conn_; }
  void IncreaseSuccessfulConn() { ++successful_conn_; }
  void IncreaseRefusedConn() { ++refused_conn_; }
 private:
  transport::TransportUDT *transport_;
  int successful_conn_, refused_conn_;

};


class MessageHandler {
 public:
  MessageHandler(transport::TransportUDT *transport,
                 bool display_stats)
      : messages_(),
        raw_messages_(),
        target_message_(),
        ids_(),
        raw_ids_(),
        dead_server_(true),
        server_ip_(),
        server_port_(0),
        transport_(transport),
        messages_sent_(0),
        messages_received_(0),
        messages_confirmed_(0),
        keep_messages_(true),
        rpc_request_(),
        rpc_response_(),
        data_sent_connection_(),
        message_connection_(),
        server_down_connection_(),
        stats_connection_() {
    rpc_request_ = transport->ConnectRpcRequestReceived(
        boost::bind(&MessageHandler::OnRPCMessage, this, _1, _2));
    rpc_response_ = transport->ConnectRpcResponseReceived(
        boost::bind(&MessageHandler::OnRPCMessage, this, _1, _2));
    data_sent_connection_ = transport->ConnectSend(
        boost::bind(&MessageHandler::OnSend, this, _1, _2));
    message_connection_ = transport->ConnectMessageReceived(
        boost::bind(&MessageHandler::OnMessage, this, _1, _2, _3));
    server_down_connection_ = transport->ConnectConnectionDown(
        boost::bind(&MessageHandler::OnDeadRendezvousServer, this, _1, _2, _3));
    if (display_stats) {
      stats_connection_ = transport->ConnectStats(
          boost::bind(&MessageHandler::OnStats, this, _1));
    }
  }
  void OnRPCMessage(const transport::RpcMessage &rpc_message,
                    const transport::SocketId &socket_id) {
    std::string message;
    rpc_message.SerializeToString(&message);
    ++messages_received_;
    if (!target_message_.empty() && message == target_message_)
      ++messages_confirmed_;
    if (keep_messages_) {
      messages_.push_back(message);
      ids_.push_back(socket_id);
    }
//    transport::TransportMessage transport_message;
//    transport_message.set_type(transport::TransportMessage::kResponse);
//    transport::RpcMessage *rpc_reply =
//        transport_message.mutable_data()->mutable_rpc_message();
//    rpc_reply->set_rpc_id(2000);
//    rpc_reply->set_method("Rply");
//    transport::RpcMessage::Detail *payload = rpc_reply->mutable_detail();
//    kad::NatDetectionPingResponse *response = payload->MutableExtension(
//        kad::NatDetectionPingResponse::nat_detection_ping_response);
//    response->set_result("Rubbish");
//    std::string sent_message;
//    rpc_reply->SerializeToString(&sent_message);
//    transport_->SendResponse(transport_message, socket_id);
  }
  void OnMessage(const std::string &message,
                 const transport::SocketId &socket_id,
                 const float&) {
    raw_messages_.push_back(message);
    raw_ids_.push_back(socket_id);
  }
  void OnDeadRendezvousServer(const bool &dead_server, const transport::IP &ip,
                              const transport::Port &port) {
    dead_server_ = dead_server;
    server_ip_ = ip;
    server_port_ = port;
  }
  void OnSend(const transport::SocketId &,
              const transport::TransportCondition &result) {
    if (result == transport::kSuccess)
      ++messages_sent_;
  }
  void OnStats(boost::shared_ptr<transport::SocketPerformanceStats> stats) {
    boost::shared_ptr<transport::UdtStats> udt_stats =
        boost::static_pointer_cast<transport::UdtStats>(stats);
    if (udt_stats->udt_socket_type_ == transport::UdtStats::kSend) {
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
  std::list<transport::SocketId> ids_, raw_ids_;
  bool dead_server_;
  transport::IP server_ip_;
  transport::Port server_port_;
  transport::TransportUDT *transport_;
  int messages_sent_, messages_received_, messages_confirmed_;
  bool keep_messages_;
 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);
  bs2::connection rpc_request_, rpc_response_;
  bs2::connection data_sent_connection_;
  bs2::connection message_connection_;
  bs2::connection server_down_connection_;
  bs2::connection stats_connection_;
};


class TransportTest: public testing::Test {
 protected:
  virtual ~TransportTest() {
  //  UDT::cleanup();
  }
};


TEST_F(TransportTest, BEH_TRANS_MultipleListeningPorts) {
  boost::uint16_t num_listening_ports = 10;
  transport::TransportUDT node;
  MessageHandler message_handler1(&node, false);
  transport::Port lp_node[100];
  transport::TransportMessage transport_message;
  transport_message.set_type(transport::TransportMessage::kRequest);
  transport::RpcMessage *rpc_message =
      transport_message.mutable_data()->mutable_rpc_message();
  rpc_message->set_rpc_id(2000);
  rpc_message->set_method("Test");
  transport::RpcMessage::Detail *payload = rpc_message->mutable_detail();
  kad::NatDetectionPingRequest *request = payload->MutableExtension(
      kad::NatDetectionPingRequest::nat_detection_ping_request);
  const std::string args = base::RandomString(256 * 1024);
  request->set_ping(args);
  std::string sent_message;
  rpc_message->SerializeToString(&sent_message);
  transport::IP ip("127.0.0.1");
  for (int i = 0; i < num_listening_ports ; ++i) {
    lp_node[i] = node.StartListening("", 0);
    EXPECT_TRUE(node.CheckListeningPort(lp_node[i]));
    if (i == 1) {
      EXPECT_FALSE(node.CheckListeningPort(0));
      EXPECT_FALSE(node.CheckListeningPort(1));
      EXPECT_FALSE(node.CheckListeningPort(4999));
      EXPECT_FALSE(node.CheckListeningPort(5000));
    }
     EXPECT_EQ(transport::kSuccess,
             node.Send(transport_message, ip, lp_node[i], 0));
  }
  EXPECT_EQ(num_listening_ports, node.listening_ports().size());
  //LOG(INFO) << "Number of messages_ sent : " << message_handler1.messages_sent_ << std::endl;
  //LOG(INFO) << "Number of messages_ received : " << message_handler1.messages_received_ << std::endl;
  while (message_handler1.messages_received_ < message_handler1.messages_sent_ ) {
    //LOG(INFO) << "Number of messages_ sent : " << message_handler1.messages_sent_ << std::endl;
    //LOG(INFO) << "Number of messages_ received : " << message_handler1.messages_received_ << std::endl;
    boost::this_thread::sleep(boost::posix_time::milliseconds(30));
  }
    // LOG(INFO) << "Number of messages_ sent : " << message_handler1.messages_sent_ << std::endl;
    //LOG(INFO) << "Number of messages_ received : " << message_handler1.messages_received_ << std::endl;
  EXPECT_EQ(message_handler1.messages_sent_, message_handler1.messages_received_);
  EXPECT_EQ(num_listening_ports, message_handler1.messages_received_);
  EXPECT_TRUE(node.StopAllListening());

}

TEST_F(TransportTest, BEH_TRANS_SendOneMessageFromOneToAnother) {
  const std::string args = base::RandomString(256 * 1024);
  const size_t kRepeats = 1;
  transport::TransportUDT node1_transudt, node2_transudt;
  MessageHandler message_handler1(&node1_transudt, false);
  MessageHandler message_handler2(&node2_transudt, false);
  transport::Port lp_node1 = node1_transudt.StartListening("", 0);
  transport::Port lp_node2 = node2_transudt.StartListening("", 0);
  EXPECT_TRUE(node1_transudt.CheckListeningPort(lp_node1));
  EXPECT_TRUE(node1_transudt.CheckListeningPort(lp_node2));
  EXPECT_FALSE(node1_transudt.CheckListeningPort(0));
  EXPECT_FALSE(node1_transudt.CheckListeningPort(1));
  EXPECT_FALSE(node1_transudt.CheckListeningPort(4999));
  EXPECT_FALSE(node1_transudt.CheckListeningPort(5000));
  transport::TransportMessage transport_message;
  transport_message.set_type(transport::TransportMessage::kRequest);
  transport::RpcMessage *rpc_message =
      transport_message.mutable_data()->mutable_rpc_message();
  rpc_message->set_rpc_id(2000);
  rpc_message->set_method("Test");
  transport::RpcMessage::Detail *payload = rpc_message->mutable_detail();
  kad::NatDetectionPingRequest *request = payload->MutableExtension(
      kad::NatDetectionPingRequest::nat_detection_ping_request);
  request->set_ping(args);
  std::string sent_message;
  rpc_message->SerializeToString(&sent_message);
  transport::IP ip("127.0.0.1");
  for (size_t i = 0; i < kRepeats; ++i) {
    EXPECT_EQ(transport::kSuccess,
              node1_transudt.Send(transport_message, ip, lp_node2, 6000));
  }

//   EXPECT_NE(transport::kSuccess, node1_transudt.SendResponse(transport_message, id))
//             << "Should fail to send to bad socket";

   // EXPECT_NE(0, node1_transudt.SendResponse(transport_message, id));
  while (message_handler2.messages_.size() < kRepeats)
     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
                       //boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
  node1_transudt.StopAllListening();
  node2_transudt.StopAllListening();
  for (size_t i = 0; i < kRepeats; ++i) {
    EXPECT_EQ(sent_message, message_handler2.messages_.front());
    message_handler2.messages_.pop_front();
  }
 // EXPECT_EQ(sent_message, message_handler1.messages_.front());
  EXPECT_EQ(static_cast<int>(kRepeats), message_handler1.messages_sent_);
                       //boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
}

TEST_F(TransportTest, BEH_TRANS_SendMessagesFromManyToOne) {
  transport::TransportUDT node4;
  transport::TransportUDT node[20]; 
  MessageHandler message_handler4(&node4, false);
  transport::Port lp_node4 = node4.StartListening("", 0);
  transport::TransportMessage transport_message;
  transport_message.set_type(transport::TransportMessage::kRequest);
  transport::RpcMessage *rpc_message =
  transport_message.mutable_data()->mutable_rpc_message();
  rpc_message->set_rpc_id(2000);
  rpc_message->set_method("Test");
  transport::RpcMessage::Detail *payload = rpc_message->mutable_detail();
  kad::NatDetectionPingRequest *request = payload->MutableExtension(
      kad::NatDetectionPingRequest::nat_detection_ping_request);
  const std::string args = base::RandomString(256 * 1024);
  request->set_ping(args);
  std::string sent_message;
  rpc_message->SerializeToString(&sent_message);
  transport::IP ip("127.0.0.1");
//  sent_messages.push_back(sent_message);
  for (int i =0; i <20 ; ++i) {
    EXPECT_EQ(0, node[i].Send(transport_message, "127.0.0.1", lp_node4, 0));
  }
  
}
