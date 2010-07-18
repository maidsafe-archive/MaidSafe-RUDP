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
  void IncreaseSuccessfulConn() { successful_conn_++; }
  void IncreaseRefusedConn() { refused_conn_++; }
 private:
  transport::TransportUDT *transport_;
  int successful_conn_, refused_conn_;

};


class MessageHandler {
 public:
  MessageHandler(transport::TransportUDT *transport): msgs(), raw_msgs(),
    target_msg_(), ids(), raw_ids(), dead_server_(true), server_ip_(),
    server_port_(0), transport_(), msgs_sent_(0), msgs_received_(0),
    msgs_confirmed_(0), keep_msgs_(true), rpc_request_(), rpc_response_(),
    data_sent_connection_(), message_connection_(), server_down_connection_() {
  rpc_request_ = transport->ConnectRpcRequestReceived(
       boost::bind(&MessageHandler::OnRPCMessage, this, _1, _2));
  rpc_response_ = transport->ConnectRpcResponseReceived(
       boost::bind(&MessageHandler::OnRPCMessage, this, _1, _2));
  data_sent_connection_ = transport->ConnectSent((
      boost::bind(&MessageHandler::OnSend, this, _1, _2)));
  message_connection_ = transport->ConnectMessageReceived((
      boost::bind(&MessageHandler::OnMessage, this, _1, _2, _3)));
  server_down_connection_= transport->ConnectConnectionDown((
      boost::bind(&MessageHandler::OnDeadRendezvousServer, this, _1, _2, _3)));
    }
  void OnRPCMessage(const transport::RpcMessage &msg,
                    const transport::SocketId &socket_id) {
    std::string message;
    msg.SerializeToString(&message);
    msgs_received_++;
    if (!target_msg_.empty() && message == target_msg_)
      msgs_confirmed_++;
    if (keep_msgs_) {
      msgs.push_back(message);
      ids.push_back(socket_id);
    }
  UDT::close(socket_id);
  }
  void OnMessage(const std::string &msg,
                 const transport::SocketId &socket_id,
                 const float&) {
    raw_msgs.push_back(msg);
    raw_ids.push_back(socket_id);
     UDT::close(socket_id); 
  }
  void OnDeadRendezvousServer(const bool &dead_server, const transport::IP &ip,
                              const transport::Port &port) {
    dead_server_ = dead_server;
    server_ip_ = ip;
    server_port_ = port;
  }
  void OnSend(const transport::SocketId &, const bool &success) {
    if (success)
      ++msgs_sent_;
  }
  std::list<std::string> msgs, raw_msgs;
  std::string target_msg_;
  std::list<transport::SocketId> ids, raw_ids;
  bool dead_server_;
  transport::IP server_ip_;
  transport::Port server_port_;
  transport::TransportUDT *transport_;
  int msgs_sent_, msgs_received_, msgs_confirmed_;

  bool keep_msgs_;
 private:
   MessageHandler(const MessageHandler&);
   MessageHandler& operator=(const MessageHandler&);
  bs2::connection rpc_request_, rpc_response_;
  bs2::connection data_sent_connection_;
  bs2::connection message_connection_;
  bs2::connection server_down_connection_;
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
  MessageHandler msg_handler1(&node);
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
  std::string sent_msg;
  rpc_message->SerializeToString(&sent_msg);
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
  EXPECT_EQ(num_listening_ports, node.GetListeningPorts().size());
   LOG(INFO) << "Number of msgs sent : " << msg_handler1.msgs_sent_ << std::endl;
    LOG(INFO) << "Number of msgs received : " << msg_handler1.msgs_received_ << std::endl;
  while (msg_handler1.msgs_received_ < msg_handler1.msgs_sent_ ) {
    LOG(INFO) << "Number of msgs sent : " << msg_handler1.msgs_sent_ << std::endl;
    LOG(INFO) << "Number of msgs received : " << msg_handler1.msgs_received_ << std::endl;
    boost::this_thread::sleep(boost::posix_time::milliseconds(30));
  }
     LOG(INFO) << "Number of msgs sent : " << msg_handler1.msgs_sent_ << std::endl;
    LOG(INFO) << "Number of msgs received : " << msg_handler1.msgs_received_ << std::endl;
  EXPECT_EQ(msg_handler1.msgs_sent_, msg_handler1.msgs_received_);
  EXPECT_EQ(num_listening_ports, msg_handler1.msgs_received_);
  EXPECT_TRUE(node.StopAllListening());

}

TEST_F(TransportTest, BEH_TRANS_SendOneMessageFromOneToAnother) {
  transport::TransportUDT node1_transudt, node2_transudt;
  MessageHandler msg_handler1(&node1_transudt);
  MessageHandler msg_handler2(&node2_transudt);
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
  const std::string args = base::RandomString(256 * 1024);
  request->set_ping(args);
  std::string sent_msg;
  rpc_message->SerializeToString(&sent_msg);
  transport::IP ip("127.0.0.1");
  EXPECT_EQ(transport::kSuccess,
            node1_transudt.Send(transport_message, ip, lp_node2, 0));

//   EXPECT_NE(transport::kSuccess, node1_transudt.SendResponse(transport_message, id))
//             << "Should fail to send to bad socket";

   // EXPECT_NE(0, node1_transudt.SendResponse(transport_message, id));
  while (msg_handler2.msgs.empty())
     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  node1_transudt.StopAllListening();
  node2_transudt.StopAllListening();
  EXPECT_FALSE(msg_handler2.msgs.empty());
  EXPECT_EQ(sent_msg, msg_handler2.msgs.front());
 // EXPECT_EQ(sent_msg, msg_handler1.msgs.front());
  EXPECT_NE(0, msg_handler1.msgs_sent_);
}

TEST_F(TransportTest, BEH_TRANS_SendMessagesFromManyToOne) {
  transport::TransportUDT node4;
  transport::TransportUDT node[20]; 
  MessageHandler msg_handler4(&node4);
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
  std::string sent_msg;
  rpc_message->SerializeToString(&sent_msg);
  transport::IP ip("127.0.0.1");
//  sent_msgs.push_back(sent_msg);
  for (int i =0; i <20 ; ++i) {
    EXPECT_EQ(0, node[i].Send(transport_message, "127.0.0.1", lp_node4, 0));
  }
  
}
