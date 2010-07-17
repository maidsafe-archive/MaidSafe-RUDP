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

// void send_string(TransportNode* node, int port, int repeat,
//     transport::RpcMessage msg, bool keep_conn, int our_port) {
//   transport::SocketId id;
//   boost::asio::ip::address local_address;
//   transport::IP ip;
//   if (base::GetLocalAddress(&local_address)) {
//     ip = local_address.to_string();
//   } else {
//     ip = transport::IP("127.0.0.1");
//   }
//   for (int i = 0; i < repeat; ++i) {
//     int send_res = node->transportUDT()->ConnectToSend(ip, port, "", 0, "", 0,
//         keep_conn, &id);
//     if (send_res == 1002) {
//       // connection refused - wait 10 sec and resend
//       boost::this_thread::sleep(boost::posix_time::seconds(10));
//       send_res = node->transportUDT()->ConnectToSend(ip, port, "", 0, "", 0,
//       keep_conn, &id);
//     }
//     std::string message;
//     msg.SerializeToString(&message);
//     if (send_res == 0) {
//       node->transportUDT()->Send(message, id, true);
//       node->IncreaseSuccessfulConn();
//     } else {
//       node->IncreaseRefusedConn();
//     }
//     boost::this_thread::sleep(boost::posix_time::milliseconds(100));
//   }
//   LOG(INFO) << "thread " << our_port << " finished sending " <<
//       node->successful_conn() << " messages." << std::endl;
// }

class MessageHandler {
 public:
  MessageHandler(transport::TransportUDT *transport): msgs(), raw_msgs(),
    ids(), dead_server_(true), server_ip_(), server_port_(0), transport_(),
    msgs_sent_(0), msgs_received_(0), msgs_confirmed_(0), target_msg_(),
    keep_msgs_(true) {
  rpc_request_ = transport->ConnectRpcRequestReceived(
       boost::bind(&MessageHandler::OnRPCMessage, this, _1, _2, _3));
  rpc_response_ = transport->ConnectRpcRequestReceived(
       boost::bind(&MessageHandler::OnRPCMessage, this, _1, _2, _3));
  data_sent_connection_ = transport->ConnectSent((
      boost::bind(&MessageHandler::OnSend, this, _1, _2)));
  message_connection_ = transport->ConnectMessageReceived((
      boost::bind(&MessageHandler::OnMessage, this, _1, _2, _3)));
  server_down_connection_= transport->ConnectConnectionDown((
      boost::bind(&MessageHandler::OnDeadRendezvousServer, this, _1, _2, _3)));
    }
  void OnRPCMessage(const transport::RpcMessage &msg,
                    const transport::SocketId &socket_id,
                    const float &rtt) {
    std::string message;
    msg.SerializeToString(&message);
    msgs_received_++;
    if (!target_msg_.empty() && message == target_msg_)
      msgs_confirmed_++;
    if (keep_msgs_) {
      msgs.push_back(message);
      ids.push_back(socket_id);
    }
//     LOG(INFO) << "message " << msgs_received_ << " arrived. RTT = " << rtt
//         << std::endl;
  UDT::close(socket_id);
  }
  void OnMessage(const std::string &msg,
                 const transport::SocketId &socket_id,
                 const float&) {
    raw_msgs.push_back(msg);
    raw_ids.push_back(socket_id);
  }
  void OnDeadRendezvousServer(const bool &dead_server, const transport::IP &ip,
                              const transport::Port &port) {
    dead_server_ = dead_server;
    server_ip_ = ip;
    server_port_ = port;
  }

  void OnSend(const transport::SocketId &, const bool &success) {
    if (success)
      msgs_sent_++;
  }
  std::list<std::string> msgs, raw_msgs;
  std::list<transport::SocketId> ids, raw_ids;
  bool dead_server_;
  transport::IP server_ip_;
  transport::Port server_port_;
  transport::TransportUDT *transport_;
  int msgs_sent_, msgs_received_, msgs_confirmed_;
  std::string target_msg_;
  bool keep_msgs_;
 private:
  // MessageHandler(const MessageHandler&);
  // MessageHandler& operator=(const MessageHandler&);
  bs2::connection rpc_request_, rpc_response_;
  bs2::connection data_sent_connection_;
  bs2::connection message_connection_;
  bs2::connection server_down_connection_;
};

class MessageHandlerEchoRequest {
 public:
  explicit MessageHandlerEchoRequest(transport::TransportUDT *node)
      : node_(node),
        msgs(),
        ids(),
        dead_server_(true),
        server_ip_(),
        server_port_(0),
        msgs_sent_(0) {
    rpc_connection_ = node_->ConnectRpcResponseReceived(
        boost::bind(&MessageHandlerEchoRequest::OnRPCMessage, this, _1, _2, _3));
  }
  void OnRPCMessage(const transport::RpcMessage &msg,
                    const transport::SocketId &socket_id,
                    const float &rtt) {
    transport::TransportMessage t_msg;
    transport::RpcMessage::Detail *pmsg =
        t_msg.mutable_data()->mutable_rpc_message()->mutable_detail();
    kad::NatDetectionPingRequest *request = pmsg->MutableExtension(
        kad::NatDetectionPingRequest::nat_detection_ping_request);
    std::string message;
    msg.SerializeToString(&message);
    request->set_ping(message);
    msgs.push_back(message);
    ids.push_back(socket_id);
    struct sockaddr addr;
    if (node_->GetPeerAddress(socket_id, &addr) != transport::kSuccess)
      LOG(INFO) << "address not found" << std::endl;
    transport::IP peer_ip(inet_ntoa(((struct sockaddr_in *)&addr)->sin_addr));
    transport::Port peer_port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
    LOG(INFO) << "message " << msgs.size() << " arrived from " << peer_ip << ":"
        << peer_port << " . RTT = " << rtt << std::endl;
   // replying same msg
    if (msgs.size() < size_t(10))
      node_->SendResponse(t_msg, socket_id);
  }
  void OnDeadRendezvousServer(const bool &dead_server, const transport::IP &ip,
                              const transport::Port &port) {
    dead_server_ = dead_server;
    server_ip_ = ip;
    server_port_ = port;
  }
  void OnSend(const transport::SocketId &, const bool &success) {
    if (success)
      msgs_sent_++;
  }
  transport::TransportUDT *node_;
  std::list<std::string> msgs;
  std::list<transport::SocketId> ids;
  bool dead_server_;
  transport::IP server_ip_;
  transport::Port server_port_;
  int msgs_sent_;
 private:
  MessageHandlerEchoRequest(const MessageHandlerEchoRequest&);
  MessageHandlerEchoRequest& operator=(const MessageHandlerEchoRequest&);
  bs2::connection rpc_connection_;
};

class MessageHandlerEchoResponse {
 public:
  explicit MessageHandlerEchoResponse(transport::TransportUDT *node)
      : node_(node), msgs(), ids(), dead_server_(true),
        server_ip_(), server_port_(0), msgs_sent_(0) {
    rpc_request_ = node->ConnectRpcRequestReceived(boost::bind(
        &MessageHandlerEchoResponse::OnRPCMessage, this, _1, _2, _3));
    rpc_response_ = node->ConnectRpcResponseReceived(boost::bind(
        &MessageHandlerEchoResponse::OnRPCMessage, this, _1, _2, _3));
  }
  void OnRPCMessage(const transport::RpcMessage &msg,
                    const transport::SocketId &socket_id,
                    const float &rtt) {
    std::string message;
    msg.SerializeToString(&message);
    msgs.push_back(message);
    ids.push_back(socket_id);
//     LOG(INFO) << "message " << msgs.size() << " arrived. RTT = " << rtt
//         << std::endl;
    // replying same msg
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
  transport::TransportUDT *node_;
  std::list<std::string> msgs;
  std::list<transport::SocketId> ids;
  bool dead_server_;
  transport::IP server_ip_;
  transport::Port server_port_;
  int msgs_sent_;
 private:
  MessageHandlerEchoResponse(const MessageHandlerEchoResponse&);
  MessageHandlerEchoResponse& operator=(const MessageHandlerEchoResponse&);
  bs2::connection rpc_request_, rpc_response_;
};

class TransportTest: public testing::Test {
 protected:
  virtual ~TransportTest() {
//    UDT::cleanup();
  }
};



// TEST_F(TransportTest, BEH_TRANS_start_stop_node) {
// // Try and start then stop and try other sockets etc.
//   transport::Port node1_port;
//   transport::TransportUDT node1, node2;
//
//   EXPECT_EQ(0, node1.Start(0));
//   EXPECT_FALSE(node1.is_stopped());
//   node1_port = node1.listening_port();
//   EXPECT_NE(0, node1_port);
//   EXPECT_NE(0, node2.Start(node1_port));
//   node1.Stop();
//   EXPECT_TRUE(node1.is_stopped());
//   EXPECT_TRUE(node2.is_stopped());
//   //node1.CleanUp();
//   EXPECT_EQ(0, node2.Start(node1_port));
//
//   EXPECT_FALSE(node2.is_stopped());
//   EXPECT_NE(0, node2.Start(node1_port)) << "whoops tried to"
//                                       << "listen twice on same port !! tsk tsk";
//   EXPECT_NE(0, node1.Start(node1_port)) << "whoops tried to"
//                                       << "listen twice on same port !! tsk tsk";
//   node2.Stop();
// }
//
//
//
// TEST_F(TransportTest, BEH_TRANS_start_1_send_from_100) {
// // set up a node type
//   transport::TransportUDT recieving_node;
//   EXPECT_EQ(0, recieving_node.Start(0));
// // OK get port we started on (binds to all addresses)
//   transport::Port recieving_node_port = recieving_node.listening_port();
// // vector of nodes of right type
//   std::vector<transport::TransportUDT*> nodes;
//   for (int i = 0 ; i < 100 ; ++i) {
//     nodes.push_back(new transport::TransportUDT);
//   }
// // connect message recived signal
// // recieving_node.connect_message_recieved(&echome);
//
// // lets start them all, check we get ports  and there all running then
// // stop them all, just for a laugh;
//   std::vector<transport::TransportUDT*>::iterator node;
//   for (node=nodes.begin(); node != nodes.end(); ++node) {
//     EXPECT_EQ(0, (*node)->Start(0));
//     EXPECT_FALSE((*node)->is_stopped());
//     int node_port = (*node)->listening_port();
//     EXPECT_NE(0, node_port);
// //   std::string hi("hi there you s;fksa;ksdgl;dgsljgrowe#gjwelk2-48");
// //   EXPECT_EQ(0, (*node)->Send(hi, "127.0.0.1" , recieving_node_port));
//     (*node)->Stop();
//     EXPECT_TRUE((*node)->is_stopped());
//   // send some info to recieving_node
//  // (*node)->
//   }
//
// // no memory leaks
//   for (node=nodes.begin(); node != nodes.end(); ++node) {
//     delete (*node);
//     node--; // important when we delete a pointer we lose our place
//     nodes.clear();
//   }
// }

TEST_F(TransportTest, FUNC_TRANS_MultipleListeningPorts) {
  transport::TransportUDT node;
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
  boost::uint16_t num_listening_ports = 20;
  for (int i = 0; i < num_listening_ports ; ++i) {
    lp_node[i] = node.StartListening("", 0);
    // LOG(INFO) << "Chosen port number for node : " << i << " "
    //            << lp_node[i] << std::endl;
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
  EXPECT_EQ(num_listening_ports, node.GetListeningPorts().size()); // shoudl all be sucessful
  
}

TEST_F(TransportTest, BEH_TRANS_SendOneMessageFromOneToAnother) {
  transport::SocketId id = 0;
  transport::TransportUDT node1_transudt, node2_transudt;
  boost::int16_t node1_id, node2_id;
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

  EXPECT_EQ(transport::kNoSocket, node1_transudt.SendResponse(transport_message, id))
            << "Should fail to send to bad socket";

   EXPECT_NE(0, node1_transudt.SendResponse(transport_message, id));
  while (msg_handler2.msgs.empty())
     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  node1_transudt.StopAllListening();
  node2_transudt.StopAllListening();
  EXPECT_FALSE(msg_handler1.msgs.empty()); // both messagehandlers are picking
                                          // up the signal, of course
  EXPECT_FALSE(msg_handler2.msgs.empty());
  EXPECT_EQ(sent_msg, msg_handler2.msgs.front());
  EXPECT_EQ(1, msg_handler1.msgs_sent_);
}
/*
TEST_F(TransportTest, BEH_TRANS_SendMessagesFromManyToOne) {
  transport::SocketId id;
  boost::int16_t node1_id, node2_id, node3_id, node4_id;
  transport::TransportUDT node1_transudt, node2_transudt, node3_transudt,
    node4_transudt;
  MessageHandler msg_handler4(&node4_transudt);
  MessageHandler msg_handler3(&node3_transudt);
  MessageHandler msg_handler2(&node2_transudt);
  MessageHandler msg_handler1(&node1_transudt);
  EXPECT_EQ(0, node1_transudt.Start(0));
  EXPECT_EQ(0, node2_transudt.Start(0));
  EXPECT_EQ(0, node3_transudt.Start(0));
  EXPECT_EQ(0, node4_transudt.Start(0));
  transport::Port lp_node4 = node4_transudt.listening_port();
  std::list<std::string> sent_msgs;
  transport::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64 * 1024));
  std::string ser_rpc_msg;
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs.push_back(ser_rpc_msg);
  EXPECT_EQ(0, node1_transudt.ConnectToSend("127.0.0.1", lp_node4, "", 0, "", 0,
    false, &id));
  EXPECT_EQ(0, node1_transudt.Send(rpc_msg, id, true));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs.push_back(ser_rpc_msg);
  EXPECT_EQ(0, node2_transudt.ConnectToSend("127.0.0.1", lp_node4, "", 0, "", 0,
    false, &id));
  EXPECT_EQ(0, node2_transudt.Send(rpc_msg, id, true));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs.push_back(ser_rpc_msg);
  EXPECT_EQ(0, node3_transudt.ConnectToSend("127.0.0.1", lp_node4, "", 0, "", 0,
    false, &id));
  EXPECT_EQ(0, node3_transudt.Send(rpc_msg, id, true));
  boost::uint32_t now = base::GetEpochTime();
  while (msg_handler4.msgs.size() < size_t(3) &&
         base::GetEpochTime() - now < 15)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  node1_transudt.Stop();
  node2_transudt.Stop();
  node3_transudt.Stop();
  node4_transudt.Stop();

  EXPECT_TRUE(msg_handler1.msgs.empty());
  EXPECT_EQ(1, msg_handler1.msgs_sent_);
  EXPECT_TRUE(msg_handler2.msgs.empty());
  EXPECT_EQ(1, msg_handler2.msgs_sent_);
  EXPECT_TRUE(msg_handler3.msgs.empty());
  EXPECT_EQ(1, msg_handler3.msgs_sent_);
//   EXPECT_EQ(msg_handler4.msgs.size(), size_t(3));
  //msg_handler4.msgs.sort();
  //sent_msgs.sort();
 // for (int i = 0; i < 3; i++) {
//     EXPECT_EQ(msg_handler4.msgs.front(), sent_msgs.front());
//     msg_handler4.msgs.pop_front();
//     sent_msgs.pop_front();
 // }
}*/
/*
TEST_F(TransportTest, BEH_TRANS_SendMessagesFromManyToMany) {
  transport::SocketId id;
  transport::TransportHandler node1_handler, node2_handler, node3_handler,
    node4_handler, node5_handler, node6_handler;
  transport::TransportUDT node1_transudt, node2_transudt, node3_transudt,
    node4_transudt, node5_transudt, node6_transudt;
  boost::int16_t node1_id, node2_id, node3_id, node4_id, node5_id, node6_id;
  node1_handler.Register(&node1_transudt, &node1_id);
  node2_handler.Register(&node2_transudt, &node2_id);
  node3_handler.Register(&node3_transudt, &node3_id);
  node4_handler.Register(&node4_transudt, &node4_id);
  node5_handler.Register(&node5_transudt, &node5_id);
  node6_handler.Register(&node6_transudt, &node6_id);
  MessageHandler msg_handler[6];
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[0], _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
//     _1, _2, _3)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[0], _1, _2)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
//   EXPECT_TRUE(node2_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[1], _1, _2, _3, _4)));
//   EXPECT_TRUE(node2_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
//     _1, _2, _3)));
//   EXPECT_TRUE(node2_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[1], _1, _2)));
  EXPECT_EQ(0, node2_handler.Start(0, node2_id));
//   EXPECT_TRUE(node3_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[2], _1, _2, _3, _4)));
//   EXPECT_TRUE(node3_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[2],
//     _1, _2, _3)));
//   EXPECT_TRUE(node3_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[2], _1, _2)));
  EXPECT_EQ(0, node3_handler.Start(0, node3_id));
//   EXPECT_TRUE(node4_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[3], _1, _2, _3, _4)));
//   EXPECT_TRUE(node4_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[3],
//     _1, _2, _3)));
//   EXPECT_TRUE(node4_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[3], _1, _2)));
  EXPECT_EQ(0, node4_handler.Start(0, node4_id));
  transport::Port lp_node4 = node4_handler.listening_port(node4_id);
//   EXPECT_TRUE(node5_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[4], _1, _2, _3, _4)));
//   EXPECT_TRUE(node5_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[4],
//     _1, _2, _3)));
//   EXPECT_TRUE(node5_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[4], _1, _2)));
  EXPECT_EQ(0, node5_handler.Start(0, node5_id));
  transport::Port lp_node5 = node5_handler.listening_port(node5_id);
//   EXPECT_TRUE(node6_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[5], _1, _2, _3, _4)));
//   EXPECT_TRUE(node6_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[5],
//     _1, _2, _3)));
//   EXPECT_TRUE(node6_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[5], _1, _2)));
  EXPECT_EQ(0, node6_handler.Start(0, node6_id));
  transport::Port lp_node6_handler = node6_handler.listening_port(node6_id);
  std::string sent_msgs[3];
  transport::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64*1024));
  std::string ser_rpc_msg;
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs[0] = ser_rpc_msg;
  EXPECT_EQ(0, node1_handler.ConnectToSend("127.0.0.1", lp_node4, "", 0, "", 0,
    false, &id, node1_id));
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64*1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs[1] = ser_rpc_msg;
  EXPECT_EQ(0, node2_handler.ConnectToSend("127.0.0.1", lp_node5, "", 0, "", 0,
    false, &id, node1_id));
  EXPECT_EQ(0, node2_handler.Send(rpc_msg, id, true, node2_id));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64*1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs[2] = ser_rpc_msg;
  EXPECT_EQ(0, node3_handler.ConnectToSend("127.0.0.1", lp_node6_handler, "",
    0, "", 0, false, &id, node3_id));
  EXPECT_EQ(0, node3_handler.Send(rpc_msg, id, true, node3_id));
  boost::uint32_t now = base::GetEpochTime();
  bool msgs_received[3] = {false, false, false};
  while ((!msgs_received[0] || !msgs_received[1] || !msgs_received[2]) &&
          base::GetEpochTime() - now < 15) {
    boost::uint16_t zero = 0;
    if (static_cast<boost::uint16_t>(msg_handler[3].msgs.size()) > zero)
      msgs_received[0] = true;
    if (static_cast<boost::uint16_t>(msg_handler[4].msgs.size()) > zero)
      msgs_received[1] = true;
    if (static_cast<boost::uint16_t>(msg_handler[5].msgs.size()) > zero)
      msgs_received[2] = true;
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
  node3_handler.Stop(node3_id);
  node4_handler.Stop(node4_id);
  node5_handler.Stop(node5_id);
  node6_handler.Stop(node6_id);
  for (int i = 0; i < 3; i++) {
    EXPECT_TRUE(msg_handler[i].msgs.empty());
    EXPECT_EQ(1, msg_handler[i].msgs_sent_);
  }
  for (int i = 3; i < 6; i++) {
    EXPECT_EQ(size_t(1), msg_handler[i].msgs.size());
    EXPECT_EQ(msg_handler[i].msgs.front(), sent_msgs[i-3]);
  }
}

TEST_F(TransportTest, BEH_TRANS_SendMessagesFromOneToMany) {
  transport::SocketId id;
  transport::TransportHandler node1_handler, node2_handler, node3_handler,
    node4_handler;
  boost::int16_t node1_id, node2_id, node3_id, node4_id;
  transport::TransportUDT node1_udttrans, node2_transudt, node3_transudt,
    node4_transudt;
  node1_handler.Register(&node1_udttrans, &node1_id);
  node2_handler.Register(&node2_transudt, &node2_id);
  node3_handler.Register(&node3_transudt, &node3_id);
  node4_handler.Register(&node4_transudt, &node4_id);
  MessageHandler msg_handler[4];
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[0], _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
//     _1, _2, _3)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[0], _1, _2)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
//   EXPECT_TRUE(node2_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[1], _1, _2, _3, _4)));
//   EXPECT_TRUE(node2_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
//     _1, _2, _3)));
//   EXPECT_TRUE(node2_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[1], _1, _2)));
  EXPECT_EQ(0, node2_handler.Start(0, node2_id));
  transport::Port lp_node2 = node2_handler.listening_port(node2_id);
//   EXPECT_TRUE(node3_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[2], _1, _2, _3, _4)));
//   EXPECT_TRUE(node3_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[2],
//     _1, _2, _3)));
//   EXPECT_TRUE(node3_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[2], _1, _2)));
  EXPECT_EQ(0, node3_handler.Start(0, node3_id));
  transport::Port lp_node3 = node3_handler.listening_port(node3_id);
//   EXPECT_TRUE(node4_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[3], _1, _2, _3, _4)));
//   EXPECT_TRUE(node4_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[3],
//     _1, _2, _3)));
//   EXPECT_TRUE(node4_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[3], _1, _2)));
  EXPECT_EQ(0, node4_handler.Start(0, node4_id));
  transport::Port lp_node4 = node4_handler.listening_port(node4_id);
  std::string sent_msgs[3];
  transport::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64 * 1024));
  std::string ser_rpc_msg;
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs[0] = ser_rpc_msg;
  EXPECT_EQ(0, node1_handler.ConnectToSend("127.0.0.1", lp_node2, "", 0, "", 0,
    false, &id, node1_id));
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs[1] = ser_rpc_msg;
  EXPECT_EQ(0, node1_handler.ConnectToSend("127.0.0.1", lp_node3, "", 0, "", 0,
    false, &id, node1_id));
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs[2] = ser_rpc_msg;
  EXPECT_EQ(0, node1_handler.ConnectToSend("127.0.0.1", lp_node4, "", 0, "", 0,
    false, &id, node1_id));
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));

  boost::uint32_t now = base::GetEpochTime();
  bool msgs_received[3] = {false, false, false};
  while ((!msgs_received[0] || !msgs_received[1] || !msgs_received[2]) &&
          base::GetEpochTime() - now < 15) {
    if (msg_handler[1].msgs.size() >= size_t(1))
      msgs_received[0] = true;
    if (msg_handler[2].msgs.size() >= size_t(1))
      msgs_received[1] = true;
    if (msg_handler[3].msgs.size() >= size_t(1))
      msgs_received[2] = true;
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
  node3_handler.Stop(node3_id);
  node4_handler.Stop(node4_id);
  EXPECT_TRUE(msg_handler[0].msgs.empty());
  EXPECT_EQ(3, msg_handler[0].msgs_sent_);
  for (int i = 0; i < 3; i++) {
    EXPECT_EQ(size_t(1), msg_handler[i+1].msgs.size());
    EXPECT_EQ(msg_handler[i+1].msgs.front(), sent_msgs[i]);
  }
}

TEST_F(TransportTest, BEH_TRANS_TimeoutForSendingToAWrongPeer) {
  transport::SocketId id;
  transport::TransportHandler node1_handler;
  boost::int16_t node1_id;
  transport::TransportUDT node1_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  MessageHandler msg_handler[1];
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[0], _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
//     _1, _2, _3)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[0], _1, _2)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
  transport::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64 * 1024));
  EXPECT_NE(1, node1_handler.ConnectToSend("127.0.0.1", 52002, "", 0, "", 0,
    false, &id, node1_id));
  EXPECT_EQ(1, node1_handler.Send(rpc_msg, id, true, node1_id));
  node1_handler.Stop(node1_id);
}

TEST_F(TransportTest, FUNC_TRANS_Send1000Msgs) {
  const int kNumNodes(6), kRepeatSend(200);
  // No. of times to repeat the send message.
  EXPECT_LT(2, kNumNodes);  // ensure enough nodes for test
  EXPECT_LT(1, kRepeatSend);  // ensure enough repeats to make test worthwhile
  MessageHandler msg_handler[kNumNodes];
  transport::TransportHandler* nodes[kNumNodes];
  boost::int16_t transport_ids[kNumNodes];
  transport::TransportUDT udt_transports[kNumNodes];
  transport::Port ports[kNumNodes];
  TransportNode* tnodes[kNumNodes-1];
  boost::thread_group thr_grp;
  boost::thread *thrd;
  transport::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64 * 1024));
  std::string sent_msg;
  rpc_msg.SerializeToString(&sent_msg);
  transport::TransportHandler *trans_handler;
  for (int i = 0; i < kNumNodes; ++i) {
    trans_handler = new transport::TransportHandler;
    trans_handler->Register(&udt_transports[i], &transport_ids[i]);
    nodes[i] = trans_handler;
    msg_handler[i].keep_msgs_ = false;
    msg_handler[i].target_msg_ = sent_msg;
    msg_handler[i].node_handler_ = nodes[i];
//     EXPECT_TRUE(nodes[i]->RegisterOnRPCMessage(
//         boost::bind(&MessageHandler::OnRPCMessage,
//                     &msg_handler[i], _1, _2, _3, _4)));
//     EXPECT_TRUE(nodes[i]->RegisterOnSend(
//         boost::bind(&MessageHandler::OnSend,
//                     &msg_handler[i], _1, _2)));
//     EXPECT_TRUE(nodes[i]->RegisterOnServerDown(
//         boost::bind(&MessageHandler::OnDeadRendezvousServer,
//                     &msg_handler[i], _1, _2, _3)));
    EXPECT_EQ(0, nodes[i]->Start(0, transport_ids[i]));
    ports[i] = nodes[i]->listening_port(transport_ids[i]);
    if (i != 0) {
      TransportNode *tnode = new TransportNode(nodes[i], transport_ids[i]);
      thrd = new boost::thread(&send_string, tnode, ports[0], kRepeatSend,
                               rpc_msg, false, ports[i]);
      thr_grp.add_thread(thrd);
      tnodes[i-1] = tnode;
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    } else {
      msg_handler[i].set_node(nodes[i]);
    }
  }

  thr_grp.join_all();
  int messages_size = 0;
  for (int i = 0; i < kNumNodes - 1; i++) {
    messages_size += tnodes[i]->successful_conn();
  }

  bool finished = false;
  boost::progress_timer t;
  while (!finished && t.elapsed() < 20) {
      if (msg_handler[0].msgs_received_ >= messages_size) {
        finished = true;
        continue;
      }
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  }

  for (int k = 0; k < kNumNodes; ++k)
    nodes[k]->Stop(transport_ids[k]);
  LOG(INFO) << "Total of successful connections = " << messages_size
      << std::endl;
  EXPECT_EQ(0, msg_handler[0].msgs.size());
  EXPECT_EQ(messages_size, msg_handler[0].msgs_received_);
  EXPECT_EQ(messages_size, msg_handler[0].msgs_confirmed_);
  for (int k = 0; k < kNumNodes; ++k) {
    if (k < kNumNodes - 1)
      delete tnodes[k];
    delete nodes[k];
  }
}

TEST_F(TransportTest, BEH_TRANS_GetRemotePeerAddress) {
  transport::SocketId id;
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportUDT node1_transudt, node2_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  node2_handler.Register(&node2_transudt, &node2_id);
  MessageHandler msg_handler[2];
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[0], _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
//     _1, _2, _3)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[0], _1, _2)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
  transport::Port lp_node1_handler = node1_handler.listening_port(node1_id);
//   EXPECT_TRUE(node2_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[1], _1, _2, _3, _4)));
//   EXPECT_TRUE(node2_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
//     _1, _2, _3)));
//   EXPECT_TRUE(node2_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[1], _1, _2)));
  EXPECT_EQ(0, node2_handler.Start(0, node2_id));
  transport::Port lp_node2 = node2_handler.listening_port(node2_id);
  transport::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64 * 1024));
  std::string sent_msg;
  rpc_msg.SerializeToString(&sent_msg);
  EXPECT_EQ(0, node1_handler.ConnectToSend("127.0.0.1", lp_node2, "", 0, "", 0,
    false, &id, node1_id));
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  while (msg_handler[1].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));

  struct sockaddr peer_addr;
  EXPECT_TRUE(node2_handler.peer_address(node1_id, &peer_addr));
  boost::asio::ip::address addr = base::NetworkInterface::SockaddrToAddress(
    &peer_addr);
  EXPECT_EQ(transport::IP("127.0.0.1"), addr.to_string());

  transport::Port peer_port =
    ntohs(((struct sockaddr_in *)&peer_addr)->sin_port);
  EXPECT_EQ(lp_node1_handler, peer_port);
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
}

TEST_F(TransportTest, BEH_TRANS_SendMessageFromOneToAnotherBidirectional) {
  transport::SocketId id;
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportUDT node1_transudt, node2_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  node2_handler.Register(&node2_transudt, &node2_id);
  MessageHandler msg_handler[2];
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[0], _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
//     _1, _2, _3)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[0], _1, _2)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
//   EXPECT_TRUE(node2_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[1], _1, _2, _3, _4)));
//   EXPECT_TRUE(node2_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
//     _1, _2, _3)));
//   EXPECT_TRUE(node2_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[1], _1, _2)));
  EXPECT_EQ(0, node2_handler.Start(0, node2_id));
  transport::Port lp_node2 = node2_handler.listening_port(node2_id);
  transport::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string sent_msg;
  rpc_msg.SerializeToString(&sent_msg);
  EXPECT_EQ(0, node1_handler.ConnectToSend("127.0.0.1", lp_node2, "", 0, "", 0,
    true, &id, node1_id));
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  while (msg_handler[1].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  // replying on same channel
  EXPECT_FALSE(msg_handler[1].msgs.empty());
  EXPECT_FALSE(msg_handler[1].ids.empty());
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string reply_msg;
  rpc_msg.SerializeToString(&reply_msg);
  EXPECT_EQ(0, node2_handler.Send(rpc_msg, msg_handler[1].ids.front(), false,
    node2_id));
  while (msg_handler[0].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  // Closing the connection
  node1_handler.CloseConnection(msg_handler[0].ids.front(), node1_id);
  node2_handler.CloseConnection(msg_handler[1].ids.front(), node2_id);
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
  EXPECT_FALSE(msg_handler[0].msgs.empty());
  EXPECT_EQ(sent_msg, msg_handler[1].msgs.front());
  EXPECT_EQ(reply_msg, msg_handler[0].msgs.front());
  EXPECT_EQ(1, msg_handler[0].msgs_sent_);
  EXPECT_EQ(1, msg_handler[1].msgs_sent_);
}

TEST_F(TransportTest, BEH_TRANS_SendMsgsFromManyToOneBidirectional) {
  transport::SocketId id;
  transport::TransportHandler node1_handler, node2_handler, node3_handler,
    node4_handler;
  transport::TransportUDT node1_transudt, node2_transudt, node3_transudt,
    node4_transudt;
  boost::int16_t node1_id, node2_id, node3_id, node4_id;
  node1_handler.Register(&node1_transudt, &node1_id);
  node2_handler.Register(&node2_transudt, &node2_id);
  node3_handler.Register(&node3_transudt, &node3_id);
  node4_handler.Register(&node4_transudt, &node4_id);
  MessageHandler msg_handler[4];
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[0], _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
//     _1, _2, _3)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[0], _1, _2)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
//   EXPECT_TRUE(node2_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[1], _1, _2, _3, _4)));
//   EXPECT_TRUE(node2_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
//     _1, _2, _3)));
//   EXPECT_TRUE(node2_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[1], _1, _2)));
  EXPECT_EQ(0, node2_handler.Start(0, node2_id));
//   EXPECT_TRUE(node3_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[2], _1, _2, _3, _4)));
//   EXPECT_TRUE(node3_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[2],
//     _1, _2, _3)));
//   EXPECT_TRUE(node3_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[2], _1, _2)));
  EXPECT_EQ(0, node3_handler.Start(0, node3_id));
//   EXPECT_TRUE(node4_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[3], _1, _2, _3, _4)));
//   EXPECT_TRUE(node4_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[3],
//     _1, _2, _3)));
//   EXPECT_TRUE(node4_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[3], _1, _2)));
  EXPECT_EQ(0, node4_handler.Start(0, node4_id));
  transport::Port lp_node4 = node4_handler.listening_port(node4_id);
  transport::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(64 * 1024));
  std::string ser_rpc_msg;
  rpc_msg.SerializeToString(&ser_rpc_msg);
  std::list<std::string> sent_msgs;
  sent_msgs.push_back(ser_rpc_msg);
  EXPECT_EQ(0, node1_handler.ConnectToSend("127.0.0.1", lp_node4, "", 0, "", 0,
    true, &id, node1_id));
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs.push_back(ser_rpc_msg);
  EXPECT_EQ(0, node2_handler.ConnectToSend("127.0.0.1", lp_node4, "", 0, "", 0,
    true, &id, node2_id));
  EXPECT_EQ(0, node2_handler.Send(rpc_msg, id, true, node2_id));
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  rpc_msg.SerializeToString(&ser_rpc_msg);
  sent_msgs.push_back(ser_rpc_msg);
  EXPECT_EQ(0, node3_handler.ConnectToSend("127.0.0.1", lp_node4, "", 0, "", 0,
    true, &id, node3_id));
  EXPECT_EQ(0, node3_handler.Send(rpc_msg, id, true, node3_id));
  // waiting for all messages to be delivered
  while (msg_handler[3].msgs.size() != size_t(3))
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  // node4_handler responding to all nodes
  std::list<transport::SocketId>::iterator it;
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(64 * 1024));
  std::string reply_str;
  rpc_msg.SerializeToString(&reply_str);
  for (it = msg_handler[3].ids.begin(); it != msg_handler[3].ids.end(); it++) {
    EXPECT_EQ(0, node4_handler.Send(rpc_msg, *it, false, node4_id));
  }
  // waiting for all replies to arrive
  while (msg_handler[0].msgs.empty() || msg_handler[1].msgs.empty() ||
         msg_handler[2].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));

  for (it = msg_handler[0].ids.begin(); it != msg_handler[0].ids.end(); it++)
    node1_handler.CloseConnection(*it, node1_id);
  for (it = msg_handler[1].ids.begin(); it != msg_handler[1].ids.end(); it++)
    node2_handler.CloseConnection(*it, node2_id);
  for (it = msg_handler[2].ids.begin(); it != msg_handler[2].ids.end(); it++)
    node3_handler.CloseConnection(*it, node3_id);
  for (it = msg_handler[3].ids.begin(); it != msg_handler[3].ids.end(); it++)
    node3_handler.CloseConnection(*it, node4_id);

  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
  node3_handler.Stop(node3_id);
  node4_handler.Stop(node4_id);
  for (int i = 0; i < 4; i++) {
    EXPECT_FALSE(msg_handler[i].msgs.empty());
    if (i == 3)
      EXPECT_EQ(3, msg_handler[i].msgs_sent_);
    else
      EXPECT_EQ(1, msg_handler[i].msgs_sent_);
  }
  EXPECT_FALSE(msg_handler[3].msgs.empty());
  EXPECT_EQ(msg_handler[3].msgs.size(), size_t(3));
  msg_handler[3].msgs.sort();
  sent_msgs.sort();
  for (int i = 0; i < 3; i++) {
    EXPECT_EQ(msg_handler[3].msgs.front(), sent_msgs.front());
    msg_handler[3].msgs.pop_front();
    sent_msgs.pop_front();
    EXPECT_EQ(size_t(1), msg_handler[i].msgs.size());
    EXPECT_EQ(reply_str, msg_handler[i].msgs.front());
  }
  EXPECT_EQ(3, msg_handler[3].msgs_sent_);
}

TEST_F(TransportTest, BEH_TRANS_SendOneMessageCloseAConnection) {
  transport::SocketId id;
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportUDT node1_transudt, node2_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  node2_handler.Register(&node2_transudt, &node2_id);
  MessageHandler msg_handler[2];
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[0], _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
//     _1, _2, _3)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[0], _1, _2)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
//   EXPECT_TRUE(node2_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[1], _1, _2, _3, _4)));
//   EXPECT_TRUE(node2_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
//     _1, _2, _3)));
//   EXPECT_TRUE(node2_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[1], _1, _2)));
  EXPECT_EQ(0, node2_handler.Start(0, node2_id));
  transport::Port lp_node2 = node2_handler.listening_port(node2_id);
  transport::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string sent_msg;
  rpc_msg.SerializeToString(&sent_msg);
  EXPECT_EQ(0, node1_handler.ConnectToSend("127.0.0.1", lp_node2, "", 0, "", 0,
    true, &id, node1_id));
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  while (msg_handler[1].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  // replying on same channel
  EXPECT_FALSE(msg_handler[1].msgs.empty());
  EXPECT_FALSE(msg_handler[1].ids.empty());
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string reply_msg;
  rpc_msg.SerializeToString(&reply_msg);
  node1_handler.CloseConnection(id, node1_id);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  EXPECT_EQ(1, node2_handler.Send(rpc_msg, msg_handler[1].ids.front(), false,
    node2_id));
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  // Closing the connection
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
  EXPECT_TRUE(msg_handler[0].msgs.empty());
  EXPECT_EQ(sent_msg, msg_handler[1].msgs.front());
}

TEST_F(TransportTest, FUNC_TRANS_PingRendezvousServer) {
  transport::TransportHandler node1_handler, rendezvous_node;
  boost::int16_t node1_id, rendezvous_id;
  transport::TransportUDT node1_transudt, rv_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  rendezvous_node.Register(&rv_transudt, &rendezvous_id);
  MessageHandler msg_handler[2];
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[0], _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
//     _1, _2, _3)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[0], _1, _2)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
//   EXPECT_TRUE(rendezvous_node.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[1], _1, _2, _3, _4)));
//   EXPECT_TRUE(rendezvous_node.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
//     _1, _2, _3)));
//   EXPECT_TRUE(rendezvous_node.RegisterOnSend(
//               boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  EXPECT_EQ(0, rendezvous_node.Start(0, rendezvous_id));
  transport::Port lp_rvn = rendezvous_node.listening_port(rendezvous_id);
  node1_handler.StartPingRendezvous(false, "127.0.0.1", lp_rvn, node1_id);
  boost::this_thread::sleep(boost::posix_time::seconds(12));
  node1_handler.Stop(node1_id);
  EXPECT_FALSE(msg_handler[0].dead_server_);
  EXPECT_EQ(transport::IP(""), msg_handler[0].server_ip_);
  EXPECT_EQ(0, msg_handler[0].server_port_);
  rendezvous_node.Stop(rendezvous_id);
}

TEST_F(TransportTest, FUNC_TRANS_PingDeadRendezvousServer) {
  transport::TransportHandler node1_handler, rendezvous_node;
  boost::int16_t node1_id, rendezvous_id;
  transport::TransportUDT node1_transudt, rv_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  rendezvous_node.Register(&rv_transudt, &rendezvous_id);
  MessageHandler msg_handler[2];
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[0], _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
//     _1, _2, _3)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[0], _1, _2)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
//   EXPECT_TRUE(rendezvous_node.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[1], _1, _2, _3, _4)));
//   EXPECT_TRUE(rendezvous_node.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
//     _1, _2, _3)));
//   EXPECT_TRUE(rendezvous_node.RegisterOnSend(
//               boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  EXPECT_EQ(0, rendezvous_node.Start(0, rendezvous_id));
  transport::Port lp_rvn = rendezvous_node.listening_port(rendezvous_id);
  node1_handler.StartPingRendezvous(false, "127.0.0.1", lp_rvn, node1_id);
  boost::this_thread::sleep(boost::posix_time::seconds(12));
  EXPECT_FALSE(msg_handler[0].dead_server_);
  EXPECT_EQ(transport::IP(""), msg_handler[0].server_ip_);
  EXPECT_EQ(0, msg_handler[0].server_port_);
  rendezvous_node.Stop(rendezvous_id);
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  node1_handler.Stop(node1_id);
  EXPECT_TRUE(msg_handler[0].dead_server_);
  EXPECT_EQ(transport::IP("127.0.0.1"), msg_handler[0].server_ip_);
  EXPECT_EQ(lp_rvn, msg_handler[0].server_port_);
}

TEST_F(TransportTest, FUNC_TRANS_ReconnectToDifferentServer) {
  transport::TransportHandler node1_handler, rendezvous_node1,
    rendezvous_node2;
  boost::int16_t node1_id, rendezvous_node1_id, rendezvous_node2_id;
  transport::TransportUDT node1_transudt, rv1_transudt, rv2_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  rendezvous_node1.Register(&rv1_transudt, &rendezvous_node1_id);
  rendezvous_node2.Register(&rv2_transudt, &rendezvous_node2_id);
  MessageHandler msg_handler[3];
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[0], _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
//     _1, _2, _3)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[0], _1, _2)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
//   EXPECT_TRUE(rendezvous_node1.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[1], _1, _2, _3, _4)));
//   EXPECT_TRUE(rendezvous_node1.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
//     _1, _2, _3)));
//   EXPECT_TRUE(rendezvous_node1.RegisterOnSend(
//               boost::bind(&MessageHandler::OnSend, &msg_handler[1], _1, _2)));
  EXPECT_EQ(0, rendezvous_node1.Start(0, rendezvous_node1_id));
  transport::Port lp_rvn1 = rendezvous_node1.listening_port(
    rendezvous_node1_id);
//   EXPECT_TRUE(rendezvous_node2.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[2], _1, _2, _3, _4)));
//   EXPECT_TRUE(rendezvous_node2.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[2],
//     _1, _2, _3)));
//   EXPECT_TRUE(rendezvous_node2.RegisterOnSend(
//               boost::bind(&MessageHandler::OnSend, &msg_handler[2], _1, _2)));
  EXPECT_EQ(0, rendezvous_node2.Start(0, rendezvous_node2_id));
  transport::Port lp_rvn2 = rendezvous_node2.listening_port(
    rendezvous_node2_id);
  node1_handler.StartPingRendezvous(false, "127.0.0.1", lp_rvn1, node1_id);
  boost::this_thread::sleep(boost::posix_time::seconds(12));
  EXPECT_FALSE(msg_handler[0].dead_server_);
  EXPECT_EQ(transport::IP(""), msg_handler[0].server_ip_);
  EXPECT_EQ(0, msg_handler[0].server_port_);
  rendezvous_node1.Stop(rendezvous_node1_id);
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  EXPECT_TRUE(msg_handler[0].dead_server_);
  EXPECT_EQ(transport::IP("127.0.0.1"), msg_handler[0].server_ip_);
  EXPECT_EQ(lp_rvn1, msg_handler[0].server_port_);
  node1_handler.StartPingRendezvous(false, "127.0.0.1", lp_rvn2, node1_id);
  boost::this_thread::sleep(boost::posix_time::seconds(12));
  EXPECT_FALSE(msg_handler[0].dead_server_);
  EXPECT_EQ(transport::IP(""), msg_handler[0].server_ip_);
  EXPECT_EQ(0, msg_handler[0].server_port_);
  node1_handler.Stop(node1_id);
  rendezvous_node2.Stop(rendezvous_node2_id);
}

TEST_F(TransportTest, FUNC_TRANS_StartStopTransport) {
  transport::SocketId id;
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportUDT node1_transudt, node2_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  node2_handler.Register(&node2_transudt, &node2_id);
  MessageHandler msg_handler[2];
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[0], _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[0],
//     _1, _2, _3)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[0], _1, _2)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
  transport::Port lp_node1_handler = node1_handler.listening_port(node1_id);
//   EXPECT_TRUE(node2_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[1], _1, _2, _3, _4)));
//   EXPECT_TRUE(node2_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
//     _1, _2, _3)));
//   EXPECT_TRUE(node2_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler[1], _1, _2)));
  EXPECT_EQ(0, node2_handler.Start(0, node2_id));
  transport::Port lp_node2 = node2_handler.listening_port(node2_id);
  transport::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string sent_msg;
  rpc_msg.SerializeToString(&sent_msg);
  EXPECT_EQ(0, node1_handler.ConnectToSend("127.0.0.1", lp_node2, "", 0, "", 0,
    false, &id, node1_id));
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  while (msg_handler[1].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_FALSE(msg_handler[1].msgs.empty());
  EXPECT_EQ(sent_msg, msg_handler[1].msgs.front());
  msg_handler[1].msgs.clear();
  // A message was received by node2_handler, now start and stop it 5 times
  for (int i = 0 ; i < 5; i++) {
    node2_handler.Stop(node2_id);
//     EXPECT_TRUE(node2_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage,
//                 &msg_handler[1], _1, _2, _3, _4)));
//     EXPECT_TRUE(node2_handler.RegisterOnServerDown(
//       boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler[1],
//       _1, _2, _3)));
//     EXPECT_TRUE(node2_handler.RegisterOnSend(boost::bind(
//       &MessageHandler::OnSend, &msg_handler[1], _1, _2)));
    EXPECT_EQ(0, node2_handler.Start(0, node2_id));
    lp_node2 = node2_handler.listening_port(node2_id);
    // Sending another message
    rpc_msg.clear_args();
    rpc_msg.set_args(base::RandomString(256 * 1024));
    rpc_msg.SerializeToString(&sent_msg);
    EXPECT_EQ(0, node1_handler.ConnectToSend("127.0.0.1", lp_node2, "", 0, "",
      0, false, &id, node1_id));
    EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
    while (msg_handler[1].msgs.empty())
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    EXPECT_FALSE(msg_handler[1].msgs.empty());
    EXPECT_EQ(sent_msg, msg_handler[1].msgs.front());
    msg_handler[1].msgs.clear();

    rpc_msg.clear_args();
    rpc_msg.set_args(base::RandomString(256 * 1024));
    rpc_msg.SerializeToString(&sent_msg);
    EXPECT_EQ(0, node2_handler.ConnectToSend("127.0.0.1", lp_node1_handler, "",
      0, "", 0, false, &id, node2_id));
    EXPECT_EQ(0, node2_handler.Send(rpc_msg, id, true, node2_id));
    while (msg_handler[0].msgs.empty())
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    EXPECT_FALSE(msg_handler[0].msgs.empty());
    EXPECT_EQ(sent_msg, msg_handler[0].msgs.front());
    msg_handler[0].msgs.clear();

    boost::this_thread::sleep(boost::posix_time::seconds(2));
  }
  // Sending another message
  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(256 * 1024));
  rpc_msg.SerializeToString(&sent_msg);
  EXPECT_EQ(0, node1_handler.ConnectToSend("127.0.0.1", lp_node2, "", 0, "", 0,
    false, &id, node2_id));
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  while (msg_handler[1].msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_FALSE(msg_handler[1].msgs.empty());
  EXPECT_EQ(sent_msg, msg_handler[1].msgs.front());

  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
}

TEST_F(TransportTest, BEH_TRANS_SendRespond) {
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportUDT node1_transudt, node2_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  node2_handler.Register(&node2_transudt, &node2_id);
  MessageHandlerEchoRequest msg_handler1(&node1_handler);
  MessageHandlerEchoResponse msg_handler2(&node2_handler);
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(boost::bind(
//     &MessageHandlerEchoRequest::OnRPCMessage, &msg_handler1, _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(
//     &MessageHandlerEchoRequest::OnSend, &msg_handler1, _1, _2)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(boost::bind(
//     &MessageHandlerEchoRequest::OnDeadRendezvousServer,
//     &msg_handler1, _1, _2, _3)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
  transport::Port lp_node1_handler = node1_handler.listening_port(node1_id);
//   EXPECT_TRUE(node2_handler.RegisterOnRPCMessage(boost::bind(
//     &MessageHandlerEchoResponse::OnRPCMessage, &msg_handler2, _1, _2, _3, _4)));
//   EXPECT_TRUE(node2_handler.RegisterOnSend(boost::bind(
//     &MessageHandlerEchoResponse::OnSend, &msg_handler2, _1, _2)));
//   EXPECT_TRUE(node2_handler.RegisterOnServerDown(boost::bind(
//     &MessageHandlerEchoResponse::OnDeadRendezvousServer,
//     &msg_handler2, _1, _2, _3)));
  EXPECT_EQ(0, node2_handler.Start(0, node2_id));
  std::vector<std::string> msgs;
  unsigned int msgs_sent = 12;
  transport::SocketId id;
  boost::asio::ip::address local_address;
  transport::IP ip;
  if (base::GetLocalAddress(&local_address)) {
    ip = local_address.to_string();
  } else {
    ip = transport::IP("127.0.0.1");
  }
  for (unsigned int i = 0; i < msgs_sent; i++) {
    transport::RpcMessage rpc_msg;
    rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
    rpc_msg.set_message_id(2000);
    rpc_msg.set_args(base::RandomString(256 * 1024));
    std::string ser_rpc_msg;
    rpc_msg.SerializeToString(&ser_rpc_msg);
    msgs.push_back(ser_rpc_msg);
    EXPECT_EQ(0, node2_handler.ConnectToSend(ip, lp_node1_handler, "", 0, "", 0,
      true, &id, node2_id));
    EXPECT_EQ(0, node2_handler.Send(rpc_msg, id, true, node2_id));
  }
  bool finished = false;
  boost::progress_timer t;
  while (!finished && t.elapsed() < 10) {
      if (msg_handler1.msgs.size() == msgs_sent &&
          msg_handler2.msgs.size() == size_t(9)) {
        finished = true;
        continue;
      }
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  }
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
  EXPECT_EQ(msgs_sent, msg_handler1.msgs.size());
  for (unsigned int i = 0; i < msgs_sent; i++) {
    for (unsigned int j = 0; j < msgs_sent; j++) {
      if (msgs[j] == msg_handler1.msgs.front()) {
        msg_handler1.msgs.pop_front();
        break;
      }
    }
  }
  EXPECT_TRUE(msg_handler1.msgs.empty());
  EXPECT_EQ(size_t(9), msg_handler2.msgs.size());
  for (int i = 0; i < 9; i++) {
    for (unsigned int j = 0; j < msgs_sent; j++) {
      if (msgs[j] == msg_handler2.msgs.front()) {
        msg_handler2.msgs.pop_front();
        break;
      }
    }
  }
  EXPECT_TRUE(msg_handler2.msgs.empty());
}

TEST_F(TransportTest, BEH_TRANS_FailStartUsedport) {
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportUDT node1_transudt, node2_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  node2_handler.Register(&node2_transudt, &node2_id);
  MessageHandler msg_handler1;
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1, _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler1,
//     _1, _2, _3)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler1, _1, _2)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
  transport::Port lp_node1_handler = node1_handler.listening_port(node1_id);
  EXPECT_EQ(1, node2_handler.Start(lp_node1_handler, node2_id));
  node1_handler.Stop(node1_id);
}

TEST_F(TransportTest, BEH_TRANS_SendMultipleMsgsSameConnection) {
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportUDT node1_transudt, node2_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  node2_handler.Register(&node2_transudt, &node2_id);
  MessageHandler msg_handler1, msg_handler2;
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1, _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler1,
//     _1, _2, _3)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler1, _1, _2)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
//   EXPECT_TRUE(node2_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler2, _1, _2, _3, _4)));
//   EXPECT_TRUE(node2_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler2,
//     _1, _2, _3)));
//   EXPECT_TRUE(node2_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler2, _1, _2)));
  EXPECT_EQ(0, node2_handler.Start(0, node2_id));
  transport::Port lp_node2 = node2_handler.listening_port(node2_id);
  transport::SocketId id;
  boost::asio::ip::address local_address;
  transport::IP ip;
  if (base::GetLocalAddress(&local_address)) {
    ip = local_address.to_string();
  } else {
    ip = transport::IP("127.0.0.1");
  }
  transport::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string msg;
  rpc_msg.SerializeToString(&msg);
  EXPECT_EQ(0, node1_handler.ConnectToSend(ip, lp_node2, "", 0, "", 0, true,
    &id, node1_id));
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  while (msg_handler2.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_FALSE(msg_handler2.msgs.empty());
  EXPECT_EQ(msg, msg_handler2.msgs.front());
  msg_handler2.msgs.clear();

  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(256 * 1024));
  rpc_msg.SerializeToString(&msg);
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, false, node1_id));
  while (msg_handler2.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_FALSE(msg_handler2.msgs.empty());
  EXPECT_EQ(msg, msg_handler2.msgs.front());
  msg_handler2.msgs.clear();

  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(256 * 1024));
  rpc_msg.SerializeToString(&msg);
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, false, node1_id));
  while (msg_handler2.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_FALSE(msg_handler2.msgs.empty());
  EXPECT_EQ(msg, msg_handler2.msgs.front());
  msg_handler2.msgs.clear();

  rpc_msg.clear_args();
  rpc_msg.set_args(base::RandomString(256 * 1024));
  rpc_msg.SerializeToString(&msg);
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, false, node1_id));
  while (msg_handler2.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_FALSE(msg_handler2.msgs.empty());
  EXPECT_EQ(msg, msg_handler2.msgs.front());
  msg_handler2.msgs.clear();
  EXPECT_EQ(4, msg_handler1.msgs_sent_);

  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
}

TEST_F(TransportTest, BEH_TRANS_SendViaRdz) {
  transport::TransportHandler node1_handler, node2_handler, node3_handler;
  boost::int16_t node1_id, node2_id, node3_id;
  transport::TransportUDT node1_transudt, node2_transudt, node3_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  node2_handler.Register(&node2_transudt, &node2_id);
  node3_handler.Register(&node3_transudt, &node3_id);
  MessageHandler msg_handler1, msg_handler2, msg_handler3;
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1, _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler1,
//     _1, _2, _3)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler1, _1, _2)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
  transport::Port lp_node1_handler = node1_handler.listening_port(node1_id);
//   EXPECT_TRUE(node2_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler2, _1, _2, _3, _4)));
//   EXPECT_TRUE(node2_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler2,
//     _1, _2, _3)));
//   EXPECT_TRUE(node2_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler2, _1, _2)));
  EXPECT_EQ(0, node2_handler.Start(0, node2_id));
//   EXPECT_TRUE(node3_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler3, _1, _2, _3, _4)));
//   EXPECT_TRUE(node3_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler3,
//     _1, _2, _3)));
//   EXPECT_TRUE(node3_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler3, _1, _2)));
  EXPECT_EQ(0, node3_handler.Start(0, node3_id));
  transport::Port lp_node3 = node3_handler.listening_port(node3_id);
  node1_handler.StartPingRendezvous(false, "127.0.0.1", lp_node3, node1_id);
  transport::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string sent_msg;
  rpc_msg.SerializeToString(&sent_msg);
  transport::SocketId id;
  EXPECT_EQ(0, node2_handler.ConnectToSend("127.0.0.1", lp_node1_handler, "", 0,
    "127.0.0.1", lp_node3, true, &id, node2_id));
  EXPECT_EQ(0, node2_handler.Send(rpc_msg, id, true, node2_id));
  while (msg_handler1.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
  node3_handler.Stop(node3_id);
  EXPECT_FALSE(msg_handler1.msgs.empty());
  EXPECT_EQ(sent_msg, msg_handler1.msgs.front());
  EXPECT_EQ(1, msg_handler2.msgs_sent_);
}

TEST_F(TransportTest, BEH_TRANS_NoNotificationForInvalidMsgs) {
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportUDT node1_transudt, node2_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  node2_handler.Register(&node2_transudt, &node2_id);
  UDT::startup();
  MessageHandler msg_handler1, msg_handler2;
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1, _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler1,
//     _1, _2, _3)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler1, _1, _2)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
  transport::Port lp_node1_handler = node1_handler.listening_port(node1_id);
//   EXPECT_TRUE(node2_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler2, _1, _2, _3, _4)));
//   EXPECT_TRUE(node2_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler2,
//     _1, _2, _3)));
//   EXPECT_TRUE(node2_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler2, _1, _2)));
  EXPECT_EQ(0, node2_handler.Start(0, node2_id));
  transport::SocketId id;
  EXPECT_EQ(0, node2_handler.ConnectToSend("127.0.0.1", lp_node1_handler, "", 0,
    "", 0, true, &id, node2_id));
  transport::RpcMessage rpc_msg;
  EXPECT_EQ(1, node2_handler.Send(rpc_msg, id, true, node2_id));
  EXPECT_EQ(0, node2_handler.ConnectToSend("127.0.0.1", lp_node1_handler, "", 0,
    "", 0, true, &id, node2_id));
  EXPECT_EQ(1, node2_handler.Send("", id, true, node2_id));
  // sending an invalid message
  std::string msg = base::RandomString(50);
  EXPECT_EQ(0, node2_handler.ConnectToSend("127.0.0.1", lp_node1_handler, "", 0,
    "", 0, true, &id, node2_id));
  EXPECT_EQ(0, node2_handler.Send(msg, id, true, node2_id));
  boost::this_thread::sleep(boost::posix_time::seconds(3));
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
  EXPECT_TRUE(msg_handler1.msgs.empty());
  EXPECT_TRUE(msg_handler2.msgs.empty());
}

TEST_F(TransportTest, BEH_TRANS_NotificationForInvalidMsgs) {
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportUDT node1_transudt, node2_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  node2_handler.Register(&node2_transudt, &node2_id);
  UDT::startup();
  MessageHandler msg_handler1, msg_handler2;
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1, _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler1,
//     _1, _2, _3)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler1, _1, _2)));
//   EXPECT_TRUE(node1_handler.RegisterOnMessage(
//     boost::bind(&MessageHandler::OnMessage, &msg_handler1, _1, _2, _3, _4)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
  transport::Port lp_node1_handler = node1_handler.listening_port(node1_id);
//   EXPECT_TRUE(node2_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler2, _1, _2, _3, _4)));
//   EXPECT_TRUE(node2_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler2,
//     _1, _2, _3)));
//   EXPECT_TRUE(node2_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler2, _1, _2)));
//   EXPECT_TRUE(node2_handler.RegisterOnMessage(
//     boost::bind(&MessageHandler::OnMessage, &msg_handler2, _1, _2, _3, _4)));
  EXPECT_EQ(0, node2_handler.Start(0, node2_id));
  transport::SocketId id;
  // sending an invalid message
  std::string msg = base::RandomString(50);
  EXPECT_EQ(0, node2_handler.ConnectToSend("127.0.0.1", lp_node1_handler, "", 0,
    "", 0, true, &id, node2_id));
  EXPECT_EQ(0, node2_handler.Send(msg, id, true, node2_id));
  while (msg_handler1.raw_msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
  EXPECT_TRUE(msg_handler1.msgs.empty());
  EXPECT_FALSE(msg_handler1.raw_msgs.empty());
  EXPECT_EQ(size_t(1), msg_handler1.raw_msgs.size());
  EXPECT_EQ(msg, msg_handler1.raw_msgs.front());
  EXPECT_TRUE(msg_handler2.msgs.empty());
}

TEST_F(TransportTest, BEH_TRANS_AddrUsable) {
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportUDT node1_transudt, node2_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  node2_handler.Register(&node2_transudt, &node2_id);
  MessageHandler msg_handler1, msg_handler2;
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1, _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler1,
//     _1, _2, _3)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler1, _1, _2)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
//   EXPECT_TRUE(node2_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler2, _1, _2, _3, _4)));
//   EXPECT_TRUE(node2_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler2,
//     _1, _2, _3)));
//   EXPECT_TRUE(node2_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler2, _1, _2)));
  EXPECT_EQ(0, node2_handler.Start(0, node2_id));
  transport::Port lp_node2 = node2_handler.listening_port(node2_id);
  EXPECT_FALSE(node1_handler.IsAddressUsable("", "127.0.0.1", lp_node2,
               node1_id));
  EXPECT_FALSE(node1_handler.IsAddressUsable("127.0.0.1", "", lp_node2,
               node1_id));
  std::vector<transport::IP> local_ips = base::GetLocalAddresses();
  if (local_ips.size() > size_t(0)) {
    transport::IP server_addr = "127.0.0.1";
    for (boost::uint32_t i = 0; i < local_ips.size(); i++) {
      LOG(INFO) << "Checking local address " << local_ips[i] <<
          " connecting to address " << server_addr << std::endl;
      EXPECT_FALSE(node1_handler.IsAddressUsable(local_ips[i], server_addr,
        lp_node2, node1_id));
    }
    EXPECT_TRUE(node1_handler.IsAddressUsable(local_ips[0], local_ips[0],
                lp_node2, node1_id));
  } else {
    LOG(INFO) << "No local addresses where retrieved" << std::endl;
  }
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
}

TEST_F(TransportTest, BEH_TRANS_StartLocal) {
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportUDT node1_transudt, node2_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  node2_handler.Register(&node2_transudt, &node2_id);
  MessageHandler msg_handler1, msg_handler2;
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1, _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler1, _1, _2)));
//   EXPECT_TRUE(node1_handler.RegisterOnMessage(
//     boost::bind(&MessageHandler::OnMessage, &msg_handler1, _1, _2, _3, _4)));
  EXPECT_EQ(0, node1_handler.StartLocal(0, node1_id));
//   EXPECT_TRUE(node2_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler2, _1, _2, _3, _4)));
//   EXPECT_TRUE(node2_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler2, _1, _2)));
//   EXPECT_TRUE(node2_handler.RegisterOnMessage(
//     boost::bind(&MessageHandler::OnMessage, &msg_handler2, _1, _2, _3, _4)));
  EXPECT_EQ(0, node2_handler.StartLocal(0, node1_id));
  transport::Port lp_node2 = node2_handler.listening_port(node2_id);
  transport::SocketId id;
  boost::asio::ip::address local_address;
  transport::IP local_ip;
  transport::IP loop_back("127.0.0.1");
  if (base::GetLocalAddress(&local_address)) {
    local_ip = local_address.to_string();
  } else {
    FAIL() << "Can not get local address";
  }
  EXPECT_NE(loop_back, local_ip);
  EXPECT_NE(0, node1_handler.ConnectToSend(local_ip, lp_node2, "", 0, "", 0,
    true, &id, node1_id));
  EXPECT_EQ(0, node1_handler.ConnectToSend(loop_back, lp_node2, "", 0, "", 0,
    true, &id, node1_id));
  transport::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string msg;
  rpc_msg.SerializeToString(&msg);
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  while (msg_handler2.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_FALSE(msg_handler2.msgs.empty());
  EXPECT_EQ(msg, msg_handler2.msgs.front());
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
}

TEST_F(TransportTest, FUNC_TRANS_StartStopLocal) {
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportUDT node1_transudt, node2_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  node2_handler.Register(&node2_transudt, &node2_id);
  MessageHandler msg_handler1, msg_handler2;
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1, _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler1, _1, _2)));
//   EXPECT_TRUE(node1_handler.RegisterOnMessage(
//     boost::bind(&MessageHandler::OnMessage, &msg_handler1, _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(boost::bind(
//     &MessageHandler::OnDeadRendezvousServer, &msg_handler1, _1, _2, _3)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
//   EXPECT_TRUE(node2_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler2, _1, _2, _3, _4)));
//   EXPECT_TRUE(node2_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler2, _1, _2)));
//   EXPECT_TRUE(node2_handler.RegisterOnMessage(
//     boost::bind(&MessageHandler::OnMessage, &msg_handler2, _1, _2, _3, _4)));
  EXPECT_EQ(0, node2_handler.StartLocal(0, node2_id));
  transport::Port lp_node2 = node2_handler.listening_port(node2_id);
  transport::SocketId id;
  boost::asio::ip::address local_address;
  transport::IP local_ip;
  transport::IP loop_back("127.0.0.1");
  if (base::GetLocalAddress(&local_address)) {
    local_ip = local_address.to_string();
  } else {
    FAIL() << "Can not get local address";
  }
  EXPECT_NE(loop_back, local_ip);
  EXPECT_NE(0, node1_handler.ConnectToSend(local_ip, lp_node2, "", 0, "", 0,
    true, &id, node1_id));
  EXPECT_EQ(0, node1_handler.ConnectToSend(loop_back, lp_node2, "", 0, "", 0,
    true, &id, node1_id));

  transport::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string msg;
  rpc_msg.SerializeToString(&msg);
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  while (msg_handler2.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_FALSE(msg_handler2.msgs.empty());
  EXPECT_EQ(msg, msg_handler2.msgs.front());
  std::string raw_msg = base::RandomString(50);
  EXPECT_EQ(0, node1_handler.ConnectToSend(loop_back, lp_node2, "", 0, "", 0,
    true, &id, node1_id));
  EXPECT_EQ(0, node1_handler.Send(raw_msg, id, true, node1_id));

  while (msg_handler2.raw_msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_FALSE(msg_handler2.raw_msgs.empty());
  EXPECT_EQ(raw_msg, msg_handler2.raw_msgs.front());
  node2_handler.Stop(node2_id);
  msg_handler2.msgs.clear();
//   EXPECT_TRUE(node2_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler2, _1, _2, _3, _4)));
//   EXPECT_TRUE(node2_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler2, _1, _2)));
//   EXPECT_TRUE(node2_handler.RegisterOnMessage(
//     boost::bind(&MessageHandler::OnMessage, &msg_handler2, _1, _2, _3, _4)));
//   EXPECT_TRUE(node2_handler.RegisterOnServerDown(boost::bind(
//     &MessageHandler::OnDeadRendezvousServer, &msg_handler2, _1, _2, _3)));
  EXPECT_EQ(0, node2_handler.Start(0, node2_id));
  lp_node2 = node2_handler.listening_port(node2_id);
  EXPECT_EQ(0, node1_handler.ConnectToSend(local_ip, lp_node2, "", 0, "", 0,
    true, &id, node1_id));
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  while (msg_handler2.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_FALSE(msg_handler2.msgs.empty());
  EXPECT_EQ(msg, msg_handler2.msgs.front());
  msg_handler2.msgs.clear();
  EXPECT_EQ(0, node1_handler.ConnectToSend(loop_back, lp_node2, "", 0, "", 0,
    true, &id, node1_id));
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  while (msg_handler2.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_FALSE(msg_handler2.msgs.empty());
  EXPECT_EQ(msg, msg_handler2.msgs.front());
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
}

TEST_F(TransportTest, BEH_TRANS_CheckPortAvailable) {
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportUDT node1_transudt, node2_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  node2_handler.Register(&node2_transudt, &node2_id);
  MessageHandler msg_handler1;
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1, _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler1, _1, _2)));
//   EXPECT_TRUE(node1_handler.RegisterOnMessage(
//     boost::bind(&MessageHandler::OnMessage, &msg_handler1, _1, _2, _3, _4)));
  EXPECT_EQ(0, node1_handler.StartLocal(0, node1_id));
  transport::Port lp_node1_handler(node1_handler.listening_port(node1_id));
  EXPECT_FALSE(node2_handler.IsPortAvailable(lp_node1_handler, node2_id));
  EXPECT_TRUE(node2_handler.IsPortAvailable(lp_node1_handler+1, node2_id));
  node1_handler.Stop(node1_id);
  EXPECT_TRUE(node2_handler.IsPortAvailable(lp_node1_handler, node2_id));
}

TEST_F(TransportTest, FUNC_TRANS_StartBadLocal) {
  transport::TransportHandler node1_handler, node2_handler;
  boost::int16_t node1_id, node2_id;
  transport::TransportUDT node1_transudt, node2_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  node2_handler.Register(&node2_transudt, &node2_id);
  MessageHandler msg_handler1, msg_handler2;
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1, _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler1, _1, _2)));
//   EXPECT_TRUE(node1_handler.RegisterOnMessage(
//     boost::bind(&MessageHandler::OnMessage, &msg_handler1, _1, _2, _3, _4)));
  EXPECT_EQ(0, node1_handler.StartLocal(0, node1_id));
//   EXPECT_TRUE(node2_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler2, _1, _2, _3, _4)));
//   EXPECT_TRUE(node2_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler2, _1, _2)));
//   EXPECT_TRUE(node2_handler.RegisterOnMessage(
//     boost::bind(&MessageHandler::OnMessage, &msg_handler2, _1, _2, _3, _4)));
  EXPECT_EQ(0, node2_handler.StartLocal(0, node2_id));
  transport::Port lp_node2 = node2_handler.listening_port(node2_id);
  transport::SocketId id;
  transport::IP loop_back("127.0.0.1");

  // Add node 2 to routing table as a local contact
  std::string kademlia_id = base::RandomString(64);
  transport::IP bad_local_ip("192.168.1.188");
  transport::Port bad_local_port = 8888;
  transport::IP rendezvous_ip("");
  transport::Port rendezvous_port = 0;
  std::string public_key = base::RandomString(64);
  float rtt = 32;
  boost::uint16_t rank = 5;
  boost::uint32_t space = 3232;
  base::PublicRoutingTableTuple tuple_to_store(kademlia_id, bad_local_ip,
      bad_local_port, rendezvous_ip, rendezvous_port, public_key, rtt, rank,
      space);

  boost::shared_ptr<base::PublicRoutingTableHandler> rt_handler =
      (*base::PublicRoutingTable::GetInstance())[
      base::IntToString(node1_handler.listening_port(node1_id))];
  EXPECT_EQ(2, rt_handler->ContactLocal(kademlia_id));
  EXPECT_EQ(0, rt_handler->AddTuple(tuple_to_store));
  EXPECT_EQ(0, rt_handler->UpdateContactLocal(kademlia_id, bad_local_ip,
            kad::LOCAL));
  EXPECT_EQ(0, rt_handler->ContactLocal(kademlia_id));

  transport::IP bad_remote_ip("192.168.1.189");
  transport::Port bad_remote_port = 8889;

  EXPECT_NE(0, node1_handler.ConnectToSend(bad_local_ip, bad_local_port, "", 0,
    "", 0, true, &id, node1_id));
  // Ensure if we fail when passing local info, local status is set to unknown.
  EXPECT_NE(0, node1_handler.ConnectToSend(bad_remote_ip, bad_remote_port,
    bad_local_ip, bad_local_port, "", 0, true, &id, node1_id));
  EXPECT_EQ(2, rt_handler->ContactLocal(kademlia_id));
  // Set status to local again, and ensure that we can connect via remote ip/
  // port if local fails and that status is set to unknown.
  EXPECT_EQ(0, rt_handler->UpdateContactLocal(kademlia_id, bad_local_ip,
            kad::LOCAL));
  EXPECT_EQ(0, node1_handler.ConnectToSend(loop_back, lp_node2, bad_local_ip,
      bad_local_port, "", 0, true, &id, node1_id));
  EXPECT_EQ(2, rt_handler->ContactLocal(kademlia_id));

  transport::RpcMessage rpc_msg;
  rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
  rpc_msg.set_message_id(2000);
  rpc_msg.set_args(base::RandomString(256 * 1024));
  std::string msg;
  rpc_msg.SerializeToString(&msg);
  EXPECT_EQ(0, node1_handler.Send(rpc_msg, id, true, node1_id));
  while (msg_handler2.msgs.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_FALSE(msg_handler2.msgs.empty());
  EXPECT_EQ(msg, msg_handler2.msgs.front());
  node1_handler.Stop(node1_id);
  node2_handler.Stop(node2_id);
}

TEST_F(TransportTest, BEH_TRANS_RegisterNotifiers) {
  transport::TransportHandler node1_handler;
  boost::int16_t node1_id;
  transport::TransportUDT node1_transudt;
  node1_handler.Register(&node1_transudt, &node1_id);
  EXPECT_EQ(1, node1_handler.Start(0, node1_id));
  MessageHandler msg_handler1;
//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1, _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler1, _1, _2)));
  EXPECT_EQ(1, node1_handler.Start(0, node1_id));
//   EXPECT_TRUE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer, &msg_handler1,
//     _1, _2, _3)));
  EXPECT_EQ(0, node1_handler.Start(0, node1_id));
//   EXPECT_FALSE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1, _1, _2, _3, _4)));
//   EXPECT_FALSE(node1_handler.RegisterOnMessage(
//     boost::bind(&MessageHandler::OnMessage, &msg_handler1, _1, _2, _3, _4)));
//   EXPECT_FALSE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler1, _1, _2)));
//   EXPECT_FALSE(node1_handler.RegisterOnServerDown(
//     boost::bind(&MessageHandler::OnDeadRendezvousServer,
//     &msg_handler1, _1, _2, _3)));
  node1_handler.Stop(node1_id);

//   EXPECT_TRUE(node1_handler.RegisterOnRPCMessage(
//     boost::bind(&MessageHandler::OnRPCMessage, &msg_handler1, _1, _2, _3, _4)));
//   EXPECT_TRUE(node1_handler.RegisterOnSend(boost::bind(&MessageHandler::OnSend,
//     &msg_handler1, _1, _2)));
  EXPECT_EQ(0, node1_handler.StartLocal(0, node1_id));
  node1_handler.Stop(node1_id);
}

*/