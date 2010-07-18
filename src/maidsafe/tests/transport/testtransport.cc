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
    target_msg_(), ids(), raw_ids(), dead_server_(true), server_ip_(),
    server_port_(0), transport_(), msgs_sent_(0), msgs_received_(0),
    msgs_confirmed_(0), keep_msgs_(true), rpc_request_(), rpc_response_(),
    data_sent_connection_(), message_connection_(), server_down_connection_() {
  rpc_request_ = transport->ConnectRpcRequestReceived(
       boost::bind(&MessageHandler::OnRPCMessage, this, _1, _2));
  rpc_response_ = transport->ConnectRpcRequestReceived(
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

class MessageHandlerEchoRequest {
 public:
  explicit MessageHandlerEchoRequest(transport::TransportUDT *node)
      : node_(node),
        msgs(),
        ids(),
        dead_server_(true),
        server_ip_(),
        server_port_(0),
        msgs_sent_(0),
        rpc_connection_() {
    rpc_connection_ = node_->ConnectRpcResponseReceived(
        boost::bind(&MessageHandlerEchoRequest::OnRPCMessage, this, _1, _2));
  }
  void OnRPCMessage(const transport::RpcMessage &msg,
                    const transport::SocketId &socket_id) {
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
//    transport::Port peer_port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
//     LOG(INFO) << "message " << msgs.size() << " arrived from " << peer_ip << ":"
//         << peer_port << " . RTT = " << rtt << std::endl;
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
        server_ip_(), server_port_(0), msgs_sent_(0),
        rpc_request_(), rpc_response_() {
    rpc_request_ = node->ConnectRpcRequestReceived(boost::bind(
        &MessageHandlerEchoResponse::OnRPCMessage, this, _1, _2));
    rpc_response_ = node->ConnectRpcResponseReceived(boost::bind(
        &MessageHandlerEchoResponse::OnRPCMessage, this, _1, _2));
  }
  void OnRPCMessage(const transport::RpcMessage &msg,
                    const transport::SocketId &socket_id) {
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
  EXPECT_TRUE(node.StopAllListening());
       boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  EXPECT_NE(num_listening_ports, node.GetListeningPorts().size()) <<
   "Expect this fail till code fixes it ";
}

TEST_F(TransportTest, BEH_TRANS_SendOneMessageFromOneToAnother) {
  transport::SocketId id = 0;
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
