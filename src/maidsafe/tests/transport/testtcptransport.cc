// /* Copyright (c) 2009 maidsafe.net limited
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//     * Neither the name of the maidsafe.net limited nor the names of its
//     contributors may be used to endorse or promote products derived from this
//     software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
// TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// */
// 
// #include <boost/cstdint.hpp>
// #include <boost/lexical_cast.hpp>
// #include <boost/progress.hpp>
// #include <gtest/gtest.h>
// #include <list>
// #include <string>
// #include "maidsafe/protobuf/rpcmessage.pb.h"
// #include "maidsafe/transport/transporttcp.h"
// #include "maidsafe/base/log.h"
// #include "maidsafe/base/utils.h"
// #include "maidsafe/base/routingtable.h"
// #include "maidsafe/base/network_interface.h"
// 
// void send_rpcmsg(transport::Transport* node, const boost::uint16_t &port,
//     const int &repeat, rpcprotocol::RpcMessage msg) {
//   boost::uint32_t id;
//   boost::asio::ip::address local_address;
//   std::string ip;
//   if (base::GetLocalAddress(&local_address)) {
//     ip = local_address.to_string();
//   } else {
//     ip = std::string("127.0.0.1");
//   }
//   for (int i = 0; i < repeat; ++i) {
//     int send_res = node->ConnectToSend(ip, port, "", 0, "", 0,
//         false, &id);
//     if (send_res == 0)
//       node->Send(msg, id, true);
//     boost::this_thread::sleep(boost::posix_time::milliseconds(100));
//   }
// }
// 
// class Handler {
//  public:
//   Handler() : msgs(), raw_msgs(), connection_ids(), raw_connection_ids(),
//               transport_ids(), raw_transport_ids(), msgs_sent(0), msgs_rec(0),
//               str_msg() {
//   }
//   void OnMsgArrived(const std::string &msg,
//                     const boost::uint32_t &connection_id,
//                     const boost::uint16_t &transport_id, const float&) {
//     raw_msgs.push_back(msg);
//     raw_connection_ids.push_back(connection_id);
//     raw_transport_ids.push_back(transport_id);
//   }
//   void OnRpcMsgArrived(const rpcprotocol::RpcMessage &msg,
//     const boost::uint32_t &connection_id, const boost::uint16_t &transport_id,
//     const float&) {
//     if (msg.IsInitialized()) {
//       msgs.push_back(msg.SerializeAsString());
//       connection_ids.push_back(connection_id);
//       transport_ids.push_back(transport_id);
//     }
//   }
//   void OnSendRpc(const boost::uint32_t&, const bool &success) {
//     if (success)
//       ++msgs_sent;
//   }
//   void OnRpcMsgArrivedCounter(const rpcprotocol::RpcMessage &msg,
//     const boost::uint32_t&, const boost::uint16_t&, const float&) {
//     if (msg.IsInitialized()) {
//       ++msgs_rec;
//       if (str_msg.empty())
//         msg.SerializeToString(&str_msg);
//     }
//   }
//   std::list<std::string> msgs, raw_msgs;
//   std::list<boost::uint32_t> connection_ids, raw_connection_ids;
//   std::list<boost::uint16_t> transport_ids, raw_transport_ids;
//   unsigned int msgs_sent;
//   unsigned int msgs_rec;
//   std::string str_msg;
// };
// 
// TEST(TestTCPTransport, BEH_TRANS_TcpSendOneMessageFromOneToAnother) {
//   transport::Transport *node1 = new transport::TransportTCP;
//   transport::Transport *node2 = new transport::TransportTCP;
//   node1->set_transport_id(1);
//   node2->set_transport_id(2);
//   Handler hdlr1, hdlr2;
//   ASSERT_TRUE(node1->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr1, _1, _2, _3, _4)));
//   ASSERT_TRUE(node1->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr1, _1, _2)));
//   ASSERT_TRUE(node2->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr2, _1, _2, _3, _4)));
//   ASSERT_TRUE(node2->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr2, _1, _2)));
// 
//   ASSERT_EQ(0, node1->Start(0));
//   boost::uint16_t lp_node1 = node1->listening_port();
//   ASSERT_EQ(0, node2->Start(0));
//   rpcprotocol::RpcMessage msg;
//   msg.set_rpc_type(rpcprotocol::REQUEST);
//   msg.set_message_id(2000);
//   msg.set_args(base::RandomString(256 * 1024));
//   std::string rpc_msg(msg.SerializeAsString());
// 
//   boost::uint32_t id = 0;
//   EXPECT_EQ(1, node2->Send(msg, id, true));
//   EXPECT_EQ(1, node2->Send(msg, id, false));
//   EXPECT_EQ(0, node2->ConnectToSend("127.0.0.1", lp_node1, "", 0, "", 0,
//     false, &id));
//   EXPECT_EQ(0, node2->Send(msg, id, true));
//   while (hdlr1.msgs.empty())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
// 
//   node1->Stop();
//   node2->Stop();
// 
//   ASSERT_TRUE(hdlr2.msgs.empty());
//   ASSERT_FALSE(hdlr1.msgs.empty());
//   ASSERT_EQ(rpc_msg, hdlr1.msgs.front());
//   ASSERT_EQ(1, hdlr2.msgs_sent);
// 
//   delete node1;
//   delete node2;
// }
// 
// TEST(TestTCPTransport, BEH_TRANS_TcpSendMessagesFromManyToOne) {
//   boost::uint32_t id;
//   Handler hdlr[4];
//   transport::Transport *node1 = new transport::TransportTCP;
//   transport::Transport *node2 = new transport::TransportTCP;
//   transport::Transport *node3 = new transport::TransportTCP;
//   transport::Transport *node4 = new transport::TransportTCP;
//   node1->set_transport_id(1);
//   node2->set_transport_id(2);
//   node3->set_transport_id(3);
//   node4->set_transport_id(4);
// 
//   ASSERT_TRUE(node1->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr[0], _1, _2, _3, _4)));
//   ASSERT_TRUE(node1->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr[0], _1, _2)));
//   ASSERT_TRUE(node2->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr[1], _1, _2, _3, _4)));
//   ASSERT_TRUE(node2->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr[1], _1, _2)));
//   ASSERT_TRUE(node3->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr[2], _1, _2, _3, _4)));
//   ASSERT_TRUE(node3->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr[2], _1, _2)));
//   ASSERT_TRUE(node4->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr[3], _1, _2, _3, _4)));
//   ASSERT_TRUE(node4->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr[3], _1, _2)));
// 
//   ASSERT_EQ(0, node1->Start(0));
//   EXPECT_EQ(0, node2->Start(0));
//   EXPECT_EQ(0, node3->Start(0));
//   EXPECT_EQ(0, node4->Start(0));
//   boost::uint16_t lp_node4 = node4->listening_port();
//   std::list<std::string> sent_msgs;
//   rpcprotocol::RpcMessage rpc_msg;
//   rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
//   rpc_msg.set_message_id(2000);
//   rpc_msg.set_args(base::RandomString(64 * 1024));
//   std::string ser_rpc_msg;
//   rpc_msg.SerializeToString(&ser_rpc_msg);
//   sent_msgs.push_back(ser_rpc_msg);
//   EXPECT_EQ(0, node1->ConnectToSend("127.0.0.1", lp_node4, "", 0, "", 0,
//     false, &id));
//   EXPECT_EQ(0, node1->Send(rpc_msg, id, true));
//   rpc_msg.clear_args();
//   rpc_msg.set_args(base::RandomString(64 * 1024));
//   rpc_msg.SerializeToString(&ser_rpc_msg);
//   sent_msgs.push_back(ser_rpc_msg);
//   EXPECT_EQ(0, node2->ConnectToSend("127.0.0.1", lp_node4, "", 0, "", 0,
//     false, &id));
//   EXPECT_EQ(0, node2->Send(rpc_msg, id, true));
//   rpc_msg.clear_args();
//   rpc_msg.set_args(base::RandomString(64 * 1024));
//   rpc_msg.SerializeToString(&ser_rpc_msg);
//   sent_msgs.push_back(ser_rpc_msg);
//   EXPECT_EQ(0, node3->ConnectToSend("127.0.0.1", lp_node4, "", 0, "", 0,
//     false, &id));
//   EXPECT_EQ(0, node3->Send(rpc_msg, id, true));
//   boost::uint32_t now = base::GetEpochTime();
//   while (hdlr[3].msgs.size() < size_t(3) &&
//          base::GetEpochTime() - now < 15)
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//   node1->Stop();
//   node2->Stop();
//   node3->Stop();
//   node4->Stop();
//   for (int i = 0; i < 3; i++) {
//     EXPECT_TRUE(hdlr[i].msgs.empty());
//     EXPECT_EQ(1, hdlr[i].msgs_sent);
//   }
//   EXPECT_FALSE(hdlr[3].msgs.empty());
//   EXPECT_EQ(hdlr[3].msgs.size(), size_t(3));
//   hdlr[3].msgs.sort();
//   sent_msgs.sort();
//   for (int i = 0; i < 3; i++) {
//     EXPECT_EQ(hdlr[3].msgs.front(), sent_msgs.front());
//     hdlr[3].msgs.pop_front();
//     sent_msgs.pop_front();
//   }
//   delete node1;
//   delete node2;
//   delete node3;
//   delete node4;
// }
// 
// TEST(TestTCPTransport, BEH_TRANS_TcpSendMessagesFromManyToMany) {
//   boost::uint32_t id;
//   Handler hdlr[6];
//   transport::Transport *node1 = new transport::TransportTCP;
//   transport::Transport *node2 = new transport::TransportTCP;
//   transport::Transport *node3 = new transport::TransportTCP;
//   transport::Transport *node4 = new transport::TransportTCP;
//   transport::Transport *node5 = new transport::TransportTCP;
//   transport::Transport *node6 = new transport::TransportTCP;
//   node1->set_transport_id(1);
//   node2->set_transport_id(2);
//   node3->set_transport_id(3);
//   node4->set_transport_id(4);
//   node3->set_transport_id(5);
//   node4->set_transport_id(6);
// 
//   ASSERT_TRUE(node1->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr[0], _1, _2, _3, _4)));
//   ASSERT_TRUE(node1->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr[0], _1, _2)));
//   ASSERT_TRUE(node2->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr[1], _1, _2, _3, _4)));
//   ASSERT_TRUE(node2->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr[1], _1, _2)));
//   ASSERT_TRUE(node3->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr[2], _1, _2, _3, _4)));
//   ASSERT_TRUE(node3->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr[2], _1, _2)));
//   ASSERT_TRUE(node4->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr[3], _1, _2, _3, _4)));
//   ASSERT_TRUE(node4->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr[3], _1, _2)));
//   ASSERT_TRUE(node5->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr[4], _1, _2, _3, _4)));
//   ASSERT_TRUE(node5->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr[4], _1, _2)));
//   ASSERT_TRUE(node6->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr[5], _1, _2, _3, _4)));
//   ASSERT_TRUE(node6->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr[5], _1, _2)));
// 
//   ASSERT_EQ(0, node1->Start(0));
//   ASSERT_EQ(0, node2->Start(0));
//   ASSERT_EQ(0, node3->Start(0));
//   ASSERT_EQ(0, node4->Start(0));
//   ASSERT_EQ(0, node5->Start(0));
//   ASSERT_EQ(0, node6->Start(0));
//   boost::uint16_t lp_node4 = node4->listening_port();
//   boost::uint16_t lp_node5 = node5->listening_port();
//   boost::uint16_t lp_node6 = node6->listening_port();
// 
// 
//   std::string sent_msgs[3];
//   rpcprotocol::RpcMessage rpc_msg;
//   rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
//   rpc_msg.set_message_id(2000);
//   rpc_msg.set_args(base::RandomString(64*1024));
//   std::string ser_rpc_msg;
//   rpc_msg.SerializeToString(&ser_rpc_msg);
//   sent_msgs[0] = ser_rpc_msg;
//   ASSERT_EQ(0, node1->ConnectToSend("127.0.0.1", lp_node4, "", 0, "", 0,
//     false, &id));
//   ASSERT_EQ(0, node1->Send(rpc_msg, id, true));
//   rpc_msg.clear_args();
//   rpc_msg.set_args(base::RandomString(64*1024));
//   rpc_msg.SerializeToString(&ser_rpc_msg);
//   sent_msgs[1] = ser_rpc_msg;
//   ASSERT_EQ(0, node2->ConnectToSend("127.0.0.1", lp_node5, "", 0, "", 0,
//     false, &id));
//   ASSERT_EQ(0, node2->Send(rpc_msg, id, true));
//   rpc_msg.clear_args();
//   rpc_msg.set_args(base::RandomString(64*1024));
//   rpc_msg.SerializeToString(&ser_rpc_msg);
//   sent_msgs[2] = ser_rpc_msg;
//   ASSERT_EQ(0, node3->ConnectToSend("127.0.0.1", lp_node6, "",
//     0, "", 0, false, &id));
//   ASSERT_EQ(0, node3->Send(rpc_msg, id, true));
//   boost::uint32_t now = base::GetEpochTime();
//   bool msgs_received[3] = {false, false, false};
//   while ((!msgs_received[0] || !msgs_received[1] || !msgs_received[2]) &&
//           base::GetEpochTime() - now < 15) {
//     if (hdlr[3].msgs.size() > 0)
//       msgs_received[0] = true;
//     if (hdlr[4].msgs.size() > 0)
//       msgs_received[1] = true;
//     if (hdlr[5].msgs.size() > 0)
//       msgs_received[2] = true;
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//   }
//   node1->Stop();
//   node2->Stop();
//   node3->Stop();
//   node4->Stop();
//   node5->Stop();
//   node6->Stop();
//   for (int i = 0; i < 3; i++) {
//     ASSERT_TRUE(hdlr[i].msgs.empty());
//     ASSERT_EQ(1, hdlr[i].msgs_sent);
//   }
//   for (int i = 3; i < 6; i++) {
//     ASSERT_EQ(size_t(1), hdlr[i].msgs.size());
//     ASSERT_EQ(hdlr[i].msgs.front(), sent_msgs[i-3]);
//   }
//   delete node1;
//   delete node2;
//   delete node3;
//   delete node4;
//   delete node5;
//   delete node6;
// }
// 
// TEST(TestTCPTransport, BEH_TRANS_TcpSendMessagesFromOneToMany) {
//   boost::uint32_t id;
//   Handler hdlr[4];
//   transport::Transport *node1 = new transport::TransportTCP;
//   transport::Transport *node2 = new transport::TransportTCP;
//   transport::Transport *node3 = new transport::TransportTCP;
//   transport::Transport *node4 = new transport::TransportTCP;
//   node1->set_transport_id(1);
//   node2->set_transport_id(2);
//   node3->set_transport_id(3);
//   node4->set_transport_id(4);
// 
//   ASSERT_TRUE(node1->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr[0], _1, _2, _3, _4)));
//   ASSERT_TRUE(node1->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr[0], _1, _2)));
//   ASSERT_TRUE(node2->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr[1], _1, _2, _3, _4)));
//   ASSERT_TRUE(node2->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr[1], _1, _2)));
//   ASSERT_TRUE(node3->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr[2], _1, _2, _3, _4)));
//   ASSERT_TRUE(node3->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr[2], _1, _2)));
//   ASSERT_TRUE(node4->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr[3], _1, _2, _3, _4)));
//   ASSERT_TRUE(node4->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr[3], _1, _2)));
// 
//   ASSERT_EQ(0, node1->Start(0));
//   EXPECT_EQ(0, node2->Start(0));
//   EXPECT_EQ(0, node3->Start(0));
//   EXPECT_EQ(0, node4->Start(0));
//   boost::uint16_t lp_node2(node2->listening_port());
//   boost::uint16_t lp_node3(node3->listening_port());
//   boost::uint16_t lp_node4(node4->listening_port());
//   std::string sent_msgs[3];
//   rpcprotocol::RpcMessage rpc_msg;
//   rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
//   rpc_msg.set_message_id(2000);
//   rpc_msg.set_args(base::RandomString(64 * 1024));
//   std::string ser_rpc_msg;
//   rpc_msg.SerializeToString(&ser_rpc_msg);
//   sent_msgs[0] = ser_rpc_msg;
//   ASSERT_EQ(0, node1->ConnectToSend("127.0.0.1", lp_node2, "", 0, "", 0,
//     false, &id));
//   ASSERT_EQ(0, node1->Send(rpc_msg, id, true));
//   rpc_msg.clear_args();
//   rpc_msg.set_args(base::RandomString(64 * 1024));
//   rpc_msg.SerializeToString(&ser_rpc_msg);
//   sent_msgs[1] = ser_rpc_msg;
//   ASSERT_EQ(0, node1->ConnectToSend("127.0.0.1", lp_node3, "", 0, "", 0,
//     false, &id));
//   ASSERT_EQ(0, node1->Send(rpc_msg, id, true));
//   rpc_msg.clear_args();
//   rpc_msg.set_args(base::RandomString(64 * 1024));
//   rpc_msg.SerializeToString(&ser_rpc_msg);
//   sent_msgs[2] = ser_rpc_msg;
//   ASSERT_EQ(0, node1->ConnectToSend("127.0.0.1", lp_node4, "", 0, "", 0,
//     false, &id));
//   ASSERT_EQ(0, node1->Send(rpc_msg, id, true));
// 
//   boost::uint32_t now = base::GetEpochTime();
//   bool msgs_received[3] = {false, false, false};
//   while ((!msgs_received[0] || !msgs_received[1] || !msgs_received[2]) &&
//           base::GetEpochTime() - now < 15) {
//     if (hdlr[1].msgs.size() >= size_t(1))
//       msgs_received[0] = true;
//     if (hdlr[2].msgs.size() >= size_t(1))
//       msgs_received[1] = true;
//     if (hdlr[3].msgs.size() >= size_t(1))
//       msgs_received[2] = true;
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//   }
//   node1->Stop();
//   node2->Stop();
//   node3->Stop();
//   node4->Stop();
//   ASSERT_TRUE(hdlr[0].msgs.empty());
//   ASSERT_EQ(3, hdlr[0].msgs_sent);
//   for (int i = 0; i < 3; i++) {
//     ASSERT_EQ(size_t(1), hdlr[i+1].msgs.size());
//     ASSERT_EQ(hdlr[i+1].msgs.front(), sent_msgs[i]);
//   }
//   delete node1;
//   delete node2;
//   delete node3;
//   delete node4;
// }
// 
// TEST(TestTCPTransport, BEH_TRANS_TcpSendMultipleMsgsSameConnection) {
//   transport::Transport *node1 = new transport::TransportTCP;
//   transport::Transport *node2 = new transport::TransportTCP;
//   node1->set_transport_id(1);
//   node1->set_transport_id(2);
//   Handler hdlr1, hdlr2;
//   ASSERT_TRUE(node1->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr1, _1, _2, _3, _4)));
//   ASSERT_TRUE(node1->RegisterOnMessage(boost::bind(&Handler::OnMsgArrived,
//     &hdlr1, _1, _2, _3, _4)));
//   ASSERT_TRUE(node1->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr1, _1, _2)));
//   ASSERT_TRUE(node2->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr2, _1, _2, _3, _4)));
//   ASSERT_TRUE(node2->RegisterOnMessage(boost::bind(&Handler::OnMsgArrived,
//     &hdlr2, _1, _2, _3, _4)));
//   ASSERT_TRUE(node2->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr2, _1, _2)));
// 
//   ASSERT_EQ(0, node1->Start(0));
//   boost::uint16_t lp_node1 = node1->listening_port();
//   ASSERT_EQ(0, node2->Start(0));
//   rpcprotocol::RpcMessage msg;
//   msg.set_rpc_type(rpcprotocol::REQUEST);
//   msg.set_message_id(2000);
//   msg.set_args(base::RandomString(256 * 1024));
//   std::string rpc_msg(msg.SerializeAsString());
//   std::string str_msg(base::RandomString(256 * 1024));
// 
//   boost::uint32_t id = 0;
//   EXPECT_EQ(1, node2->Send(msg, id, true));
//   EXPECT_EQ(1, node2->Send(msg, id, false));
//   EXPECT_EQ(0, node2->ConnectToSend("127.0.0.1", lp_node1, "", 0, "", 0,
//     true, &id));
//   EXPECT_EQ(0, node2->Send(msg, id, true));
//   while (hdlr1.msgs.empty())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//   EXPECT_EQ(0, node2->Send(str_msg, id, true));
//   while (hdlr1.raw_msgs.empty())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//   ASSERT_TRUE(hdlr2.raw_msgs.empty());
//   EXPECT_EQ(0, node1->Send(str_msg, hdlr1.raw_connection_ids.front(), true));
//   while (hdlr2.raw_msgs.empty())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
// 
//   node1->Stop();
//   node2->Stop();
//   delete node1;
//   delete node2;
// 
//   ASSERT_TRUE(hdlr2.msgs.empty());
//   ASSERT_FALSE(hdlr1.msgs.empty());
//   ASSERT_FALSE(hdlr1.raw_msgs.empty());
//   ASSERT_FALSE(hdlr2.raw_msgs.empty());
//   ASSERT_EQ(rpc_msg, hdlr1.msgs.front());
//   ASSERT_EQ(str_msg, hdlr1.raw_msgs.front());
//   ASSERT_EQ(str_msg, hdlr2.raw_msgs.front());
//   ASSERT_EQ(1, hdlr2.msgs_sent);
// }
// 
// TEST(TestTCPTransport, BEH_TRANS_TcpFailConnectToInvalidPeer) {
//   boost::uint32_t id;
//   transport::Transport *node1 = new transport::TransportTCP;
//   node1->set_transport_id(1);
//   Handler hdlr;
//   ASSERT_TRUE(node1->RegisterOnRPCMessage(
//     boost::bind(&Handler::OnRpcMsgArrived, &hdlr, _1, _2, _3, _4)));
//   ASSERT_TRUE(node1->RegisterOnSend(boost::bind(&Handler::OnSendRpc, &hdlr,
//     _1, _2)));
//   ASSERT_EQ(0, node1->Start(0));
//   rpcprotocol::RpcMessage rpc_msg;
//   rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
//   rpc_msg.set_message_id(2000);
//   rpc_msg.set_args(base::RandomString(64 * 1024));
//   ASSERT_EQ(1, node1->ConnectToSend("127.0.0.1", 52002, "", 0, "", 0,
//     false, &id));
//   ASSERT_EQ(1, node1->Send(rpc_msg, id, true));
//   node1->Stop();
// }
// 
// TEST(TestTCPTransport, BEH_TRANS_TcpGetRemotePeerAddress) {
//   boost::uint32_t id;
//   transport::Transport *node1 = new transport::TransportTCP;
//   transport::Transport *node2 = new transport::TransportTCP;
//   node1->set_transport_id(1);
//   node2->set_transport_id(2);
//   Handler hdlr1, hdlr2;
//   ASSERT_TRUE(node1->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr1, _1, _2, _3, _4)));
//   ASSERT_TRUE(node1->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr1, _1, _2)));
//   ASSERT_TRUE(node2->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr2, _1, _2, _3, _4)));
//   ASSERT_TRUE(node2->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr2, _1, _2)));
// 
//   ASSERT_EQ(0, node1->Start(0));
//   ASSERT_EQ(0, node2->Start(0));
//   boost::uint16_t lp_node2 = node2->listening_port();
//   rpcprotocol::RpcMessage rpc_msg;
//   rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
//   rpc_msg.set_message_id(2000);
//   rpc_msg.set_args(base::RandomString(64 * 1024));
//   std::string sent_msg;
//   rpc_msg.SerializeToString(&sent_msg);
//   ASSERT_EQ(0, node1->ConnectToSend("127.0.0.1", lp_node2, "", 0, "", 0,
//     false, &id));
//   ASSERT_EQ(0, node1->Send(rpc_msg, id, true));
//   while (hdlr2.msgs.empty())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
// 
//   struct sockaddr peer_addr;
//   ASSERT_TRUE(node2->peer_address(&peer_addr));
// 
//   boost::asio::ip::address addr = base::NetworkInterface::SockaddrToAddress(
//     &peer_addr);
// 
//   ASSERT_EQ(std::string("127.0.0.1"), addr.to_string());
//   node1->Stop();
//   node2->Stop();
//   delete node1;
//   delete node2;
// }
// 
// TEST(TestTCPTransport, BEH_TRANS_TcpSendMessageFromOneToAnotherBidirectional) {
//   boost::uint32_t id;
//   transport::Transport *node1 = new transport::TransportTCP;
//   transport::Transport *node2 = new transport::TransportTCP;
//   node1->set_transport_id(1);
//   node2->set_transport_id(2);
//   Handler hdlr1, hdlr2;
//   ASSERT_TRUE(node1->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr1, _1, _2, _3, _4)));
//   ASSERT_TRUE(node1->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr1, _1, _2)));
//   ASSERT_TRUE(node2->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr2, _1, _2, _3, _4)));
//   ASSERT_TRUE(node2->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr2, _1, _2)));
// 
//   ASSERT_EQ(0, node1->Start(0));
//   ASSERT_EQ(0, node2->Start(0));
//   boost::uint16_t lp_node2 = node2->listening_port();
//   rpcprotocol::RpcMessage rpc_msg;
//   rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
//   rpc_msg.set_message_id(2000);
//   rpc_msg.set_args(base::RandomString(256 * 1024));
//   std::string sent_msg;
//   rpc_msg.SerializeToString(&sent_msg);
//   ASSERT_EQ(0, node1->ConnectToSend("127.0.0.1", lp_node2, "", 0, "", 0,
//     true, &id));
//   ASSERT_EQ(0, node1->Send(rpc_msg, id, true));
//   while (hdlr2.msgs.empty())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//   // replying on same channel
//   ASSERT_FALSE(hdlr2.msgs.empty());
//   ASSERT_FALSE(hdlr2.connection_ids.empty());
//   rpc_msg.clear_args();
//   rpc_msg.set_args(base::RandomString(256 * 1024));
//   std::string reply_msg;
//   rpc_msg.SerializeToString(&reply_msg);
//   ASSERT_EQ(0, node2->Send(rpc_msg, hdlr2.connection_ids.front(), false));
//   while (hdlr1.msgs.empty())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//   // Closing the connection
//   node1->CloseConnection(hdlr1.connection_ids.front());
//   node2->CloseConnection(hdlr2.connection_ids.front());
//   node1->Stop();
//   node2->Stop();
//   ASSERT_FALSE(hdlr1.msgs.empty());
//   ASSERT_EQ(sent_msg, hdlr2.msgs.front());
//   ASSERT_EQ(reply_msg, hdlr1.msgs.front());
//   ASSERT_EQ(1, hdlr1.msgs_sent);
//   ASSERT_EQ(1, hdlr2.msgs_sent);
//   delete node1;
//   delete node2;
// }
// 
// TEST(TestTCPTransport, BEH_TRANS_TcpSendMsgsFromManyToOneBidirectional) {
//   boost::uint32_t id;
//   Handler hdlr[4];
//   transport::Transport *node1 = new transport::TransportTCP;
//   transport::Transport *node2 = new transport::TransportTCP;
//   transport::Transport *node3 = new transport::TransportTCP;
//   transport::Transport *node4 = new transport::TransportTCP;
//   node1->set_transport_id(1);
//   node2->set_transport_id(2);
//   node3->set_transport_id(3);
//   node4->set_transport_id(4);
// 
//   ASSERT_TRUE(node1->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr[0], _1, _2, _3, _4)));
//   ASSERT_TRUE(node1->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr[0], _1, _2)));
//   ASSERT_TRUE(node2->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr[1], _1, _2, _3, _4)));
//   ASSERT_TRUE(node2->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr[1], _1, _2)));
//   ASSERT_TRUE(node3->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr[2], _1, _2, _3, _4)));
//   ASSERT_TRUE(node3->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr[2], _1, _2)));
//   ASSERT_TRUE(node4->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr[3], _1, _2, _3, _4)));
//   ASSERT_TRUE(node4->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr[3], _1, _2)));
// 
//   EXPECT_EQ(0, node1->Start(0));
//   EXPECT_EQ(0, node2->Start(0));
//   EXPECT_EQ(0, node3->Start(0));
//   EXPECT_EQ(0, node4->Start(0));
//   boost::uint16_t lp_node4 = node4->listening_port();
//   rpcprotocol::RpcMessage rpc_msg;
//   rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
//   rpc_msg.set_message_id(2000);
//   rpc_msg.set_args(base::RandomString(64 * 1024));
//   std::string ser_rpc_msg(rpc_msg.SerializeAsString());
//   std::list<std::string> sent_msgs;
//   sent_msgs.push_back(ser_rpc_msg);
//   EXPECT_EQ(0, node1->ConnectToSend("127.0.0.1", lp_node4, "", 0, "", 0,
//     true, &id));
//   EXPECT_EQ(0, node1->Send(rpc_msg, id, true));
//   rpc_msg.clear_args();
//   rpc_msg.set_args(base::RandomString(64 * 1024));
//   rpc_msg.SerializeToString(&ser_rpc_msg);
//   sent_msgs.push_back(ser_rpc_msg);
//   EXPECT_EQ(0, node2->ConnectToSend("127.0.0.1", lp_node4, "", 0, "", 0,
//     true, &id));
//   EXPECT_EQ(0, node2->Send(rpc_msg, id, true));
//   rpc_msg.clear_args();
//   rpc_msg.set_args(base::RandomString(64 * 1024));
//   rpc_msg.SerializeToString(&ser_rpc_msg);
//   sent_msgs.push_back(ser_rpc_msg);
//   EXPECT_EQ(0, node3->ConnectToSend("127.0.0.1", lp_node4, "", 0, "", 0,
//     true, &id));
//   EXPECT_EQ(0, node3->Send(rpc_msg, id, true));
//   // waiting for all messages to be delivered
//   while (hdlr[3].msgs.size() != size_t(3))
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//   // node4_handler responding to all nodes
//   std::list<boost::uint32_t>::iterator it;
//   rpc_msg.clear_args();
//   rpc_msg.set_args(base::RandomString(64 * 1024));
//   std::string reply_str;
//   rpc_msg.SerializeToString(&reply_str);
//   int i = 0;
//   for (it = hdlr[3].connection_ids.begin(); it != hdlr[3].connection_ids.end();
//        it++) {
//     ++i;
//     ASSERT_EQ(0, node4->Send(rpc_msg, *it, false));
//   }
//   // waiting for all replies to arrive
//   while (hdlr[0].msgs.empty() || hdlr[1].msgs.empty() ||
//          hdlr[2].msgs.empty())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
// 
//   for (it = hdlr[0].connection_ids.begin(); it != hdlr[0].connection_ids.end();
//        it++)
//     node1->CloseConnection(*it);
//   for (it = hdlr[1].connection_ids.begin(); it != hdlr[1].connection_ids.end();
//        it++)
//     node2->CloseConnection(*it);
//   for (it = hdlr[2].connection_ids.begin(); it != hdlr[2].connection_ids.end();
//        it++)
//     node3->CloseConnection(*it);
//   for (it = hdlr[3].connection_ids.begin(); it != hdlr[3].connection_ids.end();
//        it++)
//     node4->CloseConnection(*it);
// 
//   node1->Stop();
//   node2->Stop();
//   node3->Stop();
//   node4->Stop();
//   for (int i = 0; i < 4; i++) {
//     ASSERT_FALSE(hdlr[i].msgs.empty());
//     if (i == 3)
//       ASSERT_EQ(3, hdlr[i].msgs_sent);
//     else
//       ASSERT_EQ(1, hdlr[i].msgs_sent);
//   }
//   ASSERT_FALSE(hdlr[3].msgs.empty());
//   ASSERT_EQ(hdlr[3].msgs.size(), size_t(3));
//   hdlr[3].msgs.sort();
//   sent_msgs.sort();
//   for (int i = 0; i < 3; i++) {
//     ASSERT_EQ(hdlr[3].msgs.front(), sent_msgs.front());
//     hdlr[3].msgs.pop_front();
//     sent_msgs.pop_front();
//     ASSERT_EQ(size_t(1), hdlr[i].msgs.size());
//     ASSERT_EQ(reply_str, hdlr[i].msgs.front());
//   }
//   ASSERT_EQ(3, hdlr[3].msgs_sent);
//   delete node1;
//   delete node2;
//   delete node3;
//   delete node4;
// }
// 
// TEST(TestTCPTransport, BEH_TRANS_TcpSendOneMessageCloseAConnection) {
//   boost::uint32_t id;
//   transport::Transport *node1 = new transport::TransportTCP;
//   transport::Transport *node2 = new transport::TransportTCP;
//   node1->set_transport_id(1);
//   node2->set_transport_id(2);
//   Handler hdlr1, hdlr2;
//   ASSERT_TRUE(node1->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr1, _1, _2, _3, _4)));
//   ASSERT_TRUE(node1->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr1, _1, _2)));
//   ASSERT_TRUE(node2->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr2, _1, _2, _3, _4)));
//   ASSERT_TRUE(node2->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr2, _1, _2)));
// 
//   ASSERT_EQ(0, node1->Start(0));
//   ASSERT_EQ(0, node2->Start(0));
//   boost::uint16_t lp_node2 = node2->listening_port();
//   rpcprotocol::RpcMessage rpc_msg;
//   rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
//   rpc_msg.set_message_id(2000);
//   rpc_msg.set_args(base::RandomString(256 * 1024));
//   std::string sent_msg;
//   rpc_msg.SerializeToString(&sent_msg);
//   ASSERT_EQ(0, node1->ConnectToSend("127.0.0.1", lp_node2, "", 0, "", 0,
//     true, &id));
//   ASSERT_EQ(0, node1->Send(rpc_msg, id, true));
//   while (hdlr2.msgs.empty())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//   // replying on same channel
//   ASSERT_FALSE(hdlr2.msgs.empty());
//   ASSERT_FALSE(hdlr2.connection_ids.empty());
//   rpc_msg.clear_args();
//   rpc_msg.set_args(base::RandomString(256 * 1024));
//   std::string reply_msg;
//   rpc_msg.SerializeToString(&reply_msg);
//   node1->CloseConnection(id);
//   boost::this_thread::sleep(boost::posix_time::seconds(1));
//   EXPECT_EQ(1, node2->Send(rpc_msg, hdlr2.connection_ids.front(), false));
// 
//   node1->Stop();
//   node2->Stop();
//   ASSERT_TRUE(hdlr1.msgs.empty());
//   ASSERT_EQ(sent_msg, hdlr2.msgs.front());
//   delete node1;
//   delete node2;
// }
// 
// TEST(TestTCPTransport, FUNC_TRANS_TcpStartStopTransport) {
//   boost::uint32_t id;
//   transport::Transport *node1 = new transport::TransportTCP;
//   transport::Transport *node2 = new transport::TransportTCP;
//   node1->set_transport_id(1);
//   node2->set_transport_id(2);
//   Handler hdlr1, hdlr2;
//   ASSERT_TRUE(node1->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr1, _1, _2, _3, _4)));
//   ASSERT_TRUE(node1->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr1, _1, _2)));
//   ASSERT_TRUE(node2->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr2, _1, _2, _3, _4)));
//   ASSERT_TRUE(node2->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr2, _1, _2)));
//   ASSERT_EQ(0, node1->Start(0));
//   ASSERT_EQ(0, node2->Start(0));
//   boost::uint16_t lp_node1 = node1->listening_port();
//   boost::uint16_t lp_node2 = node2->listening_port();
//   rpcprotocol::RpcMessage rpc_msg;
//   rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
//   rpc_msg.set_message_id(2000);
//   rpc_msg.set_args(base::RandomString(256 * 1024));
//   std::string sent_msg;
//   rpc_msg.SerializeToString(&sent_msg);
//   ASSERT_EQ(0, node1->ConnectToSend("127.0.0.1", lp_node2, "", 0, "", 0,
//     false, &id));
//   ASSERT_EQ(0, node1->Send(rpc_msg, id, true));
//   while (hdlr2.msgs.empty())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//   ASSERT_FALSE(hdlr2.msgs.empty());
//   ASSERT_EQ(sent_msg, hdlr2.msgs.front());
//   hdlr2.msgs.clear();
//   // A message was received by node2_handler, now start and stop it 5 times
//   for (int i = 0 ; i < 5; i++) {
//     node2->Stop();
//     ASSERT_TRUE(node2->RegisterOnRPCMessage(boost::bind(
//       &Handler::OnRpcMsgArrived, &hdlr2, _1, _2, _3, _4)));
//     ASSERT_TRUE(node2->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//       &hdlr2, _1, _2)));
//     ASSERT_EQ(0, node2->Start(0));
//     lp_node2 = node2->listening_port();
//     // Sending another message
//     rpc_msg.clear_args();
//     rpc_msg.set_args(base::RandomString(256 * 1024));
//     rpc_msg.SerializeToString(&sent_msg);
//     ASSERT_EQ(0, node1->ConnectToSend("127.0.0.1", lp_node2, "", 0, "",
//       0, false, &id));
//     ASSERT_EQ(0, node1->Send(rpc_msg, id, true));
//     while (hdlr2.msgs.empty())
//       boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//     ASSERT_FALSE(hdlr2.msgs.empty());
//     ASSERT_EQ(sent_msg, hdlr2.msgs.front());
//     hdlr2.msgs.clear();
// 
//     rpc_msg.clear_args();
//     rpc_msg.set_args(base::RandomString(256 * 1024));
//     rpc_msg.SerializeToString(&sent_msg);
//     ASSERT_EQ(0, node2->ConnectToSend("127.0.0.1", lp_node1, "",
//       0, "", 0, false, &id));
//     ASSERT_EQ(0, node2->Send(rpc_msg, id, true));
//     while (hdlr1.msgs.empty())
//       boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//     ASSERT_FALSE(hdlr1.msgs.empty());
//     ASSERT_EQ(sent_msg, hdlr1.msgs.front());
//     hdlr1.msgs.clear();
// 
//     boost::this_thread::sleep(boost::posix_time::seconds(2));
//   }
//   // Sending another message
//   rpc_msg.clear_args();
//   rpc_msg.set_args(base::RandomString(256 * 1024));
//   rpc_msg.SerializeToString(&sent_msg);
//   ASSERT_EQ(0, node1->ConnectToSend("127.0.0.1", lp_node2, "", 0, "", 0,
//     false, &id));
//   ASSERT_EQ(0, node1->Send(rpc_msg, id, true));
//   while (hdlr2.msgs.empty())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//   ASSERT_FALSE(hdlr2.msgs.empty());
//   ASSERT_EQ(sent_msg, hdlr2.msgs.front());
// 
//   node1->Stop();
//   node2->Stop();
//   delete node1;
//   delete node2;
// }
// 
// TEST(TestTCPTransport, BEH_TRANS_TcpStartLocal) {
//   transport::Transport *node1 = new transport::TransportTCP;
//   transport::Transport *node2 = new transport::TransportTCP;
//   node1->set_transport_id(1);
//   node2->set_transport_id(2);
//   Handler hdlr1, hdlr2;
//   ASSERT_TRUE(node1->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr1, _1, _2, _3, _4)));
//   ASSERT_TRUE(node1->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr1, _1, _2)));
//   ASSERT_TRUE(node2->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr2, _1, _2, _3, _4)));
//   ASSERT_TRUE(node2->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr2, _1, _2)));
//   ASSERT_EQ(0, node1->StartLocal(0));
//   ASSERT_EQ(0, node2->StartLocal(0));
//   boost::uint16_t lp_node2 = node2->listening_port();
//   boost::uint32_t id;
//   boost::asio::ip::address local_address;
//   std::string local_ip;
//   std::string loop_back("127.0.0.1");
//   if (base::GetLocalAddress(&local_address)) {
//     local_ip = local_address.to_string();
//   } else {
//     FAIL() << "Can not get local address";
//   }
//   ASSERT_NE(loop_back, local_ip)
//     << "Unable to get a local IP different from loopback";
//   ASSERT_NE(0, node1->ConnectToSend(local_ip, lp_node2, "", 0, "", 0,
//     true, &id));
//   ASSERT_EQ(0, node1->ConnectToSend(loop_back, lp_node2, "", 0, "", 0,
//     true, &id));
//   rpcprotocol::RpcMessage rpc_msg;
//   rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
//   rpc_msg.set_message_id(2000);
//   rpc_msg.set_args(base::RandomString(256 * 1024));
//   std::string msg;
//   rpc_msg.SerializeToString(&msg);
//   ASSERT_EQ(0, node1->Send(rpc_msg, id, true));
//   while (hdlr2.msgs.empty())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//   ASSERT_FALSE(hdlr2.msgs.empty());
//   ASSERT_EQ(msg, hdlr2.msgs.front());
//   node1->Stop();
//   node2->Stop();
//   delete node1;
//   delete node2;
// }
// 
// TEST(TestTCPTransport, BEH_TRANS_TcpStartStopLocal) {
//   transport::Transport *node1 = new transport::TransportTCP;
//   transport::Transport *node2 = new transport::TransportTCP;
//   node1->set_transport_id(1);
//   node2->set_transport_id(2);
//   Handler hdlr1, hdlr2;
//   ASSERT_TRUE(node1->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr1, _1, _2, _3, _4)));
//   ASSERT_TRUE(node1->RegisterOnMessage(boost::bind(&Handler::OnMsgArrived,
//     &hdlr1, _1, _2, _3, _4)));
//   ASSERT_TRUE(node1->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr1, _1, _2)));
//   ASSERT_TRUE(node2->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr2, _1, _2, _3, _4)));
//   ASSERT_TRUE(node2->RegisterOnMessage(boost::bind(&Handler::OnMsgArrived,
//     &hdlr2, _1, _2, _3, _4)));
//   ASSERT_TRUE(node2->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr2, _1, _2)));
//   ASSERT_EQ(0, node1->StartLocal(0));
//   ASSERT_EQ(0, node2->StartLocal(0));
//   boost::uint16_t lp_node2 = node2->listening_port();
//   boost::uint32_t id;
//   boost::asio::ip::address local_address;
//   std::string local_ip;
//   std::string loop_back("127.0.0.1");
//   if (base::GetLocalAddress(&local_address)) {
//     local_ip = local_address.to_string();
//   } else {
//     FAIL() << "Can not get local address";
//   }
//   ASSERT_NE(loop_back, local_ip) << "unable to get a local address";
//   ASSERT_EQ(0, node1->ConnectToSend(loop_back, lp_node2, "", 0, "", 0,
//     true, &id));
// 
//   rpcprotocol::RpcMessage rpc_msg;
//   rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
//   rpc_msg.set_message_id(2000);
//   rpc_msg.set_args(base::RandomString(256 * 1024));
//   std::string msg;
//   rpc_msg.SerializeToString(&msg);
//   ASSERT_EQ(0, node1->Send(rpc_msg, id, true));
//   while (hdlr2.msgs.empty())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//   ASSERT_FALSE(hdlr2.msgs.empty());
//   ASSERT_EQ(msg, hdlr2.msgs.front());
//   std::string raw_msg = base::RandomString(50);
//   ASSERT_EQ(0, node1->ConnectToSend(loop_back, lp_node2, "", 0, "", 0,
//     true, &id));
//   ASSERT_EQ(0, node1->Send(raw_msg, id, true));
// 
//   while (hdlr2.raw_msgs.empty())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//   ASSERT_FALSE(hdlr2.raw_msgs.empty());
//   ASSERT_EQ(raw_msg, hdlr2.raw_msgs.front());
//   node2->Stop();
//   hdlr2.msgs.clear();
//   hdlr2.raw_msgs.clear();
//   ASSERT_TRUE(node2->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr2, _1, _2, _3, _4)));
//   ASSERT_TRUE(node2->RegisterOnMessage(boost::bind(&Handler::OnMsgArrived,
//     &hdlr2, _1, _2, _3, _4)));
//   ASSERT_TRUE(node2->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr2, _1, _2)));
//   ASSERT_EQ(0, node2->Start(0));
//   lp_node2 = node2->listening_port();
//   ASSERT_EQ(0, node1->ConnectToSend(local_ip, lp_node2, "", 0, "", 0,
//     true, &id));
//   ASSERT_EQ(0, node1->Send(rpc_msg, id, true));
//   while (hdlr2.msgs.empty())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//   ASSERT_FALSE(hdlr2.msgs.empty());
//   ASSERT_EQ(msg, hdlr2.msgs.front());
//   hdlr2.msgs.clear();
//   node1->Stop();
//   node2->Stop();
//   delete node1;
//   delete node2;
// }
// 
// TEST(TestTCPTransport, BEH_TRANS_TcpCheckPortAvailable) {
//   transport::Transport *node1 = new transport::TransportTCP;
//   transport::Transport *node2 = new transport::TransportTCP;
//   node1->set_transport_id(1);
//   node2->set_transport_id(2);
//   Handler hdlr1, hdlr2;
//   ASSERT_TRUE(node1->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr1, _1, _2, _3, _4)));
//   ASSERT_TRUE(node1->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr1, _1, _2)));
//   ASSERT_EQ(0, node1->Start(0));
//   boost::uint16_t lp_node1(node1->listening_port());
// #ifndef WIN32
// // Windows allows two ip::tcp::acceptor to be bound to the same port
//   ASSERT_FALSE(node2->IsPortAvailable(lp_node1));
// #endif
//   EXPECT_TRUE(node2->IsPortAvailable(lp_node1 + 1));
//   node1->Stop();
//   ASSERT_TRUE(node2->IsPortAvailable(lp_node1));
//   delete node1;
//   delete node2;
// }
// 
// TEST(TestTCPTransport, BEH_TRANS_TcpRegisterNotifiers) {
//   transport::Transport *node = new transport::TransportTCP;
//   node->set_transport_id(1);
//   Handler hdlr;
// 
//   ASSERT_EQ(1, node->Start(0));
//   ASSERT_TRUE(node->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr, _1, _2, _3, _4)));
//   ASSERT_EQ(1, node->Start(0));
//   ASSERT_TRUE(node->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr, _1, _2)));
//   ASSERT_EQ(0, node->Start(0));
//   ASSERT_FALSE(node->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr, _1, _2, _3, _4)));
//   ASSERT_FALSE(node->RegisterOnMessage(boost::bind(&Handler::OnMsgArrived,
//     &hdlr, _1, _2, _3, _4)));
//   ASSERT_FALSE(node->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr, _1, _2)));
// 
//   node->Stop();
// 
//   ASSERT_TRUE(node->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr, _1, _2, _3, _4)));
//   ASSERT_TRUE(node->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr, _1, _2)));
//   ASSERT_EQ(0, node->StartLocal(0));
//   node->Stop();
//   delete node;
// }
// 
// TEST(TestTCPTransport, BEH_TRANS_TcpFailStartUsedport) {
//   transport::Transport *node1 = new transport::TransportTCP;
//   transport::Transport *node2 = new transport::TransportTCP;
//   node1->set_transport_id(1);
//   node2->set_transport_id(2);
//   Handler hdlr1, hdlr2;
//   ASSERT_TRUE(node1->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr1, _1, _2, _3, _4)));
//   ASSERT_TRUE(node1->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr1, _1, _2)));
//   ASSERT_TRUE(node2->RegisterOnRPCMessage(boost::bind(&Handler::OnRpcMsgArrived,
//     &hdlr2, _1, _2, _3, _4)));
//   ASSERT_TRUE(node2->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//     &hdlr2, _1, _2)));
// 
//   ASSERT_EQ(0, node1->Start(0));
// #ifndef WIN32
// // Windows allows two ip::tcp::acceptor to be bound to the same port
//   boost::uint16_t lp_node1 = node1->listening_port();
//   ASSERT_EQ(1, node2->Start(lp_node1));
// #endif
//   node1->Stop();
//   delete node1;
//   delete node2;
// }
// 
// TEST(TestTCPTransport, FUNC_TRANS_TcpSend1000Msgs) {
//   const int kNumNodes(6), kRepeatSend(200);
//   Handler hdlr[kNumNodes];
//   transport::Transport* nodes[kNumNodes];
//   boost::thread_group thr_grp;
//   rpcprotocol::RpcMessage rpc_msg;
//   rpc_msg.set_rpc_type(rpcprotocol::REQUEST);
//   rpc_msg.set_message_id(2000);
//   rpc_msg.set_args(base::RandomString(64 * 1024));
//   std::string str_rpc_msg(rpc_msg.SerializeAsString());
// 
//   for (int i = 0; i < kNumNodes; ++i) {
//     nodes[i] = new transport::TransportTCP;
//     nodes[i]->set_transport_id(i);
// 
//     ASSERT_TRUE(nodes[i]->RegisterOnRPCMessage(
//       boost::bind(&Handler::OnRpcMsgArrivedCounter, &hdlr[i], _1, _2, _3, _4)));
//     ASSERT_TRUE(nodes[i]->RegisterOnSend(boost::bind(&Handler::OnSendRpc,
//       &hdlr[i], _1, _2)));
// 
//     ASSERT_EQ(0, nodes[i]->Start(0));
//     if (i != 0) {
//       boost::thread *thrd = new boost::thread(
//         boost::bind(&send_rpcmsg, nodes[i], nodes[0]->listening_port(),
//           kRepeatSend, rpc_msg));
//       thr_grp.add_thread(thrd);
//       boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//     }
//   }
// 
//   thr_grp.join_all();
// 
//   bool finished = false;
//   boost::progress_timer t;
//   unsigned int messages_size = (kNumNodes -1) *  kRepeatSend;
//   while (!finished && t.elapsed() < 20) {
//       if (hdlr[0].msgs_rec >= messages_size) {
//         finished = true;
//         continue;
//       }
//     boost::this_thread::sleep(boost::posix_time::milliseconds(50));
//   }
// 
//   for (int k = 0; k < kNumNodes; ++k) {
//     nodes[k]->Stop();
//     delete nodes[k];
//   }
//   ASSERT_EQ(messages_size, hdlr[0].msgs_rec);
//   for (int k = 1; k < kNumNodes; ++k)
//     ASSERT_EQ(kRepeatSend, hdlr[k].msgs_sent);
//   ASSERT_EQ(str_rpc_msg, hdlr[0].str_msg);
// }
