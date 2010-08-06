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
// // This tests NAT Detection and bootstrap services between three knodes, node 1
// // being the newcomer, node 2 being the rendezvouz and node 3 being the contact
// // which node 2 uses to test direct-connection status of node 1.
//
// #include <gtest/gtest.h>
// #include <google/protobuf/descriptor.h>
// #include <boost/filesystem.hpp>
// #include "maidsafe/kademlia/kadservice.h"
// #include "maidsafe/kademlia/knodeimpl.h"
// #include "maidsafe/tests/kademlia/fake_callbacks.h"
// #include "maidsafe/base/log.h"
// #include "maidsafe/transport/transport.h"
// #include "maidsafe/transport/udttransport.h"
//
// namespace fs = boost::filesystem;
//
// namespace test_nat_detection {
//   static const boost::uint16_t K = 16;
// }  // namespace test_nat_detection
//
// namespace kad {
//
// class Callback {
//  public:
//   Callback() : response_() {}
//   explicit Callback(BootstrapResponse *response) : response_(response) {}
//   void CallbackFunction() {}
//   void CallbackSendNatDet() {
//     response_->set_result(kRpcResultSuccess);
//   }
//  private:
//   BootstrapResponse *response_;
// };
//
// class NatDetectionTest: public testing::Test {
//  protected:
//   NatDetectionTest() : trans_handlers_(), transports_(),
//                        channel_managerA_(NULL), channel_managerB_(NULL),
//                        channel_managerC_(NULL), contactA_(), contactB_(),
//                        contactC_(), remote_contact_(), contact_strA_(),
//                        contact_strB_(), contact_strC_(), remote_node_id_(),
//                        serviceA_(), serviceB_(), serviceC_(), datastoreA_(),
//                        datastoreB_(), datastoreC_(), routingtableA_(),
//                        routingtableB_(), routingtableC_(), channelA_(),
//                        channelB_(), channelC_() {
//     boost::int16_t transport_id;
//     for (boost::uint8_t i = 0; i < 3; ++i) {
//       trans_handlers_.push_back(new transport::TransportHandler);
//       transport::UdtTransport *temp_trans = new transport::UdtTransport;
//       trans_handlers_[i]->Register(temp_trans, &transport_id);
//       transports_.push_back(transport_id);
//     }
//     channel_managerA_ = rpcprotocol::ChannelManager(trans_handlers_[0]);
//     channel_managerB_ = rpcprotocol::ChannelManager(trans_handlers_[1]);
//     channel_managerC_ = rpcprotocol::ChannelManager(trans_handlers_[2]);
//   }
//
//   ~NatDetectionTest() {
//     for (boost::uint8_t i = 0; i < 3; ++i) {
//       delete trans_handlers_[i]->Get(transports_[i]);
//       trans_handlers_[i]->Remove(transports_[i]);
//       delete trans_handlers_[i];
//     }
//     transports_.clear();
//     trans_handlers_.clear();
//   }
//
//   virtual void SetUp() {
//     // Node A.
//     std::string hex_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
//         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
//         "aaa01");
//     ASSERT_TRUE(channel_managerA_.RegisterNotifiersToTransport());
//     ASSERT_TRUE(trans_handlers_[0]->RegisterOnServerDown(
//                 boost::bind(&NatDetectionTest::HandleDeadRVServer, this, _1)));
//     ASSERT_EQ(0, trans_handlers_[0]->Start(0, transports_[0]));
//     ASSERT_EQ(0, channel_managerA_.Start());
//     boost::asio::ip::address local_ip;
//     ASSERT_TRUE(base::GetLocalAddress(&local_ip));
//
//     contactA_ = Contact(base::DecodeFromHex(hex_id), local_ip.to_string(),
//                         trans_handlers_[0]->listening_port(transports_[0]),
//                         local_ip.to_string(),
//                         trans_handlers_[0]->listening_port(transports_[0]));
//     contactA_.SerialiseToString(&contact_strA_);
//
//     datastoreA_.reset(new DataStore(kRefreshTime));
//     routingtableA_.reset(new RoutingTable(contactA_.node_id(),
//                                           test_nat_detection::K));
//     serviceA_.reset(new KadService(NatRpcs(&channel_managerA_,
//         trans_handlers_[0]), datastoreA_, false,
//         boost::bind(&NatDetectionTest::AddCtc, this, _1, _2, _3, 1),
//         boost::bind(&NatDetectionTest::GetRandCtcs, this, _1, _2, _3, 1),
//         boost::bind(&NatDetectionTest::GetCtc, this, _1, _2, 1),
//         boost::bind(&NatDetectionTest::GetKCtcs, this, _1, _2, _3, 1),
//         boost::bind(&NatDetectionTest::Ping, this, _1, _2),
//         boost::bind(&NatDetectionTest::RemoveContact, this, _1)));
//     ContactInfo node_info;
//     node_info.set_node_id(contactA_.node_id().String());
//     node_info.set_ip(contactA_.host_ip());
//     node_info.set_port(contactA_.host_port());
//     node_info.set_local_ip(contactA_.local_ip());
//     node_info.set_local_port(contactA_.local_port());
//     serviceA_->set_node_info(node_info);
//     serviceA_->set_node_joined(true);
//     node_info.Clear();
//     channelA_.reset(new rpcprotocol::Channel(&channel_managerA_,
//                                              trans_handlers_[0]));
//     channelA_->SetService(serviceA_.get());
//     channel_managerA_.RegisterChannel(serviceA_->GetDescriptor()->name(),
//                                       channelA_.get());
//
//     // Node B.
//     hex_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
//              "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
//     ASSERT_TRUE(channel_managerB_.RegisterNotifiersToTransport());
//     ASSERT_TRUE(trans_handlers_[1]->RegisterOnServerDown(
//                 boost::bind(&NatDetectionTest::HandleDeadRVServer, this, _1)));
//     ASSERT_EQ(0, trans_handlers_[1]->Start(0, transports_[1]));
//     ASSERT_EQ(0, channel_managerB_.Start());
//
//     contactB_ = Contact(base::DecodeFromHex(hex_id), local_ip.to_string(),
//                         trans_handlers_[1]->listening_port(transports_[1]),
//                         local_ip.to_string(),
//                         trans_handlers_[1]->listening_port(transports_[1]));
//     contactB_.SerialiseToString(&contact_strB_);
//
//     datastoreB_.reset(new DataStore(kRefreshTime));
//     routingtableB_.reset(new RoutingTable(contactB_.node_id(),
//                                           test_nat_detection::K));
//     serviceB_.reset(new KadService(NatRpcs(&channel_managerB_,
//       trans_handlers_[1]), datastoreB_, false,
//         boost::bind(&NatDetectionTest::AddCtc, this, _1, _2, _3, 2),
//         boost::bind(&NatDetectionTest::GetRandCtcs, this, _1, _2, _3, 2),
//         boost::bind(&NatDetectionTest::GetCtc, this, _1, _2, 2),
//         boost::bind(&NatDetectionTest::GetKCtcs, this, _1, _2, _3, 2),
//         boost::bind(&NatDetectionTest::Ping, this, _1, _2),
//         boost::bind(&NatDetectionTest::RemoveContact, this, _1)));
//     node_info.set_node_id(contactB_.node_id().String());
//     node_info.set_ip(contactB_.host_ip());
//     node_info.set_port(contactB_.host_port());
//     node_info.set_local_ip(contactB_.local_ip());
//     node_info.set_local_port(contactB_.local_port());
//     serviceB_->set_node_info(node_info);
//     serviceB_->set_node_joined(true);
//     node_info.Clear();
//     channelB_.reset(new rpcprotocol::Channel(&channel_managerB_,
//                                              trans_handlers_[1]));
//     channelB_->SetService(serviceB_.get());
//     channel_managerB_.RegisterChannel(serviceB_->GetDescriptor()->name(),
//                                       channelB_.get());
//
//     // Node C.
//     hex_id = "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
//              "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
//     ASSERT_TRUE(channel_managerC_.RegisterNotifiersToTransport());
//     ASSERT_TRUE(trans_handlers_[2]->RegisterOnServerDown(
//                 boost::bind(&NatDetectionTest::HandleDeadRVServer, this, _1)));
//     ASSERT_EQ(0, trans_handlers_[2]->Start(0, transports_[2]));
//     ASSERT_EQ(0, channel_managerC_.Start());
//     contactC_ = Contact(base::DecodeFromHex(hex_id), local_ip.to_string(),
//                         trans_handlers_[2]->listening_port(transports_[2]),
//                         local_ip.to_string(),
//                         trans_handlers_[2]->listening_port(transports_[2]));
//     contactC_.SerialiseToString(&contact_strC_);
//
//     datastoreC_.reset(new DataStore(kRefreshTime));
//     routingtableC_.reset(new RoutingTable(contactC_.node_id(),
//                                           test_nat_detection::K));
//     serviceC_.reset(new KadService(NatRpcs(&channel_managerC_,
//         trans_handlers_[2]), datastoreC_, false,
//         boost::bind(&NatDetectionTest::AddCtc, this, _1, _2, _3, 3),
//         boost::bind(&NatDetectionTest::GetRandCtcs, this, _1, _2, _3, 3),
//         boost::bind(&NatDetectionTest::GetCtc, this, _1, _2, 3),
//         boost::bind(&NatDetectionTest::GetKCtcs, this, _1, _2, _3, 3),
//         boost::bind(&NatDetectionTest::Ping, this, _1, _2),
//         boost::bind(&NatDetectionTest::RemoveContact, this, _1)));
//     node_info.set_node_id(contactC_.node_id().String());
//     node_info.set_ip(contactC_.host_ip());
//     node_info.set_port(contactC_.host_port());
//     node_info.set_local_ip(contactC_.local_ip());
//     node_info.set_local_port(contactC_.local_port());
//     serviceC_->set_node_info(node_info);
//     serviceC_->set_node_joined(true);
//     node_info.Clear();
//     channelC_.reset(new rpcprotocol::Channel(&channel_managerC_,
//                                              trans_handlers_[2]));
//     channelC_->SetService(serviceC_.get());
//     channel_managerC_.RegisterChannel(serviceC_->GetDescriptor()->name(),
//                                       channelC_.get());
//
//     // Add node C's details to node B's routing table
//     ASSERT_EQ(routingtableB_->AddContact(contactC_), 0);
//
//     // Set up another contact
//     hex_id = "22222222222222222222222222222222222222222222222222222222222222222"
//              "222222222222222222222222222222222222222222222222222222222222222";
//     remote_node_id_ = kad::KadId(hex_id, kad::KadId::kHex);
//     remote_contact_.set_node_id(remote_node_id_.String());
//     remote_contact_.set_ip("127.0.0.5");
//     remote_contact_.set_port(5555);
//     remote_contact_.set_local_ip("127.0.0.6");
//     remote_contact_.set_local_port(5556);
//     remote_contact_.set_rendezvous_ip("127.0.0.7");
//     remote_contact_.set_rendezvous_port(5557);
//   }
//
//   virtual void TearDown() {
//     transport::UdtTransport * trans_temp =
//       static_cast<transport::UdtTransport*>(trans_handlers_[0]->Get(0));
//     trans_temp->CleanUp();
//     for (boost::uint16_t i = 0; i < 3; ++i) {
//       trans_handlers_[i]->Stop(transports_[i]);
//     }
//
//     channel_managerA_.UnRegisterChannel(serviceA_->GetDescriptor()->name());
//     channelA_.reset();
//     channel_managerB_.UnRegisterChannel(serviceB_->GetDescriptor()->name());
//     channelB_.reset();
//     channel_managerC_.UnRegisterChannel(serviceC_->GetDescriptor()->name());
//     channelC_.reset();
//     channel_managerA_.Stop();
//     channel_managerB_.Stop();
//     channel_managerC_.Stop();
//   }
//
//   std::vector<transport::TransportHandler*> trans_handlers_;
//   std::vector<boost::int16_t> transports_;
//   rpcprotocol::ChannelManager channel_managerA_, channel_managerB_,
//     channel_managerC_;
//   Contact contactA_, contactB_, contactC_;
//   ContactInfo remote_contact_;
//   std::string contact_strA_, contact_strB_, contact_strC_;
//   kad::KadId remote_node_id_;
//   boost::shared_ptr<KadService> serviceA_, serviceB_, serviceC_;
//   boost::shared_ptr<DataStore> datastoreA_, datastoreB_, datastoreC_;
//   boost::shared_ptr<RoutingTable>routingtableA_, routingtableB_, routingtableC_;
//   boost::shared_ptr<rpcprotocol::Channel> channelA_, channelB_, channelC_;
//  private:
//   int AddCtc(Contact ctc, const float&, const bool &only_db, const int &rt_id) {
//     int result = -1;
//     if (!only_db) {
//       switch (rt_id) {
//         case 1: result = routingtableA_->AddContact(ctc);
//                 break;
//         case 2: result = routingtableB_->AddContact(ctc);
//                 break;
//         case 3: result = routingtableC_->AddContact(ctc);
//                 break;
//         default: result = -1;
//       }
//     }
//     return result;
//   }
//   bool GetCtc(const kad::KadId &id, Contact *ctc, const int &rt_id) {
//     bool result;
//     switch (rt_id) {
//       case 1: result = routingtableA_->GetContact(id, ctc);
//               break;
//       case 2: result = routingtableB_->GetContact(id, ctc);
//               break;
//       case 3: result = routingtableC_->GetContact(id, ctc);
//               break;
//       default: result = false;
//     }
//     return result;
//   }
//   void GetRandCtcs(const size_t &count, const std::vector<Contact> &ex_ctcs,
//                   std::vector<Contact> *ctcs,  const boost::uint16_t &rt_id) {
//     ctcs->clear();
//     std::vector<Contact> all_contacts;
//     boost::uint16_t kbuckets;
//     switch (rt_id) {
//       case 1: kbuckets = routingtableA_->KbucketSize();
//               break;
//       case 2: kbuckets = routingtableB_->KbucketSize();
//               break;
//       case 3: kbuckets = routingtableC_->KbucketSize();
//               break;
//       default: kbuckets = 0;
//     }
//     for (boost::uint16_t i = 0; i < kbuckets; ++i) {
//       std::vector<kad::Contact> contacts_i;
//       switch (rt_id) {
//         case 1: routingtableA_->GetContacts(i, ex_ctcs, &contacts_i);
//                 break;
//         case 2: routingtableB_->GetContacts(i, ex_ctcs, &contacts_i);
//                 break;
//         case 3: routingtableC_->GetContacts(i, ex_ctcs, &contacts_i);
//                 break;
//       }
//       for (size_t j = 0; j < contacts_i.size(); ++j)
//         all_contacts.push_back(contacts_i[j]);
//     }
//     std::random_shuffle(all_contacts.begin(), all_contacts.end());
//     all_contacts.resize(std::min(all_contacts.size(), count));
//     *ctcs = all_contacts;
//   }
//   void GetKCtcs(const KadId &key, const std::vector<Contact> &ex_ctcs,
//                 std::vector<Contact> *ctcs, const boost::uint16_t &rt_id) {
//     switch (rt_id) {
//       case 1: routingtableA_->FindCloseNodes(key, test_nat_detection::K,
//                                              ex_ctcs, ctcs);
//               break;
//       case 2: routingtableB_->FindCloseNodes(key, test_nat_detection::K,
//                                              ex_ctcs, ctcs);
//               break;
//       case 3: routingtableC_->FindCloseNodes(key, test_nat_detection::K,
//                                              ex_ctcs, ctcs);
//               break;
//     }
//   }
//   void Ping(const Contact &ctc, VoidFunctorOneString callback) {
//     boost::thread thrd(boost::bind(&NatDetectionTest::ExePingCb, this,
//                                    ctc.node_id(), callback));
//   }
//   void ExePingCb(const kad::KadId&, VoidFunctorOneString callback) {
//     boost::this_thread::sleep(boost::posix_time::milliseconds(500));
//     PingResponse resp;
//     resp.set_result(kRpcResultFailure);
//     callback(resp.SerializeAsString());
//   }
//   void HandleDeadRVServer(const bool&) {}
//   void RemoveContact(const KadId&) {}
// };
//
// TEST_F(NatDetectionTest, BEH_KAD_NatDetPing) {
//   rpcprotocol::Controller controller;
//   NatDetectionPingRequest *nd_ping_request = new NatDetectionPingRequest;
//   nd_ping_request->set_ping("doink");
//   NatDetectionPingResponse nd_ping_response;
//   Callback cb_obj;
//   google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
//       (&cb_obj, &Callback::CallbackFunction);
//   serviceA_->NatDetectionPing(&controller, nd_ping_request, &nd_ping_response,
//       done1);
//   EXPECT_TRUE(nd_ping_response.IsInitialized());
//   EXPECT_EQ(kRpcResultFailure, nd_ping_response.result());
//   EXPECT_FALSE(nd_ping_response.has_echo());
//   EXPECT_EQ(contactA_.node_id().String(), nd_ping_response.node_id());
//   Contact contactback;
//   EXPECT_FALSE(routingtableA_->GetContact(remote_node_id_, &contactback));
//   // Check success.
//   delete nd_ping_request;
//   nd_ping_request = new NatDetectionPingRequest;
//   nd_ping_request->set_ping("nat_detection_ping");
//   google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
//       (&cb_obj, &Callback::CallbackFunction);
//   nd_ping_response.Clear();
//   serviceA_->NatDetectionPing(&controller, nd_ping_request, &nd_ping_response,
//       done2);
//   EXPECT_TRUE(nd_ping_response.IsInitialized());
//   EXPECT_EQ(kRpcResultSuccess, nd_ping_response.result());
//   EXPECT_EQ("pong", nd_ping_response.echo());
//   EXPECT_EQ(contactA_.node_id().String(), nd_ping_response.node_id());
//   delete nd_ping_request;
// }
//
// TEST_F(NatDetectionTest, BEH_KAD_SendNatDet) {
//   // Send request to node C with node A as newcomer - should fail as node C has
//   // empty routing table.
//   Contact node_c;
//   BootstrapResponse response;
//   Callback cb_obj1(&response);
//   google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
//       (&cb_obj1, &Callback::CallbackFunction);
//   std::vector<Contact> ex_contacts;
//   ex_contacts.push_back(contactA_);
//   rpcprotocol::Controller *controller = new rpcprotocol::Controller;
//   controller->set_transport_id(transports_[0]);
//   struct NatDetectionData nd_data1 = {contactA_, contact_strC_, node_c,
//       &response, done1, controller, ex_contacts};
//   serviceC_->SendNatDetection(nd_data1);
//   EXPECT_FALSE(response.IsInitialized());
//   // Send request to node B (which has node C's details in his routing table)
//   // with node A as newcomer - should succeed.
//   response.Clear();
//   Callback cb_obj2(&response);
//   google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
//       (&cb_obj2, &Callback::CallbackSendNatDet);
//   struct NatDetectionData nd_data2 = {contactA_, contact_strB_, node_c,
//       &response, done2, controller, ex_contacts};
//   serviceB_->SendNatDetection(nd_data2);
//   while (!response.IsInitialized())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(50));
//   EXPECT_EQ(kRpcResultSuccess, response.result());
//   Contact contactback;
//   EXPECT_TRUE(routingtableB_->GetContact(contactA_.node_id(), &contactback));
//   delete controller;
// }
//
// TEST_F(NatDetectionTest, BEH_KAD_BootstrapNatDetRv) {
//   NatDetectionResponse *nd_response = new NatDetectionResponse;
//   Contact node_c;
//   BootstrapResponse response;
//   Callback cb_obj;
//   google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
//       (&cb_obj, &Callback::CallbackFunction);
//   std::vector<Contact> ex_contacts;
//   ex_contacts.push_back(contactA_);
//   rpcprotocol::Controller *controller = new rpcprotocol::Controller;
//   controller->set_transport_id(transports_[0]);
//   struct NatDetectionData nd_data1 = {contactA_, contact_strB_, node_c,
//       &response, done1, controller, ex_contacts};
//   serviceB_->Bootstrap_NatDetectionRv(nd_response, nd_data1);
//   while (!response.has_nat_type())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(50));
//   // It should be able to contact another node
//   EXPECT_EQ(1, response.nat_type());
//
//   response.Clear();
//   nd_response = new NatDetectionResponse;
//   nd_response->set_result(kRpcResultFailure);
//   google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
//       (&cb_obj, &Callback::CallbackFunction);
//   struct NatDetectionData nd_data2 = {contactA_, contact_strB_, node_c,
//       &response, done2, NULL, ex_contacts};
//   serviceB_->Bootstrap_NatDetectionRv(nd_response, nd_data2);
//   while (!response.has_nat_type())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(50));
//   EXPECT_EQ(3, response.nat_type());
//   Contact contactback;
//   EXPECT_TRUE(routingtableB_->GetContact(contactA_.node_id(), &contactback));
//   routingtableB_->RemoveContact(contactA_.node_id(), false);
//   EXPECT_FALSE(routingtableB_->GetContact(contactA_.node_id(), &contactback));
//
//   nd_response = new NatDetectionResponse;
//   response.Clear();
//   nd_response->set_result(kRpcResultSuccess);
//   google::protobuf::Closure *done3 = google::protobuf::NewCallback<Callback>
//       (&cb_obj, &Callback::CallbackFunction);
//   struct NatDetectionData nd_data3 = {contactA_, contact_strB_, node_c,
//       &response, done3, NULL, ex_contacts};
//   serviceB_->Bootstrap_NatDetectionRv(nd_response, nd_data3);
//   while (!response.has_nat_type())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(50));
//   EXPECT_EQ(2, response.nat_type());
//   EXPECT_TRUE(routingtableB_->GetContact(contactA_.node_id(), &contactback));
//   delete controller;
// }
//
// TEST_F(NatDetectionTest, FUNC_KAD_CompleteBootstrapNatDet) {
//   // If NatDetectionResponse is uninitialised, NAT type can't be asserted by
//   // node C, as his routing table is empty
//   NatDetectionResponse *nd_response = new NatDetectionResponse;
//   Contact node_c;
//   BootstrapResponse response;
//   Callback cb_obj;
//   google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
//       (&cb_obj, &Callback::CallbackFunction);
//   std::vector<Contact> ex_contacts;
//   rpcprotocol::Controller *ctrl1 = new rpcprotocol::Controller;
//   ctrl1->set_transport_id(transports_[0]);
//   struct NatDetectionData nd_data1 = {contactA_, contact_strC_, node_c,
//       &response, done1, ctrl1, ex_contacts};
//   serviceC_->Bootstrap_NatDetection(nd_response, nd_data1);
//   EXPECT_EQ("", response.result());
//   EXPECT_EQ(0, response.nat_type());
//   Contact contactback;
//   EXPECT_FALSE(routingtableC_->GetContact(contactA_.node_id(), &contactback));
//   delete ctrl1;
//
// //   If NatDetectionResponse is uninitialised, NAT type can't be asserted, so
// //   node B calls new NatDetection rpc and should identify NAT type as 1.
//   nd_response = new NatDetectionResponse;
//   response.Clear();
//   rpcprotocol::Controller *ctrl2 = new rpcprotocol::Controller;
//   ctrl2->set_transport_id(transports_[0]);
//   google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
//       (&cb_obj, &Callback::CallbackFunction);
//   struct NatDetectionData nd_data2 = {contactA_, contact_strB_, node_c,
//       &response, done2, ctrl2, ex_contacts};
//   serviceB_->Bootstrap_NatDetection(nd_response, nd_data2);
//   while (!response.has_nat_type())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(50));
//
//   EXPECT_EQ(1, response.nat_type());
//   EXPECT_TRUE(routingtableB_->GetContact(contactA_.node_id(), &contactback));
//   routingtableB_->RemoveContact(contactA_.node_id(), false);
//   EXPECT_FALSE(routingtableB_->GetContact(contactA_.node_id(), &contactback));
//   delete ctrl2;
//
//   // If NatDetectionResponse is failure, NAT type can't be asserted, so node B
//   // calls new NatDetection rpc and should identify NAT type as 1.
//   nd_response = new NatDetectionResponse;
//   response.Clear();
//   nd_response->set_result(kRpcResultFailure);
//   rpcprotocol::Controller *ctrl3 = new rpcprotocol::Controller;
//   ctrl3->set_transport_id(transports_[0]);
//   google::protobuf::Closure *done3 = google::protobuf::NewCallback<Callback>
//       (&cb_obj, &Callback::CallbackFunction);
//   struct NatDetectionData nd_data3 = {contactA_, contact_strB_, node_c,
//       &response, done3, ctrl3, ex_contacts};
//   serviceB_->Bootstrap_NatDetection(nd_response, nd_data3);
//   while (!response.has_nat_type())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(50));
//   EXPECT_EQ(1, response.nat_type());
//   EXPECT_TRUE(routingtableB_->GetContact(contactA_.node_id(), &contactback));
//   routingtableB_->RemoveContact(contactA_.node_id(), false);
//   EXPECT_FALSE(routingtableB_->GetContact(contactA_.node_id(), &contactback));
//   delete ctrl3;
//
//   // If NatDetectionResponse is success, NAT type is 1.
//   nd_response = new NatDetectionResponse;
//   response.Clear();
//   nd_response->set_result(kRpcResultSuccess);
//   rpcprotocol::Controller *ctrl4 = new rpcprotocol::Controller;
//   ctrl4->set_transport_id(transports_[0]);
//   google::protobuf::Closure *done4 = google::protobuf::NewCallback<Callback>
//       (&cb_obj, &Callback::CallbackFunction);
//   struct NatDetectionData nd_data4 = {contactA_, contact_strB_, node_c,
//       &response, done4, ctrl4, ex_contacts};
//   serviceB_->Bootstrap_NatDetection(nd_response, nd_data4);
//   while (!response.has_nat_type())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(50));
//   EXPECT_EQ(1, response.nat_type());
//   EXPECT_TRUE(routingtableB_->GetContact(contactA_.node_id(), &contactback));
//   routingtableB_->RemoveContact(contactA_.node_id(), false);
//   EXPECT_FALSE(routingtableB_->GetContact(contactA_.node_id(), &contactback));
//
//   // If NatDetectionResponse is failure, NAT type can't be asserted, so node B
//   // calls new NatDetection rpc.  If node C is switched off, this should fail.
//   ex_contacts.push_back(contactA_);
//   nd_response = new NatDetectionResponse;
//   response.Clear();
//   nd_response->set_result(kRpcResultFailure);
//   rpcprotocol::Controller *ctrl5 = new rpcprotocol::Controller;
//   ctrl5->set_transport_id(transports_[0]);
//   google::protobuf::Closure *done5 = google::protobuf::NewCallback<Callback>
//       (&cb_obj, &Callback::CallbackFunction);
//   struct NatDetectionData nd_data5 = {contactA_, contact_strB_, contactC_,
//       &response, done5, ctrl5, ex_contacts};
//
//   channel_managerC_.UnRegisterChannel(serviceC_->GetDescriptor()->name());
//   serviceB_->Bootstrap_NatDetection(nd_response, nd_data5);
//   while (!response.IsInitialized())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
//   EXPECT_EQ(kad::kRpcResultFailure, response.result());
//   EXPECT_FALSE(routingtableB_->GetContact(contactA_.node_id(), &contactback));
//   delete ctrl5;
// }
//
// TEST_F(NatDetectionTest, BEH_KAD_CompleteNatDet) {
//   // With request uninitialised, fail.
//   NatDetectionRequest nd_request;
//   NatDetectionResponse nd_response;
//   Callback cb_obj;
//   google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
//       (&cb_obj, &Callback::CallbackFunction);
//   rpcprotocol::Controller controller1;
//   serviceC_->NatDetection(&controller1, &nd_request, &nd_response, done1);
//   while (!nd_response.IsInitialized())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(50));
//   EXPECT_TRUE(nd_response.IsInitialized());
//   EXPECT_EQ(kRpcResultFailure, nd_response.result());
//   Contact contactback;
//   EXPECT_FALSE(routingtableA_->GetContact(contactC_.node_id(), &contactback));
//   EXPECT_FALSE(routingtableC_->GetContact(contactA_.node_id(), &contactback));
//
//   // With request incorrectly initialised, fail.
//   nd_request.set_newcomer(contact_strA_);
//   nd_request.set_bootstrap_node(contact_strB_);
//   nd_request.set_type(11);
//   nd_request.set_sender_id(contactA_.node_id().String());
//   nd_response.Clear();
//   google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
//       (&cb_obj, &Callback::CallbackFunction);
//   rpcprotocol::Controller controller2;
//   serviceC_->NatDetection(&controller2, &nd_request, &nd_response, done2);
//   while (!nd_response.IsInitialized())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(50));
//   EXPECT_TRUE(nd_response.IsInitialized());
//   EXPECT_EQ(kRpcResultFailure, nd_response.result());
//   EXPECT_FALSE(routingtableA_->GetContact(contactC_.node_id(), &contactback));
//   EXPECT_FALSE(routingtableC_->GetContact(contactA_.node_id(), &contactback));
//
//   // With request type == 1, node C tries to ping node A.
//   nd_request.set_newcomer(contact_strA_);
//   nd_request.set_bootstrap_node(contact_strB_);
//   nd_request.set_type(1);
//   nd_request.set_sender_id(contactA_.node_id().String());
//   nd_response.Clear();
//   google::protobuf::Closure *done3 = google::protobuf::NewCallback<Callback>
//       (&cb_obj, &Callback::CallbackFunction);
//   rpcprotocol::Controller controller3;
//   serviceC_->NatDetection(&controller3, &nd_request, &nd_response, done3);
//   while (!nd_response.IsInitialized())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(50));
//   EXPECT_TRUE(nd_response.IsInitialized());
//   EXPECT_EQ(kRpcResultSuccess, nd_response.result());
//   // Node C hasn't added A's details as there weren't enough to warrant addition
//   // at the nat detection ping stage.
//   EXPECT_FALSE(routingtableC_->GetContact(contactA_.node_id(), &contactback));
//   routingtableA_->RemoveContact(contactC_.node_id(), false);
//   EXPECT_FALSE(routingtableA_->GetContact(contactC_.node_id(), &contactback));
//
//   // With request type == 2, node C tries to rendezvouz with node A via node B.
//   nd_request.set_newcomer(contact_strA_);
//   nd_request.set_bootstrap_node(contact_strB_);
//   nd_request.set_type(2);
//   nd_request.set_sender_id(contactA_.node_id().String());
//   nd_response.Clear();
//   google::protobuf::Closure *done4 = google::protobuf::NewCallback<Callback>
//       (&cb_obj, &Callback::CallbackFunction);
//   rpcprotocol::Controller controller4;
//   serviceC_->NatDetection(&controller4, &nd_request, &nd_response, done4);
//   while (!nd_response.IsInitialized())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(50));
//   EXPECT_TRUE(nd_response.IsInitialized());
//   EXPECT_EQ(kRpcResultSuccess, nd_response.result());
//   // Node C hasn't added A's details as there weren't enough to warrant addition
//   // at the nat detection ping stage.
//   EXPECT_FALSE(routingtableC_->GetContact(contactA_.node_id(), &contactback));
// }
//
// TEST_F(NatDetectionTest, BEH_KAD_FullBootstrap) {
//   // With request uninitialised, fail.
//   BootstrapRequest request;
//   BootstrapResponse response;
//   Callback cb_obj;
//
//   // Check for id == kClientId
//   request.set_newcomer_id(kClientId);
//   request.set_newcomer_local_ip(contactA_.local_ip());
//   request.set_newcomer_local_port(contactA_.local_port());
//   request.set_newcomer_ext_ip(contactA_.host_ip());
//   request.set_newcomer_ext_port(contactA_.host_port());
//   request.set_node_type(VAULT);
//
//   // Check for normal id
//   request.set_newcomer_id(contactA_.node_id().String());
//   response.Clear();
//   google::protobuf::Closure *done3 = google::protobuf::NewCallback<Callback>
//       (&cb_obj, &Callback::CallbackFunction);
//   rpcprotocol::Controller controller3;
//   serviceB_->Bootstrap(&controller3, &request, &response, done3);
//   while (!response.has_nat_type())
//     boost::this_thread::sleep(boost::posix_time::milliseconds(50));
//   EXPECT_EQ(kRpcResultSuccess, response.result());
//   EXPECT_EQ(contactB_.node_id().String(), response.bootstrap_id());
//   EXPECT_EQ(contactA_.host_ip(), response.newcomer_ext_ip());
//   EXPECT_EQ(contactA_.host_port(), response.newcomer_ext_port());
//   EXPECT_EQ(1, response.nat_type());
// }
//
// }  // namespace kad
