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
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <bitset>

#include "boost/lexical_cast.hpp"
#include "boost/thread.hpp"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "maidsafe-dht/transport/utils.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe-dht/kademlia/alternative_store.h"
#include "maidsafe-dht/kademlia/contact.h"
#include "maidsafe-dht/kademlia/datastore.h"
#include "maidsafe-dht/kademlia/message_handler.h"
#include "maidsafe-dht/kademlia/node_id.h"
#include "maidsafe-dht/kademlia/node_impl.h"
#include "maidsafe-dht/kademlia/routing_table.h"
#include "maidsafe-dht/kademlia/rpcs.pb.h"
#include "maidsafe-dht/kademlia/rpcs.h"
#include "maidsafe-dht/kademlia/securifier.h"
#include "maidsafe-dht/kademlia/service.h"
#include "maidsafe-dht/transport/transport.h"
#include "maidsafe-dht/tests/kademlia/utils.h"

namespace maidsafe {

namespace kademlia {

namespace test {

// static const boost::uint16_t k = 8;
static const boost::uint16_t alpha = 3;
static const boost::uint16_t beta = 2;
static const boost::uint16_t randomnoresponserate = 20;  // in percentage

class SecurifierValidateTrue: public Securifier {
 public:
  SecurifierValidateTrue(const std::string &public_key_id,
                          const std::string &public_key,
                          const std::string &private_key) :
      Securifier(public_key_id, public_key, private_key) {}

  bool Validate(const std::string&,
                const std::string&,
                const std::string&,
                const std::string&,
                const std::string&,
                const std::string&) const {
    return true;
  }
};

void FindNodeCallback(RankInfoPtr rank_info,
                      int result_size,
                      const std::vector<Contact> &cs,
                      bool *done,
                      std::vector<Contact> *contacts) {
  contacts->clear();
  *contacts = cs;
  *done = true;
}

struct FindValueResults {
  FindValueResults() : response_code(-3), values(), contacts() {}
  int response_code;
  std::vector<std::string> values;
  std::vector<Contact> contacts;
};

void FindValueCallback(int return_code,
                       const std::vector<std::string> &vs,
                       const std::vector<Contact> &cs,
                       const Contact &alternative_store_contact,
                       const Contact &cache_contact,
                       bool *done,
                       FindValueResults *results) {
  results->values.clear();
  results->values = vs;
  results->contacts.clear();
  results->contacts = cs;
  *done = true;
  results->response_code = return_code;
}

void ErrorCodeCallback(int error_code,
                       bool *done,
                       int *response_code) {
  *done = true;
  *response_code = error_code;
}

void GetContactCallback(int error_code,
                        Contact contact,
                        Contact *result,
                        bool *done,
                        int *response_code) {
  *done = true;
  *response_code = error_code;
  *result = contact;
}

class MockTransport : public transport::Transport {
 public:
  MockTransport() : transport::Transport(io_service_) {}
  virtual transport::TransportCondition StartListening(
      const transport::Endpoint &endpoint) {
    listening_port_ = 5483;
    return transport::kSuccess;
  }
  virtual transport::TransportCondition Bootstrap(
      const std::vector<transport::Endpoint> &candidates) {
    return transport::kSuccess;
  }
  virtual void StopListening() { listening_port_ = 0; }
  virtual void Send(const std::string &data,
                    const transport::Endpoint &endpoint,
                    const transport::Timeout &timeout) {}
 private:
  boost::asio::io_service io_service_;
};

class TestAlternativeStore : public AlternativeStore {
 public:
  ~TestAlternativeStore() {}
  bool Has(const std::string&) { return false; }
};

class NodeImplTest : public CreateContactAndNodeId, public testing::Test {
 protected:
  NodeImplTest() : CreateContactAndNodeId(),
                   data_store_(),
                   alternative_store_(),
                   securifier_(new Securifier("", "", "")),
                   transport_(new MockTransport),
                   rank_info_(),
                   asio_service_(),
                   message_handler_(new MessageHandler(securifier_)),
                   node_(new Node::Impl(asio_service_,
                                        transport_,
                                        message_handler_,
                                        securifier_,
                                        alternative_store_,
                                        false,
                                        test::k,
                                        test::alpha,
                                        test::beta,
                                        bptime::seconds(3600))),
                   threshold_((test::k * 3) / 4),
                   local_node_(
                       new Node::Impl(asio_service_,
                                      transport_,
                                      message_handler_,
                                      SecurifierPtr(new SecurifierValidateTrue(
                                                        "", "", "")),
                                      alternative_store_,
                                      true,
                                      test::k,
                                      test::alpha,
                                      test::beta,
                                      bptime::seconds(3600))) {
    data_store_ = node_->data_store_;
    node_->routing_table_ = routing_table_;
    local_node_->routing_table_ = routing_table_;
    transport_->StartListening(transport::Endpoint("127.0.0.1", 6700));
  }

  static void SetUpTestCase() {}

  static void TearDownTestCase() {}

  void PopulateRoutingTable(boost::uint16_t count, boost::uint16_t pos) {
    for (int num_contact = 0; num_contact < count; ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(node_id_, pos);
      Contact contact = ComposeContact(contact_id, 5000);
      AddContact(routing_table_, contact, rank_info_);
    }
  }

  void SetAllNumRpcsFailureToZero() {
    std::vector<Contact> contacts;
    routing_table_->GetAllContacts(&contacts);
    std::for_each(contacts.begin(), contacts.end(),
                  boost::bind(&AddContact, routing_table_, _1, rank_info_));
  }

  std::shared_ptr<Rpcs> GetRpc() {
    return node_->rpcs_;
  }

  void SetRpc(std::shared_ptr<Rpcs> rpc) {
    node_->rpcs_ = rpc;
  }

  void SetLocalRpc(std::shared_ptr<Rpcs> rpc) {
    local_node_->rpcs_ = rpc;
  }

  std::shared_ptr<DataStore> data_store_;
  AlternativeStorePtr alternative_store_;
  SecurifierPtr securifier_;
  TransportPtr transport_;
  RankInfoPtr rank_info_;
  std::shared_ptr<boost::asio::io_service> asio_service_;
  MessageHandlerPtr message_handler_;
  std::shared_ptr<Node::Impl> node_;
  int threshold_;
  std::shared_ptr<Node::Impl> local_node_;

 public:
  void NodeImplJoinCallback(int output, int* result, bool *done) {
    *result = output;
    *done = true;
  }
};  // NodeImplTest

class MockRpcs : public Rpcs, public CreateContactAndNodeId {
 public:
  explicit MockRpcs(std::shared_ptr<boost::asio::io_service> asio_service,
                    SecurifierPtr securifier)
      : Rpcs(asio_service, securifier),
        CreateContactAndNodeId(),
        node_list_mutex_(),
        node_list_(),
        rank_info_(),
        num_of_acquired_(0),
        num_of_deleted_(0),
        respond_(0),
        no_respond_(0),
        respond_contacts_(),
        target_id_(),
        threshold_((test::k * 3) / 4) {}
  MOCK_METHOD8(Store, void(const Key &key,
                           const std::string &value,
                           const std::string &signature,
                           const boost::posix_time::seconds &ttl,
                           SecurifierPtr securifier,
                           const Contact &peer,
                           StoreFunctor callback,
                           TransportType type));

  MOCK_METHOD7(Delete, void(const Key &key,
                            const std::string &value,
                            const std::string &signature,
                            SecurifierPtr securifier,
                            const Contact &peer,
                            DeleteFunctor callback,
                            TransportType type));

  MOCK_METHOD5(FindNodes, void(const NodeId &key,
                               const SecurifierPtr securifier,
                               const Contact &contact,
                               FindNodesFunctor callback,
                               TransportType type));

  MOCK_METHOD5(FindValue, void(const NodeId &key,
                               const SecurifierPtr securifier,
                               const Contact &contact,
                               FindValueFunctor callback,
                               TransportType type));

  MOCK_METHOD4(Downlist, void(const std::vector<NodeId> &node_ids,
                              SecurifierPtr securifier,
                              const Contact &peer,
                              TransportType type));

  MOCK_METHOD4(Ping, void(SecurifierPtr securifier,
                          const Contact &peer,
                          PingFunctor callback,
                          TransportType type));

  MOCK_METHOD6(StoreRefresh,
               void(const std::string &serialised_store_request,
                    const std::string &serialised_store_request_signature,
                    SecurifierPtr securifier,
                    const Contact &peer,
                    StoreRefreshFunctor callback,
                    TransportType type));

  void StoreRefreshThread(StoreRefreshFunctor callback) {
    RankInfoPtr rank_info;
    callback(rank_info, transport::kSuccess);
  }
  void StoreRefreshCallback(StoreRefreshFunctor callback) {
    boost::thread th(boost::bind(&MockRpcs::StoreRefreshThread, this,
                                 callback));
  }
  void FindNodeRandomResponseClose(const Contact &c,
                                   FindNodesFunctor callback) {
    int response_factor = RandomUint32() % 100;
    bool response(true);
    if (response_factor < test::randomnoresponserate)
      response = false;
    std::vector<Contact> response_list;
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    if (response) {
      int elements = RandomUint32() % test::k;
      for (int n = 0; n < elements; ++n) {
        int element = RandomUint32() % node_list_.size();
        // make sure the new one hasn't been set as down previously
        ContactsById key_indx = down_contacts_->get<NodeIdTag>();
        auto it = key_indx.find(node_list_[element].node_id());
        if (it == key_indx.end()) {
          response_list.push_back(node_list_[element]);
          ContactsById key_indx = respond_contacts_->get<NodeIdTag>();
          auto it = key_indx.find(node_list_[element].node_id());
          if (it == key_indx.end()) {
            RoutingTableContact new_routing_table_contact(node_list_[element],
                                                          target_id_,
                                                          0);
            respond_contacts_->insert(new_routing_table_contact);
          }
        }
      }
      boost::thread th(boost::bind(&MockRpcs::FindNodeResponseThread,
                                   this, callback, response_list));
    } else {
      ContactsById key_indx = respond_contacts_->get<NodeIdTag>();
      auto it = key_indx.find(c.node_id());
      if (it != key_indx.end()) {
        down_contacts_->insert((*it));
        respond_contacts_->erase(it);
      }
      boost::thread th(boost::bind(&MockRpcs::FindNodeNoResponseThread,
                                   this, callback, response_list));
    }
  }

  void FindNodeResponseClose(const Contact &c,
                             FindNodesFunctor callback) {
    std::vector<Contact> response_list;
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    int elements = RandomUint32() % test::k;
    for (int n = 0; n < elements; ++n) {
      int element = RandomUint32() % node_list_.size();
      response_list.push_back(node_list_[element]);
      RoutingTableContact new_routing_table_contact(node_list_[element],
                                                    target_id_,
                                                    0);
      respond_contacts_->insert(new_routing_table_contact);
    }
    boost::thread th(boost::bind(&MockRpcs::FindNodeResponseThread,
                                 this, callback, response_list));
  }

  void FindNodeResponseNoClose(const Contact &c,
                               FindNodesFunctor callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    std::vector<Contact> response_list;
    boost::thread th(boost::bind(&MockRpcs::FindNodeResponseThread,
                                 this, callback, response_list));
  }

  void FindNodeFirstNoResponse(const Contact &c,
                               FindNodesFunctor callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    std::vector<Contact> response_list;
    if (num_of_acquired_ == 0) {
      boost::thread th(boost::bind(&MockRpcs::FindNodeNoResponseThread,
                                   this, callback, response_list));
    } else {
      boost::thread th(boost::bind(&MockRpcs::FindNodeResponseThread,
                                   this, callback, response_list));
    }
    ++num_of_acquired_;
  }

  void FindNodeFirstAndLastNoResponse(const Contact &c,
                                      FindNodesFunctor callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    std::vector<Contact> response_list;
    if ((num_of_acquired_ == (test::k - 1)) || (num_of_acquired_ == 0)) {
      boost::thread th(boost::bind(&MockRpcs::FindNodeNoResponseThread,
                                   this, callback, response_list));
    } else {
      boost::thread th(boost::bind(&MockRpcs::FindNodeResponseThread,
                                   this, callback, response_list));
    }
    ++num_of_acquired_;
  }

  void FindNodeSeveralResponseNoClose(const Contact &c,
                                      FindNodesFunctor callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    std::vector<Contact> response_list;
    if (num_of_acquired_ > (test::k - threshold_)) {
      boost::thread th(boost::bind(&MockRpcs::FindNodeResponseThread,
                                   this, callback, response_list));
    } else {
      boost::thread th(boost::bind(&MockRpcs::FindNodeNoResponseThread,
                                   this, callback, response_list));
    }
    ++num_of_acquired_;
  }

  void FindNodeNoResponse(const Contact &c,
                          FindNodesFunctor callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    std::vector<Contact> response_list;
    boost::thread th(boost::bind(&MockRpcs::FindNodeNoResponseThread,
                                 this, callback, response_list));
  }

  void FindNodeResponseThread(FindNodesFunctor callback,
                              std::vector<Contact> response_list) {
    boost::uint16_t interval(10 * (RandomUint32() % 5) + 1);
    boost::this_thread::sleep(boost::posix_time::milliseconds(interval));
    callback(rank_info_, response_list.size(), response_list);
  }

  void FindNodeNoResponseThread(FindNodesFunctor callback,
                                std::vector<Contact> response_list) {
    boost::uint16_t interval(100 * (RandomUint32() % 5) + 1);
    boost::this_thread::sleep(boost::posix_time::milliseconds(interval));
    callback(rank_info_, -1, response_list);
  }

  void FindValueNoResponse(const Contact &c,
                           Rpcs::FindValueFunctor callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    std::vector<Contact> response_contact_list;
    std::vector<std::string> response_value_list;
    boost::thread th(boost::bind(&MockRpcs::FindValueNoResponseThread,
                                 this, callback,
                                 response_value_list, response_contact_list));
  }

  void FindValueResponseCloseOnly(const Contact &c,
                                  Rpcs::FindValueFunctor callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    std::vector<Contact> response_contact_list;
    int elements = RandomUint32() % test::k;
    for (int n = 0; n < elements; ++n) {
      int element = RandomUint32() % node_list_.size();
      response_contact_list.push_back(node_list_[element]);
    }
    std::vector<std::string> response_value_list;
    boost::thread th(boost::bind(&MockRpcs::FindValueResponseThread,
                                 this, callback,
                                 response_value_list, response_contact_list));
  }

  void FindValueNthResponse(const Contact &c,
                            Rpcs::FindValueFunctor callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    std::vector<Contact> response_contact_list;
    std::vector<std::string> response_value_list;
    ++num_of_acquired_;
    if (respond_ != num_of_acquired_) {
      int elements = RandomUint32() % test::k + 1;
      for (int n = 0; n < elements; ++n) {
        int element = RandomUint32() % node_list_.size();
        response_contact_list.push_back(node_list_[element]);
        RoutingTableContact new_routing_table_contact(node_list_[element],
                                                      target_id_,
                                                      0);
        respond_contacts_->insert(new_routing_table_contact);
      }
    } else {
      response_value_list.push_back("FIND");
    }
    boost::thread th(boost::bind(&MockRpcs::FindValueResponseThread,
                                 this, callback,
                                 response_value_list, response_contact_list));
  }

  void FindValueNoValueResponse(const Contact &c,
                                Rpcs::FindValueFunctor callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    std::vector<Contact> response_contact_list;
    std::vector<std::string> response_value_list;
    ++num_of_acquired_;
    int elements = RandomUint32() % test::k;
    for (int n = 0; n < elements; ++n) {
      int element = RandomUint32() % node_list_.size();
      response_contact_list.push_back(node_list_[element]);
    }
    boost::thread th(boost::bind(&MockRpcs::FindValueResponseThread,
                                 this, callback,
                                 response_value_list, response_contact_list));
  }

  void FindValueResponseThread(Rpcs::FindValueFunctor callback,
                               std::vector<std::string> response_value_list,
                               std::vector<Contact> response_contact_list) {
    boost::uint16_t interval(10 * (RandomUint32() % 5) + 1);
    boost::this_thread::sleep(boost::posix_time::milliseconds(interval));
    Contact alternative_store;
    callback(rank_info_, 0, response_value_list,
             response_contact_list, alternative_store);
  }

  void FindValueNoResponseThread(Rpcs::FindValueFunctor callback,
                                 std::vector<std::string> response_value_list,
                                 std::vector<Contact> response_contact_list) {
    boost::uint16_t interval(100 * (RandomUint32() % 5) + 1);
    boost::this_thread::sleep(boost::posix_time::milliseconds(interval));
    Contact alternative_store;
    callback(rank_info_, -1, response_value_list, response_contact_list,
             alternative_store);
  }

  void DownlistRecord(const std::vector<NodeId> &node_ids,
                      const Contact &contact) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    ContactsById key_indx = down_contacts_->get<NodeIdTag>();
    auto it_node = node_ids.begin();
    auto it_end = node_ids.end();
    while (it_node != it_end) {
      auto itr = key_indx.find((*it_node));
      if (itr == key_indx.end()) {
        Contact temp_contact = ComposeContact((*it_node), 5000);
        RoutingTableContact new_routing_table_contact(temp_contact,
                                                      target_id_,
                                                      0);
        new_routing_table_contact.num_failed_rpcs = 1;
        down_contacts_->insert(new_routing_table_contact);
      } else {
        boost::uint16_t num_failed_rpcs = (*itr).num_failed_rpcs + 1;
        key_indx.modify(itr, ChangeNumFailedRpc(num_failed_rpcs));
      }
      ++it_node;
    }
  }

  void SingleDeleteResponse(const Contact &c, Rpcs::DeleteFunctor callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    ++num_of_deleted_;
    boost::thread th(boost::bind(
        &MockRpcs::CommonResponseThread<Rpcs::DeleteFunctor>, this, callback));
  }

  template <class T>
  void Response(const Contact &c, T callback) {
// boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
// ++respond_;
    boost::thread th(boost::bind(&MockRpcs::CommonResponseThread<T>,
                                 this, callback));
  }

  template <class T>
  void NoResponse(const Contact &c, T callback) {
    boost::thread th(boost::bind(&MockRpcs::CommonNoResponseThread<T>,
                                 this, callback));
  }

  template <class T>
  void FirstSeveralNoResponse(const Contact &c, T callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    if (num_of_acquired_ > (test::k - threshold_)) {
      ++respond_;
      boost::thread th(boost::bind(&MockRpcs::CommonResponseThread<T>,
                                   this, callback));
    } else {
      ++no_respond_;
      boost::thread th(boost::bind(&MockRpcs::CommonNoResponseThread<T>,
                                   this, callback));
    }
    ++num_of_acquired_;
  }

  template <class T>
  void LastSeveralNoResponse(const Contact &c, T callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    if (num_of_acquired_ < (threshold_ - 1)) {
      ++respond_;
      boost::thread th(boost::bind(&MockRpcs::CommonResponseThread<T>,
                                   this, callback));
    } else {
      ++no_respond_;
      boost::thread th(boost::bind(&MockRpcs::CommonNoResponseThread<T>,
                                   this, callback));
    }
    ++num_of_acquired_;
  }

  template <class T>
  void LastLessNoResponse(const Contact &c, T callback) {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    if (num_of_acquired_ < threshold_) {
      ++respond_;
      boost::thread th(boost::bind(&MockRpcs::CommonResponseThread<T>,
                                   this, callback));
    } else {
      ++no_respond_;
      boost::thread th(boost::bind(&MockRpcs::CommonNoResponseThread<T>,
                                   this, callback));
    }
    ++num_of_acquired_;
  }

  template <class T>
  void CommonResponseThread(T callback) {
    boost::uint16_t interval(10 * (RandomUint32() % 5) + 1);
    boost::this_thread::sleep(boost::posix_time::milliseconds(interval));
    callback(rank_info_, RandomUint32() % test::k);
  }

  template <class T>
  void CommonNoResponseThread(T callback) {
    boost::uint16_t interval(100 * (RandomUint32() % 5) + 1);
    boost::this_thread::sleep(boost::posix_time::milliseconds(interval));
    callback(rank_info_, -1);
  }

  void PopulateResponseCandidates(int count, const int& pos) {
    PopulateContactsVector(count, pos, &node_list_);
  }

  std::vector<Contact> node_list() {
    boost::mutex::scoped_lock loch_queldomage(node_list_mutex_);
    return node_list_;
  }

  void SetCountersToZero() {
    num_of_acquired_ = 0;
    num_of_deleted_ = 0;
    respond_ = 0;
    no_respond_ = 0;
  }

  boost::mutex node_list_mutex_;
  std::vector<Contact> node_list_;
  RankInfoPtr rank_info_;

  boost::uint16_t num_of_acquired_;
  boost::uint16_t num_of_deleted_;
  boost::uint16_t respond_;
  boost::uint16_t no_respond_;

  std::shared_ptr<RoutingTableContactsContainer> respond_contacts_;
  std::shared_ptr<RoutingTableContactsContainer> down_contacts_;
  NodeId target_id_;
  int threshold_;
};  // class MockRpcs

TEST_F(NodeImplTest, BEH_KAD_GetAllContacts) {
  PopulateRoutingTable(test::k, 500);
  std::vector<Contact> contacts;
  node_->GetAllContacts(&contacts);
  EXPECT_EQ(test::k, contacts.size());
}

TEST_F(NodeImplTest, BEH_KAD_GetBootstrapContacts) {
  PopulateRoutingTable(test::k, 500);
  std::vector<Contact> contacts;
  node_->GetBootstrapContacts(&contacts);
  EXPECT_EQ(test::k, contacts.size());
}

TEST_F(NodeImplTest, BEH_KAD_GetContact) {
  PopulateRoutingTable(test::k, 500);

  std::shared_ptr<MockRpcs> new_rpcs(new MockRpcs(asio_service_, securifier_));
  new_rpcs->node_id_ = node_id_;
  SetRpc(new_rpcs);

  int count = 10 * test::k;
  new_rpcs->PopulateResponseCandidates(count, 499);
  std::shared_ptr<RoutingTableContactsContainer> temp
      (new RoutingTableContactsContainer());
  new_rpcs->respond_contacts_ = temp;

  EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                   testing::_, testing::_))
      .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
          boost::bind(&MockRpcs::FindNodeResponseClose,
                      new_rpcs.get(), _1, _2))));
  NodeId target_id = GenerateRandomId(node_id_, 498);
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // Looking for a non-exist contact
    Contact result;
    bool done(false);
    int response_code(0);
    node_->GetContact(target_id,
                  boost::bind(&GetContactCallback, _1, _2,
                              &result, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));

    EXPECT_EQ(-1, response_code);
    EXPECT_EQ(Contact(), result);
  }
  Contact target = ComposeContact(target_id, 5000);
  AddContact(routing_table_, target, rank_info_);
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // Looking for an exist contact
    Contact result;
    bool done(false);
    int response_code(0);
    node_->GetContact(target_id,
                  boost::bind(&GetContactCallback, _1, _2,
                              &result, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));

    EXPECT_EQ(1, response_code);
    EXPECT_EQ(target, result);
  }
  // sleep for a while to prevent the situation that resources got destructed
  // before all call back from rpc completed. Which will cause "Segmentation
  // Fault" in execution.
  boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
}

TEST_F(NodeImplTest, BEH_KAD_ValidateContact) {
  NodeId contact_id = GenerateRandomId(node_id_, 501);
  Contact contact = ComposeContact(contact_id, 5000);
  local_node_->EnableValidateContact();
  {
    routing_table_->AddContact(contact, rank_info_);
    // need to sleep for a while
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    Contact result;
    routing_table_->GetContact(contact.node_id(), &result);
    EXPECT_EQ(contact, result);
  }
}

TEST_F(NodeImplTest, BEH_KAD_PingOldestContact) {
  PopulateRoutingTable(test::k, 500);
  PopulateRoutingTable(test::k, 501);

  std::shared_ptr<MockRpcs> new_rpcs(new MockRpcs(asio_service_, securifier_));
  new_rpcs->node_id_ = node_id_;
  SetLocalRpc(new_rpcs);

  NodeId new_id = GenerateUniqueRandomId(node_id_, 501);
  Contact new_contact = ComposeContact(new_id, 5000);

  local_node_->EnablePingOldestContact();
  local_node_->EnableValidateContact();
  {
    // Ping success
    EXPECT_CALL(*new_rpcs, Ping(testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<1, 2>(testing::Invoke(
            boost::bind(&MockRpcs::Response<Rpcs::PingFunctor>,
                        new_rpcs.get(), _1, _2))));
    AddContact(routing_table_, new_contact, rank_info_);
    // need to sleep for a while
    boost::this_thread::sleep(boost::posix_time::milliseconds(10000));

    Contact result_new;
    routing_table_->GetContact(new_contact.node_id(), &result_new);
//    EXPECT_EQ(Contact(), result_new);
  }
  {
    // Ping failed
    EXPECT_CALL(*new_rpcs, Ping(testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<1, 2>(testing::Invoke(
            boost::bind(&MockRpcs::NoResponse<Rpcs::PingFunctor>,
                        new_rpcs.get(), _1, _2))));
    AddContact(routing_table_, new_contact, rank_info_);

    Contact result_new;
    // may need to put a timer to prevent deadlock
    do {
      routing_table_->GetContact(new_contact.node_id(), &result_new);
      boost::this_thread::sleep(boost::posix_time::milliseconds(200));
    } while (result_new == Contact());
    EXPECT_EQ(new_contact, result_new);
  }
}

TEST_F(NodeImplTest, BEH_KAD_Join) {
  std::vector<Contact> bootstrap_contacts;
  std::shared_ptr<Rpcs> old_rpcs = GetRpc();
  std::shared_ptr<MockRpcs> new_rpcs(new MockRpcs(asio_service_, securifier_));
  SetRpc(new_rpcs);

  int count = 10 * test::k;
  new_rpcs->PopulateResponseCandidates(count, 499);
  NodeId target = GenerateRandomId(node_id_, 480);
  new_rpcs->target_id_ = target;
  std::shared_ptr<RoutingTableContactsContainer> temp
      (new RoutingTableContactsContainer());
  new_rpcs->respond_contacts_ = temp;
  new_rpcs->SetCountersToZero();

  // When last contact in bootstrap_contacts is valid
  {
    int result(1);
    bool done(false);
    JoinFunctor callback = boost::bind(&NodeImplTest::NodeImplJoinCallback,
                                       this, _1, &result, &done);
    Contact contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 490)),
                                     5600);
    bootstrap_contacts.push_back(contact);

    contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 495)), 5700);
    bootstrap_contacts.push_back(contact);

    contact = ComposeContact(target, 6400);
    bootstrap_contacts.push_back(contact);

    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillOnce(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeNoResponse, new_rpcs.get(), _1,
                        _2))))
        .WillOnce(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeNoResponse, new_rpcs.get(), _1,
                        _2))))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeResponseClose,
                        new_rpcs.get(), _1, _2))));
    node_->Join(node_id_, 6300, bootstrap_contacts, callback);
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
    ASSERT_LT(0U, result);
    bootstrap_contacts.clear();
    node_->Leave(NULL);
  }
  // When first contact in bootstrap_contacts is valid
  {
    int result(1);
    bool done(false);
    JoinFunctor callback = boost::bind(&NodeImplTest::NodeImplJoinCallback,
                                       this, _1, &result, &done);
    Contact contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 490)),
                                     5600);
    bootstrap_contacts.push_back(contact);

    contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 495)), 5700);
    bootstrap_contacts.push_back(contact);

    contact = ComposeContact(target, 6400);
    bootstrap_contacts.push_back(contact);

    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeResponseClose,
                        new_rpcs.get(), _1, _2))));
    node_->Join(node_id_, 6300, bootstrap_contacts, callback);
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
    ASSERT_LT(0U, result);
    bootstrap_contacts.clear();
    node_->Leave(NULL);
  }
  // When no contacts are valid
  {
    int result(1);
    bool done(false);
    JoinFunctor callback = boost::bind(&NodeImplTest::NodeImplJoinCallback,
                                       this, _1, &result, &done);
    Contact contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 490)),
                                     5600);
    bootstrap_contacts.push_back(contact);

    contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 495)), 5700);
    bootstrap_contacts.push_back(contact);

    contact = ComposeContact(target, 6400);
    bootstrap_contacts.push_back(contact);

    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillOnce(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeNoResponse, new_rpcs.get(), _1,
                        _2))))
        .WillOnce(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeNoResponse, new_rpcs.get(), _1,
                        _2))))
        .WillOnce(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeNoResponse, new_rpcs.get(), _1,
                        _2))));
    node_->Join(node_id_, 6300, bootstrap_contacts, callback);
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
    ASSERT_EQ(transport::kError, result);
    bootstrap_contacts.clear();
    node_->Leave(NULL);
  }
  // Test for refreshing data_store entry
  {
    boost::posix_time::time_duration ttl(bptime::pos_infin);
    RequestAndSignature request_signature = std::make_pair("request",
                                                           "signature");

    node_->data_store_.reset(new DataStore(boost::posix_time::seconds(1)));
    ASSERT_TRUE(node_->data_store_->StoreValue(KeyValueSignature("key1",
                                                                 "value1",
                                                                 "sig1"),
                                               ttl, request_signature, "",
                                               false));
    int result(1);
    bool done(false);
    JoinFunctor callback = boost::bind(&NodeImplTest::NodeImplJoinCallback,
                                       this, _1, &result, &done);
    Contact contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 490)),
                                     5600);
    bootstrap_contacts.push_back(contact);

    contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 495)), 5700);
    bootstrap_contacts.push_back(contact);

    contact = ComposeContact(target, 6400);
    bootstrap_contacts.push_back(contact);

    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeResponseClose,
                        new_rpcs.get(), _1, _2))));
    EXPECT_CALL(*new_rpcs, StoreRefresh(testing::_, testing::_, testing::_,
                                       testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<4>(testing::Invoke(
            boost::bind(&MockRpcs::StoreRefreshCallback,
                        new_rpcs.get(), _1))));
    node_->Join(node_id_, 6300, bootstrap_contacts, callback);
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(1000));

    ASSERT_LT(0U, result);
    bootstrap_contacts.clear();
    ASSERT_TRUE(node_->refresh_thread_running());
    ASSERT_TRUE(node_->downlist_thread_running());
    ASSERT_LT(size_t(0), node_->thread_group_->size());
    node_->Leave(NULL);
  }
}

TEST_F(NodeImplTest, BEH_KAD_Leave) {
  PopulateRoutingTable(test::k, 500);
  std::vector<Contact> bootstrap_contacts;
  std::shared_ptr<Rpcs> old_rpcs = GetRpc();
  std::shared_ptr<MockRpcs> new_rpcs(new MockRpcs(asio_service_, securifier_));
  SetRpc(new_rpcs);

  int count = 10 * test::k;
  new_rpcs->PopulateResponseCandidates(count, 499);
  NodeId target = GenerateRandomId(node_id_, 480);
  new_rpcs->target_id_ = target;
  std::shared_ptr<RoutingTableContactsContainer> temp
      (new RoutingTableContactsContainer());
  new_rpcs->respond_contacts_ = temp;
  new_rpcs->SetCountersToZero();
  int result(1);
  bool done(false);
  JoinFunctor callback = boost::bind(&NodeImplTest::NodeImplJoinCallback,
                                     this, _1, &result, &done);
  Contact contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 490)),
                                   5600);
  bootstrap_contacts.push_back(contact);

  contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 495)), 5700);
  bootstrap_contacts.push_back(contact);

  contact = ComposeContact(target, 6400);
  bootstrap_contacts.push_back(contact);

  EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                   testing::_, testing::_))
      .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
          boost::bind(&MockRpcs::FindNodeResponseClose,
                      new_rpcs.get(), _1, _2))));
  node_->Join(node_id_, 6300, bootstrap_contacts, callback);
  while (!done)
    boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
  ASSERT_LT(0U, result);
  bootstrap_contacts.clear();
  node_->Leave(&bootstrap_contacts);
  ASSERT_FALSE(node_->joined());
  ASSERT_EQ(size_t(0), node_->thread_group_.use_count());
  ASSERT_FALSE(node_->refresh_thread_running());
  ASSERT_FALSE(node_->downlist_thread_running());
  ASSERT_LT(size_t(0), bootstrap_contacts.size());
}

TEST_F(NodeImplTest, BEH_KAD_FindNodes) {
  PopulateRoutingTable(test::k, 500);

  std::shared_ptr<Rpcs> old_rpcs = GetRpc();
  std::shared_ptr<MockRpcs> new_rpcs(new MockRpcs(asio_service_, securifier_));
  new_rpcs->node_id_ = node_id_;
  SetRpc(new_rpcs);

  NodeId key = NodeId(NodeId::kRandomId);
  {
    // All k populated contacts giving no response
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeNoResponse,
                        new_rpcs.get(), _1, _2))));
    std::vector<Contact> lcontacts;
    bool done(false);
    node_->FindNodes(key,
                     boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done,
                                 &lcontacts));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(0, lcontacts.size());
  }
  new_rpcs->num_of_acquired_ = 0;
  {
    // The first of the k populated contacts giving no response
    // all the others give response with an empty closest list
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeFirstNoResponse,
                        new_rpcs.get(), _1, _2))));
    std::vector<Contact> lcontacts;
    bool done(false);
    node_->FindNodes(key,
                     boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done,
                                 &lcontacts));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(test::k - 1, lcontacts.size());
  }
  new_rpcs->num_of_acquired_ = 0;
  {
    // The first and the last of the k populated contacts giving no response
    // all the others give response with an empty closest list
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeFirstAndLastNoResponse,
                        new_rpcs.get(), _1, _2))));
    std::vector<Contact> lcontacts;
    bool done(false);
    node_->FindNodes(key,
                     boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done,
                                 &lcontacts));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(test::k - 2, lcontacts.size());
  }
  {
    // All k populated contacts response with an empty closest list
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeResponseNoClose,
                        new_rpcs.get(), _1, _2))));
    std::vector<Contact> lcontacts;
    bool done(false);
    node_->FindNodes(key,
                     boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done,
                                 &lcontacts));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(test::k, lcontacts.size());
  }
  int count = 10 * test::k;
  new_rpcs->PopulateResponseCandidates(count, 499);
  NodeId target = GenerateRandomId(node_id_, 498);
  new_rpcs->target_id_ = target;
  std::shared_ptr<RoutingTableContactsContainer> temp
      (new RoutingTableContactsContainer());
  new_rpcs->respond_contacts_ = temp;
  {
    // All k populated contacts response with random closest list (not greater
    // than k)
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeResponseClose,
                        new_rpcs.get(), _1, _2))));
    std::vector<Contact> lcontacts;
    bool done(false);
    node_->FindNodes(target,
                     boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done,
                                 &lcontacts));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(test::k, lcontacts.size());
    EXPECT_NE(lcontacts[0], lcontacts[test::k / 2]);
    EXPECT_NE(lcontacts[0], lcontacts[test::k - 1]);

    ContactsByDistanceToThisId key_dist_indx
      = new_rpcs->respond_contacts_->get<DistanceToThisIdTag>();
    auto it = key_dist_indx.begin();
    int step(0);
    while ((it != key_dist_indx.end()) && (step < test::k)) {
      EXPECT_NE(lcontacts.end(),
                std::find(lcontacts.begin(), lcontacts.end(), (*it).contact));
      ++it;
      ++step;
    }
  }
  new_rpcs->respond_contacts_->clear();
  std::shared_ptr<RoutingTableContactsContainer> down_list
      (new RoutingTableContactsContainer());
  new_rpcs->down_contacts_ = down_list;
  {
    // All k populated contacts randomly response with random closest list
    // (not greater than k)
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeRandomResponseClose,
                        new_rpcs.get(), _1, _2))));
    std::vector<Contact> lcontacts;
    bool done(false);
    node_->FindNodes(target,
                     boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done,
                                 &lcontacts));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));

    if (new_rpcs->respond_contacts_->size() >= test::k) {
      EXPECT_EQ(test::k, lcontacts.size());
      EXPECT_NE(lcontacts[0], lcontacts[test::k / 2]);
      EXPECT_NE(lcontacts[0], lcontacts[test::k - 1]);

      ContactsByDistanceToThisId key_dist_indx
        = new_rpcs->respond_contacts_->get<DistanceToThisIdTag>();
      auto it = key_dist_indx.begin();
      int step(0);
      while ((it != key_dist_indx.end()) && (step < test::k)) {
        EXPECT_NE(lcontacts.end(),
                  std::find(lcontacts.begin(), lcontacts.end(), (*it).contact));
        ++it;
        ++step;
      }
    } else {
      // if really unlucky, some of the original seeds might be pushed into the
      // result (the chance is very small).
      EXPECT_LE(new_rpcs->respond_contacts_->size(), lcontacts.size());
    }
  }
  // sleep for a while to prevent the situation that resources got destructed
  // before all call back from rpc completed. Which will cause "Segmentation
  // Fault" in execution.
  boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
  // SetRpc(old_rpcs);
}

TEST_F(NodeImplTest, FUNC_KAD_HandleIterationStructure) {
  NodeId target = GenerateRandomId(node_id_, 497);
  bool verdad(true), falso(false);
  {
    // test::k - 1 contacted, the last one respond as contacted
    std::vector<Contact> lcontacts;
    bool done(false);
    std::shared_ptr<FindNodesArgs> fna(new FindNodesArgs(target,
        boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done, &lcontacts)));

    RoutingTableContactsContainer generated_nodes;
    for (int i = 0; i < (test::k - 1); ++i) {
      Contact contact = GenerateUniqueContact(node_id_, 499, generated_nodes,
                                              target);
      NodeContainerTuple nct(contact, fna->key, i / alpha);
      nct.state = kContacted;
      fna->nc.insert(nct);
    }
    NodeId contact_id = GenerateRandomId(node_id_, 498);
    Contact contact = ComposeContact(contact_id, 5000);
    NodeContainerTuple nct(contact, fna->key, (test::k-1) / alpha);
    nct.state = kSelectedAlpha;
    fna->nc.insert(nct);

    fna->round = (test::k-1) / alpha;
    NodeSearchState mark(kContacted);
    bool curr_iteration_done(false), calledback(false);
    int response_code;
    std::vector<Contact> closest_contacts;
    node_->HandleIterationStructure<FindNodesArgs>(contact, fna, mark,
                                                   &response_code,
                                                   &closest_contacts,
                                                   &curr_iteration_done,
                                                   &calledback);
    EXPECT_EQ(verdad, curr_iteration_done);
    EXPECT_EQ(verdad, calledback);
    EXPECT_EQ(falso, done);
    EXPECT_EQ(test::k, closest_contacts.size());
  }
  {
    // test::k - 2 contacted, the test::k -1 one pending
    // the last one respond as contacted
    std::vector<Contact> lcontacts;
    bool done(false);
    std::shared_ptr<FindNodesArgs> fna(new FindNodesArgs(target,
        boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done, &lcontacts)));

    RoutingTableContactsContainer generated_nodes;
    for (int i = 0; i < (test::k - 2); ++i) {
      Contact contact = GenerateUniqueContact(node_id_, 499, generated_nodes,
                                              target);
      NodeContainerTuple nct(contact, fna->key, i / alpha);
      nct.state = kContacted;
      fna->nc.insert(nct);
    }
    Contact pending_contact = GenerateUniqueContact(node_id_, 499,
                                                    generated_nodes, target);
    NodeContainerTuple pending_nct(pending_contact, fna->key,
                                   (test::k-2) / alpha);
    pending_nct.state = kSelectedAlpha;
    fna->nc.insert(pending_nct);
    NodeId contact_id = GenerateRandomId(node_id_, 498);
    Contact contact = ComposeContact(contact_id, 5000);
    NodeContainerTuple nct(contact, fna->key, (test::k-1) / alpha);
    nct.state = kSelectedAlpha;
    fna->nc.insert(nct);

    fna->round = (test::k-1) / alpha;
    NodeSearchState mark(kContacted);
    bool curr_iteration_done(false), calledback(false);
    int response_code;
    std::vector<Contact> closest_contacts;
    node_->HandleIterationStructure<FindNodesArgs>(contact, fna, mark,
                                                   &response_code,
                                                   &closest_contacts,
                                                   &curr_iteration_done,
                                                   &calledback);
    EXPECT_EQ(falso, curr_iteration_done);
    EXPECT_EQ(falso, calledback);
    EXPECT_EQ(falso, done);
    EXPECT_EQ(0, closest_contacts.size());
  }
  {
    // test::k / 2 contacted, the last one respond as no-response
    std::vector<Contact> lcontacts;
    bool done(false);
    std::shared_ptr<FindNodesArgs> fna(new FindNodesArgs(target,
        boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done, &lcontacts)));

    RoutingTableContactsContainer generated_nodes;
    for (int i = 0; i < (test::k / 2); ++i) {
      Contact contact = GenerateUniqueContact(node_id_, 499, generated_nodes,
                                              target);
      NodeContainerTuple nct(contact, fna->key, i / alpha);
      nct.state = kContacted;
      fna->nc.insert(nct);
    }
    NodeId contact_id = GenerateRandomId(node_id_, 498);
    Contact contact = ComposeContact(contact_id, 5000);
    NodeContainerTuple nct(contact, fna->key, (test::k / 2) / alpha);
    nct.state = kSelectedAlpha;
    fna->nc.insert(nct);

    fna->round = (test::k / 2) / alpha;
    NodeSearchState mark(kDown);
    bool curr_iteration_done(false), calledback(false);
    int response_code;
    std::vector<Contact> closest_contacts;
    node_->HandleIterationStructure<FindNodesArgs>(contact, fna, mark,
                                                   &response_code,
                                                   &closest_contacts,
                                                   &curr_iteration_done,
                                                   &calledback);
    EXPECT_EQ(verdad, curr_iteration_done);
    EXPECT_EQ(verdad, calledback);
    EXPECT_EQ(falso, done);
    EXPECT_EQ(test::k / 2, closest_contacts.size());
  }
  {
    // test::k candidates, for each previous round (alpha - beta) pending
    // for the last round, all contacted
    std::vector<Contact> lcontacts;
    bool done(false);
    std::shared_ptr<FindNodesArgs> fna(new FindNodesArgs(target,
        boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done, &lcontacts)));

    RoutingTableContactsContainer generated_nodes;
    for (int i = 0; i < (alpha * (test::k / alpha)); ++i) {
      Contact contact = GenerateUniqueContact(node_id_, 499, generated_nodes,
                                              target);
      NodeContainerTuple nct(contact, fna->key, i / alpha);
      if ((i % alpha) < beta) {
        nct.state = kContacted;
      } else {
        nct.state = kSelectedAlpha;
      }
      fna->nc.insert(nct);
    }
    for (int i = 0; i < (test::k % alpha - 2); ++i) {
      Contact contact = GenerateUniqueContact(node_id_, 499, generated_nodes,
                                              target);
      NodeContainerTuple nct(contact, fna->key, test::k / alpha);
      nct.state = kContacted;
      fna->nc.insert(nct);
    }

    Contact contact = GenerateUniqueContact(node_id_, 499, generated_nodes,
                                            target);
    NodeContainerTuple nct(contact, fna->key, test::k / alpha);
    nct.state = kSelectedAlpha;
    fna->nc.insert(nct);
    Contact last_contact = GenerateUniqueContact(node_id_, 499, generated_nodes,
                                                 target);
    NodeContainerTuple last_nct(last_contact, fna->key, test::k / alpha);
    last_nct.state = kSelectedAlpha;
    fna->nc.insert(last_nct);

    fna->round = test::k / alpha;

    NodeSearchState mark(kContacted);
    bool curr_iteration_done(false), calledback(false);
    int response_code;
    std::vector<Contact> closest_contacts;
    node_->HandleIterationStructure<FindNodesArgs>(contact, fna, mark,
                                                   &response_code,
                                                   &closest_contacts,
                                                   &curr_iteration_done,
                                                   &calledback);
    EXPECT_EQ(falso, curr_iteration_done);
    EXPECT_EQ(falso, calledback);
    EXPECT_EQ(0, closest_contacts.size());

    curr_iteration_done = false;
    calledback = false;
    closest_contacts.clear();
    node_->HandleIterationStructure<FindNodesArgs>(last_contact, fna, mark,
                                                   &response_code,
                                                   &closest_contacts,
                                                   &curr_iteration_done,
                                                   &calledback);
    EXPECT_EQ(falso, curr_iteration_done);
    EXPECT_EQ(falso, calledback);
    EXPECT_EQ(0, closest_contacts.size());
  }
  {
    // k candidates, with (beta - 1) contacted, the next one respond with
    // no response
    std::vector<Contact> lcontacts;
    bool done(false);
    std::shared_ptr<FindNodesArgs> fna(new FindNodesArgs(target,
        boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done, &lcontacts)));

    RoutingTableContactsContainer generated_nodes;
    Contact first_contact = GenerateUniqueContact(node_id_, 499,
                                                  generated_nodes,
                                                  target);
    NodeContainerTuple first_nct(first_contact, fna->key, 0);
    first_nct.state = kSelectedAlpha;
    fna->nc.insert(first_nct);
    Contact second_contact = GenerateUniqueContact(node_id_, 499,
                                                   generated_nodes,
                                                   target);
    NodeContainerTuple second_nct(second_contact, fna->key, 0);
    second_nct.state = kSelectedAlpha;
    fna->nc.insert(second_nct);

    for (int i = 2; i < test::k; ++i) {
      Contact contact = GenerateUniqueContact(node_id_, 499, generated_nodes,
                                              target);
      NodeContainerTuple nct(contact, fna->key, i / alpha);
      nct.state = kNew;
      fna->nc.insert(nct);
    }

    fna->round = 0;
    NodeSearchState mark(kContacted);
    bool curr_iteration_done(false), calledback(false);
    int response_code;
    std::vector<Contact> closest_contacts;
    node_->HandleIterationStructure<FindNodesArgs>(first_contact, fna, mark,
                                                   &response_code,
                                                   &closest_contacts,
                                                   &curr_iteration_done,
                                                   &calledback);
    EXPECT_EQ(falso, curr_iteration_done);
    EXPECT_EQ(falso, calledback);
    EXPECT_EQ(falso, done);
    EXPECT_EQ(0, closest_contacts.size());

    mark = kDown;
    closest_contacts.clear();
    node_->HandleIterationStructure<FindNodesArgs>(second_contact, fna, mark,
                                                   &response_code,
                                                   &closest_contacts,
                                                   &curr_iteration_done,
                                                   &calledback);
    EXPECT_EQ(verdad, curr_iteration_done);
    EXPECT_EQ(falso, calledback);
    EXPECT_EQ(falso, done);
    EXPECT_EQ(0, closest_contacts.size());
  }
  // sleep for a while to prevent the situation that resources got destructed
  // before call back completed. Which will cause "Segmentation Fault" in
  // execution.
  boost::this_thread::sleep(boost::posix_time::milliseconds(100));
}

TEST_F(NodeImplTest, BEH_KAD_Store) {
  PopulateRoutingTable(test::k, 500);

  std::shared_ptr<Rpcs> old_rpcs = GetRpc();
  std::shared_ptr<MockRpcs> new_rpcs(new MockRpcs(asio_service_, securifier_));
  new_rpcs->node_id_ = node_id_;
  SetRpc(new_rpcs);

  int count = 10 * test::k;
  new_rpcs->PopulateResponseCandidates(count, 499);
  NodeId target = GenerateRandomId(node_id_, 498);
  new_rpcs->target_id_ = target;
  std::shared_ptr<RoutingTableContactsContainer> temp
      (new RoutingTableContactsContainer());
  new_rpcs->respond_contacts_ = temp;
  new_rpcs->SetCountersToZero();

  std::shared_ptr<RoutingTableContactsContainer> down_list
      (new RoutingTableContactsContainer());
  new_rpcs->down_contacts_ = down_list;
  EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                   testing::_, testing::_))
      .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
          boost::bind(&MockRpcs::FindNodeResponseClose,
                      new_rpcs.get(), _1, _2))));

  NodeId key = NodeId(NodeId::kRandomId);
  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(4096);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, key.String(), "");
  bptime::time_duration old_ttl(bptime::pos_infin);
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // all k closest contacts respond with success
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            boost::bind(&MockRpcs::Response<Rpcs::StoreFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Store(key, kvs.value, kvs.signature, old_ttl, securifier_,
                 boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));

    EXPECT_EQ(threshold_, response_code);
  }
  new_rpcs->SetCountersToZero();
  EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                testing::_, testing::_, testing::_,
                                testing::_))
      .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
          boost::bind(&MockRpcs::SingleDeleteResponse,
                      new_rpcs.get(), _1, _2))));
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the last k - threshold closest contacts respond with DOWN, others respond
    // with success
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            boost::bind(&MockRpcs::LastSeveralNoResponse<Rpcs::StoreFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Store(key, kvs.value, kvs.signature, old_ttl, securifier_,
                 boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(-2, response_code);
    // wait for the delete processes to be completed
    // otherwise the counter might be incorrect
    boost::this_thread::sleep(boost::posix_time::milliseconds(300));
    EXPECT_EQ(test::k - threshold_ + 1, new_rpcs->num_of_deleted_);
  }
  new_rpcs->SetCountersToZero();
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the first k - threshold closest contacts respond with DOWN, others
    // respond with success
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            boost::bind(&MockRpcs::FirstSeveralNoResponse<Rpcs::StoreFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Store(key, kvs.value, kvs.signature, old_ttl, securifier_,
                 boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(-2, response_code);
    // wait for the delete processes to be completed
    // otherwise the counter might be incorrect
    // may not be necessary for this test
    boost::this_thread::sleep(boost::posix_time::milliseconds(300));
    EXPECT_EQ(test::k - threshold_ + 1, new_rpcs->num_of_deleted_);
  }
  new_rpcs->SetCountersToZero();
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the first k - threshold -1 closest contacts respond with DOWN, others
    // respond with success
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            boost::bind(&MockRpcs::LastLessNoResponse<Rpcs::StoreFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Store(key, kvs.value, kvs.signature, old_ttl, securifier_,
                 boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(threshold_, response_code);
    // wait to ensure in case of wrong, the wrong deletion will be executed
    boost::this_thread::sleep(boost::posix_time::milliseconds(300));
    EXPECT_EQ(0, new_rpcs->num_of_deleted_);
  }
  new_rpcs->SetCountersToZero();
  {
    // Among k populated contacts, less than threshold contacts response with
    // no closest list
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeSeveralResponseNoClose,
                        new_rpcs.get(), _1, _2))));
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            boost::bind(&MockRpcs::LastLessNoResponse<Rpcs::StoreFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Store(key, kvs.value, kvs.signature, old_ttl, securifier_,
                 boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(-3, response_code);
    EXPECT_EQ(0, new_rpcs->respond_);
    EXPECT_EQ(0, new_rpcs->no_respond_);
  }
  // sleep for a while to prevent the situation that resources got destructed
  // before all call back from rpc completed. Which will cause "Segmentation
  // Fault" in execution.
  boost::this_thread::sleep(boost::posix_time::milliseconds(1000));

  // SetRpc(old_rpcs);
}

TEST_F(NodeImplTest, BEH_KAD_Delete) {
  PopulateRoutingTable(test::k, 500);

  std::shared_ptr<Rpcs> old_rpcs = GetRpc();
  std::shared_ptr<MockRpcs> new_rpcs(new MockRpcs(asio_service_, securifier_));
  new_rpcs->node_id_ = node_id_;
  SetRpc(new_rpcs);

  int count = 10 * test::k;
  new_rpcs->PopulateResponseCandidates(count, 499);
  NodeId target = GenerateRandomId(node_id_, 498);
  new_rpcs->target_id_ = target;
  std::shared_ptr<RoutingTableContactsContainer> temp
      (new RoutingTableContactsContainer());
  new_rpcs->respond_contacts_ = temp;

  EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                   testing::_, testing::_))
      .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
          boost::bind(&MockRpcs::FindNodeResponseClose,
                      new_rpcs.get(), _1, _2))));

  NodeId key = NodeId(NodeId::kRandomId);
  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(4096);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, key.String(), "");
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // all k closest contacts respond with success
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_,
                                  testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            boost::bind(&MockRpcs::Response<Rpcs::DeleteFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Delete(key, kvs.value, kvs.signature, securifier_,
                  boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));

    EXPECT_EQ(threshold_, response_code);
  }
  new_rpcs->SetCountersToZero();
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the last k - threshold closest contacts respond with DOWN, others respond
    // with success
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_,
                                  testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            boost::bind(&MockRpcs::LastSeveralNoResponse<Rpcs::DeleteFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(0);
    bool done(false);
    node_->Delete(key, kvs.value, kvs.signature, securifier_,
                  boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(-2, response_code);
    // wait for the all delete processes to be completed
    // otherwise the counter might be incorrect
    boost::this_thread::sleep(boost::posix_time::milliseconds(300));
    EXPECT_EQ(test::k - threshold_ + 1, new_rpcs->no_respond_);
  }
  new_rpcs->SetCountersToZero();
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the first k - threshold closest contacts respond with DOWN, others
    // respond with success
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_,
                                  testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            boost::bind(&MockRpcs::FirstSeveralNoResponse<Rpcs::DeleteFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Delete(key, kvs.value, kvs.signature, securifier_,
                  boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(-2, response_code);
    // wait for the delete processes to be completed
    // otherwise the counter might be incorrect
    // may not be necessary for this test
    boost::this_thread::sleep(boost::posix_time::milliseconds(300));
    EXPECT_EQ(test::k - threshold_ + 1, new_rpcs->no_respond_);
  }
  new_rpcs->SetCountersToZero();
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the first k - threshold -1 closest contacts respond with DOWN, others
    // respond with success
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_,
                                  testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            boost::bind(&MockRpcs::LastLessNoResponse<Rpcs::DeleteFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Delete(key, kvs.value, kvs.signature, securifier_,
                  boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(threshold_, response_code);
  }
  new_rpcs->SetCountersToZero();
  {
    // Among k populated contacts, less than threshold contacts response with
    // no closest list
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeSeveralResponseNoClose,
                        new_rpcs.get(), _1, _2))));
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_,
                                  testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            boost::bind(&MockRpcs::LastLessNoResponse<Rpcs::DeleteFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Delete(key, kvs.value, kvs.signature, securifier_,
                  boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(-3, response_code);
    EXPECT_EQ(0, new_rpcs->respond_);
    EXPECT_EQ(0, new_rpcs->no_respond_);
  }
  // sleep for a while to prevent the situation that resources got destructed
  // before all call back from rpc completed. Which will cause "Segmentation
  // Fault" in execution.
  boost::this_thread::sleep(boost::posix_time::milliseconds(1000));

  // SetRpc(old_rpcs);
}

TEST_F(NodeImplTest, BEH_KAD_Update) {
  PopulateRoutingTable(test::k, 500);

  std::shared_ptr<MockRpcs> new_rpcs(new MockRpcs(asio_service_, securifier_));
  new_rpcs->node_id_ = node_id_;
  SetRpc(new_rpcs);

  int count = 10 * test::k;
  new_rpcs->PopulateResponseCandidates(count, 499);
  NodeId target = GenerateRandomId(node_id_, 498);
  new_rpcs->target_id_ = target;
  std::shared_ptr<RoutingTableContactsContainer> temp
      (new RoutingTableContactsContainer());
  new_rpcs->respond_contacts_ = temp;

  EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                   testing::_, testing::_))
      .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
          boost::bind(&MockRpcs::FindNodeResponseClose,
                      new_rpcs.get(), _1, _2))));

  NodeId key = NodeId(NodeId::kRandomId);
  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(4096);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, key.String(), "");
  KeyValueSignature kvs_new = MakeKVS(crypto_key_data, 1024, key.String(), "");
  bptime::time_duration old_ttl(bptime::pos_infin);
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // all k closest contacts respond with success both in store and delete
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_,
                                  testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            boost::bind(&MockRpcs::Response<Rpcs::DeleteFunctor>,
                        new_rpcs.get(), _1, _2))));
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            boost::bind(&MockRpcs::Response<Rpcs::StoreFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Update(key, kvs_new.value, kvs_new.signature,
                  kvs.value, kvs.signature, securifier_, old_ttl,
                  boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));

    EXPECT_EQ(threshold_, response_code);
  }
  new_rpcs->SetCountersToZero();
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the first (k - threshold) closest contacts respond with DOWN in store,
    // others respond with success
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_,
                                  testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            boost::bind(&MockRpcs::Response<Rpcs::DeleteFunctor>,
                        new_rpcs.get(), _1, _2))));
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            boost::bind(&MockRpcs::FirstSeveralNoResponse<Rpcs::StoreFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Update(key, kvs_new.value, kvs_new.signature,
                  kvs.value, kvs.signature, securifier_, old_ttl,
                  boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    // wait for the all processes to be completed
    // otherwise the counter might be incorrect
    boost::this_thread::sleep(boost::posix_time::milliseconds(300));
    EXPECT_EQ(-2, response_code);
    EXPECT_EQ(test::k - threshold_ + 1, new_rpcs->no_respond_);
    EXPECT_EQ(threshold_ - 1, new_rpcs->respond_);
  }
  new_rpcs->SetCountersToZero();
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the last (k - threshold) closest contacts respond with DOWN in store,
    // others respond with success
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_,
                                  testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            boost::bind(&MockRpcs::Response<Rpcs::DeleteFunctor>,
                        new_rpcs.get(), _1, _2))));
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            boost::bind(&MockRpcs::LastSeveralNoResponse<Rpcs::StoreFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Update(key, kvs_new.value, kvs_new.signature,
                  kvs.value, kvs.signature, securifier_, old_ttl,
                  boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    // wait for the all processes to be completed
    // otherwise the counter might be incorrect
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(-2, response_code);
    EXPECT_EQ(test::k - threshold_ + 1, new_rpcs->no_respond_);
    EXPECT_EQ(threshold_ - 1, new_rpcs->respond_);
  }
  new_rpcs->SetCountersToZero();
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the last (k - threshold) closest contacts respond with DOWN in delete,
    // others response with success
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_,
                                  testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            boost::bind(&MockRpcs::LastSeveralNoResponse<Rpcs::DeleteFunctor>,
                        new_rpcs.get(), _1, _2))));
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            boost::bind(&MockRpcs::Response<Rpcs::StoreFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Update(key, kvs_new.value, kvs_new.signature,
                  kvs.value, kvs.signature, securifier_, old_ttl,
                  boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    // wait for the all processes to be completed
    // otherwise the counter might be incorrect
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(-2, response_code);
    EXPECT_EQ(test::k - threshold_ + 1, new_rpcs->no_respond_);
    EXPECT_EQ(threshold_ - 1, new_rpcs->respond_);
  }
  new_rpcs->SetCountersToZero();
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the first (k - threshold) closest contacts respond with DOWN in delete,
    // others response with success
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_,
                                  testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            boost::bind(&MockRpcs::FirstSeveralNoResponse<Rpcs::DeleteFunctor>,
                        new_rpcs.get(), _1, _2))));
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            boost::bind(&MockRpcs::Response<Rpcs::StoreFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Update(key, kvs_new.value, kvs_new.signature,
                  kvs.value, kvs.signature, securifier_, old_ttl,
                  boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    // wait for the all processes to be completed
    // otherwise the counter might be incorrect
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(-2, response_code);
    EXPECT_EQ(test::k - threshold_ + 1, new_rpcs->no_respond_);
    EXPECT_EQ(threshold_ - 1, new_rpcs->respond_);
  }
  new_rpcs->SetCountersToZero();
  {
    // Among k populated contacts, less than threshold contacts response with
    // no closest list
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeSeveralResponseNoClose,
                        new_rpcs.get(), _1, _2))));
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_,
                                  testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            boost::bind(&MockRpcs::Response<Rpcs::DeleteFunctor>,
                        new_rpcs.get(), _1, _2))));
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            boost::bind(&MockRpcs::Response<Rpcs::StoreFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Update(key, kvs_new.value, kvs_new.signature,
                  kvs.value, kvs.signature, securifier_, old_ttl,
                  boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(-3, response_code);
    EXPECT_EQ(0, new_rpcs->respond_);
    EXPECT_EQ(0, new_rpcs->no_respond_);
  }
  // sleep for a while to prevent the situation that resources got destructed
  // before all call back from rpc completed. Which will cause "Segmentation
  // Fault" in execution.
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

TEST_F(NodeImplTest, BEH_KAD_FindValue) {
  PopulateRoutingTable(test::k, 500);
  std::shared_ptr<MockRpcs> new_rpcs(new MockRpcs(asio_service_, securifier_));
  new_rpcs->node_id_ = node_id_;
  SetRpc(new_rpcs);
  NodeId key = GenerateRandomId(node_id_, 498);
  {
    // All k populated contacts giving no response
    EXPECT_CALL(*new_rpcs, FindValue(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindValueNoResponse,
                        new_rpcs.get(), _1, _2))));
    FindValueResults results;
    bool done(false);
    node_->FindValue(key, securifier_,
                     boost::bind(&FindValueCallback,
                                 _1, _2, _3, _4, _5,
                                 &done, &results));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(-2, results.response_code);
    EXPECT_EQ(0, results.values.size());
    EXPECT_EQ(0, results.contacts.size());
  }
  new_rpcs->SetCountersToZero();
  int count = 10 * test::k;
  new_rpcs->PopulateResponseCandidates(count, 499);
  {
    // All k populated contacts giving no data find, but response with some
    // closest contacts
    EXPECT_CALL(*new_rpcs, FindValue(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindValueResponseCloseOnly,
                        new_rpcs.get(), _1, _2))));
    FindValueResults results;
    bool done(false);
    node_->FindValue(key, securifier_,
                     boost::bind(&FindValueCallback,
                                 _1, _2, _3, _4, _5,
                                 &done, &results));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(-2, results.response_code);
    EXPECT_EQ(0, results.values.size());
    EXPECT_EQ(test::k, results.contacts.size());
  }
  new_rpcs->SetCountersToZero();
  std::shared_ptr<RoutingTableContactsContainer> temp
      (new RoutingTableContactsContainer());
  new_rpcs->respond_contacts_ = temp;
  new_rpcs->target_id_ = key;
  {
    // the Nth enquired contact will response the value
    // note: there is high chance that search value will stopped after just
    // (alpha + K) tries -- get k-closest extreme fast.
    new_rpcs->respond_ = node_->alpha() + RandomUint32() % test::k + 1;
    EXPECT_CALL(*new_rpcs, FindValue(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindValueNthResponse,
                        new_rpcs.get(), _1, _2))));
    FindValueResults results;
    bool done(false);
    node_->FindValue(key, securifier_,
                     boost::bind(&FindValueCallback,
                                 _1, _2, _3, _4, _5,
                                 &done, &results));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));

    EXPECT_EQ(1, results.response_code);
    EXPECT_EQ(0, results.contacts.size());
    EXPECT_EQ(1, results.values.size());
    EXPECT_EQ("FIND", results.values[0]);
    EXPECT_LE(new_rpcs->respond_, new_rpcs->num_of_acquired_);
  }
  new_rpcs->SetCountersToZero();
  {
    // value not existed, search shall stop once top-k-closest achieved
    EXPECT_CALL(*new_rpcs, FindValue(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindValueNoValueResponse,
                        new_rpcs.get(), _1, _2))));
    FindValueResults results;
    bool done(false);
    node_->FindValue(key, securifier_,
                     boost::bind(&FindValueCallback,
                                 _1, _2, _3, _4, _5,
                                 &done, &results));
    // Prevent deadlock
    while ((!done) && (new_rpcs->num_of_acquired_ < (40 * test::k)))
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(-2, results.response_code);
    EXPECT_EQ(0, results.values.size());
    EXPECT_EQ(test::k, results.contacts.size());
    EXPECT_GT(40 * test::k, new_rpcs->num_of_acquired_);
  }
  // sleep for a while to prevent the situation that resources got destructed
  // before all call back from rpc completed. Which will cause "Segmentation
  // Fault" in execution.
  boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
}  // FindValue test

// This test will test the Downlist client handling in node_impl
// Covered part is: ReportDownContact, MonitoringDownlistThread
TEST_F(NodeImplTest, BEH_KAD_DownlistClient) {
  PopulateRoutingTable(test::k, 500);

  std::shared_ptr<MockRpcs> new_rpcs(new MockRpcs(asio_service_, securifier_));
  new_rpcs->node_id_ = node_id_;
  SetRpc(new_rpcs);

  EXPECT_CALL(*new_rpcs, Downlist(testing::_, testing::_, testing::_,
                                  testing::_))
      .WillRepeatedly(testing::WithArgs<0, 2>(testing::Invoke(
          boost::bind(&MockRpcs::DownlistRecord,
                      new_rpcs.get(), _1, _2))));

  NodeId key = NodeId(NodeId::kRandomId);
  std::vector<Contact> booststrap_contacts;
  int result;
  bool done;
  node_->JoinFindNodesCallback(0, booststrap_contacts, booststrap_contacts, key,
                               boost::bind(&NodeImplTest::NodeImplJoinCallback,
                                           this, _1, &result, &done));
  std::shared_ptr<RoutingTableContactsContainer> down_list
      (new RoutingTableContactsContainer());
  new_rpcs->down_contacts_ = down_list;
  {
    // FindNodes : All k populated contacts giving no response
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindNodeNoResponse,
                        new_rpcs.get(), _1, _2))));
    std::vector<Contact> lcontacts;
    bool done(false);
    node_->FindNodes(key,
                     boost::bind(&FindNodeCallback, rank_info_, _1, _2, &done,
                                 &lcontacts));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(0, lcontacts.size());
    // wait for the all processes to be completed
    // otherwise the counter might be incorrect
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    EXPECT_EQ(test::k, new_rpcs->down_contacts_->size());
    ContactsById key_indx = new_rpcs->down_contacts_->get<NodeIdTag>();
    auto it = key_indx.begin();
    auto it_end = key_indx.end();
    while (it != it_end) {
      EXPECT_EQ(test::k, (*it).num_failed_rpcs);
      ++it;
    }
  }
  std::shared_ptr<RoutingTableContactsContainer> temp
      (new RoutingTableContactsContainer());
  new_rpcs->respond_contacts_ = temp;

  int count = 10 * test::k;
  new_rpcs->PopulateResponseCandidates(count, 499);

  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(4096);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, key.String(), "");
  bptime::time_duration old_ttl(bptime::pos_infin);

  new_rpcs->SetCountersToZero();
  new_rpcs->down_contacts_->clear();
  SetAllNumRpcsFailureToZero();

  EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                  testing::_, testing::_))
      .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
          boost::bind(&MockRpcs::FindNodeResponseClose,
                      new_rpcs.get(), _1, _2))));
  {
    // Store : the last (k-threshold+1) closest contacts respond with DOWN
    // FindNodes : All k populated contacts giving response
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_,
                                  testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            boost::bind(&MockRpcs::SingleDeleteResponse,
                        new_rpcs.get(), _1, _2))));
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            boost::bind(&MockRpcs::LastSeveralNoResponse<Rpcs::StoreFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Store(key, kvs.value, kvs.signature, old_ttl, securifier_,
                 boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(-2, response_code);
    // wait for the delete processes to be completed
    // otherwise the counter might be incorrect
    boost::this_thread::sleep(boost::posix_time::milliseconds(300));
    EXPECT_EQ(test::k - threshold_ + 1, new_rpcs->num_of_deleted_);
    EXPECT_EQ(test::k - threshold_ + 1, new_rpcs->down_contacts_->size());
    ContactsById key_indx = new_rpcs->down_contacts_->get<NodeIdTag>();
    auto it = key_indx.begin();
    auto it_end = key_indx.end();
    while (it != it_end) {
      EXPECT_EQ(test::k, (*it).num_failed_rpcs);
      ++it;
    }
  }
  new_rpcs->SetCountersToZero();
  new_rpcs->down_contacts_->clear();
  SetAllNumRpcsFailureToZero();
  {
    // Delete : the first (k-threshold+1) closest contacts respond with DOWN
    // FindNodes : All k populated contacts giving response
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_,
                                  testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            boost::bind(&MockRpcs::FirstSeveralNoResponse<Rpcs::DeleteFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Delete(key, kvs.value, kvs.signature, securifier_,
                  boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(-2, response_code);
    // wait for the delete processes to be completed
    // otherwise the counter might be incorrect
    // may not be necessary for this test
    boost::this_thread::sleep(boost::posix_time::milliseconds(300));
    EXPECT_EQ(test::k - threshold_ + 1, new_rpcs->no_respond_);
    EXPECT_EQ(test::k - threshold_ + 1, new_rpcs->down_contacts_->size());
    ContactsById key_indx = new_rpcs->down_contacts_->get<NodeIdTag>();
    auto it = key_indx.begin();
    auto it_end = key_indx.end();
    while (it != it_end) {
      EXPECT_EQ(test::k, (*it).num_failed_rpcs);
      ++it;
    }
  }
  KeyValueSignature kvs_new = MakeKVS(crypto_key_data, 1024, key.String(), "");

  new_rpcs->SetCountersToZero();
  new_rpcs->down_contacts_->clear();
  SetAllNumRpcsFailureToZero();
  {
    // Update Store: the first (k-threshold+1) contacts respond with DOWN
    // Update Delete: all response
    // FindNodes : All k populated contacts giving response
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_,
                                  testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            boost::bind(&MockRpcs::Response<Rpcs::DeleteFunctor>,
                        new_rpcs.get(), _1, _2))));
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            boost::bind(&MockRpcs::FirstSeveralNoResponse<Rpcs::StoreFunctor>,
                        new_rpcs.get(), _1, _2))));
    int response_code(-2);
    bool done(false);
    node_->Update(key, kvs_new.value, kvs_new.signature,
                  kvs.value, kvs.signature, securifier_, old_ttl,
                  boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    // wait for the all processes to be completed
    // otherwise the counter might be incorrect
    boost::this_thread::sleep(boost::posix_time::milliseconds(300));
    EXPECT_EQ(-2, response_code);
    EXPECT_EQ(test::k - threshold_ + 1, new_rpcs->no_respond_);
    EXPECT_EQ(threshold_ - 1, new_rpcs->respond_);
    EXPECT_EQ(test::k - threshold_ + 1, new_rpcs->down_contacts_->size());
    ContactsById key_indx = new_rpcs->down_contacts_->get<NodeIdTag>();
    auto it = key_indx.begin();
    auto it_end = key_indx.end();
    while (it != it_end) {
      EXPECT_EQ(test::k, (*it).num_failed_rpcs);
      ++it;
    }
  }
  new_rpcs->SetCountersToZero();
  new_rpcs->down_contacts_->clear();
  SetAllNumRpcsFailureToZero();
  {
    // FindValue : All k populated contacts giving no response
    EXPECT_CALL(*new_rpcs, FindValue(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<2, 3>(testing::Invoke(
            boost::bind(&MockRpcs::FindValueNoResponse,
                        new_rpcs.get(), _1, _2))));
    FindValueResults results;
    bool done(false);
    node_->FindValue(key, securifier_,
                     boost::bind(&FindValueCallback,
                                 _1, _2, _3, _4, _5,
                                 &done, &results));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_EQ(-2, results.response_code);
    EXPECT_EQ(0, results.values.size());
    EXPECT_EQ(0, results.contacts.size());
    // wait for the all processes to be completed
    // otherwise the counter might be incorrect
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    EXPECT_EQ(test::k, new_rpcs->down_contacts_->size());
    ContactsById key_indx = new_rpcs->down_contacts_->get<NodeIdTag>();
    auto it = key_indx.begin();
    auto it_end = key_indx.end();
    while (it != it_end) {
      EXPECT_EQ(test::k, (*it).num_failed_rpcs);
      ++it;
    }
  }
  // sleep for a while to prevent the situation that resources got destructed
  // before all call back from rpc completed. Which will cause "Segmentation
  // Fault" in execution.
  boost::this_thread::sleep(boost::posix_time::milliseconds(300));
}  // DownListClient test

// This test will test the Downlist server handling in node_impl
// Covered parts are: Connect to Service signal, Catch signal from Service,
// PingDownlistContact, PingDownlistContactCallback
TEST_F(NodeImplTest, BEH_KAD_DownlistServer) {
  std::shared_ptr<MockRpcs> new_rpcs(new MockRpcs(asio_service_, securifier_));
  new_rpcs->node_id_ = node_id_;
  SetRpc(new_rpcs);

  std::shared_ptr<Service> local_service(new Service(routing_table_,
      data_store_, alternative_store_, securifier_));
  local_service->set_node_joined(true);
  node_->SetService(local_service);
  // given a downlist contains k nodes in the routingtable
  protobuf::DownlistNotification downlist_request;
  for (int i = 0; i < test::k; ++i) {
    NodeId contact_id = GenerateUniqueRandomId(node_id_, 497);
    Contact contact = ComposeContact(contact_id, 5000);
    downlist_request.add_node_ids(contact_id.String());
    AddContact(routing_table_, contact, rank_info_);
  }
  transport::Info info;
  {
    // Ping down contacts will success
    EXPECT_CALL(*new_rpcs, Ping(testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<1, 2>(testing::Invoke(
            boost::bind(&MockRpcs::Response<Rpcs::PingFunctor>,
                        new_rpcs.get(), _1, _2))));
    std::vector<Contact> contacts;
    routing_table_->GetAllContacts(&contacts);
    EXPECT_EQ(test::k, contacts.size());
    transport::Timeout time_out;
    for (int i = 0; i <= kFailedRpcTolerance; ++i)
      local_service->Downlist(info, downlist_request, &time_out);
    // wait a reasonable time
    boost::this_thread::sleep(boost::posix_time::milliseconds(200));
    routing_table_->GetAllContacts(&contacts);
    EXPECT_EQ(test::k, contacts.size());
  }
  {
    // Ping down contacts will failed
    EXPECT_CALL(*new_rpcs, Ping(testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<1, 2>(testing::Invoke(
            boost::bind(&MockRpcs::NoResponse<Rpcs::PingFunctor>,
                        new_rpcs.get(), _1, _2))));
    std::vector<Contact> contacts;
    routing_table_->GetAllContacts(&contacts);
    EXPECT_EQ(test::k, contacts.size());
    transport::Timeout time_out;
    for (int i = 0; i <= kFailedRpcTolerance; ++i)
      local_service->Downlist(info, downlist_request, &time_out);
    // may need to put a timer to prevent deadlock
    do {
      boost::this_thread::sleep(boost::posix_time::milliseconds(200));
      routing_table_->GetAllContacts(&contacts);
    } while (contacts.size() != 0);
  }
}  // DownListServer test

TEST_F(NodeImplTest, BEH_KAD_SetLastSeenToNow) {
  // Try to set a non-existing contact
  NodeId target_id = GenerateRandomId(node_id_, 498);
  Contact target = ComposeContact(target_id, 5000);
  node_->SetLastSeenToNow(target);
  Contact result;
  routing_table_->GetContact(target_id, &result);
  EXPECT_EQ(Contact(), result);
  // Try to set an existing contact
  AddContact(routing_table_, target, rank_info_);
  node_->SetLastSeenToNow(target);
  routing_table_->GetContact(target_id, &result);
  EXPECT_EQ(target, result);
}

TEST_F(NodeImplTest, BEH_KAD_IncrementFailedRpcs) {
  NodeId target_id = GenerateRandomId(node_id_, 498);
  Contact target = ComposeContact(target_id, 5000);
  // Keep increasing the num_of_failed_rpcs of the target contact, till it got
  // removed from the routing table
  AddContact(routing_table_, target, rank_info_);
  for (int i = 0; i <= kFailedRpcTolerance; ++i)
    node_->IncrementFailedRpcs(target);
  Contact result;
  routing_table_->GetContact(target_id, &result);
  EXPECT_EQ(Contact(), result);
}

TEST_F(NodeImplTest, BEH_KAD_GetAndUpdateRankInfo) {
  NodeId target_id = GenerateRandomId(node_id_, 498);
  Contact target = ComposeContact(target_id, 5000);
  AddContact(routing_table_, target, rank_info_);
  // Update the rank_info of the target contact
  RankInfoPtr new_rank_info(new(transport::Info));
  new_rank_info->rtt = 13313;
  node_->UpdateRankInfo(target, new_rank_info);
  // Get the rank_info of the target contact
  EXPECT_EQ(new_rank_info->rtt, node_->GetLocalRankInfo(target)->rtt);
}

TEST_F(NodeImplTest, BEH_KAD_Getters) {
  {
    // contact()
    EXPECT_EQ(Contact(), node_->contact());
  }
  {
    // joined()
    EXPECT_FALSE(local_node_->joined());
    NodeId key = NodeId(NodeId::kRandomId);
    std::vector<Contact> booststrap_contacts(1, Contact());
    int result;
    bool done;
    local_node_->JoinFindNodesCallback(0, booststrap_contacts,
                                       booststrap_contacts, key,
                                       boost::bind(
                                           &NodeImplTest::NodeImplJoinCallback,
                                           this, _1, &result, &done));
    EXPECT_TRUE(local_node_->joined());
  }
  {
    // asio_service()
    EXPECT_EQ(asio_service_, node_->asio_service());
  }
  {
    // alternative_store()
    EXPECT_EQ(alternative_store_, node_->alternative_store());
  }
  {
    // on_online_status_change()
    OnOnlineStatusChangePtr result = node_->on_online_status_change();
    if (!result)
      EXPECT_TRUE(false);
  }
  {
    // client_only_node()()
    EXPECT_TRUE(local_node_->client_only_node());
  }
  {
    // k()
    EXPECT_EQ(test::k, node_->k());
  }
  {
    // alpha()
    EXPECT_EQ(test::alpha, node_->alpha());
  }
  {
    // beta()
    EXPECT_EQ(test::beta, node_->beta());
  }
  {
    // mean_refresh_interval()
    EXPECT_EQ(bptime::seconds(3600), node_->mean_refresh_interval());
  }
}

}  // namespace test_nodeimpl

}  // namespace kademlia

}  // namespace maidsafe
