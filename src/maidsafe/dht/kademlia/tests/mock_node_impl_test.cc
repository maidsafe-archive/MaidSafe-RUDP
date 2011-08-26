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
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4244)
#endif
#include "boost/thread.hpp"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "maidsafe/common/test.h"

#include "maidsafe/common/alternative_store.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/dht/kademlia/contact.h"
#include "maidsafe/dht/kademlia/data_store.h"
#include "maidsafe/dht/kademlia/message_handler.h"
#include "maidsafe/dht/kademlia/node_id.h"
#include "maidsafe/dht/kademlia/node_impl.h"
#include "maidsafe/dht/kademlia/routing_table.h"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/dht/kademlia/rpcs.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "maidsafe/dht/kademlia/rpcs.h"
#include "maidsafe/dht/kademlia/return_codes.h"
#include "maidsafe/dht/kademlia/securifier.h"
#include "maidsafe/dht/kademlia/service.h"
#include "maidsafe/dht/transport/transport.h"
#include "maidsafe/dht/transport/utils.h"
#include "maidsafe/dht/kademlia/tests/test_utils.h"

namespace arg = std::placeholders;
namespace bptime = boost::posix_time;

namespace maidsafe {
namespace dht {
namespace kademlia {
namespace test {
namespace {

const uint16_t g_kKademliaK = 8;
const uint16_t g_kAlpha = 3;
const uint16_t g_kBeta = 2;
const uint16_t g_kRandomNoResponseRate = 20;  // in percentage


class SecurifierValidateTrue: public Securifier {
 public:
  SecurifierValidateTrue(const std::string &public_key_id,
                          const std::string &public_key,
                          const std::string &private_key)
      : Securifier(public_key_id, public_key, private_key) {}

  bool Validate(const std::string&,
                const std::string&,
                const std::string&,
                const std::string&,
                const std::string&,
                const std::string&) const {
    return true;
  }
};

void FindNodeCallback(RankInfoPtr/* rank_info */,
                      int /* result_size */,
                      const std::vector<Contact> &cs,
                      boost::condition_variable* cond_var,
                      std::vector<Contact> *contacts,
                      bool *done) {
  contacts->clear();
  *contacts = cs;
  *done = true;
  cond_var->notify_one();
}

void FindValueCallback(FindValueReturns find_value_returns_in,
                       boost::condition_variable* cond_var,
                       FindValueReturns *find_value_returns_out,
                       bool* done) {
  *find_value_returns_out = find_value_returns_in;
  *done = true;
  cond_var->notify_one();
}

void ErrorCodeCallback(int error_code,
                       boost::condition_variable* cond_var,
                       int *response_code) {
  *response_code = error_code;
  cond_var->notify_one();
}

void GetContactCallback(int error_code,
                        Contact contact,
                        Contact *result,
                        boost::condition_variable* cond_var,
                        int *response_code) {
  *response_code = error_code;
  *result = contact;
  cond_var->notify_one();
}

class MockTransport : public transport::Transport {
 public:
  MockTransport() : transport::Transport(io_service_) {}
  virtual transport::TransportCondition StartListening(
      const transport::Endpoint &/*endpoint*/) {
    listening_port_ = 5483;
    return transport::kSuccess;
  }
  virtual transport::TransportCondition Bootstrap(
      const std::vector<transport::Endpoint> &/*candidates*/) {
    return transport::kSuccess;
  }
  virtual void StopListening() { listening_port_ = 0; }
  virtual void Send(const std::string &/*data*/,
                    const transport::Endpoint &/*endpoint*/,
                    const transport::Timeout &/*timeout*/) {}
 private:
  boost::asio::io_service io_service_;
};

class TestAlternativeStore : public AlternativeStore {
 public:
  ~TestAlternativeStore() {}
  bool Has(const std::string&) { return false; }
};

template <typename TransportType>
class MockRpcs : public Rpcs<TransportType>, public CreateContactAndNodeId {
 public:
  MockRpcs(boost::asio::io_service &asio_service, SecurifierPtr securifier)  // NOLINT (Fraser)
      : Rpcs<TransportType>(asio_service, securifier),
        work_(new boost::asio::io_service::work(
            Rpcs<TransportType>::asio_service_)),
        CreateContactAndNodeId(g_kKademliaK),
        node_list_mutex_(),
        node_list_(),
        rank_info_(),
        num_of_acquired_(0),
        num_of_deleted_(0),
        respond_(0),
        no_respond_(0),
        respond_contacts_(),
        target_id_(),
        threshold_((g_kKademliaK * 3) / 4) {
  thread_group_.create_thread(
      std::bind(static_cast<size_t(boost::asio::io_service::*)()>(
      &boost::asio::io_service::run),
      std::ref(Rpcs<TransportType>::asio_service_)));
  }
  void Stop() {
    work_.reset();
    thread_group_.join_all();
  }
  MOCK_METHOD7_T(Store, void(const Key &key,
                             const std::string &value,
                             const std::string &signature,
                             const bptime::seconds &ttl,
                             SecurifierPtr securifier,
                             const Contact &peer,
                             RpcStoreFunctor callback));

  MOCK_METHOD6_T(Delete, void(const Key &key,
                              const std::string &value,
                              const std::string &signature,
                              SecurifierPtr securifier,
                              const Contact &peer,
                              RpcDeleteFunctor callback));

  MOCK_METHOD5_T(FindNodes, void(const Key &key,
                                 const uint16_t &nodes_requested,
                                 SecurifierPtr securifier,
                                 const Contact &peer,
                                 RpcFindNodesFunctor callback));

  MOCK_METHOD5_T(FindValue, void(const NodeId &key,
                                 const uint16_t &nodes_requested,
                                 const SecurifierPtr securifier,
                                 const Contact &contact,
                                 RpcFindValueFunctor callback));

  MOCK_METHOD3_T(Downlist, void(const std::vector<NodeId> &node_ids,
                                SecurifierPtr securifier,
                                const Contact &peer));

  MOCK_METHOD3_T(Ping, void(SecurifierPtr securifier,
                            const Contact &peer,
                            RpcPingFunctor callback));

  MOCK_METHOD5_T(StoreRefresh,
                 void(const std::string &serialised_store_request,
                      const std::string &serialised_store_request_signature,
                      SecurifierPtr securifier,
                      const Contact &peer,
                      RpcStoreRefreshFunctor callback));

  void StoreRefreshThread(RpcStoreRefreshFunctor callback) {
    RankInfoPtr rank_info;
    callback(rank_info, transport::kSuccess);
  }
  void StoreRefreshCallback(RpcStoreRefreshFunctor callback) {
    Rpcs<TransportType>::asio_service_.post(
        std::bind(&MockRpcs<TransportType>::StoreRefreshThread, this,
                  callback));
  }
  void FindNodeRandomResponseClose(const Contact &c,
                                   RpcFindNodesFunctor callback) {
    int response_factor = RandomUint32() % 100;
    bool response(true);
    if (response_factor < g_kRandomNoResponseRate)
      response = false;
    std::vector<Contact> response_list;
    boost::mutex::scoped_lock lock(node_list_mutex_);
    if (response) {
      int elements = RandomUint32() % g_kKademliaK;
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
      Rpcs<TransportType>::asio_service_.post(
          std::bind(&MockRpcs<TransportType>::FindNodeResponseThread,
                    this, callback, response_list));
    } else {
      ContactsById key_indx = respond_contacts_->get<NodeIdTag>();
      auto it = key_indx.find(c.node_id());
      if (it != key_indx.end()) {
        down_contacts_->insert((*it));
        respond_contacts_->erase(it);
      }
      Rpcs<TransportType>::asio_service_.post(std::bind(
          &MockRpcs<TransportType>::FindNodeNoResponseThread, this,
          callback, response_list));
    }
  }

  void FindNodeResponseClose(const Contact &/*contact*/,
                             RpcFindNodesFunctor callback) {
    std::vector<Contact> response_list;
    boost::mutex::scoped_lock lock(node_list_mutex_);
    int elements = RandomUint32() % g_kKademliaK;
    for (int n = 0; n < elements; ++n) {
      int element = RandomUint32() % node_list_.size();
      response_list.push_back(node_list_[element]);
      RoutingTableContact new_routing_table_contact(node_list_[element],
                                                    target_id_,
                                                    0);
      respond_contacts_->insert(new_routing_table_contact);
    }
    Rpcs<TransportType>::asio_service_.post(
        std::bind(&MockRpcs<TransportType>::FindNodeResponseThread,
                  this, callback, response_list));
  }

  void FindNodeResponseNoClose(const Contact &/*contact*/,
                               RpcFindNodesFunctor callback) {
    boost::mutex::scoped_lock lock(node_list_mutex_);
    std::vector<Contact> response_list;
    Rpcs<TransportType>::asio_service_.post(
        std::bind(&MockRpcs<TransportType>::FindNodeResponseThread,
                  this, callback, response_list));
  }

  void FindNodeFirstNoResponse(const Contact &/*contact*/,
                               RpcFindNodesFunctor callback) {
//    boost::this_thread::sleep(boost::posix_time::millisec(100));
    boost::mutex::scoped_lock lock(node_list_mutex_);
    std::vector<Contact> response_list;
    if (num_of_acquired_ == 0) {
      Rpcs<TransportType>::asio_service_.post(std::bind(
          &MockRpcs<TransportType>::FindNodeNoResponseThread, this,
          callback, response_list));
    } else {
      Rpcs<TransportType>::asio_service_.post(
          std::bind(&MockRpcs<TransportType>::FindNodeResponseThread,
                    this, callback, response_list));
    }
    ++num_of_acquired_;
  }

  void FindNodeFirstAndLastNoResponse(const Contact &/*contact*/,
                                      RpcFindNodesFunctor callback) {
    boost::mutex::scoped_lock lock(node_list_mutex_);
    std::vector<Contact> response_list;
    if ((num_of_acquired_ == (g_kKademliaK * 2 - 1)) ||
           (num_of_acquired_ == 0)) {
      Rpcs<TransportType>::asio_service_.post(std::bind(
          &MockRpcs<TransportType>::FindNodeNoResponseThread, this,
          callback, response_list));
    } else {
      Rpcs<TransportType>::asio_service_.post(
          std::bind(&MockRpcs<TransportType>::FindNodeResponseThread,
                    this, callback, response_list));
    }
    ++num_of_acquired_;
  }

  void FindNodeSeveralResponseNoClose(const Contact &/*contact*/,
                                      RpcFindNodesFunctor callback) {
    boost::mutex::scoped_lock lock(node_list_mutex_);
    std::vector<Contact> response_list;
    if (num_of_acquired_ > (g_kKademliaK - threshold_)) {
      Rpcs<TransportType>::asio_service_.post(
          std::bind(&MockRpcs<TransportType>::FindNodeResponseThread,
                    this, callback, response_list));
    } else {
      Rpcs<TransportType>::asio_service_.post(std::bind(
          &MockRpcs<TransportType>::FindNodeNoResponseThread, this,
          callback, response_list));
    }
    ++num_of_acquired_;
  }

  void FindNodeSeveralResponse(const uint16_t &extra_contacts,
                             RpcFindNodesFunctor callback) {
    std::vector<Contact> response_list;
    boost::mutex::scoped_lock lock(node_list_mutex_);
    int elements = RandomUint32() % (g_kKademliaK + extra_contacts);
    for (int n = 0; n < elements; ++n) {
      int element = RandomUint32() % node_list_.size();
      response_list.push_back(node_list_[element]);
      RoutingTableContact new_routing_table_contact(node_list_[element],
                                                    target_id_,
                                                    0);
      respond_contacts_->insert(new_routing_table_contact);
    }
    Rpcs<TransportType>::asio_service_.post(
        std::bind(&MockRpcs<TransportType>::FindNodeResponseThread,
                  this, callback, response_list));
  }

  void FindNodeNoResponse(const Contact &/*contact*/,
                          RpcFindNodesFunctor callback) {
    num_of_acquired_++;
    boost::mutex::scoped_lock lock(node_list_mutex_);
    std::vector<Contact> response_list;
    Rpcs<TransportType>::asio_service_.post(
        std::bind(&MockRpcs<TransportType>::FindNodeNoResponseThread,
                  this, callback, response_list));
  }

  void FindNodeResponseThread(RpcFindNodesFunctor callback,
                              std::vector<Contact> response_list) {
    uint16_t interval(10 * (RandomUint32() % 5) + 1);
    Sleep(bptime::milliseconds(interval));
    callback(rank_info_, transport::kSuccess, response_list);
  }

  void FindNodeNoResponseThread(RpcFindNodesFunctor callback,
                                std::vector<Contact> response_list) {
    uint16_t interval(100 * (RandomUint32() % 5) + 1);
    Sleep(bptime::milliseconds(interval));
    callback(rank_info_, transport::kError, response_list);
  }

  void FindValueNoResponse(const Contact &/*contact*/,
                           RpcFindValueFunctor callback) {
    boost::mutex::scoped_lock lock(node_list_mutex_);
    std::vector<Contact> response_contact_list;
    std::vector<std::string> response_value_list;
    Rpcs<TransportType>::asio_service_.post(
        std::bind(&MockRpcs<TransportType>::FindValueNoResponseThread,
                  this, callback, response_value_list, response_contact_list,
                  transport::kError));
  }

  void FindValueResponseCloseOnly(const Contact &/*contact*/,
                                  RpcFindValueFunctor callback) {
    boost::mutex::scoped_lock lock(node_list_mutex_);
    std::vector<Contact> response_contact_list;
    int elements = RandomUint32() % g_kKademliaK;
    for (int n = 0; n < elements; ++n) {
      int element = RandomUint32() % node_list_.size();
      response_contact_list.push_back(node_list_[element]);
    }
    std::vector<std::string> response_value_list;
    Rpcs<TransportType>::asio_service_.post(
        std::bind(&MockRpcs<TransportType>::FindValueNoResponseThread,
                  this, callback, response_value_list, response_contact_list,
                  kFailedToFindValue));
  }

  void FindValueNthResponse(const Contact &/*contact*/,
                            RpcFindValueFunctor callback) {
    boost::mutex::scoped_lock lock(node_list_mutex_);
    std::vector<Contact> response_contact_list;
    std::vector<std::string> response_value_list;
    ++num_of_acquired_;
    if (respond_ != num_of_acquired_) {
      int elements = RandomUint32() % g_kKademliaK + 1;
      for (int n = 0; n < elements; ++n) {
        int element = RandomUint32() % node_list_.size();
        response_contact_list.push_back(node_list_[element]);
        RoutingTableContact new_routing_table_contact(node_list_[element],
                                                      target_id_,
                                                      0);
        respond_contacts_->insert(new_routing_table_contact);
      }
      Rpcs<TransportType>::asio_service_.post(
        std::bind(&MockRpcs<TransportType>::FindValueNoResponseThread,
                  this, callback, response_value_list, response_contact_list,
                  kFailedToFindValue));
    } else {
      response_value_list.push_back("FIND");
      Rpcs<TransportType>::asio_service_.post(
          std::bind(&MockRpcs<TransportType>::FindValueResponseThread,
                    this, callback, response_value_list,
                    response_contact_list));
    }
  }

  void FindValueNoValueResponse(const Contact &/*contact*/,
                                RpcFindValueFunctor callback) {
    boost::mutex::scoped_lock lock(node_list_mutex_);
    std::vector<Contact> response_contact_list;
    std::vector<std::string> response_value_list;
    ++num_of_acquired_;
    int elements = RandomUint32() % g_kKademliaK;
    for (int n = 0; n < elements; ++n) {
      int element = RandomUint32() % node_list_.size();
      response_contact_list.push_back(node_list_[element]);
    }
    Rpcs<TransportType>::asio_service_.post(
        std::bind(&MockRpcs<TransportType>::FindValueNoResponseThread,
                  this, callback, response_value_list, response_contact_list,
                  kFailedToFindValue));
  }

  void FindValueResponseThread(RpcFindValueFunctor callback,
                               std::vector<std::string> response_value_list,
                               std::vector<Contact> response_contact_list) {
    uint16_t interval(10 * (RandomUint32() % 5) + 1);
    Sleep(bptime::milliseconds(interval));
    Contact alternative_store;
    callback(rank_info_, transport::kSuccess, response_value_list,
             response_contact_list, alternative_store);
  }

  void FindValueNoResponseThread(RpcFindValueFunctor callback,
                                 std::vector<std::string> response_value_list,
                                 std::vector<Contact> response_contact_list,
                                 int result) {
    uint16_t interval(100 * (RandomUint32() % 5) + 1);
    Sleep(bptime::milliseconds(interval));
    Contact alternative_store;
    callback(rank_info_, result, response_value_list,
             response_contact_list, alternative_store);
  }

  void DownlistRecord(const std::vector<NodeId> &node_ids,
                      const Contact &/*contact*/) {
    boost::mutex::scoped_lock lock(node_list_mutex_);
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
        uint16_t num_failed_rpcs = (*itr).num_failed_rpcs + 1;
        key_indx.modify(itr, ChangeNumFailedRpc(num_failed_rpcs));
      }
      ++it_node;
    }
  }

  void SingleDeleteResponse(const Contact &/*contact*/,
                            RpcDeleteFunctor callback) {
    boost::mutex::scoped_lock lock(node_list_mutex_);
    ++num_of_deleted_;
    Rpcs<TransportType>::asio_service_.post(std::bind(
        &MockRpcs<TransportType>::
            CommonResponseThread<RpcDeleteFunctor>, this, callback));
  }

  template <class T>
  void Response(const Contact &/*contact*/, T callback) {
// boost::mutex::scoped_lock lock(node_list_mutex_);
// ++respond_;
    Rpcs<TransportType>::asio_service_.post(
        std::bind(&MockRpcs<TransportType>::CommonResponseThread<T>,
                  this, callback));
  }

  template <class T>
  void NoResponse(const Contact &/*contact*/, T callback) {
    Rpcs<TransportType>::asio_service_.post(
        std::bind(&MockRpcs<TransportType>::CommonNoResponseThread<T>,
                  this, callback));
  }

  template <class T>
  void FirstSeveralNoResponse(const Contact &/*contact*/, T callback) {
    boost::mutex::scoped_lock lock(node_list_mutex_);
    if (num_of_acquired_ > (g_kKademliaK - threshold_)) {
      ++respond_;
      Rpcs<TransportType>::asio_service_.post(
          std::bind(&MockRpcs<TransportType>::CommonResponseThread<T>,
                    this, callback));
    } else {
      ++no_respond_;
      Rpcs<TransportType>::asio_service_.post(std::bind(
          &MockRpcs<TransportType>::CommonNoResponseThread<T>, this,
          callback));
    }
    ++num_of_acquired_;
  }

  template <class T>
  void LastSeveralNoResponse(const Contact &/*contact*/, T callback) {
    boost::mutex::scoped_lock lock(node_list_mutex_);
    if (num_of_acquired_ < (threshold_ - 1)) {
      ++respond_;
      Rpcs<TransportType>::asio_service_.post(
          std::bind(&MockRpcs<TransportType>::CommonResponseThread<T>,
                    this, callback));
    } else {
      ++no_respond_;
      Rpcs<TransportType>::asio_service_.post(std::bind(
          &MockRpcs<TransportType>::CommonNoResponseThread<T>, this,
          callback));
    }
    ++num_of_acquired_;
  }

  template <class T>
  void LastLessNoResponse(const Contact &/*contact*/, T callback) {
    boost::mutex::scoped_lock lock(node_list_mutex_);
    if (num_of_acquired_ < threshold_) {
      ++respond_;
      Rpcs<TransportType>::asio_service_.post(
          std::bind(&MockRpcs<TransportType>::CommonResponseThread<T>,
                    this, callback));
    } else {
      ++no_respond_;
      Rpcs<TransportType>::asio_service_.post(std::bind(
          &MockRpcs<TransportType>::CommonNoResponseThread<T>, this,
          callback));
    }
    ++num_of_acquired_;
  }

  template <class T>
  void CommonResponseThread(T callback) {
    uint16_t interval(10 * (RandomUint32() % 5) + 1);
    Sleep(bptime::milliseconds(interval));
    callback(rank_info_, transport::kSuccess);
  }

  template <class T>
  void CommonNoResponseThread(T callback) {
    uint16_t interval(100 * (RandomUint32() % 5) + 1);
    Sleep(bptime::milliseconds(interval));
    callback(rank_info_, transport::kError);
  }

  void PopulateResponseCandidates(int count, const int& pos) {
    PopulateContactsVector(count, pos, &node_list_);
  }

  std::vector<Contact> node_list() {
    boost::mutex::scoped_lock lock(node_list_mutex_);
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

  uint16_t num_of_acquired_;
  uint16_t num_of_deleted_;
  uint16_t respond_;
  uint16_t no_respond_;

  std::shared_ptr<RoutingTableContactsContainer> respond_contacts_;
  std::shared_ptr<RoutingTableContactsContainer> down_contacts_;
  NodeId target_id_;
  int threshold_;

 private:
  std::shared_ptr<boost::asio::io_service::work> work_;
  boost::thread_group thread_group_;
};  // class MockRpcs

}  // unnamed namespace


class MockNodeImplTest : public CreateContactAndNodeId, public testing::Test {
 protected:
  MockNodeImplTest()
      : CreateContactAndNodeId(g_kKademliaK),
        data_store_(),
        alternative_store_(),
        securifier_(new Securifier("", "", "")),
        transport_(new MockTransport),
        rank_info_(),
        asio_service_(),
        message_handler_(new MessageHandler(securifier_)),
        node_(new NodeImpl(asio_service_,
                           transport_,
                           message_handler_,
                           securifier_,
                           alternative_store_,
                           false,
                           g_kKademliaK,
                           g_kAlpha,
                           g_kBeta,
                           bptime::seconds(3600))),
        threshold_((g_kKademliaK * 3) / 4),
        local_node_(new NodeImpl(asio_service_,
                                 transport_,
                                 message_handler_,
                                 SecurifierPtr(new SecurifierValidateTrue(
                                               "", "", "")),
                                 alternative_store_,
                                 true,
                                 g_kKademliaK,
                                 g_kAlpha,
                                 g_kBeta,
                                 bptime::seconds(3600))),
                                 mutex_(),
                                 cond_var_(),
                                 unique_lock_(mutex_),
                                 kTaskTimeout_(10) {
    data_store_ = node_->data_store_;
    node_->routing_table_ = routing_table_;
    local_node_->routing_table_ = routing_table_;
    transport_->StartListening(transport::Endpoint("127.0.0.1", 6700));
    transport_->on_message_received()->connect(
        transport::OnMessageReceived::element_type::slot_type(
            &MessageHandler::OnMessageReceived, message_handler_.get(),
            _1, _2, _3, _4).track_foreign(message_handler_));
  }

  static void SetUpTestCase() {}

  static void TearDownTestCase() {}

  void PopulateRoutingTable(uint16_t count, uint16_t pos) {
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
                  std::bind(&AddContact, routing_table_, arg::_1, rank_info_));
  }

  template <typename TransportType>
  void SetRpcs(std::shared_ptr<Rpcs<TransportType>> rpcs) {
    node_->rpcs_ = rpcs;
  }

  template <typename TransportType>
  void SetLocalRpcs(std::shared_ptr<Rpcs<TransportType>> rpcs) {
    local_node_->rpcs_ = rpcs;
  }

  std::shared_ptr<DataStore> data_store_;
  AlternativeStorePtr alternative_store_;
  SecurifierPtr securifier_;
  TransportPtr transport_;
  RankInfoPtr rank_info_;
  boost::asio::io_service asio_service_;
  MessageHandlerPtr message_handler_;
  std::shared_ptr<NodeImpl> node_;
  int threshold_;
  std::shared_ptr<NodeImpl> local_node_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  boost::unique_lock<boost::mutex> unique_lock_;
  const bptime::seconds kTaskTimeout_;

 public:
  void NodeImplJoinCallback(int output, int* result,
                            boost::condition_variable* cond_var) {
    *result = output;
    cond_var->notify_one();
  }
};  // MockNodeImplTest


TEST_F(MockNodeImplTest, BEH_GetAllContacts) {
  PopulateRoutingTable(g_kKademliaK, 500);
  std::vector<Contact> contacts;
  node_->GetAllContacts(&contacts);
  EXPECT_EQ(g_kKademliaK, contacts.size());
}

TEST_F(MockNodeImplTest, BEH_GetBootstrapContacts) {
  PopulateRoutingTable(g_kKademliaK, 500);
  std::vector<Contact> contacts;
  node_->GetBootstrapContacts(&contacts);
  EXPECT_EQ(g_kKademliaK, contacts.size());
}

TEST_F(MockNodeImplTest, BEH_GetContact) {
  PopulateRoutingTable(g_kKademliaK, 500);

  std::shared_ptr<MockRpcs<transport::TcpTransport>> new_rpcs(
      new MockRpcs<transport::TcpTransport>(asio_service_, securifier_));
  new_rpcs->set_node_id(node_id_);
  SetRpcs<transport::TcpTransport>(new_rpcs);

  int count = 10 * g_kKademliaK;
  new_rpcs->PopulateResponseCandidates(count, 499);
  std::shared_ptr<RoutingTableContactsContainer> temp
      (new RoutingTableContactsContainer());
  new_rpcs->respond_contacts_ = temp;

  EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                   testing::_, testing::_))
      .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(
          std::bind(&MockRpcs<transport::TcpTransport>::FindNodeResponseClose,
                    new_rpcs, arg::_1, arg::_2))));
  NodeId target_id = GenerateRandomId(node_id_, 498);
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // Looking for a non-exist contact
    Contact result;
    int response_code(0);
    node_->GetContact(target_id, std::bind(&GetContactCallback, arg::_1,
                                           arg::_2, &result, &cond_var_,
                                           &response_code));
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    EXPECT_EQ(kFailedToGetContact, response_code);
    EXPECT_EQ(Contact(), result);
  }
  Contact target = ComposeContact(target_id, 5000);
  AddContact(routing_table_, target, rank_info_);
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // Looking for an exist contact
    Contact result;
    int response_code(0);
    node_->GetContact(target_id, std::bind(&GetContactCallback, arg::_1,
                                           arg::_2, &result, &cond_var_,
                                           &response_code));
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    EXPECT_EQ(kSuccess, response_code);
    EXPECT_EQ(target, result);
  }
  // sleep for a while to prevent the situation that resources got destructed
  // before all call back from rpc completed. Which will cause "Segmentation
  // Fault" in execution.
  Sleep(bptime::milliseconds(1000));
}

TEST_F(MockNodeImplTest, BEH_ValidateContact) {
  NodeId contact_id = GenerateRandomId(node_id_, 501);
  Contact contact = ComposeContact(contact_id, 5000);
  local_node_->ConnectValidateContact();
  {
    routing_table_->AddContact(contact, rank_info_);
    // need to sleep for a while
    Sleep(bptime::milliseconds(100));
    Contact result;
    routing_table_->GetContact(contact.node_id(), &result);
    EXPECT_EQ(contact, result);
  }
}

TEST_F(MockNodeImplTest, BEH_PingOldestContact) {
  PopulateRoutingTable(g_kKademliaK, 500);
  PopulateRoutingTable(g_kKademliaK, 501);

  std::shared_ptr<MockRpcs<transport::TcpTransport>> new_rpcs(
      new MockRpcs<transport::TcpTransport>(asio_service_, securifier_));
  new_rpcs->set_node_id(node_id_);
  SetLocalRpcs<transport::TcpTransport>(new_rpcs);

  NodeId new_id = GenerateUniqueRandomId(node_id_, 501);
  Contact new_contact = ComposeContact(new_id, 5000);

  local_node_->ConnectPingOldestContact();
  local_node_->ConnectValidateContact();
  {
    // Ping success
    EXPECT_CALL(*new_rpcs, Ping(testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<1, 2>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::Response<RpcPingFunctor>,
            new_rpcs, arg::_1, arg::_2))));
    AddContact(routing_table_, new_contact, rank_info_);
    // need to sleep for a while
    Sleep(bptime::milliseconds(10000));

    Contact result_new;
    routing_table_->GetContact(new_contact.node_id(), &result_new);
    EXPECT_EQ(Contact(), result_new);
  }
  {
    // Ping failed
    EXPECT_CALL(*new_rpcs, Ping(testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<1, 2>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::NoResponse<RpcPingFunctor>,
            new_rpcs, arg::_1, arg::_2))));
    AddContact(routing_table_, new_contact, rank_info_);

    Contact result_new;
    // may need to put a timer to prevent deadlock
    do {
      routing_table_->GetContact(new_contact.node_id(), &result_new);
      Sleep(bptime::milliseconds(2000));
    } while (result_new == Contact());
    EXPECT_EQ(new_contact, result_new);
  }
}

TEST_F(MockNodeImplTest, BEH_Join) {
  std::vector<Contact> bootstrap_contacts;
  std::shared_ptr<MockRpcs<transport::TcpTransport>> new_rpcs(
      new MockRpcs<transport::TcpTransport>(asio_service_, securifier_));
  new_rpcs->set_node_id(node_id_);
  SetRpcs<transport::TcpTransport>(new_rpcs);

  int count = 10 * g_kKademliaK;
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
    JoinFunctor callback = std::bind(&MockNodeImplTest::NodeImplJoinCallback,
                                     this, arg::_1, &result, &cond_var_);
    Contact contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 490)),
                                     5600);
    bootstrap_contacts.push_back(contact);

    contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 495)), 5700);
    bootstrap_contacts.push_back(contact);

    contact = ComposeContact(target, 6400);
    bootstrap_contacts.push_back(contact);
    EXPECT_CALL(*new_rpcs, FindValue(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillOnce(testing::WithArgs<3, 4>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::FindValueNoResponse,
                      new_rpcs, arg::_1, arg::_2))))
        .WillOnce(testing::WithArgs<3, 4>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::FindValueNoResponse,
                      new_rpcs, arg::_1, arg::_2))))
        .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::FindValueNoValueResponse,
            new_rpcs, arg::_1, arg::_2))));
    node_->Join(node_id_, bootstrap_contacts, callback);
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    ASSERT_EQ(kSuccess, result);
    node_->Leave(NULL);
  }
  // When first contact in bootstrap_contacts is valid
  {
    int result(1);
    JoinFunctor callback = std::bind(&MockNodeImplTest::NodeImplJoinCallback,
                                     this, arg::_1, &result, &cond_var_);
    Contact contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 490)),
                                     5600);
    bootstrap_contacts.push_back(contact);

    contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 495)), 5700);
    bootstrap_contacts.push_back(contact);

    contact = ComposeContact(target, 6400);
    bootstrap_contacts.push_back(contact);

    EXPECT_CALL(*new_rpcs, FindValue(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::FindValueNoValueResponse,
            new_rpcs, arg::_1, arg::_2))));
    node_->Join(node_id_, bootstrap_contacts, callback);
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    ASSERT_EQ(kSuccess, result);
    node_->Leave(NULL);
  }
  // When no contacts are valid
  {
    int result(1);
    bootstrap_contacts.clear();
    JoinFunctor callback = std::bind(&MockNodeImplTest::NodeImplJoinCallback,
                                     this, arg::_1, &result, &cond_var_);
    Contact contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 490)),
                                     5600);
    bootstrap_contacts.push_back(contact);

    contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 495)), 5700);
    bootstrap_contacts.push_back(contact);

    contact = ComposeContact(target, 6400);
    bootstrap_contacts.push_back(contact);

    EXPECT_CALL(*new_rpcs, FindValue(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillOnce(testing::WithArgs<3, 4>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::FindValueNoResponse,
                      new_rpcs, arg::_1, arg::_2))))
        .WillOnce(testing::WithArgs<3, 4>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::FindValueNoResponse,
                      new_rpcs, arg::_1, arg::_2))))
        .WillOnce(testing::WithArgs<3, 4>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::FindValueNoResponse,
                      new_rpcs, arg::_1, arg::_2))));
    node_->Join(node_id_, bootstrap_contacts, callback);
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    EXPECT_EQ(kContactFailedToRespond, result);
    node_->Leave(NULL);
  }
  // Test for refreshing data_store entry
  {
    bptime::time_duration ttl(bptime::pos_infin);
    RequestAndSignature request_signature = std::make_pair("request",
                                                           "signature");

    node_->data_store_.reset(new DataStore(bptime::seconds(1)));
    ASSERT_EQ(kSuccess, node_->data_store_->StoreValue(
              KeyValueSignature("key1", "value1", "sig1"), ttl,
              request_signature, false));
    int result(1);
    JoinFunctor callback = std::bind(&MockNodeImplTest::NodeImplJoinCallback,
                                     this, arg::_1, &result, &cond_var_);
    Contact contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 490)),
                                     5600);
    bootstrap_contacts.push_back(contact);

    contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 495)), 5700);
    bootstrap_contacts.push_back(contact);

    contact = ComposeContact(target, 6400);
    bootstrap_contacts.push_back(contact);

    EXPECT_CALL(*new_rpcs, FindValue(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::FindValueNoValueResponse,
            new_rpcs, arg::_1, arg::_2))));
    EXPECT_CALL(*new_rpcs, StoreRefresh(testing::_, testing::_, testing::_,
                                        testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<4>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::StoreRefreshCallback,
                      new_rpcs, arg::_1))));
    node_->Join(node_id_, bootstrap_contacts, callback);
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    ASSERT_EQ(kSuccess, result);
//    ASSERT_LT(size_t(0), node_->thread_group_->size());
    node_->Leave(NULL);
  }
}

TEST_F(MockNodeImplTest, BEH_Leave) {
  PopulateRoutingTable(g_kKademliaK, 500);
  std::vector<Contact> bootstrap_contacts;
  std::shared_ptr<MockRpcs<transport::TcpTransport>> new_rpcs(
      new MockRpcs<transport::TcpTransport>(asio_service_, securifier_));
  SetRpcs<transport::TcpTransport>(new_rpcs);

  int count = 10 * g_kKademliaK;
  new_rpcs->PopulateResponseCandidates(count, 499);
  NodeId target = GenerateRandomId(node_id_, 480);
  new_rpcs->target_id_ = target;
  std::shared_ptr<RoutingTableContactsContainer> temp
      (new RoutingTableContactsContainer());
  new_rpcs->respond_contacts_ = temp;
  new_rpcs->SetCountersToZero();
  int result(1);
  JoinFunctor callback = std::bind(&MockNodeImplTest::NodeImplJoinCallback,
                                   this, arg::_1, &result, &cond_var_);
  Contact contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 490)),
                                   5600);
  bootstrap_contacts.push_back(contact);

  contact = ComposeContact(NodeId(GenerateRandomId(node_id_, 495)), 5700);
  bootstrap_contacts.push_back(contact);

  contact = ComposeContact(target, 6400);
  bootstrap_contacts.push_back(contact);

  EXPECT_CALL(*new_rpcs, FindValue(testing::_, testing::_, testing::_,
                                   testing::_, testing::_))
      .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(std::bind(
          &MockRpcs<transport::TcpTransport>::FindValueNoValueResponse,
          new_rpcs, arg::_1, arg::_2))));
  node_->Join(node_id_, bootstrap_contacts, callback);
  EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
  ASSERT_EQ(kSuccess, result);
  node_->Leave(NULL);
  ASSERT_FALSE(node_->joined());
//  ASSERT_EQ(size_t(0), node_->thread_group_.use_count());
//  ASSERT_FALSE(node_->refresh_thread_running());
//  ASSERT_FALSE(node_->downlist_thread_running());
  ASSERT_LT(size_t(0), bootstrap_contacts.size());
  bootstrap_contacts.clear();
}

TEST_F(MockNodeImplTest, BEH_FindNodes) {
  bool done(false);
  PopulateRoutingTable(g_kKademliaK *2, 500);
  node_->joined_ = true;
  std::shared_ptr<MockRpcs<transport::TcpTransport>> new_rpcs(
      new MockRpcs<transport::TcpTransport>(asio_service_, securifier_));
  new_rpcs->set_node_id(node_id_);
  SetRpcs<transport::TcpTransport>(new_rpcs);

  NodeId key = NodeId(NodeId::kRandomId);
  {
    // All k populated contacts giving no response
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::FindNodeNoResponse,
                      new_rpcs, arg::_1, arg::_2))));
    std::vector<Contact> lcontacts;
    node_->FindNodes(key, std::bind(&FindNodeCallback, rank_info_, arg::_1,
                                    arg::_2, &cond_var_, &lcontacts, &done));
    while (!done) {
      bool not_timed_out = cond_var_.timed_wait(unique_lock_, kTaskTimeout_);
      if (!not_timed_out) {
        done = true;
      }
      EXPECT_TRUE(not_timed_out);
    }
    EXPECT_TRUE((lcontacts.size() == 1) && (lcontacts[0] == node_->contact()));
  }
  done = false;
  new_rpcs->num_of_acquired_ = 0;
  {
    // The first of the populated contacts giving no response
    // all the others give response with an empty closest list
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::FindNodeFirstNoResponse,
            new_rpcs, arg::_1, arg::_2))));
    std::vector<Contact> lcontacts;
    node_->FindNodes(key,
                     std::bind(&FindNodeCallback, rank_info_, arg::_1, arg::_2,
                               &cond_var_, &lcontacts, &done));
    while (!done) {
      bool not_timed_out = cond_var_.timed_wait(unique_lock_, kTaskTimeout_);
      if (!not_timed_out) {
        done = true;
      }
      EXPECT_TRUE(not_timed_out);
    }
    EXPECT_EQ(g_kKademliaK, lcontacts.size());
  }
  done = false;
  new_rpcs->num_of_acquired_ = 0;
  {
    // The first and the last of the k populated contacts giving no response
    // all the others give response with an empty closest list
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::FindNodeFirstAndLastNoResponse,
            new_rpcs, arg::_1, arg::_2))));
    std::vector<Contact> lcontacts;
    node_->FindNodes(key,
                     std::bind(&FindNodeCallback, rank_info_, arg::_1, arg::_2,
                               &cond_var_, &lcontacts, &done));
    while (!done) {
      bool not_timed_out = cond_var_.timed_wait(unique_lock_, kTaskTimeout_);
      if (!not_timed_out)
        done = true;
      EXPECT_TRUE(not_timed_out);
    }
    EXPECT_EQ(g_kKademliaK , lcontacts.size());
  }
  done = false;
  new_rpcs->num_of_acquired_ = 0;
  {
    // All k populated contacts response with an empty closest list
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::FindNodeResponseNoClose,
            new_rpcs, arg::_1, arg::_2))));
    std::vector<Contact> lcontacts;
    node_->FindNodes(key,
                     std::bind(&FindNodeCallback, rank_info_, arg::_1, arg::_2,
                               &cond_var_, &lcontacts, &done));
    while (!done) {
      bool not_timed_out = cond_var_.timed_wait(unique_lock_, kTaskTimeout_);
      if (!not_timed_out)
        done = true;
      EXPECT_TRUE(not_timed_out);
    }
    EXPECT_EQ(g_kKademliaK, lcontacts.size());
  }
  int count = 10 * g_kKademliaK;
  new_rpcs->PopulateResponseCandidates(count, 499);
  NodeId target = GenerateRandomId(node_id_, 498);
  new_rpcs->target_id_ = target;
  std::shared_ptr<RoutingTableContactsContainer> temp
      (new RoutingTableContactsContainer());
  done = false;
  new_rpcs->respond_contacts_ = temp;
  {
    // All k populated contacts response with random closest list (not greater
    // than k)
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::FindNodeResponseClose,
                      new_rpcs, arg::_1, arg::_2))));
    std::vector<Contact> lcontacts;
    node_->FindNodes(target,
                     std::bind(&FindNodeCallback, rank_info_, arg::_1,
                               arg::_2, &cond_var_, &lcontacts, &done));
    while (!done) {
      bool not_timed_out = cond_var_.timed_wait(unique_lock_, kTaskTimeout_);
      if (!not_timed_out)
        done = true;
      EXPECT_TRUE(not_timed_out);
    }
    ASSERT_EQ(g_kKademliaK, lcontacts.size());
    EXPECT_NE(lcontacts[0], lcontacts[g_kKademliaK / 2]);
    EXPECT_NE(lcontacts[0], lcontacts[g_kKademliaK - 1]);

    ContactsByDistanceToThisId key_dist_indx
      = new_rpcs->respond_contacts_->get<DistanceToThisIdTag>();
    auto it = key_dist_indx.begin();
    int step(0);
    while ((it != key_dist_indx.end()) && (step < g_kKademliaK)) {
      EXPECT_NE(lcontacts.end(),
                std::find(lcontacts.begin(), lcontacts.end(), (*it).contact));
      ++it;
      ++step;
    }
  }

  done = false;
  new_rpcs->num_of_acquired_ = 0;
  new_rpcs->respond_contacts_->clear();
  {
    // attempts to find nodes requesting n > k; the response should contain
    // n nodes
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(
            std::bind(
                &MockRpcs<transport::TcpTransport>::FindNodeResponseClose,
                      new_rpcs, arg::_1, arg::_2))));
    std::vector<Contact> lcontacts;
    node_->FindNodes(target,
                     std::bind(&FindNodeCallback, rank_info_, arg::_1,
                               arg::_2, &cond_var_, &lcontacts, &done),
                     g_kKademliaK / 2);
    while (!done) {
      bool not_timed_out = cond_var_.timed_wait(unique_lock_, kTaskTimeout_);
      if (!not_timed_out)
        done = true;
      EXPECT_TRUE(not_timed_out);
    }
    EXPECT_EQ(g_kKademliaK * 3 / 2, lcontacts.size());
  }

  new_rpcs->respond_contacts_->clear();
  std::shared_ptr<RoutingTableContactsContainer> down_list
      (new RoutingTableContactsContainer());
  done = false;
  new_rpcs->down_contacts_ = down_list;
  {
    // All k populated contacts randomly response with random closest list
    // (not greater than k)
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::FindNodeRandomResponseClose,
            new_rpcs, arg::_1, arg::_2))));
    std::vector<Contact> lcontacts;
    node_->FindNodes(target,
                     std::bind(&FindNodeCallback, rank_info_, arg::_1, arg::_2,
                               &cond_var_, &lcontacts, &done));
    while (!done) {
      bool not_timed_out = cond_var_.timed_wait(unique_lock_, kTaskTimeout_);
      if (!not_timed_out)
        done = true;
      EXPECT_TRUE(not_timed_out);
    }
    if (new_rpcs->respond_contacts_->size() >= g_kKademliaK) {
      EXPECT_EQ(g_kKademliaK, lcontacts.size());
      EXPECT_NE(lcontacts[0], lcontacts[g_kKademliaK / 2]);
      EXPECT_NE(lcontacts[0], lcontacts[g_kKademliaK - 1]);

      ContactsByDistanceToThisId key_dist_indx
        = new_rpcs->respond_contacts_->get<DistanceToThisIdTag>();
      auto it = key_dist_indx.begin();
      int step(0);
      while ((it != key_dist_indx.end()) && (step < g_kKademliaK)) {
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
  new_rpcs->Stop();
}

TEST_F(MockNodeImplTest, BEH_Store) {
  PopulateRoutingTable(g_kKademliaK, 500);
  std::shared_ptr<MockRpcs<transport::TcpTransport>> new_rpcs(
      new MockRpcs<transport::TcpTransport>(asio_service_, securifier_));
  new_rpcs->set_node_id(node_id_);
  SetRpcs<transport::TcpTransport>(new_rpcs);

  int count = 10 * g_kKademliaK;
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
      .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(
          std::bind(&MockRpcs<transport::TcpTransport>::FindNodeResponseClose,
                    new_rpcs, arg::_1, arg::_2))));

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
                                 testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::Response<RpcStoreFunctor>,
            new_rpcs, arg::_1, arg::_2))));
    int response_code(-2);
    node_->Store(key, kvs.value, kvs.signature, old_ttl, securifier_,
                 std::bind(&ErrorCodeCallback, arg::_1, &cond_var_,
                           &response_code));
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    EXPECT_EQ(kSuccess, response_code);
  }
  new_rpcs->SetCountersToZero();
  EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                testing::_, testing::_, testing::_))
      .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
          std::bind(&MockRpcs<transport::TcpTransport>::SingleDeleteResponse,
                    new_rpcs, arg::_1, arg::_2))));
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the last k - threshold closest contacts respond with DOWN, others respond
    // with success
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::
                      LastSeveralNoResponse<RpcStoreFunctor>, new_rpcs,
                      arg::_1, arg::_2))));
    int response_code(-2);
    node_->Store(key, kvs.value, kvs.signature, old_ttl, securifier_,
                 std::bind(&ErrorCodeCallback, arg::_1, &cond_var_,
                           &response_code));
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    EXPECT_EQ(kStoreTooFewNodes, response_code);
    // wait for the delete processes to be completed
    // otherwise the counter might be incorrect
    Sleep(bptime::milliseconds(300));
    EXPECT_EQ(g_kKademliaK - threshold_ + 1, new_rpcs->num_of_deleted_);
  }
  new_rpcs->SetCountersToZero();
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the first k - threshold closest contacts respond with DOWN, others
    // respond with success
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::
                      FirstSeveralNoResponse<RpcStoreFunctor>, new_rpcs,
                      arg::_1, arg::_2))));
    int response_code(-2);
    node_->Store(key, kvs.value, kvs.signature, old_ttl, securifier_,
                 std::bind(&ErrorCodeCallback, arg::_1, &cond_var_,
                           &response_code));
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    EXPECT_EQ(kStoreTooFewNodes, response_code);
    // wait for the delete processes to be completed
    // otherwise the counter might be incorrect
    // may not be necessary for this test
    Sleep(bptime::milliseconds(300));
    EXPECT_EQ(g_kKademliaK - threshold_ + 1, new_rpcs->num_of_deleted_);
  }
  new_rpcs->SetCountersToZero();
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the first k - threshold -1 closest contacts respond with DOWN, others
    // respond with success
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::
                      LastLessNoResponse<RpcStoreFunctor>, new_rpcs,
                      arg::_1, arg::_2))));
    int response_code(-2);
    node_->Store(key, kvs.value, kvs.signature, old_ttl, securifier_,
                 std::bind(&ErrorCodeCallback, arg::_1, &cond_var_,
                           &response_code));
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    EXPECT_EQ(kSuccess, response_code);
    // wait to ensure in case of wrong, the wrong deletion will be executed
    Sleep(bptime::milliseconds(300));
    EXPECT_EQ(0, new_rpcs->num_of_deleted_);
  }
  new_rpcs->SetCountersToZero();
  {
    // Among k populated contacts, less than threshold contacts response with
    // no closest list
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::
                      FindNodeSeveralResponseNoClose, new_rpcs, arg::_1,
                      arg::_2))));
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::
                      LastLessNoResponse<RpcStoreFunctor>, new_rpcs,
                      arg::_1, arg::_2))));
    int response_code(-2);
    node_->Store(key, kvs.value, kvs.signature, old_ttl, securifier_,
                 std::bind(&ErrorCodeCallback, arg::_1, &cond_var_,
                           &response_code));
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    EXPECT_EQ(kFoundTooFewNodes, response_code);
    EXPECT_EQ(0, new_rpcs->respond_);
    EXPECT_EQ(0, new_rpcs->no_respond_);
  }
  // sleep for a while to prevent the situation that resources got destructed
  // before all call back from rpc completed. Which will cause "Segmentation
  // Fault" in execution.
  Sleep(bptime::milliseconds(1000));

  // SetRpcs<transport::TcpTransport>(old_rpcs);
}

TEST_F(MockNodeImplTest, BEH_Delete) {
  PopulateRoutingTable(g_kKademliaK, 500);
  std::shared_ptr<MockRpcs<transport::TcpTransport>> new_rpcs(
      new MockRpcs<transport::TcpTransport>(asio_service_, securifier_));
  new_rpcs->set_node_id(node_id_);
  SetRpcs<transport::TcpTransport>(new_rpcs);

  int count = 10 * g_kKademliaK;
  new_rpcs->PopulateResponseCandidates(count, 499);
  NodeId target = GenerateRandomId(node_id_, 498);
  new_rpcs->target_id_ = target;
  std::shared_ptr<RoutingTableContactsContainer> temp
      (new RoutingTableContactsContainer());
  new_rpcs->respond_contacts_ = temp;

  EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                   testing::_, testing::_))
      .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(
          std::bind(&MockRpcs<transport::TcpTransport>::FindNodeResponseClose,
                    new_rpcs, arg::_1, arg::_2))));

  NodeId key = NodeId(NodeId::kRandomId);
  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(4096);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, key.String(), "");
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // all k closest contacts respond with success
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::Response<RpcDeleteFunctor>,
            new_rpcs, arg::_1, arg::_2))));
    int response_code(-2);
    node_->Delete(key, kvs.value, kvs.signature, securifier_,
             std::bind(&ErrorCodeCallback, arg::_1, &cond_var_,
                       &response_code));
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    EXPECT_EQ(kSuccess, response_code);
  }
  new_rpcs->SetCountersToZero();
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the last k - threshold closest contacts respond with DOWN, others respond
    // with success
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::
                      LastSeveralNoResponse<RpcDeleteFunctor>, new_rpcs,
                      arg::_1, arg::_2))));
    int response_code(0);
    node_->Delete(key, kvs.value, kvs.signature, securifier_,
             std::bind(&ErrorCodeCallback, arg::_1, &cond_var_,
                       &response_code));

    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    EXPECT_EQ(kDeleteTooFewNodes, response_code);
    // wait for the all delete processes to be completed
    // otherwise the counter might be incorrect
    Sleep(bptime::milliseconds(300));
    EXPECT_EQ(g_kKademliaK - threshold_ + 1, new_rpcs->no_respond_);
  }
  new_rpcs->SetCountersToZero();
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the first k - threshold closest contacts respond with DOWN, others
    // respond with success
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::
                      FirstSeveralNoResponse<RpcDeleteFunctor>, new_rpcs,
                      arg::_1, arg::_2))));
    int response_code(-2);
    node_->Delete(key, kvs.value, kvs.signature, securifier_,
             std::bind(&ErrorCodeCallback, arg::_1, &cond_var_,
                       &response_code));
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    EXPECT_EQ(kDeleteTooFewNodes, response_code);
    // wait for the delete processes to be completed
    // otherwise the counter might be incorrect
    // may not be necessary for this test
    Sleep(bptime::milliseconds(300));
    EXPECT_EQ(g_kKademliaK - threshold_ + 1, new_rpcs->no_respond_);
  }
  new_rpcs->SetCountersToZero();
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the first k - threshold -1 closest contacts respond with DOWN, others
    // respond with success
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::
                      LastLessNoResponse<RpcDeleteFunctor>, new_rpcs,
                      arg::_1, arg::_2))));
    int response_code(-2);
    node_->Delete(key, kvs.value, kvs.signature, securifier_,
             std::bind(&ErrorCodeCallback, arg::_1, &cond_var_,
                       &response_code));
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
  }
  new_rpcs->SetCountersToZero();
  {
    // Among k populated contacts, less than threshold contacts response with
    // no closest list
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::
                      FindNodeSeveralResponseNoClose, new_rpcs, arg::_1,
                      arg::_2))));
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::
                      LastLessNoResponse<RpcDeleteFunctor>, new_rpcs,
                      arg::_1, arg::_2))));
    int response_code(-2);
    node_->Delete(key, kvs.value, kvs.signature, securifier_,
             std::bind(&ErrorCodeCallback, arg::_1, &cond_var_,
                       &response_code));
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    EXPECT_EQ(kFoundTooFewNodes, response_code);
    EXPECT_EQ(0, new_rpcs->respond_);
    EXPECT_EQ(0, new_rpcs->no_respond_);
  }
  // sleep for a while to prevent the situation that resources got destructed
  // before all call back from rpc completed. Which will cause "Segmentation
  // Fault" in execution.
  Sleep(bptime::milliseconds(1000));
  // SetRpcs<transport::TcpTransport>(old_rpcs);
}

TEST_F(MockNodeImplTest, BEH_Update) {
  PopulateRoutingTable(g_kKademliaK, 500);

  std::shared_ptr<MockRpcs<transport::TcpTransport>> new_rpcs(
      new MockRpcs<transport::TcpTransport>(asio_service_, securifier_));
  new_rpcs->set_node_id(node_id_);
  SetRpcs<transport::TcpTransport>(new_rpcs);

  int count = 10 * g_kKademliaK;
  new_rpcs->PopulateResponseCandidates(count, 499);
  NodeId target = GenerateRandomId(node_id_, 498);
  new_rpcs->target_id_ = target;
  std::shared_ptr<RoutingTableContactsContainer> temp
      (new RoutingTableContactsContainer());
  new_rpcs->respond_contacts_ = temp;

  EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                   testing::_, testing::_))
      .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(
          std::bind(&MockRpcs<transport::TcpTransport>::FindNodeResponseClose,
                      new_rpcs, arg::_1, arg::_2))));

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
                                  testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::Response<RpcDeleteFunctor>,
            new_rpcs, arg::_1, arg::_2))));
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::Response<RpcStoreFunctor>,
            new_rpcs, arg::_1, arg::_2))));
    int response_code(-2);
    node_->Update(key, kvs_new.value, kvs_new.signature,
                  kvs.value, kvs.signature, old_ttl, securifier_,
                  std::bind(&ErrorCodeCallback, arg::_1, &cond_var_,
                            &response_code));
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    EXPECT_EQ(kSuccess, response_code);
  }
  new_rpcs->SetCountersToZero();
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the first (k - threshold) closest contacts respond with DOWN in store,
    // others respond with success
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::Response<RpcDeleteFunctor>,
            new_rpcs, arg::_1, arg::_2))));
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::
                      FirstSeveralNoResponse<RpcStoreFunctor>, new_rpcs,
                      arg::_1, arg::_2))));
    int response_code(-2);
    node_->Update(key, kvs_new.value, kvs_new.signature,
                  kvs.value, kvs.signature, old_ttl, securifier_,
                  std::bind(&ErrorCodeCallback, arg::_1, &cond_var_,
                            &response_code));
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    // wait for the all processes to be completed
    // otherwise the counter might be incorrect
    Sleep(bptime::milliseconds(300));
    EXPECT_EQ(kUpdateTooFewNodes, response_code);
    EXPECT_EQ(g_kKademliaK - threshold_ + 1, new_rpcs->no_respond_);
    EXPECT_EQ(threshold_ - 1, new_rpcs->respond_);
  }
  new_rpcs->SetCountersToZero();
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the last (k - threshold) closest contacts respond with DOWN in store,
    // others respond with success
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::Response<RpcDeleteFunctor>,
            new_rpcs, arg::_1, arg::_2))));
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::
                      LastSeveralNoResponse<RpcStoreFunctor>, new_rpcs,
                      arg::_1, arg::_2))));
    int response_code(-2);
    node_->Update(key, kvs_new.value, kvs_new.signature,
                  kvs.value, kvs.signature, old_ttl, securifier_,
                  std::bind(&ErrorCodeCallback, arg::_1, &cond_var_,
                            &response_code));
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    // wait for the all processes to be completed
    // otherwise the counter might be incorrect
    Sleep(bptime::milliseconds(100));
    EXPECT_EQ(kUpdateTooFewNodes, response_code);
    EXPECT_EQ(g_kKademliaK - threshold_ + 1, new_rpcs->no_respond_);
    EXPECT_EQ(threshold_ - 1, new_rpcs->respond_);
  }
  new_rpcs->SetCountersToZero();
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the last (k - threshold) closest contacts respond with DOWN in delete,
    // others response with success
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::
                      LastSeveralNoResponse<RpcDeleteFunctor>, new_rpcs,
                      arg::_1, arg::_2))));
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::Response<RpcStoreFunctor>,
            new_rpcs, arg::_1, arg::_2))));
    int response_code(-2);
    node_->Update(key, kvs_new.value, kvs_new.signature,
                  kvs.value, kvs.signature, old_ttl, securifier_,
                  std::bind(&ErrorCodeCallback, arg::_1, &cond_var_,
                            &response_code));
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    // wait for the all processes to be completed
    // otherwise the counter might be incorrect
    Sleep(bptime::milliseconds(100));
    EXPECT_EQ(kDeleteTooFewNodes, response_code);
    EXPECT_EQ(g_kKademliaK - threshold_ + 1, new_rpcs->no_respond_);
    EXPECT_EQ(threshold_ - 1, new_rpcs->respond_);
  }
  new_rpcs->SetCountersToZero();
  {
    // All k populated contacts response with random closest list
    // (not greater than k)
    // the first (k - threshold) closest contacts respond with DOWN in delete,
    // others response with success
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::
                      FirstSeveralNoResponse<RpcDeleteFunctor>, new_rpcs,
                      arg::_1, arg::_2))));
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::Response<RpcStoreFunctor>,
            new_rpcs, arg::_1, arg::_2))));
    int response_code(-2);
    node_->Update(key, kvs_new.value, kvs_new.signature,
                  kvs.value, kvs.signature, old_ttl, securifier_,
                  std::bind(&ErrorCodeCallback, arg::_1, &cond_var_,
                            &response_code));
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    // wait for the all processes to be completed
    // otherwise the counter might be incorrect
    Sleep(bptime::milliseconds(100));
    EXPECT_EQ(kDeleteTooFewNodes, response_code);
    EXPECT_EQ(g_kKademliaK - threshold_ + 1, new_rpcs->no_respond_);
    EXPECT_EQ(threshold_ - 1, new_rpcs->respond_);
  }
  new_rpcs->SetCountersToZero();
  {
    // Among k populated contacts, less than threshold contacts response with
    // no closest list
    EXPECT_CALL(*new_rpcs, FindNodes(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::
                      FindNodeSeveralResponseNoClose, new_rpcs, arg::_1,
                      arg::_2))));
    EXPECT_CALL(*new_rpcs, Delete(testing::_, testing::_, testing::_,
                                  testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<4, 5>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::Response<RpcDeleteFunctor>,
            new_rpcs, arg::_1, arg::_2))));
    EXPECT_CALL(*new_rpcs, Store(testing::_, testing::_, testing::_,
                                 testing::_, testing::_, testing::_,
                                 testing::_))
        .WillRepeatedly(testing::WithArgs<5, 6>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::Response<RpcStoreFunctor>,
            new_rpcs, arg::_1, arg::_2))));
    int response_code(-2);
    node_->Update(key, kvs_new.value, kvs_new.signature,
                  kvs.value, kvs.signature, old_ttl, securifier_,
                  std::bind(&ErrorCodeCallback, arg::_1, &cond_var_,
                            &response_code));
    EXPECT_TRUE(cond_var_.timed_wait(unique_lock_, kTaskTimeout_));
    EXPECT_EQ(kFoundTooFewNodes, response_code);
    EXPECT_EQ(0, new_rpcs->respond_);
    EXPECT_EQ(0, new_rpcs->no_respond_);
  }
  // sleep for a while to prevent the situation that resources got destructed
  // before all call back from rpc completed. Which will cause "Segmentation
  // Fault" in execution.
  Sleep(bptime::milliseconds(500));
}

TEST_F(MockNodeImplTest, BEH_FindValue) {
  bool done(false);
  PopulateRoutingTable(g_kKademliaK * 2, 500);
  node_->joined_ = true;
  std::shared_ptr<MockRpcs<transport::TcpTransport>> new_rpcs(
      new MockRpcs<transport::TcpTransport>(asio_service_, securifier_));
  new_rpcs->set_node_id(node_id_);
  SetRpcs<transport::TcpTransport>(new_rpcs);
  NodeId key = GenerateRandomId(node_id_, 498);
  {
    // All k populated contacts giving no response
    EXPECT_CALL(*new_rpcs, FindValue(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::FindValueNoResponse,
                      new_rpcs, arg::_1, arg::_2))));
    FindValueReturns results;
    node_->FindValue(key, securifier_,
                     std::bind(&FindValueCallback, arg::_1, &cond_var_,
                               &results, &done));
    while (!done) {
      bool not_timed_out = cond_var_.timed_wait(unique_lock_, kTaskTimeout_);
      if (!not_timed_out)
        done = true;
      EXPECT_TRUE(not_timed_out);
    }
    EXPECT_EQ(kFailedToFindValue, results.return_code);
    EXPECT_TRUE(results.values.empty());
    EXPECT_TRUE((results.closest_nodes.size() == 1) &&
        (results.closest_nodes[0] == node_->contact()));
  }
  done = false;
  new_rpcs->SetCountersToZero();
  int count = 10 * g_kKademliaK;
  new_rpcs->PopulateResponseCandidates(count, 499);
  {
    // All k populated contacts giving no data find, but response with some
    // closest contacts
    EXPECT_CALL(*new_rpcs, FindValue(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::FindValueResponseCloseOnly,
            new_rpcs, arg::_1, arg::_2))));
    FindValueReturns results;
    node_->FindValue(key, securifier_,
                     std::bind(&FindValueCallback, arg::_1, &cond_var_,
                               &results, &done));
    while (!done) {
      bool not_timed_out = cond_var_.timed_wait(unique_lock_, kTaskTimeout_);
      if (!not_timed_out)
        done = true;
      EXPECT_TRUE(not_timed_out);
    }
    EXPECT_EQ(kFailedToFindValue, results.return_code);
    EXPECT_TRUE(results.values.empty());
    EXPECT_EQ(g_kKademliaK, results.closest_nodes.size());
  }
  done = false;
  new_rpcs->SetCountersToZero();
  std::shared_ptr<RoutingTableContactsContainer> temp
      (new RoutingTableContactsContainer());
  new_rpcs->respond_contacts_ = temp;
  new_rpcs->target_id_ = key;
  {
    // the Nth enquired contact will response the value
    // note: there is high chance that search value will stopped after just
    // (g_kAlpha + K) tries -- get g_kKademliaK-closest extreme fast.
    new_rpcs->respond_ = g_kAlpha + RandomUint32() % g_kKademliaK + 1;
    EXPECT_CALL(*new_rpcs, FindValue(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(
            std::bind(&MockRpcs<transport::TcpTransport>::FindValueNthResponse,
                      new_rpcs, arg::_1, arg::_2))));
    FindValueReturns results;
    node_->FindValue(key, securifier_,
                     std::bind(&FindValueCallback, arg::_1, &cond_var_,
                               &results, &done));
    while (!done) {
      bool not_timed_out = cond_var_.timed_wait(unique_lock_, kTaskTimeout_);
      if (!not_timed_out)
        done = true;
      EXPECT_TRUE(not_timed_out);
    }
    EXPECT_EQ(kSuccess, results.return_code);
    EXPECT_TRUE(results.closest_nodes.empty());
    ASSERT_EQ(1, results.values.size());
    EXPECT_EQ("FIND", results.values[0]);
    EXPECT_LE(new_rpcs->respond_, new_rpcs->num_of_acquired_);
  }
  done = false;
  new_rpcs->SetCountersToZero();
  {
    // value not existed, search shall stop once top-k-closest achieved
    EXPECT_CALL(*new_rpcs, FindValue(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(std::bind(
            &MockRpcs<transport::TcpTransport>::FindValueNoValueResponse,
            new_rpcs, arg::_1, arg::_2))));
    FindValueReturns results;
    node_->FindValue(key, securifier_,
                     std::bind(&FindValueCallback, arg::_1, &cond_var_,
                               &results, &done));
    while (!done) {
      bool not_timed_out = cond_var_.timed_wait(unique_lock_, kTaskTimeout_);
      if (!not_timed_out)
        done = true;
      EXPECT_TRUE(not_timed_out);
    }
    EXPECT_EQ(kFailedToFindValue, results.return_code);
    EXPECT_TRUE(results.values.empty());
    EXPECT_EQ(g_kKademliaK, results.closest_nodes.size());
    EXPECT_GT(40 * g_kKademliaK, new_rpcs->num_of_acquired_);
  }

  done = false;
  new_rpcs->SetCountersToZero();
  {
    // attempts to find value requesting n > k; the response should contain
    // n nodes
    EXPECT_CALL(*new_rpcs, FindValue(testing::_, testing::_, testing::_,
                                     testing::_, testing::_))
        .WillRepeatedly(testing::WithArgs<3, 4>(testing::Invoke(
            std::bind(
                &MockRpcs<transport::TcpTransport>::FindValueResponseCloseOnly,
                      new_rpcs, arg::_1, arg::_2))));
    FindValueReturns results;
    node_->FindValue(key, securifier_,
                     std::bind(&FindValueCallback, arg::_1, &cond_var_,
                               &results, &done),
                     g_kKademliaK / 2);
    while (!done) {
      bool not_timed_out = cond_var_.timed_wait(unique_lock_, kTaskTimeout_);
      if (!not_timed_out)
        done = true;
      EXPECT_TRUE(not_timed_out);
    }
    EXPECT_EQ(g_kKademliaK * 3 / 2, results.closest_nodes.size());
  }
  new_rpcs->Stop();
}

TEST_F(MockNodeImplTest, BEH_SetLastSeenToNow) {
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

TEST_F(MockNodeImplTest, BEH_IncrementFailedRpcs) {
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

TEST_F(MockNodeImplTest, BEH_GetAndUpdateRankInfo) {
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

TEST_F(MockNodeImplTest, BEH_Getters) {
  {
    // contact()
    EXPECT_EQ(Contact(), node_->contact());
  }
  std::shared_ptr<MockRpcs<transport::TcpTransport>> new_rpcs(
      new MockRpcs<transport::TcpTransport>(asio_service_, securifier_));
  new_rpcs->set_node_id(node_id_);
  SetLocalRpcs<transport::TcpTransport>(new_rpcs);
  {
    // joined()
    EXPECT_FALSE(local_node_->joined());
    NodeId key = NodeId(NodeId::kRandomId);
    std::vector<Contact> booststrap_contacts(1, Contact());
    int result;
    FindValueReturns find_value_returns;
    find_value_returns.return_code = kSuccess;

    local_node_->JoinFindValueCallback(
        find_value_returns, booststrap_contacts, key,
        std::bind(&MockNodeImplTest::NodeImplJoinCallback, this, arg::_1,
                  &result, &cond_var_), true);
    EXPECT_TRUE(local_node_->joined());
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
    EXPECT_EQ(g_kKademliaK, node_->k());
  }
}

}  // namespace test
}  // namespace kademlia
}  // namespace dht
}  // namespace maidsafe
