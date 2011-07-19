/* Copyright (c) 2011 maidsafe.net limited
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


#ifndef MAIDSAFE_DHT_KADEMLIA_NODE_CONTAINER_H_
#define MAIDSAFE_DHT_KADEMLIA_NODE_CONTAINER_H_

#include <memory>
#include <string>
#include <vector>

#include "boost/asio/io_service.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/thread.hpp"
#include "maidsafe/common/crypto.h"
#include "maidsafe/dht/kademlia/securifier.h"

#include "maidsafe/dht/transport/tcp_transport.h"
#include "maidsafe/dht/kademlia/config.h"
#include "maidsafe/dht/kademlia/utils.h"
#include "maidsafe/dht/kademlia/message_handler.h"
#include "maidsafe/dht/version.h"

#if MAIDSAFE_DHT_VERSION != 3002
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-dht library.
#endif

namespace arg = std::placeholders;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace dht {

namespace kademlia {

template <typename NodeType>
class NodeContainer {
 public:
  NodeContainer()
      : asio_service_(),
        work_(new boost::asio::io_service::work(asio_service_)),
        thread_group_(),
        listening_transport_(),
        message_handler_(),
        securifier_(),
        node_() {}

  virtual ~NodeContainer() {}

  virtual void Init(
      uint8_t thread_count,
      SecurifierPtr securifier,
      AlternativeStorePtr alternative_store,
      bool client_only_node,
      uint16_t k = 8,
      uint16_t alpha = 3,
      uint16_t beta = 2,
      bptime::time_duration mean_refresh_interval = bptime::hours(1));

  int Start(std::vector<Contact> bootstrap_contacts, const Port &port);

  int Stop(std::vector<Contact> *bootstrap_contacts);

  // These 7 functions call the corresponding function on node_ using the
  // corresponding class member functors.
  void Join(const NodeId &node_id,
            const std::vector<Contact> &bootstrap_contacts);
  void Store(const Key &key,
             const std::string &value,
             const std::string &signature,
             const boost::posix_time::time_duration &ttl,
             SecurifierPtr securifier);
  void Delete(const Key &key,
              const std::string &value,
              const std::string &signature,
              SecurifierPtr securifier);
  void Update(const Key &key,
              const std::string &new_value,
              const std::string &new_signature,
              const std::string &old_value,
              const std::string &old_signature,
              SecurifierPtr securifier,
              const boost::posix_time::time_duration &ttl);
  void FindValue(const Key &key,
                 SecurifierPtr securifier);
  void FindNodes(const Key &key);
  void GetContact(const NodeId &node_id);

  // These Make<XXX>Functor functions set the appropriate <XXX>_functor_ by
  // binding the corresponding private <XXX>Callback method.
  void MakeJoinFunctor(boost::mutex *mutex,
                       boost::condition_variable *cond_var,
                       int *result);
  void MakeStoreFunctor(boost::mutex *mutex,
                        boost::condition_variable *cond_var,
                        int *result);
  void MakeDeleteFunctor(boost::mutex *mutex,
                         boost::condition_variable *cond_var,
                         int *result);
  void MakeUpdateFunctor(boost::mutex *mutex,
                         boost::condition_variable *cond_var,
                         int *result);
  void MakeFindValueFunctor(boost::mutex *mutex,
                            boost::condition_variable *cond_var,
                            FindValueReturns *find_value_returns);
  void MakeFindNodesFunctor(boost::mutex *mutex,
                            boost::condition_variable *cond_var,
                            int *result,
                            std::vector<Contact> *closest_nodes);
  void MakeGetContactFunctor(boost::mutex *mutex,
                             boost::condition_variable *cond_var,
                             int *result,
                             Contact *contact);

  void set_join_functor(const JoinFunctor &functor) {
    join_functor_ = functor;
  }
  void set_store_functor(const StoreFunctor &functor) {
    store_functor_ = functor;
  }
  void set_delete_functor(const DeleteFunctor &functor) {
    delete_functor_ = functor;
  }
  void set_update_functor(const UpdateFunctor &functor) {
    update_functor_ = functor;
  }
  void set_find_value_functor(const FindValueFunctor &functor) {
    find_value_functor_ = functor;
  }
  void set_find_nodes_functor(const FindNodesFunctor &functor) {
    find_nodes_functor_ = functor;
  }
  void set_get_contact_functor(const GetContactFunctor &functor) {
    get_contact_functor_ = functor;
  }

  std::shared_ptr<NodeType> node() const { return node_; }
  JoinFunctor join_functor() const { return join_functor_; }
  StoreFunctor store_functor() const { return store_functor_; }
  DeleteFunctor delete_functor() const { return delete_functor_; }
  UpdateFunctor update_functor() const { return update_functor_; }
  FindValueFunctor find_value_functor() const { return find_value_functor_; }
  FindNodesFunctor find_nodes_functor() const { return find_nodes_functor_; }
  GetContactFunctor get_contact_functor() const { return get_contact_functor_; }

 protected:
  AsioService asio_service_;
  std::shared_ptr<boost::asio::io_service::work> work_;
  boost::thread_group thread_group_;
  TransportPtr listening_transport_;
  MessageHandlerPtr message_handler_;
  SecurifierPtr securifier_;
  std::shared_ptr<NodeType> node_;

 private:
  void DefaultCallback(int result_in,
                       boost::mutex *mutex,
                       boost::condition_variable *cond_var,
                       int *result_out);
  void FindValueCallback(FindValueReturns find_value_returns_in,
                         boost::mutex *mutex,
                         boost::condition_variable *cond_var,
                         FindValueReturns *find_value_returns_out);
  void FindNodesCallback(int result_in,
                         std::vector<Contact> closest_nodes_in,
                         boost::mutex *mutex,
                         boost::condition_variable *cond_var,
                         int *result_out,
                         std::vector<Contact> *closest_nodes_out);
  void GetContactCallback(int result_in,
                          Contact contact_in,
                          boost::mutex *mutex,
                          boost::condition_variable *cond_var,
                          int *result_out,
                          Contact *contact_out);
  bool ResultReady(const int &pending, int *result) {
    return *result != pending;
  }
  NodeContainer(const NodeContainer&);
  NodeContainer &operator=(const NodeContainer&);
  JoinFunctor join_functor_;
  StoreFunctor store_functor_;
  DeleteFunctor delete_functor_;
  UpdateFunctor update_functor_;
  FindValueFunctor find_value_functor_;
  FindNodesFunctor find_nodes_functor_;
  GetContactFunctor get_contact_functor_;
};

template <typename NodeType>
std::string DebugId(const NodeContainer<NodeType> &container) {
  return maidsafe::dht::kademlia::DebugId(container.node()->contact());
}


template <typename NodeType>
void NodeContainer<NodeType>::Init(
    uint8_t thread_count,
    SecurifierPtr securifier,
    AlternativeStorePtr alternative_store,
    bool client_only_node,
    uint16_t k,
    uint16_t alpha,
    uint16_t beta,
    bptime::time_duration mean_refresh_interval) {
  // set thread pool for asio service
  for (uint8_t i = 0; i != thread_count; ++i) {
    thread_group_.create_thread(
        std::bind(static_cast<size_t(boost::asio::io_service::*)()>(
            &boost::asio::io_service::run), std::ref(asio_service_)));
  }

  // set up securifier if it wasn't passed in - make signing_key_id compatible
  // with type NodeId so that the node's ID can be set as the securifier's ID
  if (securifier) {
    securifier_ = securifier;
  } else {
    crypto::RsaKeyPair key_pair;
    key_pair.GenerateKeys(4096);
    std::string id(crypto::Hash<crypto::SHA512>(key_pair.public_key()));
    securifier_.reset(new Securifier(id, key_pair.public_key(),
                                     key_pair.private_key()));
  }

  // If this is not a client node, connect message handler to transport for
  // incoming raw messages.  Don't need to connect to on_error() as service
  // doesn't care if reply succeeds or not.
  if (!client_only_node) {
    listening_transport_.reset(new transport::TcpTransport(asio_service_));
    message_handler_.reset(new MessageHandler(securifier_));
    listening_transport_->on_message_received()->connect(
        transport::OnMessageReceived::element_type::slot_type(
            &MessageHandler::OnMessageReceived, message_handler_.get(),
            _1, _2, _3, _4).track_foreign(message_handler_));
  }

  // create node
  node_.reset(new NodeType(asio_service_, listening_transport_,
                           message_handler_, securifier_, alternative_store,
                           client_only_node, k, alpha, beta,
                           mean_refresh_interval));
}

template <typename NodeType>
int NodeContainer<NodeType>::Start(
    std::vector<dht::kademlia::Contact> bootstrap_contacts,
    const boost::uint16_t &port) {
  int result(kPendingResult);
  if (!node_->client_only_node()) {
    transport::Endpoint endpoint("127.0.0.1", port);
    int result = listening_transport_->StartListening(endpoint);
    if (transport::kSuccess != result) {
      listening_transport_->StopListening();
      return result;
    }
  }

  result = kPendingResult;
  boost::mutex mutex;
  boost::condition_variable cond_var;
  NodeId node_id(securifier_->kSigningKeyId());
  JoinFunctor join_functor(std::bind(&NodeContainer<NodeType>::DefaultCallback,
                           this, arg::_1, &mutex, &cond_var, &result));

  boost::function<bool()> wait_functor = boost::bind(
      &NodeContainer<NodeType>::ResultReady, this, kPendingResult, &result);
  const bptime::time_duration kTimeout(bptime::seconds(10));
  boost::mutex::scoped_lock lock(mutex);
  node_->Join(node_id, bootstrap_contacts, join_functor);
  return cond_var.timed_wait(lock, kTimeout, wait_functor) ? result : -1;
}

template <typename NodeType>
int NodeContainer<NodeType>::Stop(std::vector<Contact> *bootstrap_contacts) {
  try {
    node_->Leave(bootstrap_contacts);
    work_.reset();
    asio_service_.stop();
    thread_group_.join_all();
  } catch(const std::exception&) {
    return -1;
  }
  return 0;
}

template <typename NodeType>
void NodeContainer<NodeType>::Join(
    const NodeId &node_id,
    const std::vector<Contact> &bootstrap_contacts) {
  node_->Join(node_id, bootstrap_contacts, join_functor_);
}

template <typename NodeType>
void NodeContainer<NodeType>::Store(const Key &key,
                                    const std::string &value,
                                    const std::string &signature,
                                    const boost::posix_time::time_duration &ttl,
                                    SecurifierPtr securifier) {
  node_->Store(key, value, signature, ttl, securifier, store_functor_);
}

template <typename NodeType>
void NodeContainer<NodeType>::Delete(const Key &key,
                                     const std::string &value,
                                     const std::string &signature,
                                     SecurifierPtr securifier) {
  node_->Delete(key, value, signature, securifier, delete_functor_);
}

template <typename NodeType>
void NodeContainer<NodeType>::Update(
    const Key &key,
    const std::string &new_value,
    const std::string &new_signature,
    const std::string &old_value,
    const std::string &old_signature,
    SecurifierPtr securifier,
    const boost::posix_time::time_duration &ttl) {
  node_->Update(key, new_value, new_signature, old_value, old_signature,
                securifier, ttl, update_functor_);
}

template <typename NodeType>
void NodeContainer<NodeType>::FindValue(const Key &key,
                                        SecurifierPtr securifier) {
  node_->FindValue(key, securifier, find_value_functor_);
}

template <typename NodeType>
void NodeContainer<NodeType>::FindNodes(const Key &key) {
  node_->FindNodes(key, find_nodes_functor_);
}

template <typename NodeType>
void NodeContainer<NodeType>::GetContact(const NodeId &node_id) {
  node_->GetContact(node_id, get_contact_functor_);
}

template <typename NodeType>
void NodeContainer<NodeType>::DefaultCallback(
    int result_in,
    boost::mutex *mutex,
    boost::condition_variable *cond_var,
    int *result_out) {
  boost::mutex::scoped_lock lock(*mutex);
  if (result_out)
    *result_out = result_in;
  cond_var->notify_one();
}

template <typename NodeType>
void NodeContainer<NodeType>::FindValueCallback(
    FindValueReturns find_value_returns_in,
    boost::mutex *mutex,
    boost::condition_variable *cond_var,
    FindValueReturns *find_value_returns_out) {
  boost::mutex::scoped_lock lock(*mutex);
  if (find_value_returns_out)
    *find_value_returns_out = find_value_returns_in;
  cond_var->notify_one();
}

template <typename NodeType>
void NodeContainer<NodeType>::FindNodesCallback(
    int result_in,
    std::vector<Contact> closest_nodes_in,
    boost::mutex *mutex,
    boost::condition_variable *cond_var,
    int *result_out,
    std::vector<Contact> *closest_nodes_out) {
  boost::mutex::scoped_lock lock(*mutex);
  if (result_out)
    *result_out = result_in;
  if (closest_nodes_out)
    *closest_nodes_out = closest_nodes_in;
  cond_var->notify_one();
}

template <typename NodeType>
void NodeContainer<NodeType>::GetContactCallback(
    int result_in,
    Contact contact_in,
    boost::mutex *mutex,
    boost::condition_variable *cond_var,
    int *result_out,
    Contact *contact_out) {
  boost::mutex::scoped_lock lock(*mutex);
  if (result_out)
    *result_out = result_in;
  if (contact_out)
    *contact_out = contact_in;
  cond_var->notify_one();
}

template <typename NodeType>
void NodeContainer<NodeType>::MakeJoinFunctor(
    boost::mutex *mutex,
    boost::condition_variable *cond_var,
    int *result) {
  join_functor_ = std::bind(&NodeContainer<NodeType>::DefaultCallback, this,
                            arg::_1, mutex, cond_var, result);
}

template <typename NodeType>
void NodeContainer<NodeType>::MakeStoreFunctor(
    boost::mutex *mutex,
    boost::condition_variable *cond_var,
    int *result) {
  store_functor_ = std::bind(&NodeContainer<NodeType>::DefaultCallback, this,
                             arg::_1, mutex, cond_var, result);
}

template <typename NodeType>
void NodeContainer<NodeType>::MakeDeleteFunctor(
    boost::mutex *mutex,
    boost::condition_variable *cond_var,
    int *result) {
  delete_functor_ = std::bind(&NodeContainer<NodeType>::DefaultCallback, this,
                              arg::_1, mutex, cond_var, result);
}

template <typename NodeType>
void NodeContainer<NodeType>::MakeUpdateFunctor(
    boost::mutex *mutex,
    boost::condition_variable *cond_var,
    int *result) {
  update_functor_ = std::bind(&NodeContainer<NodeType>::DefaultCallback, this,
                              arg::_1, mutex, cond_var, result);
}

template <typename NodeType>
void NodeContainer<NodeType>::MakeFindValueFunctor(
    boost::mutex *mutex,
    boost::condition_variable *cond_var,
    FindValueReturns *find_value_returns) {
  find_value_functor_ = std::bind(&NodeContainer<NodeType>::FindValueCallback,
                                  this, arg::_1, mutex, cond_var,
                                  find_value_returns);
}

template <typename NodeType>
void NodeContainer<NodeType>::MakeFindNodesFunctor(
    boost::mutex *mutex,
    boost::condition_variable *cond_var,
    int *result,
    std::vector<Contact> *closest_nodes) {
  find_nodes_functor_ = std::bind(&NodeContainer<NodeType>::FindNodesCallback,
                                  this, arg::_1, arg::_2, mutex, cond_var,
                                  result, closest_nodes);
}

template <typename NodeType>
void NodeContainer<NodeType>::MakeGetContactFunctor(
    boost::mutex *mutex,
    boost::condition_variable *cond_var,
    int *result,
    Contact *contact) {
  get_contact_functor_ = std::bind(&NodeContainer<NodeType>::GetContactCallback,
                                   this, arg::_1, arg::_2, mutex, cond_var,
                                   result, contact);
}



}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_NODE_CONTAINER_H_
