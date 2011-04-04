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
#include "maidsafe-dht/tests/functional_kademlia/test_node_environment.h"

#include <ShlObj.h>

namespace maidsafe {

namespace kademlia {

namespace test {

boost::uint16_t kNetworkSize;
boost::uint16_t kK_;
boost::uint16_t kAlpha_;
boost::uint16_t kBeta_;
boost::uint16_t kNumServers_;
boost::posix_time::time_duration kMeanRefresh_;
const boost::uint16_t kThreadGroupSize = 3;

std::string test_dir_;
std::string kad_config_file_;
typedef std::shared_ptr<boost::asio::io_service::work> WorkPtr;
typedef std::shared_ptr<boost::thread_group> ThreadGroupPtr;

std::vector<IoServicePtr> asio_services_;
std::vector<WorkPtr> works_;
std::vector<ThreadGroupPtr> thread_groups_;
std::vector<TransportPtr> transports_;
std::vector<MessageHandlerPtr> message_handlers_;
std::vector<AlternativeStorePtr> alternative_stores_;
std::vector<SecurifierPtr> securifiers_;

std::vector<std::shared_ptr<Node> > nodes_;
std::vector<NodeId> node_ids_;
std::vector<std::string> dbs_;
std::vector<Contact> bootstrap_contacts_;
std::vector<crypto::RsaKeyPair> crypto_key_pairs_;

std::vector<boost::uint16_t> ports_;

NodeId GenerateUniqueRandomId(const NodeId& holder, const int& pos) {
  std::string holder_id = holder.ToStringEncoded(NodeId::kBinary);
  std::bitset<kKeySizeBits> holder_id_binary_bitset(holder_id);
  NodeId new_node;
  std::string new_node_string;
  bool repeat(true);
  boost::uint16_t times_of_try(0);
  // generate a random ID and make sure it has not been generated previously
  do {
    new_node = NodeId(NodeId::kRandomId);
    std::string new_id = new_node.ToStringEncoded(NodeId::kBinary);
    std::bitset<kKeySizeBits> binary_bitset(new_id);
    for (int i = kKeySizeBits - 1; i >= pos; --i)
      binary_bitset[i] = holder_id_binary_bitset[i];
    binary_bitset[pos].flip();
    new_node_string = binary_bitset.to_string();
    new_node = NodeId(new_node_string, NodeId::kBinary);
    // make sure the new contact not already existed in the routing table
    auto it = std::find(node_ids_.begin(), node_ids_.end(), new_node);
    if (it == node_ids_.end()) {
      repeat = false;
      node_ids_.push_back(new_node);
    }
    ++times_of_try;
  } while (repeat && (times_of_try < 1000));
  // prevent deadlock, throw out an error message in case of deadlock
  if (times_of_try == 1000)
    EXPECT_LT(1000, times_of_try);
  return new_node;
}

void ErrorCodeCallback(int error_code,
                       bool *done,
                       int *response_code) {
  *done = true;
  *response_code = error_code;
}

std::string get_app_directory() {
  boost::filesystem::path app_path;
#if defined(MAIDSAFE_POSIX)
  app_path = fs::path("/var/cache/maidsafe/");
#elif defined(MAIDSAFE_WIN32)
  TCHAR szpth[MAX_PATH];
  if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, 0, szpth))) {
    std::ostringstream stm;
    const std::ctype<char> &ctfacet =
        std::use_facet< std::ctype<char> >(stm.getloc());
    for (size_t i = 0; i < wcslen(szpth); ++i)
      stm << ctfacet.narrow(szpth[i], 0);
    app_path = fs::path(stm.str());
    app_path /= "maidsafe";
  }

#elif defined(MAIDSAFE_APPLE)
  app_path = fs::path("/Library/maidsafe/");
#endif
  return app_path.string();
}

EnvironmentNodes::EnvironmentNodes(boost::uint16_t num_of_nodes,
    boost::uint16_t k,
    boost::uint16_t alpha,
    boost::uint16_t beta,
    boost::uint16_t num_of_servers,
    const boost::posix_time::time_duration &mean_refresh_interval) {
  kNetworkSize = num_of_nodes;
  kK_ = k;
  if (kK_ > kNetworkSize)
    kK_ = kNetworkSize;
  kAlpha_ = alpha;
  if (kAlpha_ > kK_)
    kAlpha_ = kK_;
  kBeta_ = beta;
  if (kBeta_ > kAlpha_)
    kBeta_ = kAlpha_;
  kNumServers_ = num_of_servers;
  if (kNumServers_ > kNetworkSize)
    kNumServers_ = kNetworkSize;
  kMeanRefresh_ = mean_refresh_interval;
}

void EnvironmentNodes::SetUp() {
  test_dir_ = fs::path(fs::unique_path(fs::temp_directory_path() /
                       "MaidSafe_Test_Kad_API_%%%%-%%%%-%%%%")).string();
  kad_config_file_ = test_dir_ + std::string("/.kadconfig");
  try {
    if (fs::exists(test_dir_))
      fs::remove_all(test_dir_);
    fs::create_directories(test_dir_);
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "filesystem error: " << e.what() << std::endl;
  }

  // setup the nodes without starting them
  std::string priv_key, pub_key;
  NodeId seed_id(NodeId::kRandomId);

  for (boost::int16_t  i = 0; i < kNetworkSize; ++i) {
    crypto::RsaKeyPair rsa_key_pair;
    rsa_key_pair.GenerateKeys(4096);
    crypto_key_pairs_.push_back(rsa_key_pair);
    IoServicePtr local_asio(new boost::asio::io_service());
    WorkPtr local_work(new boost::asio::io_service::work(*local_asio));
    works_.push_back(local_work);
    asio_services_.push_back(local_asio);
    ThreadGroupPtr local_thread_group;

    local_thread_group.reset(new boost::thread_group());

    for (int i = 0; i < kThreadGroupSize; ++i)
       local_thread_group->create_thread(std::bind(static_cast<
          std::size_t(boost::asio::io_service::*)()>
              (&boost::asio::io_service::run), local_asio));

    thread_groups_.push_back(local_thread_group);

    TransportPtr local_transport(new transport::TcpTransport(*local_asio));
    EXPECT_EQ(transport::kSuccess, local_transport->StartListening(
        transport::Endpoint("127.0.0.1", 5000 + i)));
    transports_.push_back(local_transport);
    AlternativeStorePtr alternative_store;
    alternative_stores_.push_back(alternative_store);
    SecurifierPtr securifier(new Securifier("",
                                            rsa_key_pair.public_key(),
                                            rsa_key_pair.private_key()));
    securifiers_.push_back(securifier);
    MessageHandlerPtr message_handler(new MessageHandler(securifier));
    message_handlers_.push_back(message_handler);
    ports_.push_back(5000 + i);
    GenerateUniqueRandomId(seed_id, 511 - i);
    bool client_only_node(true);
    if (i < kNumServers_) {
      client_only_node = false;
      std::string ip("127.0.0.1");
      std::vector<transport::Endpoint> local_endpoints;
      transport::Endpoint end_point(ip, ports_[i]);
      local_endpoints.push_back(end_point);
      Contact contact(node_ids_[i], end_point, local_endpoints, end_point,
                      false, false, "", rsa_key_pair.public_key(), "");
      bootstrap_contacts_.push_back(contact);
    }
    std::shared_ptr<Node> cur_node(new Node(local_asio, local_transport,
                                            message_handler,
                                            securifier,
                                            alternative_store,
                                            client_only_node,
                                            kK_, kAlpha_, kBeta_,
                                            kMeanRefresh_));
    nodes_.push_back(cur_node);
    std::string db_local(test_dir_ + std::string("/datastore") +
                         boost::lexical_cast<std::string>(i));
    boost::filesystem::create_directories(db_local);
    dbs_.push_back(db_local);
    bool done(false);
    int response_code(-3);
    nodes_[i]->Join(node_ids_[i], ports_[i], bootstrap_contacts_,
                    boost::bind(&ErrorCodeCallback, _1, &done, &response_code));
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    EXPECT_TRUE(nodes_[i]->joined());
  }
  // TODO(qi.ma@maidsafe.net): the first bootstrap contact may need to be
  // joined before others. However, it depends on what to be tested
}

void EnvironmentNodes::TearDown() {
    DLOG(INFO) << "TestNode, TearDown Starting..." << std::endl;
    boost::this_thread::sleep(boost::posix_time::seconds(1));

    for (boost::int16_t i = kNetworkSize-1; i >= 0; i--) {
      DLOG(INFO) << "stopping node " << i << std::endl;
      std::vector<Contact> local_boostrap_contacts;
      nodes_[i]->Leave(&local_boostrap_contacts);
      EXPECT_FALSE(nodes_[i]->joined());
    }

    for (auto it = ports_.begin(); it != ports_.end(); ++it) {
      // Deleting the DBs in the app dir
      fs::path db_dir(get_app_directory());
      db_dir /= boost::lexical_cast<std::string>(*it);
      try {
        if (fs::exists(db_dir))
          fs::remove_all(db_dir);
      }
      catch(const std::exception &e) {
        DLOG(ERROR) << "filesystem error: " << e.what() << std::endl;
      }
    }

    try {
      if (fs::exists(test_dir_))
        fs::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "filesystem error: " << e.what() << std::endl;
    }
    for (size_t i = 0; i < asio_services_.size(); ++i) {
      works_[i].reset();
      asio_services_[i]->stop();
      thread_groups_[i]->join_all();
      thread_groups_[i].reset();
    }
    dbs_.clear();
    bootstrap_contacts_.clear();
    nodes_.clear();
    node_ids_.clear();
    ports_.clear();
    securifiers_.clear();
    alternative_stores_.clear();
    transports_.clear();
    asio_services_.clear();
    works_.clear();
    thread_groups_.clear();
    crypto_key_pairs_.clear();
    DLOG(INFO) << "TestNode, TearDown Finished." << std::endl;
}

}   //  namespace test

}   //  namespace kademlia

}   //   namespace maidsafe
