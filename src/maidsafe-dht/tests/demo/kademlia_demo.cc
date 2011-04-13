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

#include <signal.h>
#include <iostream>  //  NOLINT
#include <functional>
#include <memory>
#include "boost/program_options.hpp"
#include "boost/filesystem/fstream.hpp"
#include "boost/filesystem.hpp"
#include "boost/format.hpp"
#include "boost/shared_ptr.hpp"
#include "boost/thread/thread.hpp"
#include "boost/lexical_cast.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe-dht/kademlia/config.h"
#include "maidsafe-dht/kademlia/contact.h"
#include "maidsafe-dht/kademlia/node_id.h"
#include "maidsafe-dht/kademlia/node-api.h"
#include "maidsafe-dht/kademlia/node_impl.h"
#include "maidsafe-dht/kademlia/securifier.h"
#include "maidsafe-dht/tests/demo/commands.h"
#include "maidsafe-dht/transport/transport.h"
#include "maidsafe-dht/transport/tcp_transport.h"
#include "maidsafe-dht/transport/udp_transport.h"

namespace arg = std::placeholders;
namespace bptime = boost::posix_time;
namespace po = boost::program_options;
namespace mk = maidsafe::kademlia;

namespace maidsafe {

namespace kademlia {

namespace test_kaddemo {

class KademliaDemoUtils {
 public:
  KademliaDemoUtils() : transport_type_(kTcp),
                        asio_service_(),
                        transport_(),
                        work_(),
                        end_point_(),
                        rsa_key_pair_(),
                        securifier_(),
                        message_handler_(),
                        alternative_store_(),
                        node_(),
                        client_only_node_(false),
                        k_(4),
                        alpha_(3),
                        beta_(2),
                        mean_refresh_interval_(3600),
                        bootstrap_contacts_() {
  }

  transport::TransportCondition SetUpTransport(
      const TransportType& type,
      const transport::Endpoint& endpoint) {
    end_point_ = endpoint;
    transport_type_ = type;
    asio_service_.reset(new boost::asio::io_service);
    work_.reset(new boost::asio::io_service::work(*asio_service_));
    boost::thread_group thread_group_;
    size_t(boost::asio::io_service::*fn)() = &boost::asio::io_service::run;
    thread_group_.create_thread(std::bind(fn, asio_service_));
    switch (transport_type_) {
      case kTcp:
        transport_.reset(new transport::TcpTransport(*asio_service_));
        break;
      case kUdp:
        transport_.reset(new transport::UdpTransport(*asio_service_));
        break;
      default:
        return transport::kError;
    }
    // Start Listening
    return transport_->StartListening(end_point_);
  }

  void StopListeningTransport() {
    transport_->StopListening();
  }

  void SetUpNode(const bool &client_only_node,
                 const boost::uint16_t &k,
                 const boost::uint16_t &alpha,
                 const boost::uint16_t &beta,
                 bptime::seconds &mean_refresh_interval,
                 const bool &secure) {
    client_only_node_ = client_only_node;
    k_ = k;
    alpha_ = alpha;
    beta_ = beta;
    mean_refresh_interval_ = mean_refresh_interval;
    if (secure) {
      rsa_key_pair_.GenerateKeys(4096);
      securifier_.reset(new maidsafe::Securifier("an_id",
                                                 rsa_key_pair_.public_key(),
                                                 rsa_key_pair_.private_key()));
    } else {
      securifier_.reset(new maidsafe::Securifier("", "", ""));
    }
    message_handler_.reset(new MessageHandler(securifier_));
    node_.reset(new Node(asio_service_, transport_, message_handler_,
                         securifier_, alternative_store_, client_only_node,
                         k_, alpha_, beta_, mean_refresh_interval));
  }

  int JoinNode(const NodeId &node_id,
               const std::vector<Contact> &bootstrap_contacts) {
    bool done(false);
    int response(-1);
    JoinFunctor callback = std::bind(&KademliaDemoUtils::Callback, this,
                                     arg::_1, &done, &response);
    JoinNode(node_id, bootstrap_contacts, callback);
    while (!done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    return response;
  }

  void JoinNode(const NodeId &node_id,
                const std::vector<Contact> &bootstrap_contacts,
                JoinFunctor callback) {
    bootstrap_contacts_ = bootstrap_contacts;
    node_->Join(node_id, bootstrap_contacts_, callback);
  }

  void LeaveNode(std::vector<Contact> *bootstrap_contacts) {
    node_->Leave(bootstrap_contacts);
  }

  void Callback(const int &result, bool *done, int *response_code) {
    *done = true;
    *response_code = result;
  }

  void print_node_info(Contact contact) {
    std::cout <<
      boost::format("Node id: [ %1% ] \nNode ip: [%2%] Node port: [%3%]\n")
        % contact.node_id().ToStringEncoded(NodeId::kHex)
        % contact.endpoint().ip.to_string()
        % contact.endpoint().port;
    std::cout << std::endl;
  }

  std::shared_ptr<Node> get_node() {
    return node_;
  }

  std::shared_ptr<Securifier> get_securifier() {
    return securifier_;
  }

  Contact ComposeContact(const NodeId& node_id,
                         const transport::Endpoint& end_point) {
    std::vector<transport::Endpoint> local_endpoints;
    local_endpoints.push_back(end_point);
    Contact contact(node_id, end_point, local_endpoints, end_point, false,
                    false, "", "", "");
    return contact;
  }

  Contact ComposeContactWithKey(const NodeId& node_id,
                                const transport::Endpoint& end_point,
                                const crypto::RsaKeyPair& crypto_key) {
    std::vector<transport::Endpoint> local_endpoints;
    local_endpoints.push_back(end_point);
    Contact contact(node_id, end_point, local_endpoints, end_point, false,
                    false, node_id.String(), crypto_key.public_key(), "");
    return contact;
  }

 private:
  typedef std::shared_ptr<Node> NodePtr;
  TransportType transport_type_;
  IoServicePtr asio_service_;
  TransportPtr transport_;
  std::shared_ptr<boost::asio::io_service::work> work_;
  transport::Endpoint end_point_;
  crypto::RsaKeyPair rsa_key_pair_;
  SecurifierPtr securifier_;
  MessageHandlerPtr message_handler_;
  AlternativeStorePtr alternative_store_;
  std::shared_ptr<Node> node_;
  bool client_only_node_;
  boost::uint16_t k_;
  boost::uint16_t alpha_;
  boost::uint16_t beta_;
  bptime::seconds mean_refresh_interval_;
  std::vector<Contact> bootstrap_contacts_;
};

void conflicting_options(const po::variables_map& vm,
                         const char* opt1,
                         const char* opt2) {
  if (vm.count(opt1) && !vm[opt1].defaulted()
      && vm.count(opt2) && !vm[opt2].defaulted())
    throw std::logic_error(std::string("Conflicting options '")  + opt1 +
        "' and '" + opt2 + "'.");
}

// Function used to check that if 'for_what' is specified, then
// 'required_option' is specified too.
void option_dependency(const po::variables_map& vm,
                       const char* for_what,
                       const char* required_option) {
  if (vm.count(for_what) && !vm[for_what].defaulted())
    if (vm.count(required_option) == 0 || vm[required_option].defaulted())
      throw std::logic_error(std::string("Option '") + for_what
          + "' requires option '" + required_option + "'.");
}

}  // namespace test_kaddemo

}  // namespace kademlia

}  // namespace maidsafe

volatile int ctrlc_pressed = 0;

void ctrlc_handler(int b) {
  b = 1;
  ctrlc_pressed = b;
}

int main(int argc, char **argv) {
  try {
    std::string logpath, kadconfigpath, bs_ip, bs_id, ext_ip, configfile,
                bs_local_ip, thisnodekconfigpath, idpath;
    boost::uint16_t bs_port(0), port(0);
    boost::uint16_t type(0), k(2), alpha(1), beta(1);
    boost::uint32_t refresh_interval(0);

    po::options_description desc("Options");
    desc.add_options()
      ("help,h", "Print options information and exit.")
      ("logfilepath,l", po::value(&logpath), "Path of logfile")
      ("verbose,v", po::bool_switch(), "Print log to console.")
//      ("kadconfigfile,g",
//        po::value(&kadconfigpath)->default_value(kadconfigpath),
//        "Complete pathname of kadconfig file. Default is Node<port>/."
//        "kadconfig")
      ("client,c", po::bool_switch(), "Start the node as a client node.")
      ("first_node,f", po::bool_switch(), "First node of the network.")
      ("type,t", po::value(&type)->default_value(type),
        "Type of transport Tcp(0), Udt(1), Other(2) -> Default is Tcp.")
      ("port,p", po::value(&port)->default_value(port),
        "Local port to start node->  Default is 0, that starts in random port.")
      ("bs_ip", po::value(&bs_ip), "Bootstrap node ip.")
      ("bs_port", po::value(&bs_port), "Bootstrap node port.")
      ("bs_id", po::value(&bs_id), "Bootstrap node id.")
      ("k", po::value(&k)->default_value(k),
       "Kademlia k, Number of contacts returned from a Find RPC")
      ("alpha,a", po::value(&alpha)->default_value(alpha),
        "Kademlia alpha, parallel level of Find RPCs")
      ("beta,b", po::value(&beta)->default_value(beta),
        "Kademlia beta, Number of returned Find RPCs required to start a "
        "subsequent iteration")
//      ("upnp", po::bool_switch(), "Use UPnP for Nat Traversal.")
//      ("port_fw", po::bool_switch(), "Manually port forwarded local port.")
      ("secure", po::bool_switch(),
       "Node with keys. Can only communicate with other secure nodes")
      ("noconsole", po::bool_switch(),
        "Do not have access to Kademlia functions (store/findvalue/findnode) "
        "after node startup.")
//      ("nodeinfopath", po::value(&thisnodekconfigpath),
//      "Writes to this path a kadconfig file (with name .kadconfig) with this"
//        " node's information.")
//      ("append_id", po::value(&idpath),
//        "Appends to the text file at this path the node's ID in a new line.")
      ("refresh_intv,r", po::value(&refresh_interval),
        "Average interval time in minutes to refresh values.");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    if (vm.count("help")) {
      std::cout << desc << std::endl;
      return 0;
    }
    mk::test_kaddemo::option_dependency(vm, "bs_id", "bs_ip");
    mk::test_kaddemo::option_dependency(vm, "bs_ip", "bs_id");
    mk::test_kaddemo::option_dependency(vm, "bs_id", "bs_port");
    mk::test_kaddemo::option_dependency(vm, "bs_port", "bs_id");
//    mk::test_kaddemo::conflicting_options(vm, "upnp", "port_fw");
    mk::test_kaddemo::conflicting_options(vm, "client", "noconsole");
    mk::test_kaddemo::conflicting_options(vm, "verbose", "logfilepath");
    mk::test_kaddemo::conflicting_options(vm, "first_node", "bs_id");
    mk::test_kaddemo::conflicting_options(vm, "first_node", "bs_ip");
    mk::test_kaddemo::conflicting_options(vm, "first_node", "bs_port");

    bool first_node(vm["first_node"].as<bool>());
    if (!first_node && !vm.count("bs_id")) {
      printf("No bootstrapping info.\n");
      return 1;
    }
    // setting log
#ifndef HAVE_GLOG
    std::string FLAGS_log_dir;
#endif
    if (vm.count("logfilepath")) {
#ifdef HAVE_GLOG
      try {
        if (!boost::filesystem::exists(vm["logfilepath"].as<std::string>()))
          boost::filesystem::create_directories(
              vm["logfilepath"].as<std::string>());
        FLAGS_log_dir = vm["logfilepath"].as<std::string>();
      }
      catch(const std::exception &e) {
        printf("Error creating directory for log path: %s\n", e.what());
        printf("Logfile going to default dir (/tmp)\n");
      }
#endif
    } else {
      FLAGS_logtostderr = vm["verbose"].as<bool>();
    }
    google::InitGoogleLogging(argv[0]);

    std::shared_ptr<mk::test_kaddemo::KademliaDemoUtils>
        kademlia_demo_utils(new mk::test_kaddemo::KademliaDemoUtils);
    // Transport Setup
    type = (vm["type"].as<boost::uint16_t>());
    if (type > 2) {
      printf("Invalid transport type %d.\n", type);
      return 1;
    }
    mk::TransportType transport_type = (mk::TransportType)type;
    port = vm["port"].as<boost::uint16_t>();
    maidsafe::transport::Endpoint end_point("127.0.0.1", port);
    maidsafe::transport::TransportCondition tc;
    tc = kademlia_demo_utils->SetUpTransport(transport_type, end_point);

    if (maidsafe::transport::kSuccess != tc) {
      printf("Node failed to start transport on port %d,", port);
      printf(" with error code  %d.", tc);
      return 1;
    }

    // Node Setup
    bool client_only_node(vm["client"].as<bool>());
    if (vm.count("refresh_interval")) {
      refresh_interval = vm["refresh_interval"].as<boost::uint32_t>();
      refresh_interval = refresh_interval * 60;
    } else {
      refresh_interval = 3600;
    }
    bptime::seconds mean_refresh_interval(refresh_interval);
    bool secure(vm["secure"].as<bool>());
    kademlia_demo_utils->SetUpNode(client_only_node, k, alpha, beta,
                                   mean_refresh_interval, secure);

    // Joining the node to the network
    std::vector<maidsafe::kademlia::Contact> bootstrap_contacts;
    int response;
    if (first_node) {
      mk::NodeId node_id(mk::NodeId::kRandomId);
      mk::Contact contact = kademlia_demo_utils->ComposeContact(node_id,
                                                                end_point);
      bootstrap_contacts.push_back(contact);
      response =  kademlia_demo_utils->JoinNode(node_id, bootstrap_contacts);
    } else {
      std::string bs_id(vm["bs_id"].as<std::string>());
      mk::NodeId node_id(mk::NodeId::kRandomId);
      mk::NodeId bs_node_id(bs_id);
      maidsafe::transport::Endpoint end_point(vm["bs_ip"].as<std::string>(),
          vm["bs_port"].as<boost::uint16_t>());
      mk::Contact contact(kademlia_demo_utils->ComposeContact(bs_node_id,
                                                              end_point));
      bootstrap_contacts.push_back(contact);
      response =  kademlia_demo_utils->JoinNode(node_id, bootstrap_contacts);
    }

    if (response != maidsafe::transport::kSuccess) {
      printf("Node failed to join the network with return code <%d>.\n",
             response);
      kademlia_demo_utils->StopListeningTransport();
      return 1;
    }

    // Printing Node Info
    kademlia_demo_utils->print_node_info(
        kademlia_demo_utils->get_node()->contact());

    if (!vm["noconsole"].as<bool>()) {
      mk::kaddemo::Commands cmds(kademlia_demo_utils->get_node(),
                                 kademlia_demo_utils->get_securifier(), k);
      cmds.Run();
    } else {
      printf("=====================================\n");
      printf("Press Ctrl+C to exit\n");
      printf("=====================================\n\n");
      signal(SIGINT, ctrlc_handler);
      while (!ctrlc_pressed) {
        boost::this_thread::sleep(boost::posix_time::seconds(1));
      }
    }
    bootstrap_contacts.clear();
    kademlia_demo_utils->LeaveNode(&bootstrap_contacts);
    kademlia_demo_utils->StopListeningTransport();
    printf("\nNode stopped successfully.\n");
  }
  catch(const std::exception &e) {
    printf("Error: %s\n", e.what());
    return 1;
  }
  return 0;
}
