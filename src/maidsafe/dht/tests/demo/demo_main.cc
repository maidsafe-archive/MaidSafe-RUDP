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
#include "boost/program_options.hpp"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/dht/log.h"
#include "maidsafe/dht/version.h"
#include "maidsafe/dht/kademlia/contact.h"
#include "maidsafe/dht/kademlia/node_id.h"
#include "maidsafe/dht/kademlia/node-api.h"
#include "maidsafe/dht/tests/demo/commands.h"
#include "maidsafe/dht/tests/demo/demo_node.h"

namespace bptime = boost::posix_time;
namespace fs = boost::filesystem;
namespace po = boost::program_options;
namespace mk = maidsafe::dht::kademlia;
namespace mt = maidsafe::dht::transport;


namespace {

void ConflictingOptions(const po::variables_map &variables_map,
                        const char *opt1,
                        const char *opt2) {
  if (variables_map.count(opt1) && !variables_map[opt1].defaulted()
      && variables_map.count(opt2) && !variables_map[opt2].defaulted()) {
    throw std::logic_error(std::string("Conflicting options '") + opt1 +
                           "' and '" + opt2 + "'.");
  }
}

// Function used to check that if 'for_what' is specified, then
// 'required_option' is specified too.
void OptionDependency(const po::variables_map &variables_map,
                      const char *for_what,
                      const char *required_option) {
  if (variables_map.count(for_what) && !variables_map[for_what].defaulted()) {
    if (variables_map.count(required_option) == 0 ||
        variables_map[required_option].defaulted()) {
      throw std::logic_error(std::string("Option '") + for_what
                             + "' requires option '" + required_option + "'.");
    }
  }
}

volatile bool ctrlc_pressed(false);

void CtrlCHandler(int /*a*/) {
  ctrlc_pressed = true;
}

mk::Contact ComposeContact(const mk::NodeId &node_id,
                           const mt::Endpoint &endpoint) {
  std::vector<mt::Endpoint> local_endpoints;
  local_endpoints.push_back(endpoint);
  mk::Contact contact(node_id, endpoint, local_endpoints, endpoint, false,
                      false, "", "", "");
  return contact;
}

mk::Contact ComposeContactWithKey(
    const mk::NodeId &node_id,
    const mt::Endpoint &endpoint,
    const maidsafe::crypto::RsaKeyPair &crypto_key) {
  std::vector<mt::Endpoint> local_endpoints;
  local_endpoints.push_back(endpoint);
  mk::Contact contact(node_id, endpoint, local_endpoints, endpoint, false,
                      false, node_id.String(), crypto_key.public_key(), "");
  return contact;
}

}  // unnamed namespace


int main(int argc, char **argv) {
  google::InitGoogleLogging(argv[0]);
  try {
    std::string logfile, kadconfigpath, bootstrap_ip, bootstrap_id;
    uint16_t bootstrap_port(0), listening_port(0), k(4), alpha(3), beta(2);
    int type(0);
    uint32_t refresh_interval(3600);
    size_t thread_count(3);

    po::options_description options_description("Options");
    options_description.add_options()
        ("help,h", "Print options information and exit.")
        ("version,V", "Print program version.")
        ("logfile,l", po::value(&logfile), "Path of log file.")
        ("verbose,v", po::bool_switch(), "Verbose logging to console and file.")
//        ("kadconfigfile,g",
//          po::value(&kadconfigpath)->default_value(kadconfigpath),
//          "Complete pathname of kadconfig file. Default is Node<port>/."
//          "kadconfig")
        ("client,c", po::bool_switch(), "Start the node as a client node.")
        ("first_node,f", po::bool_switch(), "First node of the network.")
        ("type,t", po::value(&type)->default_value(type),
            "Type of transport: 0 - TCP (default), 1 - UDP, 2 - Other.")
        ("port,p", po::value(&listening_port)->default_value(listening_port),
            "Local listening port of node.  Default is 0 == random port.")
        ("bootstrap_id", po::value(&bootstrap_id), "Bootstrap node ID.")
        ("bootstrap_ip", po::value(&bootstrap_ip), "Bootstrap node IP.")
        ("bootstrap_port", po::value(&bootstrap_port), "Bootstrap node port.")
        ("k", po::value(&k)->default_value(k),
            "Kademlia k, Number of contacts returned from a Find RPC")
        ("alpha,a", po::value(&alpha)->default_value(alpha),
            "Kademlia alpha, parallel level of Find RPCs")
        ("beta,b", po::value(&beta)->default_value(beta),
            "Kademlia beta, Number of returned Find RPCs required to start a "
            "subsequent iteration")
//        ("upnp", po::bool_switch(), "Use UPnP for Nat Traversal.")
//        ("port_fw", po::bool_switch(), "Manually port forwarded local port.")
        ("secure", po::bool_switch(),
            "Node with keys. Can only communicate with other secure nodes")
        ("thread_count", po::value(&thread_count)->default_value(thread_count),
            "Number of worker threads.")
        ("noconsole", po::bool_switch(),
            "Do not have access to Kademlia functions (store/findvalue/findnode"
             "findnode) after node startup.")
//        ("nodeinfopath", po::value(&thisnodekconfigpath),
//        "Writes to this path a kadconfig file (with name .kadconfig) with "
//          "this node's information.")
        ("refresh_interval,r", po::value(&refresh_interval),
            "Average interval time in minutes to refresh values.");

    po::variables_map variables_map;
    po::store(po::parse_command_line(argc, argv, options_description),
              variables_map);

    if (variables_map.count("help")) {
      std::cout << options_description << std::endl;
      return 0;
    }

    if (variables_map.count("version")) {
      std::cout << "MaidSafe-DHT "
                << maidsafe::GetMaidSafeVersion(MAIDSAFE_DHT_VERSION)
                << std::endl;
      return 0;
    }

    OptionDependency(variables_map, "bootstrap_id", "bootstrap_ip");
    OptionDependency(variables_map, "bootstrap_ip", "bootstrap_id");
    OptionDependency(variables_map, "bootstrap_id", "bootstrap_port");
    OptionDependency(variables_map, "bootstrap_port", "bootstrap_id");
//    ConflictingOptions(variables_map, "upnp", "port_fw");
    ConflictingOptions(variables_map, "client", "noconsole");
    ConflictingOptions(variables_map, "first_node", "bootstrap_id");
    ConflictingOptions(variables_map, "first_node", "bootstrap_ip");
    ConflictingOptions(variables_map, "first_node", "bootstrap_port");

    // Set up logging
    FLAGS_ms_logging_common = variables_map["verbose"].as<bool>();
    FLAGS_ms_logging_dht = variables_map["verbose"].as<bool>();
    FLAGS_log_prefix = variables_map["verbose"].as<bool>();
    FLAGS_ms_logging_user = true;
    FLAGS_minloglevel = google::INFO;
    FLAGS_logtostderr = true;
    if (variables_map.count("logfile")) {
      fs::path log_path;
      try {
        log_path = fs::path(variables_map["logfile"].as<std::string>());
        if (!fs::exists(log_path.parent_path()) &&
            !fs::create_directories(log_path.parent_path())) {
          ULOG(ERROR) << "Could not create directory for log file.";
          log_path = fs::temp_directory_path() / "kademlia_demo.log";
        }
      }
      catch(const std::exception &e) {
        ULOG(ERROR) << "Error creating directory for log file: " << e.what();
        boost::system::error_code error_code;
        log_path = fs::temp_directory_path(error_code) / "kademlia_demo.log";
      }

      ULOG(INFO) << "Log file at " << log_path << std::endl;
      for (google::LogSeverity severity(google::WARNING);
           severity != google::NUM_SEVERITIES; ++severity) {
        google::SetLogDestination(severity, "");
      }
      google::SetLogDestination(google::INFO, log_path.string().c_str());
      FLAGS_alsologtostderr = true;
    }

    // Set up DemoNode
    bool first_node(variables_map["first_node"].as<bool>());
    if (!first_node && !variables_map.count("bootstrap_id")) {
      ULOG(ERROR) << "No bootstrapping info.  Either run with -f if this is the"
                  << " first node, or add bootstrap information.  To see all "
                  << "available options, run with -h";
      return 1;
    }

    thread_count = variables_map["thread_count"].as<size_t>();
    if (thread_count > 100) {
      ULOG(WARNING) << "Too many threads.  Setting thread count to 3.";
      thread_count = 3;
    }

    bool client_only_node(variables_map["client"].as<bool>());

    type = (variables_map["type"].as<int>());
    if (type > 2) {
      ULOG(ERROR) << "Invalid transport type.  Choose 0, 1 or 2.";
      return 1;
    }

    listening_port = variables_map["port"].as<uint16_t>();
    mt::Endpoint endpoint("127.0.0.1", listening_port);

    if (variables_map.count("refresh_interval")) {
      refresh_interval = variables_map["refresh_interval"].as<uint32_t>();
      refresh_interval = refresh_interval * 60;
    } else {
      refresh_interval = 3600;
    }
    bptime::seconds mean_refresh_interval(refresh_interval);

    bool secure(variables_map["secure"].as<bool>());

    std::shared_ptr<mk::DemoNode> demo_node(new mk::DemoNode);
    int result = demo_node->Init(thread_count, client_only_node, type, endpoint,
                                 k, alpha, beta, mean_refresh_interval, secure);

    if (result != 0) {
      ULOG(ERROR) << "Node failed to start transport on port " << listening_port
                  << " with error code " << result;
      return 1;
    }

    // Joining the node to the network
    std::vector<maidsafe::dht::kademlia::Contact> bootstrap_contacts;
    int response;
    if (first_node) {
      mk::NodeId node_id(mk::NodeId::kRandomId);
      bootstrap_contacts.push_back(ComposeContact(node_id, endpoint));
      response = demo_node->JoinNode(node_id, bootstrap_contacts);
    } else {
      std::string bootstrap_id(variables_map["bootstrap_id"].as<std::string>());
      mk::NodeId node_id(mk::NodeId::kRandomId);
      mk::NodeId bootstrap_node_id(bootstrap_id);
      mt::Endpoint bootstrap_endpoint(
          variables_map["bootstrap_ip"].as<std::string>(),
          variables_map["bootstrap_port"].as<uint16_t>());
      bootstrap_contacts.push_back(ComposeContact(bootstrap_node_id,
                                                  bootstrap_endpoint));
      response = demo_node->JoinNode(node_id, bootstrap_contacts);
    }

    if (response != mt::kSuccess) {
      if ((response == 1) && !first_node) {
        ULOG(ERROR) << "Node failed to join the network with return code "
                    << response;
        demo_node->StopListeningTransport();
        return 1;
      }
    }

    PrintNodeInfo(demo_node->kademlia_node()->contact());

    if (!variables_map["noconsole"].as<bool>()) {
      mk::demo::Commands commands(demo_node);
      commands.Run();
    } else {
      ULOG(INFO) << "===============================";
      ULOG(INFO) << "     Press Ctrl+C to exit.";
      ULOG(INFO) << "===============================";
      signal(SIGINT, CtrlCHandler);
      while (!ctrlc_pressed)
        maidsafe::Sleep(boost::posix_time::seconds(1));
    }
    bootstrap_contacts.clear();
    demo_node->LeaveNode(&bootstrap_contacts);
    demo_node->StopListeningTransport();
    ULOG(INFO) << "Node stopped successfully.";
  }
  catch(const std::exception &e) {
    ULOG(ERROR) << "Error: " << e.what();
    return 1;
  }
  return 0;
}
