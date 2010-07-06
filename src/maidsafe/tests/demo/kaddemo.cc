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
#include <boost/program_options.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/thread.hpp>
#include <boost/lexical_cast.hpp>
#include <iostream>  //  NOLINT
#include "maidsafe/base/log.h"
#include "maidsafe/maidsafe-dht.h"
#include "maidsafe/tests/demo/commands.h"
#include "maidsafe/protobuf/contact_info.pb.h"
#include "maidsafe/protobuf/general_messages.pb.h"
#include "maidsafe/transport/transport-api.h"
#include "maidsafe/transport/transportudt.h"
#include "maidsafe/transport/transporthandler-api.h"

namespace po = boost::program_options;

namespace test_kaddemo {
  static const boost::uint16_t K = 16;
}  // namespace test_kaddemo

class JoinCallback {
 public:
  JoinCallback() : result_arrived_(false), success_(false) {}
  void Callback(const std::string &result) {
    base::GeneralResponse msg;
    if (!msg.ParseFromString(result))
      success_ = false;
    else if (msg.result() == kad::kRpcResultSuccess)
      success_ = true;
    else
      success_ = false;
    result_arrived_ = true;
  }
  bool result_arrived() const { return result_arrived_; }
  bool success() const { return success_; }
 private:
  bool result_arrived_, success_;
};

void conflicting_options(const po::variables_map& vm, const char* opt1,
    const char* opt2) {
  if (vm.count(opt1) && !vm[opt1].defaulted()
      && vm.count(opt2) && !vm[opt2].defaulted())
    throw std::logic_error(std::string("Conflicting options '")  + opt1 +
        "' and '" + opt2 + "'.");
}

// Function used to check that if 'for_what' is specified, then
// 'required_option' is specified too.
void option_dependency(const po::variables_map& vm,
    const char* for_what, const char* required_option) {
  if (vm.count(for_what) && !vm[for_what].defaulted())
    if (vm.count(required_option) == 0 || vm[required_option].defaulted())
      throw std::logic_error(std::string("Option '") + for_what
          + "' requires option '" + required_option + "'.");
}

bool kadconfig_empty(const std::string &path) {
  base::KadConfig kadconfig;
  try {
    boost::filesystem::ifstream input(path.c_str(),
                                      std::ios::in | std::ios::binary);
    if (!kadconfig.ParseFromIstream(&input)) {;
      return true;
    }
    input.close();
    if (kadconfig.contact_size() == 0)
      return true;
  }
  catch(const std::exception &) {
    return true;
  }
  return false;
}

bool write_to_kadconfig(const std::string &path, const std::string &node_id,
    const std::string &ip, const boost::uint16_t &port,
    const std::string &local_ip, const boost::uint16_t &local_port) {
  base::KadConfig kadconfig;
  try {
    base::KadConfig::Contact *ctc = kadconfig.add_contact();
    ctc->set_ip(ip);
    ctc->set_node_id(node_id);
    ctc->set_port(port);
    ctc->set_local_ip(local_ip);
    ctc->set_local_port(local_port);
    boost::filesystem::fstream output(path.c_str(), std::ios::out |
                                      std::ios::trunc | std::ios::binary);
    if (!kadconfig.SerializeToOstream(&output)) {
      output.close();
      return false;
    }
    output.close();
  }
    catch(const std::exception &) {
    return false;
  }
  return boost::filesystem::exists(path);
}

volatile int ctrlc_pressed = 0;

void ctrlc_handler(int b) {
  b = 1;
  ctrlc_pressed = b;
}

void printf_info(kad::ContactInfo info) {
  kad::Contact ctc(info);
  printf("Node info: %s", ctc.DebugString().c_str());
}

int main(int argc, char **argv) {
  try {
    std::string logpath, kadconfigpath, bs_ip, bs_id, ext_ip, configfile,
        bs_local_ip, thisnodekconfigpath, idpath;
    boost::uint16_t bs_port(0), bs_local_port(0), port(0), ext_port(0);
    boost::uint32_t refresh_time(0);
    bool first_node = false;
    po::options_description desc("Options");
    desc.add_options()
      ("help,h", "Print options information and exit.")
      ("logfilepath,l", po::value(&logpath), "Path of logfile")
      ("verbose,v", po::bool_switch(), "Print log to console.")
      ("kadconfigfile,k",
        po::value(&kadconfigpath)->default_value(kadconfigpath),
        "Complete pathname of kadconfig file. Default is KNode<port>/."
        "kadconfig")
      ("client,c", po::bool_switch(), "Start the node as a client node.")
      ("port,p", po::value(&port)->default_value(port),
        "Local port to start node.  Default is 0, that starts in random port.")
      ("bs_ip", po::value(&bs_ip), "Bootstrap node ip.")
      ("bs_port", po::value(&bs_port), "Bootstrap node port.")
      ("bs_local_ip", po::value(&bs_local_ip), "Bootstrap node local ip.")
      ("bs_local_port", po::value(&bs_local_port), "Bootstrap node local port.")
      ("bs_id", po::value(&bs_id), "Bootstrap node id.")
      ("upnp", po::bool_switch(), "Use UPnP for Nat Traversal.")
      ("port_fw", po::bool_switch(), "Manually port forwarded local port.")
      ("externalip", po::value(&ext_ip),
        "Node's external ip. "
        "Use only when it is the first node in the network.")
      ("externalport", po::value(&ext_port),
          "Node's external port. "
          "Use only when it is the first node in the network.")
      ("noconsole", po::bool_switch(),
        "Do not have access to Kademlia functions (store/load/ping) "
        "after node startup.")
      ("nodeinfopath", po::value(&thisnodekconfigpath),
        "Writes to this path a kadconfig file (with name .kadconfig) with this"
        " node's information.")
      ("append_id", po::value(&idpath),
        "Appends to the text file at this path the node's ID in a new line.")
      ("refresh_time,r", po::value(&refresh_time),
          "Time in minutes to refresh values and kbuckets.");
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    if (vm.count("help")) {
      std::cout << desc << "\n";
      return 0;
    }
    option_dependency(vm, "bs_id", "bs_ip");
    option_dependency(vm, "bs_ip", "bs_id");
    option_dependency(vm, "bs_id", "bs_port");
    option_dependency(vm, "bs_port", "bs_id");
    option_dependency(vm, "bs_id", "bs_local_ip");
    option_dependency(vm, "bs_id", "bs_local_port");
    option_dependency(vm, "bs_local_ip", "bs_id");
    option_dependency(vm, "bs_local_port", "bs_id");
    option_dependency(vm, "externalip", "externalport");
    option_dependency(vm, "externalport", "externalip");
    option_dependency(vm, "externalport", "port");
    conflicting_options(vm, "upnp", "port_fw");
    conflicting_options(vm, "client", "noconsole");
    conflicting_options(vm, "bs_id", "externalip");
    conflicting_options(vm, "verbose", "logfilepath");

    if (vm.count("externalip"))
      first_node = true;

    if (vm.count("refresh_time")) {
      refresh_time = vm["refresh_time"].as<boost::uint32_t>();
      refresh_time = refresh_time * 60;
    } else {
      refresh_time = kad::kRefreshTime;
    }

    // checking if path of kadconfigfile exists
    if (vm.count("kadconfigfile")) {
      kadconfigpath = vm["kadconfigfile"].as<std::string>();
      boost::filesystem::path kadconfig(kadconfigpath);
      if (!boost::filesystem::exists(kadconfig.parent_path())) {
        try {
          boost::filesystem::create_directories(kadconfig.parent_path());
          if (!first_node)
            if (!vm.count("bs_id")) {
              printf("No bootstrapping info.\n");
              return 1;
            }
        }
        catch(const std::exception &) {
          if (!first_node)
            if (!vm.count("bs_id")) {
              printf("No bootstrapping info.\n");
              return 1;
            }
        }
      } else {
        if (kadconfig_empty(kadconfigpath) && !vm.count("bs_id")) {
          printf("No bootstrapping info.\n");
          return 1;
        }
      }
    } else {
      if (!first_node)
        if (!vm.count("bs_id")) {
          printf("No bootstrapping info.\n");
          return 1;
        }
    }

    // setting log
#ifndef HAVE_GLOG
    bool FLAGS_logtostderr;
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

    // Starting transport on port
    port = vm["port"].as<boost::uint16_t>();
    transport::TransportHandler trans_handler;
    boost::int16_t transport_id;
    trans_handler.Register(new transport::TransportUDT, &transport_id);
    rpcprotocol::ChannelManager chmanager(&trans_handler);
    kad::NodeType type;
    if (vm["client"].as<bool>())
      type = kad::CLIENT;
    else
      type = kad::VAULT;
    kad::KNode node(&chmanager, &trans_handler, type, test_kaddemo::K,
                    kad::kAlpha, kad::kBeta, refresh_time, "", "",
                    vm["port_fw"].as<bool>(), vm["upnp"].as<bool>());
    node.set_transport_id(transport_id);
    if (!chmanager.RegisterNotifiersToTransport() ||
        !trans_handler.RegisterOnServerDown(boost::bind(
        &kad::KNode::HandleDeadRendezvousServer, &node, _1))) {
      return 1;
    }
    if (0 != trans_handler.Start(port, transport_id) || 0!= chmanager.Start()) {
      printf("Unable to start node on port %d\n", port);
      return 1;
    }
    // setting kadconfig file if it was not in the options
    if (kadconfigpath.empty()) {
      kadconfigpath = "KnodeInfo" + boost::lexical_cast<std::string>(
         trans_handler.listening_port(transport_id));
      boost::filesystem::create_directories(kadconfigpath);
      kadconfigpath += "/.kadconfig";
    }

    // if not the first vault, write to kadconfig file bootstrapping info
    // if provided in options
    if (!first_node && vm.count("bs_id")) {
      if (!write_to_kadconfig(kadconfigpath, vm["bs_id"].as<std::string>(),
          vm["bs_ip"].as<std::string>(), vm["bs_port"].as<boost::uint16_t>(),
          vm["bs_local_ip"].as<std::string>(),
          vm["bs_local_port"].as<boost::uint16_t>())) {
        printf("Unable to write kadconfig file to %s\n", kadconfigpath.c_str());
        trans_handler.Stop(transport_id);
        chmanager.Stop();
        return 1;
      }
    }

    // Joining the node to the network
    JoinCallback callback;
    if (first_node)
      node.Join(kadconfigpath, vm["externalip"].as<std::string>(),
          vm["externalport"].as<boost::uint16_t>(), boost::bind(
          &JoinCallback::Callback, &callback, _1));
    else
      node.Join(kadconfigpath, boost::bind(&JoinCallback::Callback, &callback,
                _1));
    while (!callback.result_arrived())
      boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    // Checking result of callback
    if (!callback.success()) {
      printf("Node failed to join the network.\n");
      trans_handler.Stop(transport_id);
      chmanager.Stop();
      return 1;
    }
    // Printing Node Info
    printf_info(node.contact_info());

    // append ID to text file
    if (vm.count("append_id")) {
      try {
        boost::filesystem::ofstream of(vm["append_id"].as<std::string>(),
                                       std::ios::out | std::ios::app);
        of << node.node_id().ToStringEncoded(kad::KadId::kHex) << "\n";
        of.close();
      }
      catch(const std::exception &) {
      }
    }

    // Creating a kadconfig file with this node's info
    if (vm.count("nodeinfopath")) {
      std::string thiskconfig = vm["nodeinfopath"].as<std::string>();
      boost::filesystem::path thisconfig(thiskconfig);
      if (!boost::filesystem::exists(thisconfig)) {
        try {
          boost::filesystem::create_directories(thisconfig);
          thisconfig /= ".kadconfig";
          write_to_kadconfig(thisconfig.string(),
              node.node_id().ToStringEncoded(kad::KadId::kHex), node.host_ip(),
              node.host_port(), node.local_host_ip(), node.local_host_port());
        }
        catch(const std::exception &e) {
        }
      } else {
        thisconfig /= ".kadconfig";
        write_to_kadconfig(thisconfig.string(),
            node.node_id().ToStringEncoded(kad::KadId::kHex), node.host_ip(),
            node.host_port(), node.local_host_ip(), node.local_host_port());
      }
    }

    if (!vm["noconsole"].as<bool>()) {
      kaddemo::Commands cmds(&node, &chmanager, test_kaddemo::K);
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
    trans_handler.StopPingRendezvous();
    node.Leave();
    trans_handler.Stop(transport_id);
    chmanager.Stop();
    printf("\nNode stopped successfully.\n");
  }
  catch(const std::exception &e) {
    printf("Error: %s\n", e.what());
    return 1;
  }

  return 0;
}

