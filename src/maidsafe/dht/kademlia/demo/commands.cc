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

#include "maidsafe/dht/kademlia/demo/commands.h"

#include <iostream>  // NOLINT

#include "boost/format.hpp"
#include "boost/filesystem.hpp"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127)
#endif
#include "boost/tokenizer.hpp"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "boost/lexical_cast.hpp"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/dht/log.h"
#include "maidsafe/dht/kademlia/contact.h"
#include "maidsafe/dht/kademlia/node_id.h"
#include "maidsafe/dht/kademlia/node-api.h"

namespace arg = std::placeholders;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace dht {

namespace kademlia {

namespace demo {

void PrintNodeInfo(const Contact &contact) {
  ULOG(INFO)
      << boost::format("Node ID:   %1%")
                       % contact.node_id().ToStringEncoded(NodeId::kBase64);
  ULOG(INFO)
      << boost::format("Node IP:   %1%") % contact.endpoint().ip.to_string();
  ULOG(INFO)
      << boost::format("Node port: %1%") % contact.endpoint().port;
}

Commands::Commands(DemoNodePtr demo_node) : demo_node_(demo_node),
                                            null_securifier_(),
                                            result_arrived_(false),
                                            finish_(false),
                                            wait_mutex_(),
                                            wait_cond_var_(),
                                            mark_results_arrived_() {
  mark_results_arrived_ = std::bind(&Commands::MarkResultArrived, this);
}

void Commands::Run() {
  PrintUsage();
  while (!finish_) {
    std::cout << "Enter command > ";
    std::string cmdline;
    std::getline(std::cin, cmdline);
    ULOG(INFO) << "Entered: " << cmdline;
    {
      boost::mutex::scoped_lock lock(wait_mutex_);
      ProcessCommand(cmdline);
      wait_cond_var_.wait(lock, std::bind(&Commands::ResultArrived, this));
      result_arrived_ = false;
    }
  }
}

void Commands::Store(const Arguments &args, bool read_from_file) {
  std::string value;
  if (read_from_file) {
    if (args.size() != 3U) {
      ULOG(ERROR) << "Invalid number of arguments for storefile command.";
      return demo_node_->asio_service().post(mark_results_arrived_);
    }
    if (!ReadFile(args[1], &value) || value.empty()) {
      ULOG(ERROR) << "File read error for storefile command.";
      return demo_node_->asio_service().post(mark_results_arrived_);
    }
  } else {
    value = args[1];
  }

  int32_t minutes_to_live(0);
  try {
    minutes_to_live = boost::lexical_cast<int32_t>(args[2]);
  }
  catch(const std::exception &e) {
    ULOG(ERROR) << "Invalid ttl for storefile command." << e.what();
    return demo_node_->asio_service().post(mark_results_arrived_);
  }

  bptime::time_duration ttl;
  if (minutes_to_live == -1)
    ttl = bptime::pos_infin;
  else
    ttl = bptime::minutes(minutes_to_live);

  Key key(args[0], NodeId::kBase64);
  if (!key.IsValid())
    key = Key(crypto::Hash<crypto::SHA512>(args[0]));

  demo_node_->node()->Store(key, value, "", ttl, null_securifier_,
      std::bind(&Commands::StoreCallback, this, arg::_1, key, ttl));
}

void Commands::StoreCallback(const int &result,
                             const NodeId &key,
                             const bptime::time_duration &ttl) {
  if (result != transport::kSuccess) {
    ULOG(ERROR) << "Store operation failed with return code: " << result;
  } else {
    ULOG(INFO) <<
        boost::format("Successfully stored key [ %1% ] with ttl [%2%] min.")
                      % key.ToStringEncoded(NodeId::kBase64) % ttl.minutes();
  }
  demo_node_->asio_service().post(mark_results_arrived_);
}

void Commands::FindValue(const Arguments &args, bool write_to_file) {
  std::string path;
  if (write_to_file) {
    if (args.size() != 2U) {
      ULOG(ERROR) << "Invalid number of arguments for findfile command.";
      return demo_node_->asio_service().post(mark_results_arrived_);
    }
    path = args[1];
  } else {
    if (args.size() != 1U) {
      ULOG(ERROR) << "Invalid number of arguments for findvalue command.";
      return demo_node_->asio_service().post(mark_results_arrived_);
    }
  }

  Key key(std::string(args.at(0)), NodeId::kBase64);
  if (!key.IsValid())
    key = Key(crypto::Hash<crypto::SHA512>(args[0]));

  demo_node_->node()->FindValue(key, null_securifier_,
      std::bind(&Commands::FindValueCallback, this, arg::_1, path));
}

void Commands::FindValueCallback(FindValueReturns find_value_returns,
                                 std::string path) {
  if (find_value_returns.return_code != transport::kSuccess) {
    ULOG(ERROR) << "FindValue operation failed with return code: "
                << find_value_returns.return_code;
  } else {
    ULOG(INFO)
        << boost::format("FindValue returned: %1% value(s), %2% closest "
                         "contact(s).") %
                         find_value_returns.values_and_signatures.size() %
                         find_value_returns.closest_nodes.size();
    ULOG(INFO)
        << boost::format("Node holding value in its alternative_store: [ %1% ]")
               % find_value_returns.alternative_store_holder.node_id().
               ToStringEncoded(NodeId::kBase64);
    ULOG(INFO)
        << boost::format("Node needing a cache copy of the values: [ %1% ]")
              % find_value_returns.needs_cache_copy.node_id().
              ToStringEncoded(NodeId::kBase64);
    // Writing only 1st value
    if (!find_value_returns.values_and_signatures.empty() && !path.empty())
      WriteFile(path, find_value_returns.values_and_signatures[0].first);
  }
  demo_node_->asio_service().post(mark_results_arrived_);
}

void Commands::GetContact(const Arguments &args) {
  if (args.size() != 1U) {
    ULOG(ERROR) << "Invalid number of arguments for getcontact command.";
    return demo_node_->asio_service().post(mark_results_arrived_);
  }

  kademlia::NodeId node_id(args[0], NodeId::kBase64);
  if (!node_id.IsValid()) {
    ULOG(ERROR) << "Invalid Node ID for getcontact command.";
    return demo_node_->asio_service().post(mark_results_arrived_);
  }

  demo_node_->node()->GetContact(node_id,
      std::bind(&Commands::GetContactsCallback, this, arg::_1, arg::_2));
}

void Commands::GetContactsCallback(const int &result, Contact contact) {
  if (result != transport::kSuccess) {
    ULOG(ERROR) << "GetContacts operation failed with error code: " << result;
  } else {
    ULOG(INFO) << "GetContacts operation successfully returned:";
    PrintNodeInfo(contact);
  }
  demo_node_->asio_service().post(mark_results_arrived_);
}

void Commands::FindNodes(const Arguments &args, bool write_to_file) {
  std::string path;
  if (write_to_file) {
    if (args.size() != 2U) {
      ULOG(ERROR) << "Invalid number of arguments for findnodesfile command.";
      return demo_node_->asio_service().post(mark_results_arrived_);
    }
    path = args[1];
  } else {
    if (args.size() != 1U) {
      ULOG(ERROR) << "Invalid number of arguments for findnodes command.";
      return demo_node_->asio_service().post(mark_results_arrived_);
    }
  }

  kademlia::NodeId node_id(args[0], NodeId::kBase64);
  if (!node_id.IsValid()) {
    ULOG(ERROR) << "Invalid Node ID.";
    return demo_node_->asio_service().post(mark_results_arrived_);
  }

  demo_node_->node()->FindNodes(node_id,
      std::bind(&Commands::FindNodesCallback, this, arg::_1, arg::_2, path));
}

void Commands::FindNodesCallback(const int &result,
                                 std::vector<Contact> contacts,
                                 std::string path) {
  if (result != transport::kSuccess) {
    ULOG(ERROR) << "FindNodes operation failed with error code: " << result;
  } else {
    if (path.empty()) {
      ULOG(INFO) << "FindNodes returned the following " << contacts.size()
                << " contact(s):";
      for (auto it = contacts.begin(); it != contacts.end(); ++it)
        ULOG(INFO) << (*it).node_id().ToStringEncoded(NodeId::kBase64);
    } else {
      std::string content;
      for (auto it = contacts.begin(); it != contacts.end(); ++it)
        content += ((*it).node_id().ToStringEncoded(NodeId::kBase64) + "\n");
      WriteFile(path, content);
    }
  }
  demo_node_->asio_service().post(mark_results_arrived_);
}

void Commands::Store50Values(const Arguments &args) {
  if (args.size() != 1U) {
    ULOG(ERROR) << "Invalid number of arguments for store50values command.";
    return demo_node_->asio_service().post(mark_results_arrived_);
  }

  const uint16_t kCount(50);
  const std::string kPrefix(args[0]);
  uint16_t returned_count(0);
  for (uint16_t i = 0; i != kCount; ++i) {
    Key key(crypto::Hash<crypto::SHA512>(kPrefix +
                                         boost::lexical_cast<std::string>(i)));
    std::string key_str = key.ToStringEncoded(NodeId::kBase64);

    std::string value;
    for (int j = 0; j != 102400; ++j)
      value += (kPrefix + boost::lexical_cast<std::string>(i));

    bptime::time_duration ttl(boost::posix_time::pos_infin);
    demo_node_->node()->Store(key, value, "", ttl, null_securifier_,
        std::bind(&Commands::Store50Callback, this, arg::_1, key_str,
                  &returned_count));
  }
  {
    boost::mutex::scoped_lock lock(wait_mutex_);
    while (returned_count != kCount) {
      wait_cond_var_.wait(lock);
    }
  }
  demo_node_->asio_service().post(mark_results_arrived_);
}

void Commands::Store50Callback(const int &result,
                               const std::string &key,
                               uint16_t *returned_count) {
  if (result != transport::kSuccess) {
    ULOG(ERROR) << boost::format("ERROR. Invalid response. Kademlia Store Value"
                                 " key:[ %1% ]") % key;
  } else {
    ULOG(INFO) << boost::format("Successfully stored key [ %1% ]") % key;
  }
  boost::mutex::scoped_lock lock(wait_mutex_);
  ++(*returned_count);
  wait_cond_var_.notify_one();
}

void Commands::PrintUsage() {
  ULOG(INFO) << "\thelp                              Print options.";
  ULOG(INFO) << "\tgetinfo                           Print this node's info.";
  ULOG(INFO) << "\tgetcontact <node_id>              Get contact details of "
             << "node_id.";
  ULOG(INFO) << "\tstorefile <key> <filepath> <ttl>  Store contents of file in "
             << "the network.  ttl in minutes (-1 for infinite).";
  ULOG(INFO) << "\tstorevalue <key> <value> <ttl>    Store value in the "
             << "network.  ttl in minutes (-1 for infinite).";
  ULOG(INFO) << "\tfindfile <key> <filepath>         Find value stored with "
             << "key and save it to filepath.";
  ULOG(INFO) << "\tfindvalue <key>                   Find value stored with "
             << "key.";
  ULOG(INFO) << "\tfindnodes <key>                   Find k closest nodes to "
             << "key.";
  ULOG(INFO) << "\tfindnodesfile <key> <filepath>    Find k closest nodes to "
             << "key and save their IDs to filepath.";
  ULOG(INFO) << "\tstore50values <prefix>            Store 50 key value pairs "
             << "of form (prefix[i], prefix[i]*100).";
//  ULOG(INFO) << "\ttimings                           Print statistics for RPC"
//             << " timings.";
  ULOG(INFO) << "\texit                              Stop the node and exit.";
  ULOG(INFO) << "\tNOTE -- node_id should be base64 encoded.";
  ULOG(INFO) << "\tNOTE -- If key is not a valid 512 hash key (base64 encoded "
             << "format), it will be hashed.";
}

void Commands::ProcessCommand(const std::string &cmdline) {
  std::string cmd;
  Arguments args;
  try {
    boost::char_separator<char> sep(" ");
    boost::tokenizer<boost::char_separator<char>> tok(cmdline, sep);
    for (auto it = tok.begin(); it != tok.end(); ++it) {
      if (it == tok.begin())
        cmd = *it;
      else
        args.push_back(*it);
    }
  }
  catch(const std::exception &e) {
    ULOG(ERROR) << "Error processing command: " << e.what();
    demo_node_->asio_service().post(mark_results_arrived_);
  }

  if (cmd == "help") {
    PrintUsage();
    demo_node_->asio_service().post(mark_results_arrived_);
  } else if (cmd == "getinfo") {
    PrintNodeInfo(demo_node_->node()->contact());
    demo_node_->asio_service().post(mark_results_arrived_);
  } else if (cmd == "getcontact") {
    GetContact(args);
  } else if (cmd == "storefile") {
    Store(args, true);
  } else if (cmd == "storevalue") {
    Store(args, false);
  } else if (cmd == "findvalue") {
    FindValue(args, false);
  } else if (cmd == "findfile") {
    FindValue(args, true);
  } else if (cmd == "findnodes") {
    FindNodes(args, false);
  } else if (cmd == "findnodesfile") {
    FindNodes(args, true);
  } else if (cmd == "store50values") {
    Store50Values(args);
  } else if (cmd == "exit") {
    ULOG(INFO) << "Exiting application...";
    finish_ = true;
    demo_node_->asio_service().post(mark_results_arrived_);
  } else {
    ULOG(ERROR) << "Invalid command: " << cmd;
    demo_node_->asio_service().post(mark_results_arrived_);
  }
}



void Commands::PrintRpcTimings() {
//  rpcprotocol::RpcStatsMap rpc_timings(chmanager_->RpcTimings());
//  ULOG(INFO) << boost::format("Calls  RPC Name  %40t% min/avg/max\n");
//  for (rpcprotocol::RpcStatsMap::const_iterator it = rpc_timings.begin();
//       it != rpc_timings.end();
//       ++it) {
//  ULOG(INFO) << boost::format("%1% : %2% %40t% %3% / %4% / %5% \n")
//           % it->second.Size()
//           % it->first.c_str()
//           % it->second.Min()  // / 1000.0
//           % it->second.Mean()  // / 1000.0
//           % it->second.Max();  // / 1000.0;
//  }
}

void Commands::MarkResultArrived() {
  boost::mutex::scoped_lock lock(wait_mutex_);
  result_arrived_ = true;
  wait_cond_var_.notify_one();
}


}  // namespace demo

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe
