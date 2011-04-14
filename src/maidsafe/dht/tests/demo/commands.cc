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

#include "maidsafe/dht/tests/demo/commands.h"

#include <cassert>
#include <iomanip>
#include <iostream>  // NOLINT
#include <string>
#include <vector>

#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "boost/format.hpp"
#include "boost/filesystem.hpp"
#include "boost/filesystem/fstream.hpp"
#include "boost/thread.hpp"
#include "boost/tokenizer.hpp"
#include "boost/lexical_cast.hpp"

#include "maidsafe/dht/kademlia/config.h"
#include "maidsafe/dht/kademlia/contact.h"
#include "maidsafe/dht/kademlia/node_id.h"
#include "maidsafe/dht/kademlia/node-api.h"

namespace arg = std::placeholders;

namespace maidsafe {

namespace dht {

namespace kademlia {

namespace kaddemo {

Commands::Commands(std::shared_ptr<Node> node,
                   std::shared_ptr<Securifier> securifier,
                   const boost::uint16_t &K)
    : node_(node), securifier_(securifier), result_arrived_(false),
      finish_(false),
      min_succ_stores_(K * kMinSuccessfulPecentageStore) {}

void Commands::Run() {
  PrintUsage();
  bool wait = false;
  boost::mutex wait_mutex;
  while (!finish_) {
    std::cout << "demo > ";
    std::string cmdline;
    std::getline(std::cin, cmdline);
    ProcessCommand(cmdline, &wait);
    if (wait) {
      while (!result_arrived_)
        boost::this_thread::sleep(boost::posix_time::milliseconds(500));
      result_arrived_ = false;
    }
  }
}

void Commands::print_node_info(const Contact &contact) {
  std::cout <<
      boost::format("Node id: [ %1% ] Node ip: [%2%] Node port: [%3%]\n")
        % contact.node_id().ToStringEncoded(NodeId::kHex)
        % contact.endpoint().ip.to_string()
        % contact.endpoint().port;
}
void Commands::Store(const std::vector<std::string> &args, bool *wait_for_cb,
                     bool read_from_file) {
    std::string value;
    if (read_from_file) {
      if (args.size() != 3) {
        *wait_for_cb = false;
        std::cout << "Invalid number of arguments for storefile command"
                  << std::endl;
        return;
      }
      if (!ReadFile(args[1], &value)) {
        *wait_for_cb = false;
        std::cout<< "File read error for storefile command" << std::endl;
        return;
      }
    } else {
      value = args[1];
    }
    bptime::time_duration ttl;
    if (args[2] == "-1")
      ttl = bptime::pos_infin;
    else
      ttl = bptime::minutes(boost::lexical_cast<boost::int32_t>(args[2]));
    kademlia::Key key(std::string(args.at(0)), NodeId::kHex);
    if (!key.IsValid()) {
      key = kademlia::NodeId(crypto::Hash<crypto::SHA512>(args.at(0)));
    }
    std::string signature;
    StoreFunctor callback = std::bind(&Commands::StoreCallback, this, arg::_1,
                                      key, ttl);
    node_->Store(key, value, signature, ttl, securifier_, callback);
    *wait_for_cb = true;
  }

void Commands::StoreCallback(const int& result, const NodeId& key,
                             const bptime::time_duration &ttl) {
  if (result != transport::kSuccess) {
    std::cout << "Store operation Failed with return code : " << result
              << std::endl;
    result_arrived_ = true;
    return;
  }
  std::cout <<
    boost::format("Successfully stored key [ %1% ] with ttl [%2%] min")
      % key.ToStringEncoded(NodeId::kHex) % ttl.minutes();
  std::cout << std::endl;
  result_arrived_ = true;
}

void Commands::FindValue(const std::vector<std::string> &args,
                         bool *wait_for_cb, bool write_to_file) {
  std::string path;
  if (write_to_file) {
    if (args.size() != 2) {
      *wait_for_cb = false;
      std::cout << "Invalid number of arguments for findfile command"
                << std::endl;
      return;
    }
    path = args[1];
  } else {
    if (args.size() != 1) {
      *wait_for_cb = false;
      std::cout << "Invalid number of arguments for findvalue command"
                << std::endl;
      return;
    }
  }
  Key key(std::string(args.at(0)), NodeId::kHex);
  if (!key.IsValid()) {
    key = kademlia::NodeId(crypto::Hash<crypto::SHA512>(args.at(0)));
  }
  FindValueFunctor callback(std::bind(&Commands::FindValueCallback, this,
                                      arg::_1, arg::_2, arg::_3, arg::_4,
                                      arg::_5, path));
  node_->FindValue(key, securifier_, callback);
  *wait_for_cb = true;
}

void Commands::FindValueCallback(int result, std::vector<std::string> values,
                                 std::vector<Contact> closest_contacts,
                                 Contact alternative_value_holder,
                                 Contact contact_to_cache,
                                 std::string path) {
  if (result != transport::kSuccess) {
    std::cout << "FindValue operation Failed with return code : " << result
              << std::endl;
    result_arrived_ = true;
    return;
  }
  std::cout <<
    boost::format("FindValue returns : %1% value(s), %2% closest contacts")
        %values.size() % closest_contacts.size();
  std::cout <<std::endl;
  std::cout <<
    boost::format("Node holding value in its alternative_store: [ %1% ]")
      % alternative_value_holder.node_id().ToStringEncoded(NodeId::kHex);
  std::cout <<std::endl;
  std::cout <<
    boost::format("Node needing a cache copy of the values: [ %1% ]")
      % contact_to_cache.node_id().ToStringEncoded(NodeId::kHex);
  std::cout <<std::endl;
  if (values.size() != 0 && !path.empty()) {
    // Writing only first value
    WriteToFile(path, values.at(0));
  }
  result_arrived_ = true;
}

void Commands::GetContact(const std::vector<std::string> &args,
                          bool *wait_for_cb) {
  if (args.size() != 1) {
    *wait_for_cb = false;
    std::cout << "Invalid number of arguments for getcontact command"
              << std::endl;
    return;
  }

  kademlia::NodeId node_id(std::string(args.at(0)), NodeId::kHex);
  if (!node_id.IsValid()) {
    std::cout << "Invalid Node id" << std::endl;
    *wait_for_cb = false;
    return;
  }
  GetContactFunctor callback = std::bind(&Commands::GetContactsCallback, this,
                                         arg::_1, arg::_2);
  node_->GetContact(node_id, callback);
  *wait_for_cb = true;
}

void Commands::GetContactsCallback(const int &result, Contact contact) {
  if (result != transport::kSuccess) {
    std::cout << "GetContacts operation Failed with error code:" << result
              << std::endl;
    result_arrived_ = true;
    return;
  }
  std::cout << "GetContacts operation successfully returned:" << std::endl;
  print_node_info(contact);
  result_arrived_ = true;
}

void Commands::FindNodes(const std::vector<std::string> &args,
                         bool *wait_for_cb, bool write_to_file) {
  std::string path;
  if (write_to_file) {
    if (args.size() != 2) {
      *wait_for_cb = false;
      std::cout << "Invalid number of arguments for findnodesfile command"
                << std::endl;
      return;
    }
    path = args[1];
  } else {
    if (args.size() != 1) {
      *wait_for_cb = false;
      printf("Invalid number of arguments for findnodes command\n");
      return;
    }
  }
  kademlia::NodeId key(std::string(args.at(0)), NodeId::kHex);
  if (!key.IsValid()) {
    std::cout << "Invalid Node id" << std::endl;
    *wait_for_cb = false;
    return;
  }
  FindNodesFunctor callback = std::bind(&Commands::FindNodesCallback, this,
                                        arg::_1, arg::_2, path);
  node_->FindNodes(key, callback);
  *wait_for_cb = true;
}

void Commands::FindNodesCallback(const int &result,
                                 std::vector<Contact> contacts,
                                 std::string path) {
  if (result != transport::kSuccess) {
    std::cout << "FindNodes operation Failed with error code:" << result
              << std::endl;
    result_arrived_ = true;
    return;
  }
  if (path.empty()) {
    std::cout << "FindNode returns below contacts" << std::endl;
    for (auto it = contacts.begin(); it != contacts.end(); ++it) {
      std::cout << (*it).node_id().ToStringEncoded(NodeId::kHex)
                << std::endl;
    }
    std::cout << "FindNode returned : " << contacts.size() << " Contact(s)"
              << std::endl;
  } else {
    std::string content;
      for (auto it = contacts.begin(); it != contacts.end(); ++it) {
        content += (*it).node_id().ToStringEncoded(NodeId::kHex);
        content += "\n";
      }
      WriteToFile(path, content);
    }
  result_arrived_ = true;
}

void Commands::Store50Values(const std::vector<std::string> &args,
                             bool *wait_for_cb) {
  if (args.size() != 1) {
    *wait_for_cb = false;
    printf("Invalid number of arguments for store50values command\n");
    return;
  }
  const std::string prefix= args[0];
  *wait_for_cb = true;
  bool arrived;
  std::string value;
  for (boost::uint16_t i = 0; i < 50; ++i) {
    arrived = false;
    kademlia::NodeId key(crypto::Hash<crypto::SHA512>(prefix +
                         boost::lexical_cast<std::string>(i)));
    value.clear();
    for (int j = 0; j < 1024 * 100; ++j) {
      value += prefix + boost::lexical_cast<std::string>(i);
    }
    std::string key_str = key.ToStringEncoded(NodeId::kHex);
    bptime::time_duration ttl(boost::posix_time::pos_infin);
    StoreFunctor callback = std::bind(&Commands::Store50Callback, this, arg::_1,
                                      key_str, &arrived);
    std::string signature;
    node_->Store(key, value, signature, ttl, securifier_, callback);
    while (!arrived) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    }
  }
  result_arrived_ = true;
}

void Commands::Store50Callback(const int& result, const std::string &key,
                               bool *arrived) {
  if (result != transport::kSuccess) {
    boost::format("ERROR. Invalid response. Kademlia Store Value key:[ %1% ]")
        % key;
    std::cout << std::endl;
    result_arrived_ = true;
    return;
  }
  std::cout << boost::format("Successfully stored key [ %1% ]") % key;
  std::cout << std::endl;
  *arrived = true;
}

bool Commands::ReadFile(const std::string &path, std::string *content) {
  content->empty();
  if (!boost::filesystem::exists(path) ||
      boost::filesystem::is_directory(path)) {
    printf("%s does not exist or is a directory\n", path.c_str());
    return false;
  }
  try {
    boost::filesystem::ifstream fin;
    boost::uint64_t size = boost::filesystem::file_size(path);
    if (size == 0) {
      printf("File %s is empty\n", path.c_str());
    }
    fin.open(path, std::ios_base::in | std::ios::binary);
    if (fin.eof() || !fin.is_open()) {
      printf("Can not open file %s\n", path.c_str());
      return false;
    }
    char *temp = new char[size_t(size)];
    fin.read(temp, size);
    fin.close();
    *content = std::string(temp, size_t(size));
    delete [] temp;
  }
  catch(const std::exception &ex) {
    printf("Error reading from file %s: %s\n", path.c_str(), ex.what());
    return false;
  }
  return true;
}

void Commands::WriteToFile(const std::string &path,
                           const std::string &content) {
  try {
    boost::filesystem::ofstream fout;
    fout.open(path, std::ios_base::out | std::ios::binary);
    fout.write(content.c_str(), content.size());
    fout.close();
  }
  catch(const std::exception &ex) {
    printf("Error writing to file %s: %s\n", path.c_str(), ex.what());
  }
}

void Commands::PrintUsage() {
  printf("\thelp                        Print help.\n");
  printf("\tgetinfo                     Print this node's info.\n");
  printf("\tgetcontact node_id          Get contact details of node_id.\n");
  printf("\tstorefile key filepath ttl  Store contents of file in the network");
  printf(". ttl in minutes (-1 for infinite).\n");
  printf("\tstorevalue key value ttl    Store value in the network");
  printf(". ttl in minutes (-1 for infinite).\n");
  printf("\tfindfile key filepath       Find value stored with key and save ");
  printf("it to filepath.\n");
  printf("\tfindvalue key               Find value stored with key.\n");
  printf("\tfindnodes key               Find k closest nodes to key .\n");
  printf("\tfindnodesfile key filepath  Find k closest nodes to key & save.\n");
  printf("\tstore50values prefix        Store 50 key value pairs of for ");
  printf("(prefix[i],prefix[i]*100.\n");
//  printf("\ttimings                     Print statistics for RPC timings.\n");
  printf("\texit                        Stop the node and exit.\n");
  printf("\n\tNOTE -- node_id should be input encoded.\n");
  printf("\t          If key is not a valid 512 hash key (encoded format),\n");
  printf("\t          it will be hashed.\n\n");
}

void Commands::ProcessCommand(const std::string &cmdline, bool *wait_for_cb) {
  std::string cmd;
  std::vector<std::string> args;
  try {
    boost::char_separator<char> sep(" ");
    boost::tokenizer< boost::char_separator<char> > tok(cmdline, sep);
    for (boost::tokenizer< boost::char_separator<char> >::iterator
         it = tok.begin(); it != tok.end(); ++it) {
      if (it == tok.begin())
        cmd = *it;
      else
        args.push_back(*it);
    }
  }
  catch(const std::exception &ex) {
    printf("Error processing command: %s\n", ex.what());
    *wait_for_cb = false;
    return;
  }
  if (cmd == "help") {
    PrintUsage();
    *wait_for_cb = false;
  } else if (cmd == "getinfo") {
    print_node_info(node_->contact());
    *wait_for_cb = false;
  } else if (cmd == "getcontact") {
    GetContact(args, wait_for_cb);
  } else if (cmd == "storefile") {
    Store(args, wait_for_cb, true);
  } else if (cmd == "storevalue") {
    Store(args, wait_for_cb, false);
  } else if (cmd == "findvalue") {
    FindValue(args, wait_for_cb, false);
  } else if (cmd == "findfile") {
    FindValue(args, wait_for_cb, true);
  } else if (cmd == "findnodes") {
    FindNodes(args, wait_for_cb, false);
  } else if (cmd == "findnodesfile") {
    FindNodes(args, wait_for_cb, true);
  } else if (cmd == "store50values") {
    Store50Values(args, wait_for_cb);
  } else if (cmd == "exit") {
    printf("Exiting application...\n");
    finish_ = true;
    *wait_for_cb = false;
  } else {
    printf("Invalid command %s\n", cmd.c_str());
    *wait_for_cb = false;
  }
}



void Commands::PrintRpcTimings() {
//  rpcprotocol::RpcStatsMap rpc_timings(chmanager_->RpcTimings());
//  std::cout << boost::format("Calls  RPC Name  %40t% min/avg/max\n");
//  for (rpcprotocol::RpcStatsMap::const_iterator it = rpc_timings.begin();
//       it != rpc_timings.end();
//       ++it) {
//  std::cout << boost::format("%1% : %2% %40t% %3% / %4% / %5% \n")
//           % it->second.Size()
//           % it->first.c_str()
//           % it->second.Min()  // / 1000.0
//           % it->second.Mean()  // / 1000.0
//           % it->second.Max();  // / 1000.0;
//  }
}

}  // namespace kaddemo

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe
