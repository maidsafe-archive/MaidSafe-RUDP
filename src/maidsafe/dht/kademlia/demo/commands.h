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

#ifndef MAIDSAFE_DHT_KADEMLIA_DEMO_COMMANDS_H_
#define MAIDSAFE_DHT_KADEMLIA_DEMO_COMMANDS_H_

#include <memory>
#include <string>
#include <vector>

#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/dht/kademlia/config.h"
#include "maidsafe/dht/kademlia/node-api.h"
#include "maidsafe/dht/kademlia/node_container.h"

namespace bptime = boost::posix_time;

namespace maidsafe {
namespace dht {
namespace kademlia {

class NodeId;


namespace demo {

void PrintNodeInfo(const Contact &contact);

typedef NodeContainer<Node> DemoNode;
typedef std::shared_ptr<NodeContainer<Node>> DemoNodePtr;

class Commands {
 public:
  explicit Commands(DemoNodePtr demo_node);
  void Run();
 private:
  typedef std::vector<std::string> Arguments;
  void Store(const Arguments &args, bool read_from_file);
  void StoreCallback(const int &result,
                     const NodeId &key,
                     const bptime::time_duration &ttl);
  void FindValue(const Arguments &args, bool write_to_file);
  void FindValueCallback(FindValueReturns find_value_returns, std::string path);
  void GetContact(const Arguments &args);
  void GetContactsCallback(const int &result, Contact contact);
  void FindNodes(const Arguments &args, bool write_to_file);
  void FindNodesCallback(const int &result,
                         std::vector<Contact> contacts,
                         std::string path);
  void Store50Values(const Arguments &args);
  void Store50Callback(const int &result,
                       const std::string &key,
                       uint16_t *returned_count);
  void PrintUsage();
  void ProcessCommand(const std::string &cmdline);
  void PrintRpcTimings();
  void MarkResultArrived();
  bool ResultArrived() { return result_arrived_; }
  std::shared_ptr<DemoNode> demo_node_;
  SecurifierPtr null_securifier_;
  bool result_arrived_, finish_;
  boost::mutex wait_mutex_;
  boost::condition_variable wait_cond_var_;
  std::function<void()> mark_results_arrived_;
};

}  // namespace demo

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_DEMO_COMMANDS_H_
