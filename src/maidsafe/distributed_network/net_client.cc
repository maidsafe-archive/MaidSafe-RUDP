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
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <signal.h>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include "maidsafe/base/log.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/distributed_network/mysqlppwrap.h"
#include "maidsafe/maidsafe-dht.h"
#include "maidsafe/protobuf/general_messages.pb.h"

namespace fs = boost::filesystem;

namespace net_client {

static const boost::uint16_t K = 4;

void RunSmallTest() {
  MySqlppWrap msw;
  msw.Init("kademlia_network_test", "127.0.0.1", "root", "m41ds4f3",
           "kademliavalues");

  int n = msw.Delete("", "");
  printf("Deleted %d previous entries.\n", n);

  std::vector<std::string> values;
  n = msw.Get("", &values);
  if (n != 0 || !values.empty()) {
    printf("Failed in Get #1: %d\n", n);
    return;
  }

  std::string k("key1");
  for (int a = 0; a < 10; ++a) {
    std::string v("value_" + base::IntToString(a));
    n = msw.Insert(k, v);
    if (n != 0) {
      printf("Failed inserting #1 value %d\n", a);
      return;
    }
  }

  n = msw.Get("", &values);
  if (n != 0 || values.size() != size_t(10)) {
    printf("Failed in Get #2\n");
    return;
  }

  n = msw.Get("key1", &values);
  if (n != 0 || values.size() != size_t(10)) {
    printf("Failed in Get #3\n");
    return;
  }

  k = "key2";
  for (int a = 0; a < 5; ++a) {
    std::string v("value_" + base::IntToString(a));
    n = msw.Insert(k, v);
    if (n != 0) {
      printf("Failed inserting #2 value %d\n", a);
      return;
    }
  }

  n = msw.Get("", &values);
  if (n != 0 || values.size() != size_t(15)) {
    printf("Failed in Get #4\n");
    return;
  }

  n = msw.Get("key2", &values);
  if (n != 0 || values.size() != size_t(5)) {
    printf("Failed in Get #5\n");
    return;
  }

  n = msw.Delete("key1", "");
  if (n != 10) {
    printf("Failed in Delete #2\n");
    return;
  }

  n = msw.Get("", &values);
  if (n != 0 || values.size() != size_t(5)) {
    printf("Failed in Get #4\n");
    return;
  }

  n = msw.Get("key2", &values);
  if (n != 0 || values.size() != size_t(5)) {
    printf("Failed in Get #5\n");
    return;
  }

  n = msw.Update("key2", "value_0", "value_5");
  if (n != 0) {
    printf("Failed in Update #1\n");
    return;
  }

  n = msw.Get("key2", &values);
  if (n != 0 || values.size() != size_t(5)) {
    printf("Failed in Get #5\n");
    return;
  }

  std::set<std::string> s(values.begin(), values.end());
  values = std::vector<std::string>(s.begin(), s.end());
  for (size_t y = 0; y < values.size(); ++y) {
    if (values[y] != std::string("value_" + base::IntToString(y+1))) {
      printf("Checking update #1 at value %d\n", y);
      return;
    }
  }

  n = msw.Delete("key2", "value_1");
  if (n != 1) {
    printf("Failed in Delete #3\n");
    return;
  }

  n = msw.Get("key2", &values);
  if (n != 0 || values.size() != size_t(4)) {
    printf("Failed in Get #6\n");
    return;
  }

  s = std::set<std::string>(values.begin(), values.end());
  values = std::vector<std::string>(s.begin(), s.end());
  for (size_t y = 0; y < values.size(); ++y) {
    if (values[y] != std::string("value_" + base::IntToString(y+2))) {
      printf("Checking delete #3 at value %d\n", y);
      return;
    }
  }
}

}  // namespace net_client

class JoinCallback {
 public:
  JoinCallback() : mutex_(),
                   cond_var_(),
                   result_arrived_(false),
                   success_(false) {}
  void AssessResult(const std::string &result) {
    base::GeneralResponse message;
    boost::mutex::scoped_lock lock(mutex_);
    success_ = true;
    if (!message.ParseFromString(result)) {
      DLOG(ERROR) << "Can't parse join response." << std::endl;
      success_ = false;
    }
    if (success_ && !message.IsInitialized()) {
      DLOG(ERROR) << "Join response isn't initialised." << std::endl;
      success_ = false;
    }
    if (success_ && message.result() != kad::kRpcResultSuccess) {
      DLOG(ERROR) << "Join failed." << std::endl;
      success_ = false;
    }
    result_arrived_ = true;
    cond_var_.notify_one();
  }
  bool result_arrived() const { return result_arrived_; }
  bool JoinedNetwork() {
    boost::mutex::scoped_lock lock(mutex_);
    try {
      bool wait_success = cond_var_.timed_wait(lock,
          boost::posix_time::milliseconds(30000),
          boost::bind(&JoinCallback::result_arrived, this));
      if (!wait_success) {
        DLOG(ERROR) << "Failed to wait for join callback." << std::endl;
        return false;
      }
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "Error waiting to join: " << e.what() << std::endl;
      return false;
    }
    return success_;
  }
 private:
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  bool result_arrived_, success_;
};

bool KadConfigOK() {
  base::KadConfig kadconfig;
  fs::path kadconfig_path("/.kadconfig");
  try {
    fs::ifstream input(kadconfig_path.string().c_str(),
                       std::ios::in | std::ios::binary);
    if (!kadconfig.ParseFromIstream(&input)) {
      return false;
    }
    input.close();
    if (kadconfig.contact_size() == 0)
      return false;
  }
  catch(const std::exception &) {
    return false;
  }
  return true;
}

volatile int ctrlc_pressed = 0;

void CtrlcHandler(int b) {
  b = 1;
  ctrlc_pressed = b;
}

int main(int argc, char **argv) {
  google::InitGoogleLogging(argv[0]);
#ifndef HAVE_GLOG
  bool FLAGS_logtostderr;
#endif
  FLAGS_logtostderr = true;

  if (!KadConfigOK()) {
    DLOG(ERROR) << "Can't find .kadconfig" << std::endl;
    return 1;
  }

  // Create required objects
  transport::TransportHandler transport_handler;
  transport::TransportUDT transport_udt;
  boost::int16_t transport_id;
  transport_handler.Register(&transport_udt, &transport_id);
  rpcprotocol::ChannelManager channel_manager(&transport_handler);
  crypto::RsaKeyPair rsa_key_pair;
  rsa_key_pair.GenerateKeys(4096);
  kad::KNode node(&channel_manager, &transport_handler, kad::CLIENT,
                  rsa_key_pair.private_key(), rsa_key_pair.public_key(),
                  false, false, net_client::K);
  node.set_transport_id(transport_id);
  if (!channel_manager.RegisterNotifiersToTransport() ||
      !transport_handler.RegisterOnServerDown(boost::bind(
      &kad::KNode::HandleDeadRendezvousServer, &node, _1))) {
    return 2;
  }
  if (0 != transport_handler.Start(0, transport_id) ||
      0 != channel_manager.Start()) {
    return 3;
  }

  // Join the test network
  JoinCallback callback;
  node.Join("/.kadconfig",
            boost::bind(&JoinCallback::AssessResult, &callback, _1));
  if (!callback.JoinedNetwork()) {
    transport_handler.Stop(transport_id);
    channel_manager.Stop();
    return 4;
  }
  printf("Node info: %s", node.contact_info().DebugString().c_str());
  printf("=====================================\n");
  printf("Press Ctrl+C to exit\n");
  printf("=====================================\n\n");
  signal(SIGINT, CtrlcHandler);
  while (!ctrlc_pressed) {
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  }
  transport_handler.StopPingRendezvous();
  node.Leave();
  transport_handler.Stop(transport_id);
  channel_manager.Stop();
  return 0;
}

