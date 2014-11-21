/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#include <chrono>
#include <condition_variable>
#include <iostream>
#include <memory>
#include <mutex>
#include <vector>
#include <fstream>

#include "maidsafe/common/log.h"

#include "maidsafe/rudp/managed_connections.h"
#include "maidsafe/rudp/return_codes.h"
#include "maidsafe/rudp/tests/test_utils.h"

namespace {

bool ParseArgs(int argc, char** argv, int& message_count, int& message_size,
               double& packet_loss_constant, double& packet_loss_bursty, std::string& path) {
  auto fail([]()->bool {
    std::cout << "Pass no. of messages and size of messages (in bytes) as first 2 arguments.\n";
    std::cout << "Optionally pass in packet loss percentage as third argument and CSV append\n";
    std::cout << "file path as fourth argument.\n";
    return false;
  });

  if (argc < 3)
    return fail();

  try {
    message_count = std::stoi(argv[1]);
    message_size = std::stoi(argv[2]);
    if (message_count < 1 || message_size < 12) {
      std::cerr << "Message count must be >= 1 and size of messages must be >= 12.\n";
      return false;
    }
    if (message_size > maidsafe::rudp::managed_connections::max_message_size()) {
      std::cerr << "Maximum message size is "
                << maidsafe::rudp::managed_connections::max_message_size() << std::endl;
      return false;
    }
    if (argc > 3) {
      packet_loss_constant = std::stod(argv[3]);
      const char *slash = std::strchr(argv[3], '/');
      if (slash)
        packet_loss_bursty = std::stod(slash + 1);
      else
        packet_loss_constant = packet_loss_bursty = 100.0
          * (1 - sqrt(1 - (packet_loss_constant / 100.0)));
      packet_loss_constant /= 100.0;
      packet_loss_bursty /= 100.0;
    }
    if (argc > 4)
      path = argv[4];
  }
  catch (const std::exception&) {
    return fail();
  }

  return true;
}

}  // unnamed namespace

int main(int argc, char** argv) {
  auto message_count(0), message_size(0);
  double packet_loss_constant(0), packet_loss_bursty(0);
  std::string csv_file_path;
  if (!ParseArgs(argc, argv, message_count, message_size, packet_loss_constant,
      packet_loss_bursty, csv_file_path))
    return -1;

  // Patch in logging always on to a local directory
  argv[1]=const_cast<char *>("--log_folder=./maidsafe_logs");
  argv[2]=const_cast<char *>("--log_rudp=V");
  maidsafe::log::Logging::Instance().Initialise(argc, argv);
  TLOG(kDefaultColour) << "Starting RUDP benchmark using " << message_count << " messages of "
                       << message_size << " bytes with a constant packet loss of "
                       << packet_loss_constant * 100.0 << "% and a bursty packet loss of "
                       << packet_loss_bursty * 100.0 << "%.\n";

  if (packet_loss_constant > 0 || packet_loss_bursty > 0)
    maidsafe::rudp::set_debug_packet_loss_rate(packet_loss_constant, packet_loss_bursty);
  std::vector<maidsafe::rudp::test::NodePtr> nodes;
  std::vector<maidsafe::rudp::Endpoint> bootstrap_endpoints;
  if (!maidsafe::rudp::test::SetupNetwork(nodes, bootstrap_endpoints, 2)) {
    LOG(kError) << "Failed to setup network.";
    std::cerr << "Failed to setup network.";
    return -2;
  }

  maidsafe::rudp::MessageReceivedFunctor do_nothing_on_message;
  maidsafe::rudp::ConnectionLostFunctor do_nothing_on_connection_lost;

  nodes[0]->ResetData();
  nodes[1]->ResetData();
  auto messages_futures(nodes[1]->GetFutureForMessages(message_count));
  std::vector<std::string> messages;
  messages.reserve(message_count);
  std::string message(maidsafe::RandomAlphaNumericString(message_size - 12));
  for (int i(0); i != message_count; ++i) {
    std::string prefix(std::to_string(i));
    prefix.insert(0, 10 - prefix.size(), '0');
    messages.push_back(prefix + ": " + message);
  }
  int result_of_send(maidsafe::rudp::kConnectError);
  int result_arrived_count(0);
  std::condition_variable cond_var;
  std::mutex mutex;
  std::unique_lock<std::mutex> lock(mutex);
  maidsafe::rudp::message_sent_functor handler([&](int result_in) {
    std::lock_guard<std::mutex> lock(mutex);
    result_of_send = result_in;
    ++result_arrived_count;
    cond_var.notify_one();
  });

  // Send and assess results
  TLOG(kDefaultColour) << "Starting to send ... ";
  auto start_point(std::chrono::steady_clock::now());
  for (int i(0); i != message_count; ++i)
    nodes[0]->managed_connections()->Send(nodes[1]->node_id(), messages[i], handler);

  TLOG(kDefaultColour) << "All messages enqueued ... ";
  cond_var.wait(lock, [message_count, &result_arrived_count] {
    std::cout << result_arrived_count << " ";
    return result_arrived_count == message_count;
  });  // NOLINT (Fraser)
  std::cout << std::endl;

  auto received_messages(messages_futures.get());
  if (received_messages.size() != static_cast<size_t>(message_count)) {
    LOG(kError) << "Only received " << received_messages.size() << " of " << message_count
                << " messages.";
    std::cerr   << "Only received " << received_messages.size() << " of " << message_count
                << " messages.";
    return -3;
  }
  std::chrono::milliseconds elapsed(std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - start_point));

  TLOG(kDefaultColour) << "All messages sent and received.";
  intmax_t transfer_rate(static_cast<intmax_t>
                           ((message_count * message_size * 1000.0) / elapsed.count()));
  intmax_t message_rate(static_cast<intmax_t>((message_count * 1000.0) / elapsed.count()));
  TLOG(kDefaultColour) << "\nSent " << message_count << " messages of " << message_size
                       << " bytes in " << elapsed.count() << " milliseconds.\nTransfer rate: "
                       << maidsafe::BytesToDecimalSiUnits(transfer_rate)
                       << "/sec.\nMessage rate:  " << message_rate << " msg/sec.\n\n";
  if (!csv_file_path.empty()) {
    std::ofstream out(csv_file_path, std::ios_base::app);
    out << message_count << "," << message_size << "," << packet_loss_constant << ","
        << packet_loss_bursty << "," << elapsed.count() << "," << transfer_rate << ","
        << message_rate;
  }

  return 0;
}
