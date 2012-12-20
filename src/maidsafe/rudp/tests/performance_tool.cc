/*******************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of MaidSafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the licence   *
 *  file licence.txt found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of MaidSafe.net. *
 ******************************************************************************/

#include <chrono>
#include <condition_variable>
#include <iostream>
#include <memory>
#include <mutex>
#include <vector>

#include "maidsafe/common/log.h"

#include "maidsafe/rudp/managed_connections.h"
#include "maidsafe/rudp/return_codes.h"
#include "maidsafe/rudp/tests/test_utils.h"


namespace {

bool ParseArgs(int argc, char **argv, int& message_count, int& message_size) {
  auto fail([]()->bool {
    std::cout << "Pass no. of messages and size of messages (in bytes) as first 2 arguments.\n";
    return false;
  });

  if (argc < 3)
    return fail();

  try {
    message_count = std::stoi(argv[1]);
    message_size = std::stoi(argv[2]);
    if (message_count < 1 || message_size < 12) {
      std::cout << "Message count must be >= 1 and size of messages must be >= 12.\n";
      return false;
    }
  }
  catch(const std::exception&) {
    return fail();
  }
  
  return true;
}

}  // unnamed namespace



int main(int argc, char **argv) {
  int message_count(0), message_size(0);
  if (!ParseArgs(argc, argv, message_count, message_size))
    return -1;

  maidsafe::log::Logging::Instance().Initialise(argc, argv);
  TLOG(kDefaultColour) << "Starting RUDP benchmark using " << message_count << " messages of "
                       << message_size << " bytes.\n";

  std::vector<maidsafe::rudp::test::NodePtr> nodes;
  std::vector<maidsafe::rudp::Endpoint> bootstrap_endpoints;
  if (!maidsafe::rudp::test::SetupNetwork(nodes, bootstrap_endpoints, 2)) {
    LOG(kError) << "Failed to setup network.";
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
  maidsafe::rudp::MessageSentFunctor message_sent_functor([&](int result_in) {
    std::lock_guard<std::mutex> lock(mutex);
    result_of_send = result_in;
    ++result_arrived_count;
    cond_var.notify_one();
  });

  // Send and assess results
  LOG(kSuccess) << "Starting to send.";
  auto start_point(std::chrono::steady_clock::now());
  for (int i(0); i != message_count; ++i)
    nodes[0]->managed_connections()->Send(nodes[1]->node_id(), messages[i], message_sent_functor);

  LOG(kSuccess) << "All messages enqueued.";
  cond_var.wait(lock,
      [message_count, &result_arrived_count] { return result_arrived_count == message_count; });  // NOLINT (Fraser)

  auto received_messages(messages_futures.get());
  if (received_messages.size() != (unsigned)message_count) {
    LOG(kError) << "Only received " << received_messages.size() << " of " << message_count
                << " messages.";
    return -3;
  }
  auto finish_point(std::chrono::steady_clock::now());
  std::chrono::milliseconds elapsed(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_point));

  LOG(kSuccess) << "All messages sent and received.";
  intmax_t transfer_rate((message_count * message_size * 1000) / elapsed.count());
  intmax_t message_rate((message_count * 1000) / elapsed.count());
  TLOG(kDefaultColour) << "\nSent " << message_count << " messages of " << message_size
                       << " bytes in " << elapsed.count() << " milliseconds.\nTransfer rate: "
                       << maidsafe::BytesToDecimalSiUnits(transfer_rate) << "/sec.\nMessage rate:  "
                       << message_rate << " msg/sec.\n\n";

  return 0;
}
