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
#ifndef MAIDSAFE_RUDP_TESTS_TEST_UTILS_H_
#define MAIDSAFE_RUDP_TESTS_TEST_UTILS_H_

#include <memory>
#include <cstdint>
#include <string>
#include <vector>

#include "boost/asio/ip/udp.hpp"
#include "boost/thread/future.hpp"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"


namespace maidsafe {

namespace rudp {

class ManagedConnections;

typedef boost::asio::ip::udp::endpoint Endpoint;

typedef std::shared_ptr<ManagedConnections> ManagedConnectionsPtr;


namespace test {

class Node;
typedef std::shared_ptr<Node> NodePtr;


uint16_t GetRandomPort();

testing::AssertionResult SetupNetwork(std::vector<NodePtr> &nodes,
                                      std::vector<Endpoint> &bootstrap_endpoints,
                                      const int &node_count);


class Node {
 public:
  explicit Node(int id);
  std::vector<Endpoint> connection_lost_endpoints() const;
  std::vector<std::string> messages() const;
  Endpoint Bootstrap(const std::vector<Endpoint> &bootstrap_endpoints,
                     Endpoint local_endpoint = Endpoint());
  boost::unique_future<std::vector<std::string>> GetFutureForMessages(
      const uint32_t &message_count);
  std::string kId() const { return kId_; }
  std::string kValidationData() const { return kValidationData_; }
  ManagedConnectionsPtr managed_connections() const { return managed_connections_; }
  int GetReceivedMessageCount(const std::string &message) const;
  void ResetData();

 private:
  void SetPromiseIfDone();

  const std::string kId_, kValidationData_;
  mutable std::mutex mutex_;
  std::vector<Endpoint> connection_lost_endpoints_;
  std::vector<std::string> messages_;
  ManagedConnectionsPtr managed_connections_;
  bool promised_;
  uint32_t total_message_count_expectation_;
  boost::promise<std::vector<std::string>> message_promise_;
};


}  // namespace test

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_TESTS_TEST_UTILS_H_
