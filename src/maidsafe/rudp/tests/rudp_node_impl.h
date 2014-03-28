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

/*
 * @file  rudp_node_impl.h
 * @brief Head File for rudp_node_impl.cc .
 * @date  2012-02-26
 */

#ifndef MAIDSAFE_RUDP_TESTS_RUDP_NODE_IMPL_H_
#define MAIDSAFE_RUDP_TESTS_RUDP_NODE_IMPL_H_

#include <memory>
#include <string>
#include <vector>
#include <mutex>

#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/asio.hpp"

#include "maidsafe/passport/types.h"

#include "maidsafe/rudp/transport.h"
#include "maidsafe/rudp/utils.h"
#include "maidsafe/rudp/tests/test_utils.h"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

namespace test {

class RudpNode {
 public:
  RudpNode(std::vector<maidsafe::passport::Pmid> all_pmids, int identity_index,
           int peer_identity_index, const std::string& peer);
  void Run();
  void GetPeer(const std::string& peer);

 private:
  void PrintUsage();
  void ProcessCommand(const std::string& cmdline);

  void OnMessageSlot(const std::string& message);
  void OnConnectionAddedSlot(const NodeId& peer_id, std::shared_ptr<detail::Transport> transport,
                             bool temporary_connection,
                             std::atomic<bool> & is_duplicate_normal_connection);
  void OnConnectionLostSlot(const NodeId& peer_id, std::shared_ptr<detail::Transport> transport,
                            bool temporary_connection);
  void OnNatDetectionRequestedSlot(const Endpoint& this_local_endpoint, const NodeId& peer_id,
                                   const Endpoint& peer_endpoint, uint16_t& another_external_port);

  std::vector<maidsafe::passport::Pmid> all_pmids_;
  std::vector<NodeId> all_ids_;
  int identity_index_;
  int peer_identity_index_;
  boost::asio::ip::udp::endpoint bootstrap_peer_ep_;
  AsioService asio_service_;
  NatType nat_type_;
  std::shared_ptr<maidsafe::rudp::detail::Transport> transport_;
  bool reply_;
  size_t data_size_;
  //  size_t data_rate_;  (dirvine) currently unused
  bool result_arrived_, finish_;
  boost::mutex wait_mutex_;
  boost::condition_variable wait_cond_var_;
  std::function<void()> mark_results_arrived_;
};

}  //  namespace test

}  //  namespace rudp

}  //  namespace maidsafe

#endif  // MAIDSAFE_RUDP_TESTS_RUDP_NODE_IMPL_H_
