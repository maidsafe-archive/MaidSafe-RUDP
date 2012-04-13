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

#include <functional>
#include <vector>
#include <atomic>
#include <future>
#include <chrono>
#include "boost/lexical_cast.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/managed_connections.h"
#include "maidsafe/rudp/return_codes.h"
#include "maidsafe/rudp/log.h"


namespace args = std::placeholders;
namespace asio = boost::asio;
namespace bptime = boost::posix_time;
namespace ip = asio::ip;

namespace maidsafe {

namespace rudp {

typedef boost::asio::ip::udp::endpoint Endpoint;

namespace test {


void MessageReceived(const std::string &message) {
  DLOG(INFO) << "Received: " << message;
}

void ConnectionLost(const Endpoint &endpoint, std::atomic_int *count) {
  DLOG(INFO) << "Lost connection to " << endpoint;
  ++(*count);
}

TEST(ManagedConnectionsTest, API_BEH_Bootstrap) {
  ManagedConnections managed_connections1, managed_connections2, managed_connections3;
  Endpoint endpoint1(ip::address_v4::loopback(), 9000),
           endpoint2(ip::address_v4::loopback(), 11111),
           endpoint3(ip::address_v4::loopback(), 11112);
  MessageReceivedFunctor message_received_functor(std::bind(MessageReceived,
                                                            args::_1));
  boost::mutex mutex;
  std::atomic_int connection_lost_count(0);
  ConnectionLostFunctor connection_lost_functor(
      std::bind(ConnectionLost, args::_1, &connection_lost_count));

  // get a future type (endpoint type)
  auto a1 = std::async(std::launch::async,  // force launch in new thread
            [&] { return managed_connections1.Bootstrap(std::vector<Endpoint>(1, endpoint2),
                  message_received_functor,
                  connection_lost_functor,
                  endpoint1); } );

  auto a2 = std::async(std::launch::async,
            [&] { return managed_connections2.Bootstrap(std::vector<Endpoint>(1, endpoint1),
                  message_received_functor,
                  connection_lost_functor,
                  endpoint2); } );

  EXPECT_FALSE(a2.get().address().is_unspecified());  // wait for promise !
  EXPECT_FALSE(a1.get().address().is_unspecified());  // wait for promise !

  std::vector<Endpoint> end_vec {endpoint3};
  boost::asio::ip::udp::endpoint bootstrap_endpoint =
             managed_connections3.Bootstrap(end_vec,
                                            message_received_functor,
                                            connection_lost_functor,
                                            endpoint3);

  EXPECT_FALSE(bootstrap_endpoint.address().is_unspecified());

  for (int i(0); i != 200; ++i) {
    Sleep(bptime::milliseconds(10));
    std::string message("Message " + boost::lexical_cast<std::string>(i / 2));
    if (i % 2)
      managed_connections1.Send(endpoint2, message + " from 9000 to 11111");
    else
      managed_connections2.Send(endpoint1, message + " from 11111 to 9000");
  }

  DLOG(INFO) << "==================== REMOVING ENDPOINT 2 ====================";
  managed_connections1.Remove(endpoint2);
  boost::mutex::scoped_lock lock(mutex);
  do {
    lock.unlock();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    lock.lock();
  } while (connection_lost_count != 2);
}

}  // namespace test

}  // namespace rudp

}  // namespace maidsafe
