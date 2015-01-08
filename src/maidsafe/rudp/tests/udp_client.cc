// NoCheck
//
// blocking_udp_echo_client.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2008 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <cstdlib>
#include <cstring>
#include <iostream>

#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "boost/system/error_code.hpp"

#include "maidsafe/common/utils.h"

using boost::asio::ip::udp;

namespace bptime = boost::posix_time;

enum { kMaxLength = 65506 };

int main(int argc, char* argv[]) {
  if (argc != 3) {
    std::cerr << "Usage: udp_client <host> <port>\n";
    return 1;
  }
  try {
    boost::asio::io_service io_service;
    udp::socket s(io_service, udp::endpoint(udp::v4(), 0));
    udp::resolver resolver(io_service);
    udp::resolver::query query(udp::v4(), argv[1], argv[2]);
    udp::resolver::iterator iterator = resolver.resolve(query);
    size_t msg_size(1), iteration(1);
    char reply[kMaxLength];
    do {
      std::string msg(maidsafe::RandomString(msg_size));
      char *request = const_cast<char*>(msg.c_str());  // NOLINT
      auto start_time(bptime::microsec_clock::universal_time());
//       std::cout << "sending started at : " << start_time << std::endl;
      s.send_to(boost::asio::buffer(request, msg_size), *iterator);

      udp::endpoint sender_endpoint;
      size_t reply_length = s.receive_from(
          boost::asio::buffer(reply, kMaxLength), sender_endpoint);
      auto end_time(bptime::microsec_clock::universal_time());
      if (reply_length == msg_size) {
//         std::cout << "reply received at : " << end_time << std::endl;
        auto rate((msg_size * 2) * 1000 / (end_time - start_time).total_microseconds());
        std::cout << "Transmit of data_size " << msg_size << " Bytes " << " completed in "
                  << (end_time - start_time).total_microseconds() << " microseconds "
                  << " have a throughput rate of " << rate << " kBytes/s" << std::endl;
      } else {
        std::cout << "incorrect received msg size " << reply_length
                  << " for data_size " << msg_size << std::endl;
      }
      msg_size = 1000 * iteration;
      iteration *= 2;
    } while (msg_size < kMaxLength);
  } catch(std::exception& e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}
