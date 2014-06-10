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

int main(int argc, char* argv[])
{
  if (argc != 4)
  {
    std::cerr << "Usage: udp_client <host> <port> <msg_size>\n";
    return 1;
  }
  try {
    boost::asio::io_service io_service;
    udp::socket s(io_service, udp::endpoint(udp::v4(), 0));

    udp::resolver resolver(io_service);
    udp::resolver::query query(udp::v4(), argv[1], argv[2]);
    udp::resolver::iterator iterator = resolver.resolve(query);

    int msg_size(std::atoi(argv[3]));
    std::string msg(maidsafe::RandomString(msg_size));
    char *request = (char*)msg.c_str();  // NOLINT

    std::cout << "sending started at : " << bptime::microsec_clock::universal_time() << std::endl;
    s.send_to(boost::asio::buffer(request, msg_size), *iterator);

    char reply[kMaxLength];
    udp::endpoint sender_endpoint;
    size_t reply_length = s.receive_from(
        boost::asio::buffer(reply, kMaxLength), sender_endpoint);
    if (reply_length == 5)
      std::cout << "reply received at : " << bptime::microsec_clock::universal_time() << std::endl;
  } catch(std::exception& e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}
