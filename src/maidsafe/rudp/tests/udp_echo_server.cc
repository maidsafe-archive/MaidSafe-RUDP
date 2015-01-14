// NoCheck
//
// async_udp_echo_server.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2008 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <cstdlib>
#include <iostream>

#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/system/error_code.hpp"

using boost::asio::ip::udp;
namespace args = std::placeholders;

class server {
  enum { kMaxLength = 65506 };

 public:
  server(boost::asio::io_service& io_service, unsigned short port)
    : socket_(io_service, udp::endpoint(udp::v4(), port)),
      sender_endpoint_() {
    socket_.async_receive_from(
        boost::asio::buffer(data_, kMaxLength), sender_endpoint_,
        std::bind(&server::handle_receive_from, this, args::_1, args::_2));
  }

  void handle_receive_from(const boost::system::error_code& error,
      size_t bytes_recvd) {
    if (!error && bytes_recvd > 0) {
      std::string msg(data_, bytes_recvd);
      std::cout << "bytes_recvd : " << bytes_recvd << " msg size : " << msg.size() << std::endl;
      char *reply = const_cast<char*>(msg.c_str());  // NOLINT
      socket_.async_send_to(
          boost::asio::buffer(reply, msg.size()), sender_endpoint_,
          std::bind(&server::handle_send_to, this, args::_1, args::_2));
    }
    socket_.async_receive_from(
        boost::asio::buffer(data_, kMaxLength), sender_endpoint_,
        std::bind(&server::handle_receive_from, this, args::_1, args::_2));
  }

  void handle_send_to(const boost::system::error_code& /*error*/, size_t /*bytes_sent*/) {
    socket_.async_receive_from(
        boost::asio::buffer(data_, kMaxLength), sender_endpoint_,
        std::bind(&server::handle_receive_from, this, args::_1, args::_2));
  }

 private:
  udp::socket socket_;
  udp::endpoint sender_endpoint_;
  char data_[kMaxLength];
};

int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: udp_echo_server <port>\n";
    return 1;
  }
  try {
    std::cout << "Listening on port " << std::atoi(argv[1]) << std::endl;
    boost::asio::io_service io_service;
    server s(io_service, static_cast<unsigned short>(std::atoi(argv[1])));  // NOLINT
    io_service.run();
  } catch(std::exception& e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }
  return 0;
}
