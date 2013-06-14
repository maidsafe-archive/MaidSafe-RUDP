//
// async_udp_echo_server.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2008 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <cstdint>
#include <cstdlib>
#include <iostream>

#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/system/error_code.hpp"

using boost::asio::ip::udp;
namespace args = std::placeholders;

class Server {
  enum { kMaxLength = 65506 };

 public:
  Server(boost::asio::io_service& io_service, uint16_t port)
    : // TODO (dirvine) unused io_service_(io_service),
      socket_(io_service, udp::endpoint(udp::v4(), port)),
      sender_endpoint_() {
    socket_.async_receive_from(
        boost::asio::buffer(data_, kMaxLength), sender_endpoint_,
        std::bind(&Server::HandleReceiveFrom, this, args::_1, args::_2));
  }

  void HandleReceiveFrom(const boost::system::error_code& error, size_t bytes_recvd) {
    if (!error && bytes_recvd > 0) {
      std::string msg("reply");
      char *reply = (char*)msg.c_str();  // NOLINT
      socket_.async_send_to(
          boost::asio::buffer(reply, msg.size()), sender_endpoint_,
          std::bind(&Server::HandleSendTo, this, args::_1, args::_2));
    } else {
      socket_.async_receive_from(
          boost::asio::buffer(data_, kMaxLength), sender_endpoint_,
          std::bind(&Server::HandleReceiveFrom, this, args::_1, args::_2));
    }
  }

  void HandleSendTo(const boost::system::error_code& /*error*/, size_t /*bytes_sent*/) {
    socket_.async_receive_from(
        boost::asio::buffer(data_, kMaxLength), sender_endpoint_,
        std::bind(&Server::HandleReceiveFrom, this, args::_1, args::_2));
  }

 private:
//  boost::asio::io_service& io_service_; Unused
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
    boost::asio::io_service io_service;
    Server server(io_service, static_cast<uint16_t>(std::atoi(argv[1])));
    io_service.run();
  } catch(std::exception& e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }
  return 0;
}
