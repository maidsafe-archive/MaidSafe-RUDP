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
// Original author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#ifndef MAIDSAFE_TRANSPORT_MC_CONNECTION_H_
#define MAIDSAFE_TRANSPORT_MC_CONNECTION_H_

#include <memory>
#include <string>
#include <vector>
#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/asio/strand.hpp"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/rudp_socket.h"
#include "maidsafe/transport/rudp_transport.h"

namespace maidsafe {

namespace transport {

class RudpMultiplexer;
class RudpSocket;

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Weffc++"
#endif
class RudpConnection : public std::enable_shared_from_this<RudpConnection> {
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

 public:
  RudpConnection(const std::shared_ptr<RudpTransport> &transport,
                 const boost::asio::io_service::strand &strand,
                 const std::shared_ptr<RudpMultiplexer> &multiplexer,
                 const boost::asio::ip::udp::endpoint &remote);
  ~RudpConnection();

  RudpSocket &Socket();

  void Close();
  void StartReceiving();
  void StartSending(const std::string &data, const Timeout &timeout);
  void Connect(const Timeout &timeout, ConnectFunctor callback);

 private:
  RudpConnection(const RudpConnection&);
  RudpConnection &operator=(const RudpConnection&);

  void DoClose();
  void DoStartReceiving();
  void DoStartSending();
  void DoConnect(ConnectFunctor callback);

  void CheckTimeout(const boost::system::error_code &ec);
  bool Stopped() const;

  void StartTick();
  void HandleTick();

  void StartServerConnect();
  void HandleServerConnect(const boost::system::error_code &ec);

  void StartClientConnect();
  void HandleClientConnect(const boost::system::error_code &ec);

  void SimpleClientConnect(ConnectFunctor callback);
  void HandleSimpleClientConnect(const boost::system::error_code &ec,
                                 ConnectFunctor callback);

  void StartReadSize();
  void HandleReadSize(const boost::system::error_code &ec);

  void StartReadData();
  void HandleReadData(const boost::system::error_code &ec, size_t length);

  void StartWrite();
  void HandleWrite(const boost::system::error_code &ec);

  void DispatchMessage();
  void EncodeData(const std::string &data);
  void CloseOnError(const TransportCondition &error);

  std::weak_ptr<RudpTransport> transport_;
  boost::asio::io_service::strand strand_;
  std::shared_ptr<RudpMultiplexer> multiplexer_;
  RudpSocket socket_;
  boost::asio::deadline_timer timer_;
  boost::posix_time::ptime response_deadline_;
  boost::asio::ip::udp::endpoint remote_endpoint_;
  std::vector<unsigned char> buffer_;
  size_t data_size_, data_received_;
  Timeout timeout_for_response_;
  enum TimeoutState { kNoTimeout, kSending, kReceiving } timeout_state_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_MC_CONNECTION_H_
