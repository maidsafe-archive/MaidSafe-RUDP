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

#ifndef MAIDSAFE_RUDP_CONNECTION_H_
#define MAIDSAFE_RUDP_CONNECTION_H_

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/asio/strand.hpp"

#include "maidsafe/rudp/core/socket.h"
#include "maidsafe/rudp/transport.h"

namespace maidsafe {

namespace rudp {

namespace detail {

typedef int32_t DataSize;

class Multiplexer;


#ifdef __GNUC__
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Weffc++"
#endif
class Connection : public std::enable_shared_from_this<Connection> {
#ifdef __GNUC__
#  pragma GCC diagnostic pop
#endif

 public:
  Connection(const std::shared_ptr<Transport> &transport,
             const boost::asio::io_service::strand& strand,
             const std::shared_ptr<Multiplexer> &multiplexer,
             const boost::asio::ip::udp::endpoint& remote);

  detail::Socket& Socket();

  void Close();
  // If lifespan is 0, only handshaking will be done.  Otherwise, the connection will be closed
  // after lifespan has passed.
  void StartConnecting(std::shared_ptr<asymm::PublicKey> this_public_key,
                       const std::string& validation_data,
                       const boost::posix_time::time_duration& lifespan);
  void Ping(std::shared_ptr<asymm::PublicKey> this_public_key,
            const std::function<void(int)> &ping_functor);  // NOLINT (Fraser)
  void StartSending(const std::string& data, const std::function<void(int)> &message_sent_functor);  // NOLINT (Fraser)
  // Returns true if lifespan_timer_ expires at < pos_infin.
  bool IsTemporary() const;
  // Sets the lifespan_timer_ to expire at pos_infin.
  void MakePermanent();

 private:
  Connection(const Connection&);
  Connection& operator=(const Connection&);

  void DoClose(bool timed_out = false);
  void DoStartConnecting(std::shared_ptr<asymm::PublicKey> this_public_key,
                         const std::string& validation_data,
                         const boost::posix_time::time_duration& lifespan,
                         const std::function<void(int)> &ping_functor);  // NOLINT (Fraser)
  void DoStartSending(const std::string& data,
                      const std::function<void(int)> &message_sent_functor);  // NOLINT (Fraser)

  void CheckTimeout(const boost::system::error_code& ec);
  void CheckLifespanTimeout(const boost::system::error_code& ec);
  bool Stopped() const;

  void StartTick();
  void HandleTick();

  void StartConnect(std::shared_ptr<asymm::PublicKey> this_public_key,
                    const std::string& validation_data,
                    const boost::posix_time::time_duration& lifespan,
                    const std::function<void(int)> &ping_functor);  // NOLINT (Fraser)
  void HandleConnect(const boost::system::error_code& ec,
                     const std::string& validation_data,
                     const std::function<void(int)> &ping_functor);  // NOLINT (Fraser)

  void StartReadSize();
  void HandleReadSize(const boost::system::error_code& ec);

  void StartReadData();
  void HandleReadData(const boost::system::error_code& ec, size_t length);

  void StartWrite(const std::function<void(int)> &message_sent_functor);  // NOLINT (Fraser)
  void HandleWrite(const boost::system::error_code& ec,
                   const std::function<void(int)> &message_sent_functor);  // NOLINT (Fraser)

  void StartProbing();
  void DoProbe(const boost::system::error_code& ec);
  void HandleProbe(const boost::system::error_code& ec);

  void DoMakePermanent();

  void DispatchMessage();
  bool EncodeData(const std::string& data);

  void InvokeSentFunctor(const std::function<void(int)> &message_sent_functor, int result) const;  // NOLINT (Fraser)

  std::weak_ptr<Transport> transport_;
  boost::asio::io_service::strand strand_;
  std::shared_ptr<Multiplexer> multiplexer_;
  maidsafe::rudp::detail::Socket socket_;
  boost::asio::deadline_timer timer_, probe_interval_timer_, lifespan_timer_;
  boost::asio::ip::udp::endpoint remote_endpoint_;
  std::vector<unsigned char> send_buffer_, receive_buffer_;
  size_t data_size_, data_received_;
  uint8_t failed_probe_count_;
  enum TimeoutState { kConnecting, kConnected, kClosing } timeout_state_;
  bool sending_;
  std::atomic<bool> is_temporary_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CONNECTION_H_
