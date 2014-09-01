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

// Original author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#ifndef MAIDSAFE_RUDP_CORE_MULTIPLEXER_H_
#define MAIDSAFE_RUDP_CORE_MULTIPLEXER_H_

#include <array>  // NOLINT
#include <mutex>
#include <vector>

#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/udp.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/operations/dispatch_op.h"
#include "maidsafe/rudp/core/dispatcher.h"
#include "maidsafe/rudp/packets/packet.h"
#include "maidsafe/rudp/parameters.h"
#include "maidsafe/rudp/return_codes.h"

namespace maidsafe {

namespace rudp {

namespace detail {

class ConnectionManager;
class Socket;

class Multiplexer {
 public:
  explicit Multiplexer(boost::asio::io_service& asio_service);

  // Open the multiplexer.  If endpoint is valid, the new socket will be bound to it.
  ReturnCode Open(const boost::asio::ip::udp::endpoint& endpoint);

  // Whether the multiplexer is open.
  bool IsOpen() const;

  // Close the multiplexer.
  void Close();

  // Asynchronously receive a single packet and dispatch it.
  template <typename DispatchHandler>
  void AsyncDispatch(DispatchHandler handler) {
    DispatchOp<DispatchHandler> op(handler, socket_, boost::asio::buffer(receive_buffer_),
                                   sender_endpoint_, dispatcher_);
    std::lock_guard<std::mutex> lock(mutex_);
    socket_.async_receive_from(boost::asio::buffer(receive_buffer_), sender_endpoint_, 0, op);
  }

 private:
  struct packet_loss_state {
    std::mutex lock;
    bool enabled, in_error_burst;
    double constant, bursty;
    smallprng::ranctx ctx;
    size_t count, total_byte_count, error_count;
    packet_loss_state() : enabled(false), in_error_burst(false), constant(0.0),
                          bursty(0.0), count(0), total_byte_count(0), error_count(0) {
      const char *constantenv = std::getenv("MAIDSAFE_RUDP_CONSTANT_PACKET_LOSS");
      if (constantenv)
        constant = std::strtod(constantenv, nullptr);
      const char *burstyenv = std::getenv("MAIDSAFE_RUDP_BURSTY_PACKET_LOSS");
      if (burstyenv)
        bursty = std::strtod(burstyenv, nullptr);
      smallprng::raninit(&ctx, /*0xdeadbeef*/ (smallprng::u4) std::time(nullptr));
    }
    bool should_drop_this_packet(size_t size) {
      bool ret = false;
      std::lock_guard<decltype(lock)> g(lock);
      ++count;
      total_byte_count += size;
      if (bursty > 0.0) {
        if (in_error_burst)
          error_count += size;
        auto v = smallprng::ranval(&ctx);
        if (!(v & 7)) {
          if (in_error_burst) {
            if (double(error_count) / total_byte_count > bursty)
              in_error_burst = false;
          } else {
            if (double(error_count) / total_byte_count <= bursty)
              in_error_burst = true;
          }
        }
        ret |= in_error_burst;
      }
      if (constant > 0.0) {
        // If UDP packets exceed MTU, they get chopped up into MTU sized pieces the failure
        // any of which loses the entire packet
        for (size_t n = 0; n < size / 1500; n++) {
          if (double(smallprng::ranval(&ctx)) / ((smallprng::u4) -1) <= constant) {
            ret = true;
            break;
          }
        }
      }
      // if (ret) {
      //   std::cerr << "Losing packet " << count << " sized " << size
      //             << " total=" << total_byte_count << std::endl;
      // }
      return ret;
    }
  };
  static packet_loss_state &getPacketLossState() {
    static packet_loss_state state;
    return state;
  }

 public:
  // Fail to send a constant and bursty ratio of packets. Useful for debugging. Note that values
  // are cumulative, so 0.1 each is 20% of packets overall.
  static void SetDebugPacketLossRate(double constant, double bursty) {
    auto &state = getPacketLossState();
    std::lock_guard<decltype(state.lock)> g(state.lock);
    if (state.enabled < (constant > 0.0 || bursty > 0.0)) {
      state.constant = constant;
      state.bursty = bursty;
      state.enabled = true;
    } else {
      state.enabled = false;
    }
  }

  // Called by the socket objects to send a packet. Returns kSuccess if the data was sent
  // successfully, kSendFailure otherwise.
  template <typename Packet>
  ReturnCode SendTo(const Packet& packet, const boost::asio::ip::udp::endpoint& endpoint) {
    std::array<unsigned char, Parameters::kUDPPayload> data;
    auto buffer = boost::asio::buffer(&data[0], Parameters::max_size);
    if (size_t length = packet.Encode(buffer)) {
      boost::system::error_code ec;
      auto &state = getPacketLossState();
      if (state.enabled && state.should_drop_this_packet(length))
        return kSuccess;
      {
        std::lock_guard<std::mutex> lock(mutex_);
        socket_.send_to(boost::asio::buffer(buffer, length), endpoint, 0, ec);
      }
      if (ec) {
#ifndef NDEBUG
        if (!local_endpoint().address().is_unspecified()) {
          LOG(kWarning) << "Error sending " << length << " bytes from " << local_endpoint()
                        << " to << " << endpoint << " - " << ec.message();
        }
#endif
        return kSendFailure;
      } else {
        return kSuccess;
      }
    }
    return kSendFailure;
  }

  boost::asio::ip::udp::endpoint local_endpoint() const;

  // Returns external_endpoint_ if valid, else best_guess_external_endpoint_.
  boost::asio::ip::udp::endpoint external_endpoint() const;

  friend class ConnectionManager;
  friend class Socket;

 private:
  // Disallow copying and assignment.
  Multiplexer(const Multiplexer&);
  Multiplexer& operator=(const Multiplexer&);

  // The UDP socket used for all RUDP protocol communication.
  boost::asio::ip::udp::socket socket_;

  // Data members used to receive information about incoming packets.
  std::vector<unsigned char> receive_buffer_;
  boost::asio::ip::udp::endpoint sender_endpoint_;

  // Dispatcher keeps track of the active sockets.
  Dispatcher dispatcher_;

  // This node's external endpoint - passed to session and set during handshaking.
  boost::asio::ip::udp::endpoint external_endpoint_;

  // This node's best guess at its external endpoint - set when bootstrapping a new transport
  // which is behind symmetric NAT, therefore no actual temporary connection is made.
  boost::asio::ip::udp::endpoint best_guess_external_endpoint_;

  // Mutex to protect access to external_endpoint_.
  mutable std::mutex mutex_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CORE_MULTIPLEXER_H_
