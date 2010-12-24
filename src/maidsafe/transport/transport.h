/* Copyright (c) 2010 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*******************************************************************************
 * NOTE: This header should not be regarded as finalised until this notice is  *
 *       removed.                                                              *
 ******************************************************************************/

#ifndef MAIDSAFE_TRANSPORT_TRANSPORT_H_
#define MAIDSAFE_TRANSPORT_TRANSPORT_H_

#include <boost/shared_ptr.hpp>
#include <boost/signals2/signal.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/date_time/posix_time/posix_time_duration.hpp>
#include <string>
#include <iostream>  // NOLINT

// #if MAIDSAFE_DHT_VERSION < 25
// #error This API is not compatible with the installed library.
// #error Please update the maidsafe-dht library.
// #endif

namespace bs2 = boost::signals2;

namespace transport {

typedef boost::asio::ip::address IP;
typedef boost::uint16_t Port;
typedef boost::int32_t DataSize;
typedef boost::posix_time::milliseconds Timeout;

enum TransportCondition {
  kSuccess = 0,
  kError = -1,
  kRemoteUnreachable = -2,
  kNoConnection = -3,
  kNoNetwork = -4,
  kInvalidIP = -5,
  kInvalidPort = -6,
  kInvalidData = -7,
  kNoSocket = -8,
  kInvalidAddress = -9,
  kNoRendezvous = -10,
  kBehindFirewall = -11,
  kBindError = -12,
  kConnectError = -13,
  kAlreadyStarted = -14,
  kListenError = -15,
  kCloseSocketError = -16,
  kSendFailure = -17,
  kSendTimeout = -18,
  kSendStalled = -19,
  kSendParseFailure = -20,
  kSendSizeFailure = -21,
  kReceiveFailure = -22,
  kReceiveTimeout = -23,
  kReceiveStalled = -24,
  kReceiveParseFailure = -25,
  kReceiveSizeFailure = -26,
  kAddManagedEndpointError = -27,
  kAddManagedEndpointTimedOut = -28,
  kManagedEndpointLost = -29,
  kSetOptionFailure = -30,
  kMessageSizeTooLarge = -31
};

enum NatType { kManualPortMapped,  // behind manually port-mapped router.
               kDirectConnected,   // directly connected to the net:
                                   // external IP/Port == local IP/Port.
               kNatPmp,            // behind NAT-PMP port-mapped router.
               kUPnP,              // behind UPnP port-mapped router.
               kFullCone,          // behind full-cone NAT - need to continually
                                   // ping bootstrap node to keep hole open.
               kPortRestricted,    // behind port restricted NAT - node can only
                                   // be contacted via its rendezvous node.
               kNotConnected };    // behind symmetric NAT or offline.

struct Endpoint {
  Endpoint() : ip(), port(0) {}
  Endpoint(const IP &ip, const Port &port) : ip(ip), port(port) {}
  Endpoint(const std::string &ip_as_string, const Port &port)
      : ip(),
        port(port) {
    boost::system::error_code ec;
    ip = IP::from_string(ip_as_string, ec);
  }
  IP ip;
  Port port;
};

struct Info {
  Info() : endpoint(), rtt(0) {}
  Endpoint endpoint;
  boost::uint32_t rtt;
};

// In bytes
const DataSize kMaxTransportMessageSize = 67108864;
// Default timeout for RPCs
const Timeout kDefaultInitialTimeout(10000);
// Used to indicate timeout should be calculated by transport
const Timeout kDynamicTimeout(-1);
// Indicates timeout to expire immediately
const Timeout kImmediateTimeout(0);
// Minimum timeout if being calculated dynamically
const Timeout kMinTimeout(500);
// Factor of message size used to calculate timeout dynamically
const float kTimeoutFactor(0.01);
// Maximum period of inactivity on a send or receive before timeout triggered
const Timeout kStallTimeout(3000);
// Maximum number of accepted incoming connections
const int kMaxAcceptedConnections(5);

// transport signals
typedef boost::shared_ptr<bs2::signal<void(const std::string&,
                                           const Info&,
                                           std::string*,
                                           Timeout*)> > OnMessageReceived;
typedef boost::shared_ptr<bs2::signal<void(const TransportCondition&)> >
    OnError;

// Base class for all transport types.
class Transport {
 public:
  virtual ~Transport() {}
  /**
   * Enables the transport to accept incoming communication. Fails if already
   * listening or the requested endpoint is unavailable.
   * @param endpoint The endpoint to listen for messages on.
   * @return Success or an appropriate error code.
   */
  virtual TransportCondition StartListening(const Endpoint &endpoint) = 0;
  /**
   * Stops the transport from accepting incoming communication.
   */
  virtual void StopListening() = 0;
  /**
   * Sends the given message to the specified receiver.
   * @param data The message data to transmit.
   * @param endpoint The data receiver's endpoint.
   * @param timeout Time after which to terminate a conversation.
   */
  virtual void Send(const std::string &data,
                    const Endpoint &endpoint,
                    const Timeout &timeout) = 0;
  /**
   * Sends data that is being streamed from the given source.
   * @param data The input stream delivering data to send.
   * @param endpoint The data receiver's endpoint.
   */
  virtual void SendStream(const std::istream &data,
                          const Endpoint &endpoint) = 0;
  /**
   * Getter for the listening port.
   * @return The port number or 0 if not listening.
   */
  Port listening_port() const { return listening_port_; }
  OnMessageReceived on_message_received() { return on_message_received_; }
  OnError on_error() { return on_error_; }
 protected:
  explicit Transport(boost::shared_ptr<boost::asio::io_service> asio_service)
      : asio_service_(asio_service),
        listening_port_(0),
        on_message_received_(new OnMessageReceived::element_type),
        on_error_(new OnError::element_type) {}
  boost::shared_ptr<boost::asio::io_service> asio_service_;
  Port listening_port_;
  OnMessageReceived on_message_received_;
  OnError on_error_;
 private:
  Transport(const Transport&);
  Transport& operator=(const Transport&);
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORT_H_
