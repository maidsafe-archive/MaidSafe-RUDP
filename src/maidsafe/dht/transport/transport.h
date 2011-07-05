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

#ifndef MAIDSAFE_DHT_TRANSPORT_TRANSPORT_H_
#define MAIDSAFE_DHT_TRANSPORT_TRANSPORT_H_

#include <memory>
#include <string>
#include <iostream>  // NOLINT
#include <vector>

#include "boost/asio/ip/address.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/signals2/signal.hpp"

#include "maidsafe/dht/version.h"



#if MAIDSAFE_DHT_VERSION != 3002
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-dht library.
#endif

namespace bs2 = boost::signals2;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace dht {

namespace transport {

typedef boost::asio::ip::address IP;
typedef uint16_t Port;
typedef int32_t DataSize;
typedef bptime::time_duration Timeout;

class MessageHandler;
class Service;

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
  kMessageSizeTooLarge = -31,
  kWrongIpVersion = -32
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
  Endpoint(const IP &ip_in, const Port &port_in) : ip(ip_in), port(port_in) {}
  Endpoint(const std::string &ip_as_string, const Port &port_in)
      : ip(),
        port(port_in) {
    boost::system::error_code ec;
    ip = IP::from_string(ip_as_string, ec);
    if (ec)
      port = 0;
  }
  IP ip;
  Port port;
};

struct Info {
  Info() : endpoint(), rtt(0) {}
  virtual ~Info() {}
  Endpoint endpoint;
  uint32_t rtt;
};

struct TransportDetails {
  TransportDetails() : endpoint(), local_endpoints(), rendezvous_endpoint() {}
  transport::Endpoint endpoint;
  std::vector<transport::Endpoint> local_endpoints;
  transport::Endpoint rendezvous_endpoint;
};

// Maximum number of bytes to read at a time
const DataSize kMaxTransportChunkSize = 65536;
// Default timeout for RPCs
const Timeout kDefaultInitialTimeout(bptime::seconds(10));
// Used to indicate timeout should be calculated by transport
const Timeout kDynamicTimeout(bptime::seconds(-1));
// Indicates timeout to expire immediately
const Timeout kImmediateTimeout(bptime::seconds(0));
// Minimum timeout if being calculated dynamically
const Timeout kMinTimeout(bptime::milliseconds(500));
// Factor of message size used to calculate timeout dynamically
const float kTimeoutFactor(0.01f);
// Maximum period of inactivity on a send or receive before timeout triggered
const Timeout kStallTimeout(bptime::seconds(3));
// Maximum number of accepted incoming connections
const int kMaxAcceptedConnections(5);

// transport signals
typedef std::shared_ptr<bs2::signal<void(const std::string&,
                                         const Info&,
                                         std::string*,
                                         Timeout*)>> OnMessageReceived;
typedef std::shared_ptr<bs2::signal<void(const TransportCondition&,
                                         const Endpoint&)>> OnError;

// Base class for all transport types.
class Transport {
 public:
  /**
   * Enables the transport to accept incoming communication. Fails if already
   * listening or the requested endpoint is unavailable.
   * @param endpoint The endpoint to listen for messages on.
   * @return Success or an appropriate error code.
   */
  virtual TransportCondition StartListening(const Endpoint &endpoint) = 0;
  /**
   * Enables the transport to accept incoming communication. Fails if already
   * listening or the requested endpoint is unavailable.
   * @param candidates The vector of candidate Endpoints for bootstrapping.
   * @return Success or an appropriate error code.
   */
  virtual TransportCondition Bootstrap(
      const std::vector<Endpoint> &candidates) = 0;
  /**
   * Stops the transport from accepting incoming communication.
   */
  virtual void StopListening() = 0;
  /**
   * Sends the given message to the specified receiver.
   * @param data The message data to transmit.
   * @param endpoint The data receiver's endpoint.
   * @param timeout Time after which to terminate a conversation.
   * @param close_on_response Whether the connection should be kept alive after
   * the response arrives (or timeout occurs) or not.
   */
  virtual void Send(const std::string &data,
                    const Endpoint &endpoint,
                    const Timeout &timeout) = 0;
  /**
   * Getter for the listening port.
   * @return The port number or 0 if not listening.
   */
  Port listening_port() const { return listening_port_; }
  OnMessageReceived on_message_received() { return on_message_received_; }
  OnError on_error() { return on_error_; }
  DataSize kMaxTransportMessageSize() const {
    return kMaxTransportMessageSize_;
  }
  TransportDetails transport_details() const { return transport_details_; }
  int bootstrap_status() { return bootstrap_status_; }
//  std::shared_ptr<Service> transport_service() { return transport_service_; }

 protected:
  /**
   * Protected destructor to prevent deletion through this type.
   */
  virtual ~Transport() {}
  Transport(boost::asio::io_service &asio_service,  // NOLINT
            const DataSize &data_size = 67108864)
      : asio_service_(asio_service),
        listening_port_(0),
        on_message_received_(new OnMessageReceived::element_type),
        on_error_(new OnError::element_type),
        kMaxTransportMessageSize_(data_size),
        transport_details_(),
        bootstrap_status_(-2) {}
  boost::asio::io_service &asio_service_;
  Port listening_port_;
  OnMessageReceived on_message_received_;
  OnError on_error_;

  const DataSize kMaxTransportMessageSize_;  // In bytes
  TransportDetails transport_details_;
  int bootstrap_status_;

 private:
  Transport(const Transport&);
  Transport& operator=(const Transport&);
};

}  // namespace transport

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_TRANSPORT_TRANSPORT_H_
