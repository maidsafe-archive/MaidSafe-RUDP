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

#ifndef MAIDSAFE_TRANSPORT_TRANSPORT_H_
#define MAIDSAFE_TRANSPORT_TRANSPORT_H_

#include <memory>
#include <string>
#include <iostream>  // NOLINT
#include <vector>

#include "boost/asio/ip/address.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/serialization/nvp.hpp"
#include "boost/signals2/signal.hpp"
#include "boost/thread/shared_mutex.hpp"
#include "boost/thread/locks.hpp"


namespace bs2 = boost::signals2;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace transport {

typedef boost::asio::ip::address IP;
typedef uint16_t Port;
typedef int32_t DataSize;
typedef bptime::time_duration Timeout;
typedef boost::shared_lock<boost::shared_mutex> SharedLock;
typedef boost::upgrade_lock<boost::shared_mutex> UpgradeLock;
typedef boost::unique_lock<boost::shared_mutex> UniqueLock;
typedef boost::upgrade_to_unique_lock<boost::shared_mutex> UpgradeToUniqueLock;

class Contact;
class MessageHandler;
class Service;
class NatDetection;


enum TransportCondition {
  kSuccess = 0,
  kError = -350001,
  kRemoteUnreachable = -350002,
  kNoConnection = -350003,
  kNoNetwork = -350004,
  kInvalidIP = -350005,
  kInvalidPort = -350006,
  kInvalidData = -350007,
  kNoSocket = -350008,
  kInvalidAddress = -350009,
  kNoRendezvous = -350010,
  kBehindFirewall = -350011,
  kBindError = -350012,
  kConnectError = -350013,
  kAlreadyStarted = -350014,
  kListenError = -350015,
  kCloseSocketError = -350016,
  kSendFailure = -350017,
  kSendTimeout = -350018,
  kSendStalled = -350019,
  kSendParseFailure = -350020,
  kSendSizeFailure = -350021,
  kReceiveFailure = -350022,
  kReceiveTimeout = -350023,
  kReceiveStalled = -350024,
  kReceiveParseFailure = -350025,
  kReceiveSizeFailure = -350026,
  kAddManagedEndpointError = -350027,
  kAddManagedEndpointTimedOut = -350028,
  kManagedEndpointLost = -350029,
  kSetOptionFailure = -350030,
  kMessageSizeTooLarge = -350031,
  kWrongIpVersion = -350032,
  kPendingResult = -350033,

  // Managed Connections
  kNoneAvailable = -350100,
  kFull = -350101,
  kNullParameter = -350102,
  kInvalidMcTransport = -350103,
  kInvalidMcConnection = -350104,

  // Upper limit of values for this enum.
  kTransportConditionLimit = -359999
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

  bool operator==(const Endpoint &other) const {
    return (ip == other.ip && port == other.port);
  }
  bool operator!=(const Endpoint &other) const {
    return !(*this == other);
  }
  bool operator<(const Endpoint &other) const {
    if (ip != other.ip)
      return (ip < other.ip);
    else
      return port < other.port;
  }
  bool operator>(const Endpoint &other) const {
    if (ip != other.ip)
      return (ip > other.ip);
    else
      return port > other.port;
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
      const std::vector<Contact> &candidates) = 0;
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

  friend class NatDetection;
  friend class NatDetectionService;

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

typedef std::shared_ptr<Transport> TransportPtr;

}  // namespace transport

}  // namespace maidsafe



namespace mt = maidsafe::transport;

namespace boost {

namespace serialization {

template <typename Archive>
void serialize(Archive &archive,                              // NOLINT (Fraser)
               mt::Endpoint &endpoint,
               const unsigned int& /*version*/) {
  std::string ip;
  boost::uint16_t port = endpoint.port;
  if (Archive::is_saving::value) {
    ip = endpoint.ip.to_string();
    port = endpoint.port;
  }
  archive& boost::serialization::make_nvp("ip", ip);
  archive& boost::serialization::make_nvp("port", port);
  if (Archive::is_loading::value) {
    boost::system::error_code ec;
    endpoint.ip = boost::asio::ip::address::from_string(ip, ec);
    if (ec)
      port = 0;
    endpoint.port = port;
  }
}

}  // namespace serialization

}  // namespace boost


#endif  // MAIDSAFE_TRANSPORT_TRANSPORT_H_
