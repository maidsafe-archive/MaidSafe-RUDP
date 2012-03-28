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

#ifndef MAIDSAFE_TRANSPORT_RUDP_HANDSHAKE_PACKET_H_
#define MAIDSAFE_TRANSPORT_RUDP_HANDSHAKE_PACKET_H_

#include <string>

#include "boost/asio/buffer.hpp"
#include "boost/asio/ip/address.hpp"
#include "boost/cstdint.hpp"
#include "boost/system/error_code.hpp"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/rudp_control_packet.h"

namespace maidsafe {

namespace transport {

class RudpHandshakePacket : public RudpControlPacket {
 public:
  enum { kPacketSize = RudpControlPacket::kHeaderSize + 48 };
  enum { kPacketType = 0 };

  RudpHandshakePacket();
  virtual ~RudpHandshakePacket() {}

  boost::uint32_t RudpVersion() const;
  void SetRudpVersion(boost::uint32_t n);

  static const boost::uint32_t kStreamSocketType = 0;
  static const boost::uint32_t kDatagramSocketType = 1;
  boost::uint32_t SocketType() const;
  void SetSocketType(boost::uint32_t n);

  boost::uint32_t InitialPacketSequenceNumber() const;
  void SetInitialPacketSequenceNumber(boost::uint32_t n);

  boost::uint32_t MaximumPacketSize() const;
  void SetMaximumPacketSize(boost::uint32_t n);

  boost::uint32_t MaximumFlowWindowSize() const;
  void SetMaximumFlowWindowSize(boost::uint32_t n);

  boost::uint32_t ConnectionType() const;
  void SetConnectionType(boost::uint32_t n);

  boost::uint32_t SocketId() const;
  void SetSocketId(boost::uint32_t n);

  boost::uint32_t SynCookie() const;
  void SetSynCookie(boost::uint32_t n);

  boost::asio::ip::address IpAddress() const;
  void SetIpAddress(const boost::asio::ip::address &address);

  static bool IsValid(const boost::asio::const_buffer &buffer);
  bool Decode(const boost::asio::const_buffer &buffer);
  size_t Encode(const boost::asio::mutable_buffer &buffer) const;

 private:
  boost::uint32_t rudp_version_;
  boost::uint32_t socket_type_;
  boost::uint32_t initial_packet_sequence_number_;
  boost::uint32_t maximum_packet_size_;
  boost::uint32_t maximum_flow_window_size_;
  boost::uint32_t connection_type_;
  boost::uint32_t socket_id_;
  boost::uint32_t syn_cookie_;
  boost::asio::ip::address_v6 ip_address_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_HANDSHAKE_PACKET_H_
