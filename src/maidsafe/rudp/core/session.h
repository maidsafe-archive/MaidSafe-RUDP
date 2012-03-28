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

#ifndef MAIDSAFE_TRANSPORT_RUDP_SESSION_H_
#define MAIDSAFE_TRANSPORT_RUDP_SESSION_H_

#include "boost/cstdint.hpp"
#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "maidsafe/transport/rudp_handshake_packet.h"

namespace maidsafe {

namespace transport {

class RudpPeer;
class RudpTickTimer;

class RudpSession {
 public:
  explicit RudpSession(RudpPeer &peer, RudpTickTimer &tick_timer);  // NOLINT (Fraser)

  // Open the session as a client or server.
  enum Mode { kClient, kServer };
  void Open(boost::uint32_t id, boost::uint32_t sequence_number, Mode mode);

  // Get whether the session is already open. May not be connected.
  bool IsOpen() const;

  // Get whether the session is currently connected to the peer.
  bool IsConnected() const;

  // Get the id assigned to the session.
  boost::uint32_t Id() const;

  // Get the first sequence number for packets received.
  boost::uint32_t ReceivingSequenceNumber() const;

  // Get the peer connection type.
  boost::uint32_t PeerConnectionType() const;

  // Close the session. Clears the id.
  void Close();

  // Handle a handshake packet.
  void HandleHandshake(const RudpHandshakePacket &packet);

  // Handle a tick in the system time.
  void HandleTick();

 private:
  // Disallow copying and assignment.
  RudpSession(const RudpSession&);
  RudpSession &operator=(const RudpSession&);

  // Helper functions to send the packets that make up the handshaking process.
  void SendPacket();
  void SendConnectionRequest();
  void SendCookieChallenge();
  void SendCookieResponse();
  void SendConnectionAccepted();

  // The peer with which we are communicating.
  RudpPeer &peer_;

  // The timer used to generate tick events.
  RudpTickTimer &tick_timer_;

  // The local socket id.
  boost::uint32_t id_;

  // The initial sequence number for packets sent in this session.
  boost::uint32_t sending_sequence_number_;

  // The initial sequence number for packets received in this session.
  boost::uint32_t receiving_sequence_number_;

  // The peer's connection type
  boost::uint32_t peer_connection_type_;

  // Are we a client or a server?
  Mode mode_;

  // The state of the session.
  enum State { kClosed, kProbing, kHandshaking, kConnected } state_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_SESSION_H_
