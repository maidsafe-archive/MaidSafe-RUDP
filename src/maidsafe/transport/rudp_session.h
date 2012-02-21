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

// Author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

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
