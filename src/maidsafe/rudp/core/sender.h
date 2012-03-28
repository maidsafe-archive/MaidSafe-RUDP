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

#ifndef MAIDSAFE_TRANSPORT_RUDP_SENDER_H_
#define MAIDSAFE_TRANSPORT_RUDP_SENDER_H_

#include "boost/asio/buffer.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/cstdint.hpp"
#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "maidsafe/transport/rudp_ack_packet.h"
#include "maidsafe/transport/rudp_data_packet.h"
#include "maidsafe/transport/rudp_negative_ack_packet.h"
#include "maidsafe/transport/rudp_shutdown_packet.h"
#include "maidsafe/transport/rudp_sliding_window.h"

namespace maidsafe {

namespace transport {

class RudpCongestionControl;
class RudpPeer;
class RudpTickTimer;

class RudpSender {
 public:
  explicit RudpSender(RudpPeer &peer,  // NOLINT (Fraser)
                      RudpTickTimer &tick_timer,
                      RudpCongestionControl &congestion_control);

  // Get the sequence number that will be used for the next packet.
  boost::uint32_t GetNextPacketSequenceNumber() const;

  // Determine whether all data has been transmitted to the peer.
  bool Flushed() const;

  // Adds some application data to be sent. Returns number of bytes copied.
  size_t AddData(const boost::asio::const_buffer &data);

  // Notify the other side that the current connection is to be dropped
  void NotifyClose();

  // Handle an acknowlegement packet.
  void HandleAck(const RudpAckPacket &packet);

  // Handle an negative acknowlegement packet.
  void HandleNegativeAck(const RudpNegativeAckPacket &packet);

  // Handle a tick in the system time.
  void HandleTick();

 private:
  // Disallow copying and assignment.
  RudpSender(const RudpSender&);
  RudpSender &operator=(const RudpSender&);

  // Send waiting packets.
  void DoSend();

  // The peer with which we are communicating.
  RudpPeer &peer_;

  // The timer used to generate tick events.
  RudpTickTimer &tick_timer_;

  // The congestion control information associated with the connection.
  RudpCongestionControl &congestion_control_;

  struct UnackedPacket {
    UnackedPacket() : packet(),
                      lost(false),
                      last_send_time() {}
    RudpDataPacket packet;
    bool lost;
    boost::posix_time::ptime last_send_time;
  };

  // The sender's window of unacknowledged packets.
  typedef RudpSlidingWindow<UnackedPacket> UnackedPacketWindow;
  UnackedPacketWindow unacked_packets_;

  // The next time at which all unacked packets will be considered lost.
  boost::posix_time::ptime send_timeout_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_SENDER_H_
