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

#ifndef MAIDSAFE_TRANSPORT_RUDP_PACKET_H_
#define MAIDSAFE_TRANSPORT_RUDP_PACKET_H_

#include "boost/asio/buffer.hpp"
#include "boost/cstdint.hpp"
#include "maidsafe/transport/transport.h"

namespace maidsafe {

namespace transport {

class RudpPacket {
 public:
  // Get the destination socket id from an encoded packet.
  static bool DecodeDestinationSocketId(boost::uint32_t *id,
                                        const boost::asio::const_buffer &data);

 protected:
  // Prevent deletion through this type.
  virtual ~RudpPacket();

  // Helper functions for encoding and decoding integers.
  static void DecodeUint32(boost::uint32_t *n, const unsigned char *p);
  static void EncodeUint32(boost::uint32_t n, unsigned char *p);
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_PACKET_H_
