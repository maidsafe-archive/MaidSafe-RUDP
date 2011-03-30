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

#ifndef MAIDSAFE_DHT_TRANSPORT_RUDP_PACKET_WINDOW_H_
#define MAIDSAFE_DHT_TRANSPORT_RUDP_PACKET_WINDOW_H_

#include <deque>

#include "boost/cstdint.hpp"
#include "maidsafe-dht/transport/rudp_data_packet.h"

namespace maidsafe {

namespace transport {

class RudpPacketWindow {
 public:
  // A constant that probably should be configurable.
  enum { kMaxWindowSize = 16 };

  // The maximum possible sequence number. When reached, sequence numbers are
  // wrapped around to start from 0.
  enum { kMaxSequenceNumber = 0x7fffffff };

  RudpPacketWindow(boost::uint32_t initial_sequence_number);

  // Get the sequence number of the first packet in window.
  boost::uint32_t Begin() const;

  // Get the one-past-the-end sequence number.
  boost::uint32_t End() const;

  // Determine whether a sequence number is in the window.
  bool Contains(boost::uint32_t n) const;

  // Get whether the window is empty.
  bool IsEmpty() const;

  // Get whether the window is full.
  bool IsFull() const;

  // Add a new packet to the end.
  // Precondition: !IsFull().
  boost::uint32_t Append();

  // Remove the first packet from the window.
  // Precondition: !IsEmpty().
  void Remove();

  // Get the packet with the specified sequence number.
  // Precondition: Contains(sequence_number).
  RudpDataPacket &Packet(boost::uint32_t n);

  // Get the sequence number that follows a given number.
  static boost::uint32_t Next(boost::uint32_t n);

 private:
  // Disallow copying and assignment.
  RudpPacketWindow(const RudpPacketWindow&);
  RudpPacketWindow &operator=(const RudpPacketWindow&);

  // The packets in the window.
  std::deque<RudpDataPacket> packets_;

  // The sequence number of the first packet in window.
  boost::uint32_t begin_;

  // The one-past-the-end sequence number for the window. Will be used as the
  // sequence number of the next packet added.
  boost::uint32_t end_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_TRANSPORT_RUDP_PACKET_WINDOW_H_
