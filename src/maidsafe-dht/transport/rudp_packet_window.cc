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

#include "maidsafe-dht/transport/rudp_packet_window.h"

#include <cassert>

namespace maidsafe {

namespace transport {

RudpPacketWindow::RudpPacketWindow(boost::uint32_t initial_sequence_number)
  : begin_(initial_sequence_number),
    end_(initial_sequence_number) {
  assert(initial_sequence_number <= kMaxSequenceNumber);
}

boost::uint32_t RudpPacketWindow::Begin() const {
  return begin_;
}

boost::uint32_t RudpPacketWindow::End() const {
  return end_;
}

bool RudpPacketWindow::Contains(boost::uint32_t n) const {
  if (begin_ <= end_)
    return (begin_ <= n) && (n < end_);
  else
    return (n < end_) || ((n >= begin_) && (n <= kMaxSequenceNumber));
}

bool RudpPacketWindow::IsEmpty() const {
  return packets_.empty();
}

bool RudpPacketWindow::IsFull() const {
  return packets_.size() == kMaxWindowSize;
}

boost::uint32_t RudpPacketWindow::Append() {
  assert(!IsFull());
  packets_.push_back(RudpDataPacket());
  boost::uint32_t n = end_;
  end_ = Next(end_);
  return n;
}

void RudpPacketWindow::Remove() {
  assert(!IsEmpty());
  packets_.erase(packets_.begin());
  begin_ = Next(begin_);
}

RudpDataPacket &RudpPacketWindow::Packet(boost::uint32_t n) {
  assert(Contains(n));
  if (begin_ <= end_)
    return packets_[n - begin_];
  else if (n < end_)
    return packets_[kMaxSequenceNumber - begin_ + n + 1];
  else
    return packets_[n - begin_];
}

boost::uint32 RudpPacketWindow::Next(boost::uint32 n) {
  return (n == kMaxSequenceNumber) ? 0 : n + 1;
}

}  // namespace transport

}  // namespace maidsafe
