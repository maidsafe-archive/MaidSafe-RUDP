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

#ifndef MAIDSAFE_DHT_TRANSPORT_RUDP_SLIDING_WINDOW_H_
#define MAIDSAFE_DHT_TRANSPORT_RUDP_SLIDING_WINDOW_H_

#include <cassert>
#include <deque>

#include "boost/cstdint.hpp"

namespace maidsafe {

namespace transport {

template <typename T>
class RudpSlidingWindow {
 public:
  // A constant that probably should be configurable.
  enum { kMaxWindowSize = 64 };

  // The maximum possible sequence number. When reached, sequence numbers are
  // wrapped around to start from 0.
  enum { kMaxSequenceNumber = 0x7fffffff };

  RudpSlidingWindow(boost::uint32_t initial_sequence_number)
    : begin_(initial_sequence_number), end_(initial_sequence_number) {
    assert(initial_sequence_number <= kMaxSequenceNumber);
  }

  // Get the sequence number of the first item in window.
  boost::uint32_t Begin() const {
    return begin_;
  }

  // Get the one-past-the-end sequence number.
  boost::uint32_t End() const {
    return end_;
  }

  // Determine whether a sequence number is in the window.
  bool Contains(boost::uint32_t n) const {
    if (begin_ <= end_)
      return (begin_ <= n) && (n < end_);
    else
      return (n < end_) || ((n >= begin_) && (n <= kMaxSequenceNumber));
  }

  // Get whether the window is empty.
  bool IsEmpty() const {
    return items_.empty();
  }

  // Get whether the window is full.
  bool IsFull() const {
    return items_.size() == kMaxWindowSize;
  }

  // Add a new item to the end.
  // Precondition: !IsFull().
  boost::uint32_t Append() {
    assert(!IsFull());
    items_.push_back(T());
    boost::uint32_t n = end_;
    end_ = Next(end_);
    return n;
  }

  // Remove the first item from the window.
  // Precondition: !IsEmpty().
  void Remove() {
    assert(!IsEmpty());
    items_.erase(items_.begin());
    begin_ = Next(begin_);
  }

  // Get the item with the specified sequence number.
  // Precondition: Contains(n).
  T &operator[](boost::uint32_t n) {
    assert(Contains(n));
    if (begin_ <= end_)
      return items_[n - begin_];
    else if (n < end_)
      return items_[kMaxSequenceNumber - begin_ + n + 1];
    else
      return items_[n - begin_];
  }

  // Get the sequence number that follows a given number.
  static boost::uint32_t Next(boost::uint32_t n) {
    return (n == kMaxSequenceNumber) ? 0 : n + 1;
  }

 private:
  // Disallow copying and assignment.
  RudpSlidingWindow(const RudpSlidingWindow&);
  RudpSlidingWindow &operator=(const RudpSlidingWindow&);

  // The items in the window.
  std::deque<T> items_;

  // The sequence number of the first item in window.
  boost::uint32_t begin_;

  // The one-past-the-end sequence number for the window. Will be used as the
  // sequence number of the next item added.
  boost::uint32_t end_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_TRANSPORT_RUDP_SLIDING_WINDOW_H_
