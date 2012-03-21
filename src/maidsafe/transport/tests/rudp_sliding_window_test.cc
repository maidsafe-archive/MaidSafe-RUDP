/* Copyright (c) 2011 maidsafe.net limited
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

#include "maidsafe/common/test.h"
#include "maidsafe/transport/log.h"
#include "maidsafe/transport/rudp_sliding_window.h"

namespace maidsafe {

namespace transport {

namespace test {

static const size_t kTestPacketCount = 100000;

static void TestWindowRange(boost::uint32_t first_sequence_number) {
  RudpSlidingWindow<boost::uint32_t> window(first_sequence_number);

  for (size_t i = 0; i < window.MaximumSize(); ++i) {
    boost::uint32_t n = window.Append();
    window[n] = n;
  }

  for (size_t i = 0; i < kTestPacketCount; ++i) {
    ASSERT_EQ(window.Begin(), window[window.Begin()]);
    window.Remove();
    boost::uint32_t n = window.Append();
    window[n] = n;
  }

  for (size_t i = 0; i < window.MaximumSize(); ++i) {
    ASSERT_EQ(window.Begin(), window[window.Begin()]);
    window.Remove();
  }
}

TEST(RudpSlidingWindowTest, BEH_FromZero) {
  TestWindowRange(0);
}

TEST(RudpSlidingWindowTest, BEH_FromN) {
  TestWindowRange(123456);
}

TEST(RudpSlidingWindowTest, BEH_Wraparound) {
  TestWindowRange(RudpSlidingWindow<boost::uint32_t>::kMaxSequenceNumber -
                  kTestPacketCount / 2);
}

}  // namespace test

}  // namespace transport

}  // namespace maidsafe
