/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

// Original author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#include "maidsafe/common/test.h"
#include "maidsafe/common/log.h"
#include "maidsafe/rudp/core/sliding_window.h"

namespace maidsafe {

namespace rudp {

namespace detail {

namespace test {

static const size_t kTestPacketCount = 100000;

static void TestWindowRange(uint32_t first_sequence_number) {
  SlidingWindow<uint32_t> window(first_sequence_number);

  for (size_t i = 0; i < window.MaximumSize(); ++i) {
    uint32_t n = window.Append();
    window[n] = n;
  }

  for (size_t i = 0; i < kTestPacketCount; ++i) {
    ASSERT_EQ(window.Begin(), window[window.Begin()]);
    window.Remove();
    uint32_t n = window.Append();
    window[n] = n;
  }

  for (size_t i = 0; i < window.MaximumSize(); ++i) {
    ASSERT_EQ(window.Begin(), window[window.Begin()]);
    window.Remove();
  }
}

TEST(SlidingWindowTest, BEH_FromZero) {
  TestWindowRange(0);
}

TEST(SlidingWindowTest, BEH_FromN) {
  TestWindowRange(123456);
}

TEST(SlidingWindowTest, BEH_Wraparound) {
  TestWindowRange(SlidingWindow<uint32_t>::kMaxSequenceNumber - kTestPacketCount / 2);
}

}  // namespace test

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
