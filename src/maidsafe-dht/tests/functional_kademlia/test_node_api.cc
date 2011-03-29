/* Copyright (c) 2009 maidsafe.net limited
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

#include <exception>
#include <list>
#include <set>
#include <vector>

#include "gtest/gtest.h"
#include "boost/asio.hpp"
#include "boost/bind.hpp"
#include "boost/function.hpp"
#include "boost/cstdint.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/progress.hpp"
#include "boost/lexical_cast.hpp"

#include "maidsafe-dht/kademlia/node-api.h"
#include "maidsafe-dht/kademlia/node_impl.h"

extern std::vector<boost::shared_ptr<maidsafe::kademlia::Node> > nodes_;
extern boost::uint16_t kNetworkSize;

namespace maidsafe {

namespace kademlia {

namespace test {

class NodeApiTest: public testing::Test {
 protected:
  NodeApiTest() {}
  ~NodeApiTest() {}
};

TEST_F(NodeApiTest, BEH_KAD_NodeApi) {
  EXPECT_EQ(kNetworkSize, nodes_.size());
}

}  // namespace test_node

}  // namespace kademlia

}  // namespace maidsafe
