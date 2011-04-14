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

#ifndef MAIDSAFE_DHT_TESTS_FUNCTIONAL_KADEMLIA_TEST_NODE_ENVIRONMENT_H_
#define MAIDSAFE_DHT_TESTS_FUNCTIONAL_KADEMLIA_TEST_NODE_ENVIRONMENT_H_

#include <bitset>
#include <memory>

#include "gtest/gtest.h"

#include "boost/filesystem.hpp"
#include "boost/lexical_cast.hpp"
#include "boost/thread.hpp"
#include "boost/asio/io_service.hpp"

#include "maidsafe/common/utils.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/dht/kademlia/config.h"
#include "maidsafe/dht/kademlia/alternative_store.h"
#include "maidsafe/dht/kademlia/securifier.h"
#include "maidsafe/dht/kademlia/utils.h"
#include "maidsafe/dht/kademlia/contact.h"
#include "maidsafe/dht/kademlia/node-api.h"
#include "maidsafe/dht/kademlia/node_impl.h"
#include "maidsafe/dht/transport/tcp_transport.h"
#include "maidsafe/dht/transport/transport.h"
#include "maidsafe/dht/kademlia/message_handler.h"
#include "maidsafe/dht/transport/utils.h"

namespace fs = boost::filesystem;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace dht {

namespace kademlia {

namespace test {

typedef std::shared_ptr<boost::asio::io_service::work> WorkPtr;
typedef std::shared_ptr<boost::thread_group> ThreadGroupPtr;

class EnvironmentNodes : public ::testing::Environment {
 public:
  EnvironmentNodes(
      boost::uint16_t num_of_nodes,
      boost::uint16_t k,
      boost::uint16_t alpha,
      boost::uint16_t beta,
      boost::uint16_t num_of_servers,
      const bptime::time_duration &mean_refresh_interval);

 protected:
  virtual void SetUp();
  virtual void TearDown();
};

}   //  namespace test

}   //  namespace kademlia

}   //  namespace dht

}   //   namespace maidsafe

#endif  // MAIDSAFE_DHT_TESTS_FUNCTIONAL_KADEMLIA_TEST_NODE_ENVIRONMENT_H_
