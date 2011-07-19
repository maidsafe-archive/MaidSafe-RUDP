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

#ifndef MAIDSAFE_DHT_TRANSPORT_TESTS_TRANSPORT_API_TEST_H_
#define MAIDSAFE_DHT_TRANSPORT_TESTS_TRANSPORT_API_TEST_H_

#include <memory>
#include <string>
#include <vector>
#include <utility>
#include "boost/thread/mutex.hpp"
#include "boost/thread/thread.hpp"
#include "maidsafe/common/test.h"
#include "maidsafe/dht/transport/transport.h"

namespace maidsafe {

namespace dht {

namespace transport {

namespace test {

class TestMessageHandler;

static const IP kIP(boost::asio::ip::address_v4::loopback());
static const uint16_t kThreadGroupSize = 8;
typedef boost::asio::io_service AsioService;
typedef std::shared_ptr<boost::asio::io_service::work> WorkPtr;
typedef std::shared_ptr<Transport> TransportPtr;
typedef boost::shared_ptr<TestMessageHandler> TestMessageHandlerPtr;
typedef std::vector<std::string> Messages;

typedef std::vector<std::pair<std::string, Info>> IncomingMessages;
typedef std::vector<std::string> OutgoingResponses;
typedef std::vector<TransportCondition> Results;

class TestMessageHandler {
 public:
  explicit TestMessageHandler(const std::string &id);
  void DoOnRequestReceived(const std::string &request,
                           const Info &info,
                           std::string *response,
                           Timeout *timeout);
  void DoOnResponseReceived(const std::string &request,
                            const Info &info,
                            std::string *response,
                            Timeout *timeout);
  void DoOnError(const TransportCondition &tc);
  void ClearContainers();
  IncomingMessages requests_received();
  IncomingMessages responses_received();
  OutgoingResponses responses_sent();
  Results results();
 private:
  TestMessageHandler(const TestMessageHandler&);
  TestMessageHandler& operator=(const TestMessageHandler&);
  std::string this_id_;
  IncomingMessages requests_received_, responses_received_;
  OutgoingResponses responses_sent_;
  Results results_;
  boost::mutex mutex_;
};


template <typename T>
class TransportAPITest: public testing::Test {
 public:
  TransportAPITest();
  ~TransportAPITest();
 protected:
  // Create a transport and an io_service listening on the given or random port
  // (if zero) if listen == true.  If not, only a transport is created, and the
  // test member asio_service_ is used.
  void SetupTransport(bool listen, Port lport);
  void RunTransportTest(const int &num_messages);
  void SendRPC(TransportPtr sender_pt, TransportPtr listener_pt);
  void CheckMessages();

  AsioService asio_service_, asio_service_1_, asio_service_2_, asio_service_3_;
  WorkPtr work_, work_1_, work_2_, work_3_;
  std::vector<TransportPtr> listening_transports_;
  std::vector<TestMessageHandlerPtr> listening_message_handlers_;
  std::vector<TransportPtr> sending_transports_;
  std::vector<TestMessageHandlerPtr> sending_message_handlers_;
  boost::thread_group thread_group_;
  boost::thread_group thread_group_1_;
  boost::thread_group thread_group_2_;
  boost::thread_group thread_group_3_;
  boost::mutex mutex_;
  std::vector<std::string> request_messages_;
  uint16_t count_;
};

TYPED_TEST_CASE_P(TransportAPITest);

}  // namespace test

}  // namespace transport

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_TRANSPORT_TESTS_TRANSPORT_API_TEST_H_
