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

#include <functional>
#include <vector>

#include "maidsafe/common/test.h"

#include "maidsafe/transport/managed_connection.h"
#include "maidsafe/transport/log.h"


namespace args = std::placeholders;
namespace asio = boost::asio;
namespace bptime = boost::posix_time;
namespace ip = asio::ip;

namespace maidsafe {

namespace transport {

namespace test {

void AddCallback(const TransportCondition &expected,
                 const TransportCondition &actual) {
  EXPECT_EQ(expected, actual);
  DLOG(INFO) << "AddCallback called - result : " << actual;
}

void LostCallback(const Endpoint& expected, const Endpoint& actual) {
  EXPECT_EQ(expected, actual);
  DLOG(INFO) << "LostCallback called for peer endpoint : " << actual.port;
}


void DoOnResponseReceived(const std::string &sent_request,
                          const TransportCondition& result,
                          std::string response) {
  DLOG(INFO) << " - Received response callback returned: (" << result
             << ") response: \"" << response << "\""
             <<  "sent_request = " << sent_request;
}

void DoOnRequestReceived(const std::string &request,
                         const Info &/*info*/,
                         std::string *response,
                         Timeout *timeout) {
  Sleep(boost::posix_time::milliseconds(10));
  *response = "Accepted";
  *timeout = kDefaultInitialTimeout;
  DLOG(INFO) << " - Received request: \"" << request
             << "\".  Responding with \"" << *response << "\"";
}

void DoOnManagedConnectionRequest(const std::string &request,
                                  const Info &info,
                                  std::string *response,
                                  Timeout *timeout,
                                  std::shared_ptr<ManagedConnection> mngd_conn) {
  Sleep(boost::posix_time::milliseconds(10));
  *timeout = kDefaultInitialTimeout;
  *timeout= boost::posix_time::pos_infin;
  *response = "Accepted";
  DLOG(INFO) << " - Received managed connection request: \"" << request
             << "\".  Responding with \"" << *response << "\"";
  mngd_conn->AcceptConnection(info.endpoint, true);
  DLOG(INFO) << " - Done AcceptConnection";
}

TEST(ManagedConnectionTest, BEH_AddConnection) {
  std::shared_ptr<ManagedConnection> mngd_conn_1, mngd_conn_2;
  Endpoint endpoint_1, endpoint_2;

  mngd_conn_1.reset(new ManagedConnection);
  mngd_conn_2.reset(new ManagedConnection);

  EXPECT_EQ(kSuccess, mngd_conn_1->Init(20));
  EXPECT_EQ(kSuccess, mngd_conn_2->Init(20));

  endpoint_1 = mngd_conn_1->GetOurEndpoint();
  EXPECT_NE(0U, endpoint_1.port);
  endpoint_2 = mngd_conn_2->GetOurEndpoint();
  EXPECT_NE(0U, endpoint_2.port);
  ASSERT_FALSE(endpoint_1 == endpoint_2);

  Sleep(bptime::milliseconds(100));

  auto managed_connection_request2 =
      mngd_conn_2->on_message_received()->connect(
        std::bind(&DoOnManagedConnectionRequest, args::_1,  args::_2, args::_3,
                  args::_4, mngd_conn_2));


  AddFunctor add_functor(std::bind(&AddCallback, kSuccess, args::_1));
  mngd_conn_1->AddConnection(endpoint_2, "validation_data_1", add_functor);

  Sleep(bptime::milliseconds(20000));
  managed_connection_request2.disconnect();
  DLOG(INFO) << "Testing Send() now ..........................................";

  auto on_message_received_2 = mngd_conn_2->on_message_received()->connect(
        std::bind(&DoOnRequestReceived, args::_1,  args::_2, args::_3,
                  args::_4));
  // Send on managed connection
  std::string sent_request("send_data from 1");

  ResponseFunctor response_functor = std::bind(&DoOnResponseReceived,
                                               sent_request, args::_1, args::_2);
  mngd_conn_1->Send(endpoint_2, sent_request, response_functor);

  Sleep(bptime::milliseconds(2000));

#if 0
  DLOG(INFO) << "Testing ConnectionLost ......................................";

  LostFunctor lost_functor(std::bind(&LostCallback, endpoint_2, args::_1));
  mngd_conn_1->ConnectionLost(lost_functor);
  mngd_conn_2->RemoveConnection(endpoint_1);
  Sleep(bptime::milliseconds(30000));

#endif
}

}  // namespace test

}  // namespace transport

}  // namespace maidsafe
