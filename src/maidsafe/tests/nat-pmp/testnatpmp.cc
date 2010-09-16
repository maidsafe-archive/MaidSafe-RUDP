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

#include <gtest/gtest.h>

#include <boost/asio/io_service.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>

#include "maidsafe/nat-pmp/natpmpclient.h"

class NATPMPTest : public testing::Test {
 public:
  NATPMPTest() {}
};

TEST_F(NATPMPTest, FUNC_NATPMP_Test) {
  boost::asio::io_service ios;

  natpmp::NatPmpClient client(&ios);

  boost::uint16_t tcp_port = 33333;
  boost::uint16_t udp_port = 33333;

  printf("Starting NAT-PMP...\n");

  printf("Requesting external ip address from gateway.\n");

  client.Start();

  printf("Queueing mapping request for tcp port %d to %d.\n", tcp_port,
         tcp_port);

  client.MapPort(natpmp::Protocol::kTcp, 33333, 33333, 3600);

  printf("Queueing mapping request for udp port %d to %d.\n", udp_port,
         udp_port);

  client.MapPort(natpmp::Protocol::kUdp, 33333, 33333, 3600);

  boost::shared_ptr<boost::thread> thread(new boost::thread(
      boost::bind(&boost::asio::io_service::run, &ios)));

  printf("Sleeping for 64 seconds...\n");

  boost::this_thread::sleep(boost::posix_time::seconds(64));

  printf("Stopping NAT-PMP...\n");

  client.Stop();
}
