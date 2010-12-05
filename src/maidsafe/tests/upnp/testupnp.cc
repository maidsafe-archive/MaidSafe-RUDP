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
#include <boost/bind.hpp>
#include "maidsafe/base/log.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/upnp/upnpclient.h"

// Test depends on external UPnP device, but doesn't fail if none found

class UpnpTest: public testing::Test {
 public:
  UpnpTest() : num_total_mappings(3), num_curr_mappings(0) {}
  void OnNewMapping(const int &port, const upnp::ProtocolType &protocol);
  void OnLostMapping(const int &port, const upnp::ProtocolType &protocol);
  void OnFailedMapping(const int &port, const upnp::ProtocolType &protocol);

  int num_total_mappings;
  int num_curr_mappings;
};

void UpnpTest::OnNewMapping(const int &port,
                            const upnp::ProtocolType &protocol) {
  num_curr_mappings++;
  DLOG(INFO) << "New port mapping: " << (protocol == upnp::kUdp ? "UDP" : "TCP")
             << " " << port << std::endl;
}

void UpnpTest::OnLostMapping(const int &port,
                             const upnp::ProtocolType &protocol) {
  num_curr_mappings--;
  DLOG(INFO) << "Lost port mapping: " << (protocol == upnp::kUdp ? "UD" : "TC")
             << "P " << port << std::endl;
}

void UpnpTest::OnFailedMapping(const int &port,
                               const upnp::ProtocolType &protocol) {
  DLOG(INFO) << "Failed port mapping: "
             << (protocol == upnp::kUdp ? "UDP" : "TCP") << " " << port
             << std::endl;
}

TEST_F(UpnpTest, FUNC_UPNP_PortMappingTest) {
  upnp::UpnpIgdClient upnp;

  DLOG(INFO) << "Initialising UPnP..." << std::endl;

  ASSERT_TRUE(upnp.InitControlPoint());

  if (upnp.IsAsync()) {
    upnp.SetNewMappingCallback(
      boost::bind(&UpnpTest::OnNewMapping, this, _1, _2));
    upnp.SetLostMappingCallback(
      boost::bind(&UpnpTest::OnLostMapping, this, _1, _2));
    upnp.SetFailedMappingCallback(
      boost::bind(&UpnpTest::OnFailedMapping, this, _1, _2));
  }

  // boost::this_thread::sleep(boost::posix_time::seconds(2));

  boost::int32_t start_port((base::RandomUint32() % 15000)
                   + 50000);

  bool all_added = true;
  for (int i = 0; i < num_total_mappings; ++i) {
    all_added &= upnp.AddPortMapping(start_port + i, upnp::kTcp);
  }

  if (upnp.IsAsync()) {
    DLOG(INFO) << "Waiting..." << std::endl;
    boost::this_thread::sleep(boost::posix_time::seconds(3));
  }

  if (upnp.HasServices()) {
    DLOG(INFO) << "External IP: " << upnp.GetExternalIpAddress() << std::endl;
    ASSERT_TRUE(all_added);
    if (upnp.IsAsync()) {
      ASSERT_TRUE(num_curr_mappings == num_total_mappings);
    }
    DLOG(INFO) << "All UPnP mappings successful." << std::endl;
  } else {
    DLOG(INFO) << "Sorry, no port mappings via UPnP possible." << std::endl;
  }
  ASSERT_TRUE(upnp.DeletePortMapping(start_port + num_total_mappings - 1,
                                     upnp::kTcp));
}
