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
#include "maidsafe/base/calllatertimer.h"
#include "maidsafe/base/online.h"

bool o1, o2, o3, o4;

void Observer1(bool b) {
  o1 = b;
  printf("Variable 1 has changed to %s.\n", b ? "TRUE" : "FALSE");
}

void Observer2(bool b) {
  o2 = b;
  printf("Variable 2 has changed to %s.\n", b ? "TRUE" : "FALSE");
}

void Observer3(bool b) {
  o3 = b;
  printf("Variable 3 has changed to %s.\n", b ? "TRUE" : "FALSE");
}

void Observer4(bool b) {
  o4 = b;
  printf("Variable 4 has changed to %s.\n", b ? "TRUE" : "FALSE");
}

TEST(OnlineControllerTest, BEH_BASE_SingletonAddress) {
  base::OnlineController *olc1 = base::OnlineController::Instance();
  olc1->Reset();
  base::OnlineController *olc2 = base::OnlineController::Instance();
  ASSERT_EQ(olc1, olc2);
  olc1 = olc2 = NULL;
}

TEST(OnlineControllerTest, BEH_BASE_OnlineReset) {
  base::OnlineController *olc1 = base::OnlineController::Instance();
  olc1->Reset();
  base::OnlineController *olc2 = base::OnlineController::Instance();
  ASSERT_EQ(olc1, olc2);
  ASSERT_FALSE(olc1->Online(0));
  ASSERT_FALSE(olc2->Online(0));

  olc1->SetOnline(0, true);
  ASSERT_TRUE(olc1->Online(0));
  ASSERT_TRUE(olc2->Online(0));

  olc2->Reset();
  ASSERT_FALSE(olc1->Online(0));
  ASSERT_FALSE(olc2->Online(0));

  olc1 = olc2 = NULL;
}

TEST(OnlineControllerTest, BEH_BASE_SetGetOnline) {
  base::OnlineController *olc1 = base::OnlineController::Instance();
  olc1->Reset();
  base::OnlineController *olc2 = base::OnlineController::Instance();
  ASSERT_EQ(olc1, olc2);
  ASSERT_FALSE(olc1->Online(0));
  ASSERT_FALSE(olc2->Online(0));

  olc1->SetOnline(0, true);
  ASSERT_TRUE(olc1->Online(0));
  ASSERT_TRUE(olc2->Online(0));

  olc2->SetOnline(0, false);
  ASSERT_FALSE(olc1->Online(0));
  ASSERT_FALSE(olc2->Online(0));

  olc2->SetOnline(0, true);
  ASSERT_TRUE(olc1->Online(0));
  ASSERT_TRUE(olc2->Online(0));

  olc2->SetOnline(0, false);
  ASSERT_FALSE(olc1->Online(0));
  ASSERT_FALSE(olc2->Online(0));

  olc1->Reset();
  olc1 = olc2 = NULL;
}

TEST(OnlineControllerTest, BEH_BASE_ThreadedSetGetOnline) {
  base::OnlineController *olc1 = base::OnlineController::Instance();
  olc1->Reset();
  base::OnlineController *olc2 = base::OnlineController::Instance();
  ASSERT_EQ(olc1, olc2);
  ASSERT_FALSE(olc1->Online(0));
  ASSERT_FALSE(olc2->Online(0));

  base::CallLaterTimer clt_;
  ASSERT_TRUE(clt_.IsStarted());
  clt_.CancelAll();
  clt_.AddCallLater(500, boost::bind(&base::OnlineController::SetOnline,
                    olc1, 0, true));

  while (!olc2->Online(0))
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));

  ASSERT_TRUE(olc1->Online(0));
  ASSERT_TRUE(olc2->Online(0));

  clt_.AddCallLater(500, boost::bind(&base::OnlineController::SetOnline,
                    olc2, 0, false));

  while (olc1->Online(0))
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));

  ASSERT_FALSE(olc1->Online(0));
  ASSERT_FALSE(olc2->Online(0));

  olc1 = olc2 = NULL;
}

TEST(OnlineControllerTest, BEH_BASE_ObserverRegistration) {
  base::OnlineController *olc1 = base::OnlineController::Instance();
  olc1->Reset();
  base::OnlineController *olc2 = base::OnlineController::Instance();
  ASSERT_EQ(olc1, olc2);
  ASSERT_FALSE(olc1->Online(0));
  ASSERT_FALSE(olc2->Online(0));

  ASSERT_EQ(0, olc1->ObserversCount());
  ASSERT_EQ(0, olc2->ObserversCount());

  boost::uint16_t id1 = olc1->RegisterObserver(0, boost::bind(&Observer1, _1));
  ASSERT_LT(0, id1);
  ASSERT_GT(65536, id1);
  ASSERT_EQ(1, olc1->ObserversCount());
  ASSERT_EQ(1, olc2->ObserversCount());

  olc1->SetOnline(0, false);
  ASSERT_FALSE(o1);

  olc2->SetOnline(0, true);
  ASSERT_TRUE(o1);

  olc1->Reset();
  ASSERT_EQ(0, olc1->ObserversCount());
  ASSERT_EQ(0, olc2->ObserversCount());
  ASSERT_TRUE(o1);

  id1 = olc1->RegisterObserver(0, boost::bind(&Observer1, _1));
  ASSERT_EQ(1, olc1->ObserversCount());
  ASSERT_FALSE(olc1->UnregisterObserver((id1 + 1) % 65536));
  ASSERT_EQ(1, olc1->ObserversCount());
  ASSERT_TRUE(olc1->UnregisterObserver(id1));
  ASSERT_EQ(0, olc1->ObserversCount());

  olc1 = olc2 = NULL;
}

TEST(OnlineControllerTest, BEH_BASE_MultipleObserverRegistration) {
  base::OnlineController *olc1 = base::OnlineController::Instance();
  olc1->Reset();
  base::OnlineController *olc2 = base::OnlineController::Instance();
  ASSERT_EQ(olc1, olc2);
  ASSERT_FALSE(olc1->Online(0));
  ASSERT_FALSE(olc2->Online(0));

  ASSERT_EQ(0, olc1->ObserversCount());
  ASSERT_EQ(0, olc2->ObserversCount());

  boost::uint16_t id1 = olc1->RegisterObserver(0, boost::bind(&Observer1, _1));
  ASSERT_EQ(1, olc1->ObserversCount());
  ASSERT_EQ(1, olc2->ObserversCount());

  boost::uint16_t id2 = olc1->RegisterObserver(0, boost::bind(&Observer2, _1));
  ASSERT_EQ(2, olc1->ObserversCount());
  ASSERT_EQ(2, olc2->ObserversCount());
  ASSERT_NE(id1, id2);

  olc1->SetOnline(0, false);
  ASSERT_FALSE(o1);
  ASSERT_FALSE(o2);

  olc2->SetOnline(0, true);
  ASSERT_TRUE(o1);
  ASSERT_TRUE(o2);

  ASSERT_TRUE(olc1->UnregisterObserver(id2));
  ASSERT_EQ(1, olc1->ObserversCount());
  ASSERT_EQ(1, olc2->ObserversCount());

  olc1->SetOnline(0, false);
  ASSERT_FALSE(o1);
  ASSERT_TRUE(o2);

  olc1->Reset();
  ASSERT_EQ(0, olc1->ObserversCount());
  ASSERT_EQ(0, olc2->ObserversCount());
  ASSERT_FALSE(o1);
  ASSERT_TRUE(o2);

  olc1 = olc2 = NULL;
}

TEST(OnlineControllerTest, BEH_BASE_GroupedObserverRegistration) {
  printf("Zeroth.\n");
  base::OnlineController *olc = base::OnlineController::Instance();
  olc->Reset();

  ASSERT_EQ(0, olc->ObserversCount());
  ASSERT_EQ(0, olc->ObserversInGroupCount(0));
  ASSERT_EQ(0, olc->ObserversInGroupCount(1));
  ASSERT_EQ(0, olc->ObserversInGroupCount(2));
  printf("After first group count.\n");

  ASSERT_FALSE(olc->Online(0));
  ASSERT_FALSE(olc->Online(1));
  ASSERT_FALSE(olc->Online(2));
  printf("After first online check.\n");

  olc->RegisterObserver(0, boost::bind(&Observer1, _1));
  olc->RegisterObserver(0, boost::bind(&Observer2, _1));
  boost::uint16_t id3 = olc->RegisterObserver(0, boost::bind(&Observer3, _1));
  olc->RegisterObserver(1, boost::bind(&Observer4, _1));
  printf("After registering some observers %d.\n", id3);

  ASSERT_EQ(4, olc->ObserversCount());
  ASSERT_EQ(3, olc->ObserversInGroupCount(0));
  ASSERT_EQ(1, olc->ObserversInGroupCount(1));
  ASSERT_EQ(0, olc->ObserversInGroupCount(2));
  printf("After second group count.\n");

  olc->SetAllOnline(true);
  ASSERT_TRUE(olc->Online(0));
  ASSERT_TRUE(olc->Online(1));
  ASSERT_FALSE(olc->Online(2));  // group never used
  ASSERT_TRUE(o1);
  ASSERT_TRUE(o2);
  ASSERT_TRUE(o3);
  ASSERT_TRUE(o4);
  printf("After second online check.\n");

  olc->SetOnline(0, false);
  ASSERT_FALSE(olc->Online(0));
  ASSERT_TRUE(olc->Online(1));
  ASSERT_FALSE(olc->Online(2));
  ASSERT_FALSE(o1);
  ASSERT_FALSE(o2);
  ASSERT_FALSE(o3);
  ASSERT_TRUE(o4);
  printf("After third online check.\n");

  olc->UnregisterObserver(id3);
  ASSERT_EQ(3, olc->ObserversCount());
  ASSERT_EQ(2, olc->ObserversInGroupCount(0));
  ASSERT_EQ(1, olc->ObserversInGroupCount(1));
  ASSERT_EQ(0, olc->ObserversInGroupCount(2));
  printf("After unregistering observer 3.\n");

  olc->SetOnline(0, true);
  ASSERT_TRUE(olc->Online(0));
  ASSERT_TRUE(olc->Online(1));
  ASSERT_FALSE(olc->Online(2));
  ASSERT_TRUE(o1);
  ASSERT_TRUE(o2);
  ASSERT_FALSE(o3);
  ASSERT_TRUE(o4);
  printf("After fourth online check.\n");

  olc->UnregisterGroup(0);
  printf("After call to unregister\n");
  ASSERT_EQ(1, olc->ObserversCount());
  ASSERT_EQ(0, olc->ObserversInGroupCount(0));
  ASSERT_EQ(1, olc->ObserversInGroupCount(1));
  ASSERT_EQ(0, olc->ObserversInGroupCount(2));
  printf("After unregistering observer 0.\n");

  olc->SetAllOnline(false);
  ASSERT_FALSE(olc->Online(0));
  ASSERT_FALSE(olc->Online(1));
  ASSERT_FALSE(olc->Online(2));
  ASSERT_TRUE(o1);
  ASSERT_TRUE(o2);
  ASSERT_FALSE(o3);
  ASSERT_FALSE(o4);
  printf("After fifth online check.\n");

  olc->UnregisterAll();
  ASSERT_EQ(0, olc->ObserversCount());
  ASSERT_EQ(0, olc->ObserversInGroupCount(0));
  ASSERT_EQ(0, olc->ObserversInGroupCount(1));
  ASSERT_EQ(0, olc->ObserversInGroupCount(2));
  printf("After unregistering all observers.\n");

  olc->SetOnline(0, true);
  ASSERT_TRUE(olc->Online(0));
  olc->Reset();
  ASSERT_FALSE(olc->Online(0));
  printf("After last online check.\n");

  olc = NULL;
}
