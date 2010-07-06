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
#include <boost/lexical_cast.hpp>
#include "maidsafe/kademlia/kadid.h"
#include "maidsafe/base/crypto.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/base/routingtable.h"


TEST(PublicRoutingTableHandlerTest, BEH_BASE_AddTuple) {
  std::string kademlia_id = base::RandomString(64);
  std::string host_ip("192.168.1.188");
  boost::uint16_t host_port = 8888;
  std::string rendezvous_ip("81.149.64.82");
  boost::uint16_t rendezvous_port = 5555;
  std::string public_key = base::RandomString(64);
  float rtt = 200;
  boost::uint16_t rank = 5;
  boost::uint32_t space = 55555;
  base::PublicRoutingTableTuple tuple_to_store(kademlia_id, host_ip, host_port,
      rendezvous_ip, rendezvous_port, public_key, rtt, rank, space);
  base::PublicRoutingTableHandler rt_handler;
  ASSERT_EQ(0, rt_handler.AddTuple(tuple_to_store));
  ASSERT_EQ(0, rt_handler.AddTuple(tuple_to_store));

  base::PublicRoutingTableHandler rt_handler1;
  ASSERT_EQ(0, rt_handler1.AddTuple(tuple_to_store));
  ASSERT_EQ(0, rt_handler1.AddTuple(tuple_to_store));
  rt_handler.Clear();
  rt_handler1.Clear();
}

TEST(PublicRoutingTableHandlerTest, BEH_BASE_ReadTuple) {
  std::string kademlia_id = base::RandomString(64);
  std::string host_ip("192.168.1.188");
  boost::uint16_t host_port = 8888;
  std::string rendezvous_ip("81.149.64.82");
  boost::uint16_t rendezvous_port = 5555;
  std::string public_key = base::RandomString(64);
  float rtt = 200;
  boost::uint16_t rank = 5;
  boost::uint32_t space = 55555;
  base::PublicRoutingTableTuple tuple_to_store(kademlia_id, host_ip, host_port,
      rendezvous_ip, rendezvous_port, public_key, rtt, rank, space);

  base::PublicRoutingTableHandler rt_handler;

  base::PublicRoutingTableTuple non_existing_tuple;
  ASSERT_EQ(1, rt_handler.GetTupleInfo(kademlia_id, &non_existing_tuple));
  ASSERT_EQ(0, rt_handler.AddTuple(tuple_to_store));
  base::PublicRoutingTableTuple retrieved_tuple;
  ASSERT_EQ(0, rt_handler.GetTupleInfo(kademlia_id, &retrieved_tuple));
  ASSERT_EQ(tuple_to_store.kademlia_id, retrieved_tuple.kademlia_id);
  ASSERT_EQ(tuple_to_store.rendezvous_ip, retrieved_tuple.rendezvous_ip);
  ASSERT_EQ(tuple_to_store.rendezvous_port,
    retrieved_tuple.rendezvous_port);
  ASSERT_EQ(tuple_to_store.public_key, retrieved_tuple.public_key);
  ASSERT_EQ(tuple_to_store.rtt, retrieved_tuple.rtt);
  ASSERT_EQ(tuple_to_store.rank, retrieved_tuple.rank);
  ASSERT_EQ(tuple_to_store.space, retrieved_tuple.space);

  base::PublicRoutingTableTuple tuple_to_store1(kademlia_id, host_ip,
                                                host_port + 1, rendezvous_ip,
                                                rendezvous_port + 1, public_key,
                                                rtt + 1, rank, space + 1);

  ASSERT_EQ(0, rt_handler.AddTuple(tuple_to_store1));
  base::PublicRoutingTableTuple retrieved_tuple1;
  ASSERT_EQ(0, rt_handler.GetTupleInfo(kademlia_id, &retrieved_tuple1));
  ASSERT_EQ(tuple_to_store1.kademlia_id, retrieved_tuple1.kademlia_id);
  ASSERT_EQ(tuple_to_store1.rendezvous_ip, retrieved_tuple1.rendezvous_ip);
  ASSERT_EQ(tuple_to_store1.rendezvous_port,
    retrieved_tuple1.rendezvous_port);
  ASSERT_EQ(tuple_to_store1.public_key, retrieved_tuple1.public_key);
  ASSERT_EQ(tuple_to_store1.rtt, retrieved_tuple1.rtt);
  ASSERT_EQ(tuple_to_store1.rank, retrieved_tuple1.rank);
  ASSERT_EQ(tuple_to_store1.space, retrieved_tuple1.space);

  float prev_rtt = tuple_to_store1.rtt;
  tuple_to_store1.rtt = 0.0;
  ASSERT_EQ(0, rt_handler.AddTuple(tuple_to_store1));
  base::PublicRoutingTableTuple retrieved_tuple2;
  ASSERT_EQ(0, rt_handler.GetTupleInfo(kademlia_id, &retrieved_tuple2));
  ASSERT_EQ(tuple_to_store1.kademlia_id, retrieved_tuple2.kademlia_id);
  ASSERT_EQ(tuple_to_store1.rendezvous_ip, retrieved_tuple2.rendezvous_ip);
  ASSERT_EQ(tuple_to_store1.rendezvous_port,
    retrieved_tuple2.rendezvous_port);
  ASSERT_EQ(tuple_to_store1.public_key, retrieved_tuple2.public_key);
  ASSERT_EQ(prev_rtt, retrieved_tuple2.rtt);
  ASSERT_EQ(tuple_to_store1.rank, retrieved_tuple2.rank);
  ASSERT_EQ(tuple_to_store1.space, retrieved_tuple2.space);

  rt_handler.Clear();
}

TEST(PublicRoutingTableHandlerTest, BEH_BASE_DeleteTuple) {
  std::string kademlia_id = base::RandomString(64);
  std::string host_ip("192.168.1.188");
  boost::uint16_t host_port = 8888;
  std::string rendezvous_ip("81.149.64.82");
  boost::uint16_t rendezvous_port = 5555;
  std::string public_key = base::RandomString(64);
  float rtt = 32;
  boost::uint16_t rank = 5;
  boost::uint32_t space = 3232;
  base::PublicRoutingTableTuple tuple_to_store(kademlia_id, host_ip, host_port,
      rendezvous_ip, rendezvous_port, public_key, rtt, rank, space);

  base::PublicRoutingTableHandler rt_handler;

  ASSERT_EQ(0, rt_handler.AddTuple(tuple_to_store));
  base::PublicRoutingTableTuple retrieved_tuple;
  ASSERT_EQ(0, rt_handler.GetTupleInfo(kademlia_id, &retrieved_tuple));
  ASSERT_EQ(0, rt_handler.DeleteTupleByKadId(kademlia_id));
  ASSERT_EQ(1, rt_handler.GetTupleInfo(kademlia_id, &retrieved_tuple));

  rt_handler.Clear();
}

TEST(PublicRoutingTableHandlerTest, BEH_BASE_UpdateTuple) {
  std::string kademlia_id = base::RandomString(64);
  std::string host_ip("192.168.1.188");
  boost::uint16_t host_port = 8888;
  std::string rendezvous_ip("81.149.64.82");
  boost::uint16_t rendezvous_port = 5555;
  std::string public_key = base::RandomString(64);
  float rtt = 32;
  boost::uint16_t rank = 5;
  boost::uint32_t space = 3232;
  base::PublicRoutingTableTuple tuple_to_store(kademlia_id, host_ip, host_port,
      rendezvous_ip, rendezvous_port, public_key, rtt, rank, space);
  base::PublicRoutingTableHandler rt_handler;

  ASSERT_EQ(2, rt_handler.ContactLocal(kademlia_id));
  ASSERT_EQ(0, rt_handler.AddTuple(tuple_to_store));
  ASSERT_EQ(2, rt_handler.ContactLocal(kademlia_id));
  ASSERT_EQ(0, rt_handler.UpdateHostIp(kademlia_id, "211.11.11.11"));
  ASSERT_EQ(0, rt_handler.UpdateHostPort(kademlia_id, 9999));
  ASSERT_EQ(0, rt_handler.UpdateRendezvousIp(kademlia_id, "86.11.11.11"));
  ASSERT_EQ(0, rt_handler.UpdateRendezvousPort(kademlia_id, 888));
  ASSERT_EQ(0, rt_handler.UpdatePublicKey(kademlia_id, "fafevcddc"));
  ASSERT_EQ(0, rt_handler.UpdateRtt(kademlia_id, 50));
  ASSERT_EQ(0, rt_handler.UpdateRank(kademlia_id, 10));
  ASSERT_EQ(0, rt_handler.UpdateSpace(kademlia_id, 6666));
  ASSERT_EQ(0, rt_handler.UpdateContactLocal(kademlia_id, "211.11.11.11",
            kad::LOCAL));
  ASSERT_EQ(0, rt_handler.ContactLocal(kademlia_id));
  base::PublicRoutingTableTuple retrieved_tuple;
  ASSERT_EQ(0, rt_handler.GetTupleInfo(kademlia_id, &retrieved_tuple));
  ASSERT_EQ("211.11.11.11", retrieved_tuple.host_ip);
  ASSERT_EQ(9999, retrieved_tuple.host_port);
  ASSERT_EQ("86.11.11.11", retrieved_tuple.rendezvous_ip);
  ASSERT_EQ(888, retrieved_tuple.rendezvous_port);
  ASSERT_EQ("fafevcddc", retrieved_tuple.public_key);
  ASSERT_EQ(static_cast<boost::uint32_t>(50), retrieved_tuple.rtt);
  ASSERT_EQ(static_cast<boost::uint16_t>(10), retrieved_tuple.rank);
  ASSERT_EQ(static_cast<boost::uint32_t>(6666), retrieved_tuple.space);
  ASSERT_EQ(0, rt_handler.UpdateContactLocal(kademlia_id, "210.11.11.11",
            kad::REMOTE));
  ASSERT_EQ(1, rt_handler.ContactLocal(kademlia_id));
  ASSERT_EQ(0, rt_handler.GetTupleInfo(kademlia_id, &retrieved_tuple));
  ASSERT_EQ("210.11.11.11", retrieved_tuple.host_ip);

  rt_handler.Clear();
}

TEST(PublicRoutingTableHandlerTest, BEH_BASE_UpdateToUnknown) {
  std::string kademlia_id = base::RandomString(64);
  std::string host_ip("192.168.1.188");
  std::string local_ip("192.168.1.187");
  boost::uint16_t local_port = 7777;
  std::string rendezvous_ip("81.149.64.82");
  boost::uint16_t rendezvous_port = 5555;
  std::string public_key = base::RandomString(64);
  float rtt = 32;
  boost::uint16_t rank = 5;
  boost::uint32_t space = 3232;
  base::PublicRoutingTableTuple tuple_to_store(kademlia_id, local_ip,
                                               local_port, rendezvous_ip,
                                               rendezvous_port, public_key, rtt,
                                               rank, space);
  base::PublicRoutingTableHandler rt_handler;
  ASSERT_EQ(2, rt_handler.ContactLocal(kademlia_id));
  ASSERT_EQ(0, rt_handler.AddTuple(tuple_to_store));
  ASSERT_EQ(2, rt_handler.ContactLocal(kademlia_id));
  ASSERT_EQ(0, rt_handler.UpdateContactLocal(kademlia_id, local_ip,
            kad::LOCAL));
  ASSERT_EQ(0, rt_handler.ContactLocal(kademlia_id));
  ASSERT_EQ(0, rt_handler.UpdateLocalToUnknown(local_ip, local_port));
  ASSERT_EQ(2, rt_handler.ContactLocal(kademlia_id));
  rt_handler.Clear();
}

TEST(PublicRoutingTableHandlerTest, BEH_BASE_GetClosestRtt) {
  std::vector<base::PublicRoutingTableTuple> tuples;
  tuples.push_back(base::PublicRoutingTableTuple("id1", "192.168.1.188", 8888,
                   "", 0, "", 35.55, 1, 3232));
  tuples.push_back(base::PublicRoutingTableTuple("id2", "192.168.1.186", 8889,
                   "", 0, "", 24.95, 1, 3232));
  tuples.push_back(base::PublicRoutingTableTuple("id3", "192.168.1.188", 8890,
                   "", 0, "", 64.8, 1, 3232));
  tuples.push_back(base::PublicRoutingTableTuple("id4", "192.168.1.187", 8891,
                   "", 0, "", 35.44, 1, 3232));
  tuples.push_back(base::PublicRoutingTableTuple("id5", "192.168.1.190", 8892,
                   "", 0, "", 48.69, 1, 3232));
  base::PublicRoutingTableHandler rt_handler;
  float rtt = 30;
  std::set<std::string> ex_ids;
  base::PublicRoutingTableTuple rec_tuple;
  ASSERT_EQ(1, rt_handler.GetClosestRtt(rtt, ex_ids, &rec_tuple));
  for (unsigned int n = 0; n < tuples.size(); n++)
    ASSERT_EQ(0, rt_handler.AddTuple(tuples[n]));
  ASSERT_EQ(0, rt_handler.GetClosestRtt(rtt, ex_ids, &rec_tuple));
  ASSERT_EQ(tuples[1].kademlia_id, rec_tuple.kademlia_id);
  ASSERT_EQ(tuples[1].host_ip, rec_tuple.host_ip);
  ASSERT_EQ(tuples[1].rendezvous_ip, rec_tuple.rendezvous_ip);
  ASSERT_EQ(tuples[1].rendezvous_port, rec_tuple.rendezvous_port);
  ASSERT_EQ(tuples[1].rank, rec_tuple.rank);
  ASSERT_EQ(tuples[1].rtt, rec_tuple.rtt);
  ASSERT_EQ(tuples[1].space, rec_tuple.space);

  float distance = rtt - rec_tuple.rtt;
  if (distance < 0)
    distance = distance * -1;

  for (unsigned int n = 0; n < tuples.size(); n++) {
    float tmp_distance = rtt - tuples[n].rtt;
    if (tmp_distance < 0)
      tmp_distance = tmp_distance * -1;
    ASSERT_LE(distance, tmp_distance);
  }

  ex_ids.insert(rec_tuple.kademlia_id);
  ASSERT_EQ(0, rt_handler.GetClosestRtt(rtt, ex_ids, &rec_tuple));
  ASSERT_EQ(tuples[3].kademlia_id, rec_tuple.kademlia_id);
  ASSERT_EQ(tuples[3].host_ip, rec_tuple.host_ip);
  ASSERT_EQ(tuples[3].rendezvous_ip, rec_tuple.rendezvous_ip);
  ASSERT_EQ(tuples[3].rendezvous_port, rec_tuple.rendezvous_port);
  ASSERT_EQ(tuples[3].rank, rec_tuple.rank);
  ASSERT_EQ(tuples[3].rtt, rec_tuple.rtt);
  ASSERT_EQ(tuples[3].space, rec_tuple.space);
  distance = rtt - rec_tuple.rtt;
  if (distance < 0)
    distance = distance * -1;

  for (unsigned int n = 0; n < tuples.size(); n++) {
    if (ex_ids.find(tuples[n].kademlia_id) == ex_ids.end()) {
      float tmp_distance = rtt - tuples[n].rtt;
      if (tmp_distance < 0)
        tmp_distance = tmp_distance * -1;
      ASSERT_LE(distance, tmp_distance);
    }
  }

  rtt = tuples[4].rtt;
  ASSERT_EQ(0, rt_handler.GetClosestRtt(rtt, ex_ids, &rec_tuple));
  ASSERT_EQ(tuples[4].kademlia_id, rec_tuple.kademlia_id);
  ASSERT_EQ(tuples[4].host_ip, rec_tuple.host_ip);
  ASSERT_EQ(tuples[4].rendezvous_ip, rec_tuple.rendezvous_ip);
  ASSERT_EQ(tuples[4].rendezvous_port, rec_tuple.rendezvous_port);
  ASSERT_EQ(tuples[4].rank, rec_tuple.rank);
  ASSERT_EQ(tuples[4].rtt, rec_tuple.rtt);
  ASSERT_EQ(tuples[4].space, rec_tuple.space);
}

TEST(PublicRoutingTableHandlerTest, BEH_BASE_GetClosestContacts) {
  typedef std::map<kad::KadId, base::PublicRoutingTableTuple> TuplesMap;
  TuplesMap tuples;
  std::pair<TuplesMap::iterator, bool> result;
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string target_key = co.Hash(base::RandomString(222), "",
                                   crypto::STRING_STRING, false);
  kad::KadId target_id(target_key);
  const int kTupleCount(177);
  base::PublicRoutingTableHandler rt_handler;
  for (int i = 0; i < kTupleCount; ++i) {
    std::string kad_id = co.Hash(base::RandomString(111), "",
                                 crypto::STRING_STRING, false);
    kad::KadId id(kad_id);
    kad::KadId dist = id ^ target_id;
    result = tuples.insert(std::pair<kad::KadId, base::PublicRoutingTableTuple>(
        dist,
        base::PublicRoutingTableTuple(kad_id, "192.168.1." +
            base::IntToString(i % 256), 8000 + (i % 1000), "", 0, "",
            static_cast<float>(i), 1, 3232)));
    ASSERT_TRUE(result.second);
    ASSERT_EQ(0, rt_handler.AddTuple((*result.first).second));
  }

  std::list<base::PublicRoutingTableTuple> returned_tuples;
  boost::uint32_t requested_count(7);
  ASSERT_EQ(-1, rt_handler.GetClosestContacts(target_key, requested_count,
            NULL));
  ASSERT_EQ(0, rt_handler.GetClosestContacts(target_key, requested_count,
            &returned_tuples));
  ASSERT_EQ(requested_count, returned_tuples.size());
  TuplesMap::iterator tuples_map_itr = tuples.begin();
  std::list<base::PublicRoutingTableTuple>::iterator tuples_itr =
      returned_tuples.begin();
  kad::KadId dist, previous_dist;
  while (tuples_itr != returned_tuples.end()) {
    kad::KadId id((*tuples_itr).kademlia_id);
    dist = id ^ target_id;
    ASSERT_TRUE((*tuples_map_itr).first == dist);
    ASSERT_TRUE(dist > previous_dist);
    ASSERT_EQ((*tuples_map_itr).second.kademlia_id,
              (*tuples_itr).kademlia_id);
    ASSERT_EQ((*tuples_map_itr).second.host_ip, (*tuples_itr).host_ip);
    ASSERT_EQ((*tuples_map_itr).second.host_port, (*tuples_itr).host_port);
    ASSERT_EQ((*tuples_map_itr).second.rtt, (*tuples_itr).rtt);
    ++tuples_map_itr;
    ++tuples_itr;
    previous_dist = dist;
  }

  requested_count = kTupleCount;
  ASSERT_EQ(0, rt_handler.GetClosestContacts(target_key, requested_count,
            &returned_tuples));
  ASSERT_EQ(kTupleCount, returned_tuples.size());
  tuples_map_itr = tuples.begin();
  tuples_itr = returned_tuples.begin();
  kad::KadId zero_id;
  previous_dist = zero_id;
  while (tuples_itr != returned_tuples.end()) {
    kad::KadId id((*tuples_itr).kademlia_id);
    dist = id ^ target_id;
    ASSERT_TRUE((*tuples_map_itr).first == dist);
    ASSERT_TRUE(dist > previous_dist);
    ASSERT_EQ((*tuples_map_itr).second.kademlia_id,
              (*tuples_itr).kademlia_id);
    ASSERT_EQ((*tuples_map_itr).second.host_ip, (*tuples_itr).host_ip);
    ASSERT_EQ((*tuples_map_itr).second.host_port, (*tuples_itr).host_port);
    ASSERT_EQ((*tuples_map_itr).second.rtt, (*tuples_itr).rtt);
    ++tuples_map_itr;
    ++tuples_itr;
    previous_dist = dist;
  }

  requested_count = 2 * kTupleCount;
  ASSERT_EQ(0, rt_handler.GetClosestContacts(target_key, requested_count,
            &returned_tuples));
  ASSERT_EQ(kTupleCount, returned_tuples.size());
  tuples_map_itr = tuples.begin();
  tuples_itr = returned_tuples.begin();
  previous_dist = zero_id;
  while (tuples_itr != returned_tuples.end()) {
    kad::KadId id((*tuples_itr).kademlia_id);
    dist = id ^ target_id;
    ASSERT_TRUE((*tuples_map_itr).first == dist);
    ASSERT_TRUE(dist > previous_dist);
    ASSERT_EQ((*tuples_map_itr).second.kademlia_id,
              (*tuples_itr).kademlia_id);
    ASSERT_EQ((*tuples_map_itr).second.host_ip, (*tuples_itr).host_ip);
    ASSERT_EQ((*tuples_map_itr).second.host_port, (*tuples_itr).host_port);
    ASSERT_EQ((*tuples_map_itr).second.rtt, (*tuples_itr).rtt);
    ++tuples_map_itr;
    ++tuples_itr;
    previous_dist = dist;
  }

  requested_count = 0;
  ASSERT_EQ(0, rt_handler.GetClosestContacts(target_key, requested_count,
            &returned_tuples));
  ASSERT_EQ(kTupleCount, returned_tuples.size());
  tuples_map_itr = tuples.begin();
  tuples_itr = returned_tuples.begin();
  previous_dist = zero_id;
  while (tuples_itr != returned_tuples.end()) {
    kad::KadId id((*tuples_itr).kademlia_id);
    dist = id ^ target_id;
    ASSERT_TRUE((*tuples_map_itr).first == dist);
    ASSERT_TRUE(dist > previous_dist);
    ASSERT_EQ((*tuples_map_itr).second.kademlia_id,
              (*tuples_itr).kademlia_id);
    ASSERT_EQ((*tuples_map_itr).second.host_ip, (*tuples_itr).host_ip);
    ASSERT_EQ((*tuples_map_itr).second.host_port, (*tuples_itr).host_port);
    ASSERT_EQ((*tuples_map_itr).second.rtt, (*tuples_itr).rtt);
    ++tuples_map_itr;
    ++tuples_itr;
    previous_dist = dist;
  }
}

TEST(PublicRoutingTableTest, BEH_BASE_MultipleHandlers) {
  std::string dbname1("routingtable");
  dbname1 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".db");
  std::string dbname2("routingtable");
  dbname2 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".db");
  ASSERT_NE(dbname1, dbname2);
  std::string kademlia_id1 = base::RandomString(64);
  std::string kademlia_id2 = base::RandomString(64);
  ASSERT_NE(kademlia_id1, kademlia_id2);
  std::string host_ip("192.168.1.188");
  boost::uint16_t host_port = 8888;
  std::string rendezvous_ip("81.149.64.82");
  boost::uint16_t rendezvous_port = 5555;
  std::string public_key = base::RandomString(64);
  float rtt = 200;
  boost::uint16_t rank = 5;
  boost::uint32_t space = 55555;
  base::PublicRoutingTableTuple tuple_to_store1(kademlia_id1, host_ip,
                                                host_port, rendezvous_ip,
                                                rendezvous_port, public_key,
                                                rtt, rank, space);
  ASSERT_EQ(0, (*base::PublicRoutingTable::GetInstance())[dbname1]->AddTuple(
      tuple_to_store1));
  base::PublicRoutingTableTuple tuple_to_store2(kademlia_id2, host_ip,
                                                host_port - 1, rendezvous_ip,
                                                rendezvous_port - 1, public_key,
                                                rtt - 100, rank - 2, space);
  ASSERT_EQ(0, (*base::PublicRoutingTable::GetInstance())[dbname2]->AddTuple(
      tuple_to_store2));

  base::PublicRoutingTableTuple rec_tuple_1, rec_tuple_2;
  ASSERT_EQ(1, (*base::PublicRoutingTable::GetInstance())[dbname1]->
            GetTupleInfo(kademlia_id2, &rec_tuple_1));
  ASSERT_EQ(0, (*base::PublicRoutingTable::GetInstance())[dbname1]->
            GetTupleInfo(kademlia_id1, &rec_tuple_1));
  ASSERT_EQ(tuple_to_store1.kademlia_id, rec_tuple_1.kademlia_id);
  ASSERT_EQ(tuple_to_store1.rendezvous_ip, rec_tuple_1.rendezvous_ip);
  ASSERT_EQ(tuple_to_store1.rendezvous_port, rec_tuple_1.rendezvous_port);
  ASSERT_EQ(tuple_to_store1.public_key, rec_tuple_1.public_key);
  ASSERT_EQ(tuple_to_store1.rtt, rec_tuple_1.rtt);
  ASSERT_EQ(tuple_to_store1.rank, rec_tuple_1.rank);
  ASSERT_EQ(tuple_to_store1.space, rec_tuple_1.space);

  ASSERT_EQ(1, (*base::PublicRoutingTable::GetInstance())[dbname2]->
            GetTupleInfo(kademlia_id1, &rec_tuple_2));
  ASSERT_EQ(0, (*base::PublicRoutingTable::GetInstance())[dbname2]->
            GetTupleInfo(kademlia_id2, &rec_tuple_2));
  ASSERT_EQ(tuple_to_store2.kademlia_id, rec_tuple_2.kademlia_id);
  ASSERT_EQ(tuple_to_store2.rendezvous_ip, rec_tuple_2.rendezvous_ip);
  ASSERT_EQ(tuple_to_store2.rendezvous_port, rec_tuple_2.rendezvous_port);
  ASSERT_EQ(tuple_to_store2.public_key, rec_tuple_2.public_key);
  ASSERT_EQ(tuple_to_store2.rtt, rec_tuple_2.rtt);
  ASSERT_EQ(tuple_to_store2.rank, rec_tuple_2.rank);
  ASSERT_EQ(tuple_to_store2.space, rec_tuple_2.space);
}
