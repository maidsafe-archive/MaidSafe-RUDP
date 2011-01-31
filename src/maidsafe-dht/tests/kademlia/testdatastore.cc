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

#include <string>
#include <vector>
#include "boost/cstdint.hpp"
#include "boost/shared_ptr.hpp"
#include "boost/thread/thread.hpp"
#include "boost/thread/barrier.hpp"
#include "boost/lexical_cast.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"
#include "gtest/gtest.h"
#include "maidsafe-dht/common/platform_config.h"
#include "maidsafe-dht/common/crypto.h"
#include "maidsafe-dht/common/utils.h"
#include "maidsafe-dht/kademlia/config.h"
#include "maidsafe-dht/kademlia/datastore.h"

namespace maidsafe {

namespace kademlia {

namespace test {
  typedef std::vector<std::pair<std::string, std::string>> KeyValuePair;
  const boost::uint16_t kIterartorSize = 23;
  const boost::uint16_t kThreadBarrierSize = 5;
class DataStoreTest: public testing::Test {
 public:
  DataStoreTest() : test_ds_() {}

  virtual void SetUp() {
    test_ds_.reset(new kademlia::DataStore(bptime::seconds(3600)));
    thread_barrier_.reset(new boost::barrier(kThreadBarrierSize));
    thread_barrier_1_.reset(new boost::barrier(kThreadBarrierSize));
  }
  bool findValue(std::pair<std::string, std::string> element, 
                 std::pair<std::string, std::string> value) {
    return ((element.first == value.first) && (element.second == value.second));  
  }
  void CheckKey(const std::string &key) {
    thread_barrier_->wait();
    EXPECT_TRUE(test_ds_->HasKey(key));
  }
  void CheckLoadKeyAppendableAttr(const std::string &key) {
    thread_barrier_1_->wait();
    auto appendable_attr = test_ds_->LoadKeyAppendableAttr(key);
    EXPECT_FALSE(appendable_attr[0].second);
  }
  void MakeMultipleEntries() {
    for(int i = 1; i < 1001; ++i) {
      bptime::ptime expire_time = bptime::microsec_clock::universal_time();
      expire_time += bptime::hours(20);
      bptime::ptime refresh_time = expire_time - bptime::hours(10);
      KeyValueSignature key_value_signature(RandomString(i*7),
                                            RandomString(i*11),
                                            RandomString(i*13));
      test_ds_->key_value_index_.insert(KeyValueTuple(key_value_signature,
                                                      expire_time,
                                                      refresh_time, false));
      if(i > 0 && i < 47) // kIterartorSize * 2
        key_value_from_front_.push_back(make_pair(key_value_signature.key,
                                                  key_value_signature.value));
      if(i > 500 && i < 570) // kIterartorSize * 3
        key_value_from_mid_.push_back(key_value_signature);
      if(i > 942 && i < 990) // kIterartorSize * 2
        key_value_from_end_.push_back(make_pair(key_value_signature.key,
                                                key_value_signature.value));
    }
  }

  KeyValueIndex& GetKeyValueIndex() { return test_ds_->key_value_index_; }

protected:
  boost::shared_ptr<boost::barrier> thread_barrier_, thread_barrier_1_;
  boost::shared_ptr<DataStore> test_ds_;
  KeyValuePair key_value_from_front_, key_value_from_end_;
  std::vector<KeyValueSignature> key_value_from_mid_;
  DataStoreTest(const DataStoreTest&);
  DataStoreTest &operator=(const DataStoreTest&);
};

TEST_F(DataStoreTest, BEH_KAD_StoreValidData) {
  EXPECT_EQ(size_t(0), GetKeyValueIndex().size());
  std::string key1 = crypto::Hash<crypto::SHA512>(RandomString(1024));
  std::string key2 = crypto::Hash<crypto::SHA512>(RandomString(1024));
  std::string value1 = crypto::Hash<crypto::SHA512>(RandomString(1024));
  std::string value2;
  value2.reserve(5 * 1024 * 1024);  // big value 5MB
  std::string random_substring(RandomString(1024));
  for (int i = 0; i < 5 * 1024; ++i)
    value2 += random_substring;
  std::string signature1 = crypto::Hash<crypto::SHA512>(RandomString(1024));
  std::string signature2 = crypto::Hash<crypto::SHA512>(RandomString(1024));
  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key1, value1, signature1), 
                                   bptime::seconds(3600*24), false));
  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key2, value2, signature2), 
                                   bptime::seconds(3600*24), false));
  EXPECT_EQ(size_t(2), GetKeyValueIndex().size());
  EXPECT_EQ(size_t(1), GetKeyValueIndex().count(key1));
  EXPECT_EQ(size_t(1), GetKeyValueIndex().count(key2));
  std::vector<std::pair<std::string, std::string>> values;
  EXPECT_TRUE(test_ds_->GetValues(key1, &values));
  EXPECT_EQ(1, values.size());
  EXPECT_EQ(make_pair(value1, signature1), values[0]);
  values.clear();
  EXPECT_TRUE(test_ds_->GetValues(key2, &values));
  ASSERT_EQ(size_t(1), values.size());
  EXPECT_EQ(make_pair(value2, signature2), values[0]);
}

TEST_F(DataStoreTest, BEH_KAD_StoreExistingData) {
  std::string value1(crypto::Hash<crypto::SHA512>("bb33"));
  std::string signature1(crypto::Hash<crypto::SHA512>("bb33444"));
  std::string key1(crypto::Hash<crypto::SHA512>(value1));
  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key1, value1, signature1), 
																	 bptime::seconds(3600*24), false));
  std::vector<std::pair<std::string, std::string>> values; 
  EXPECT_TRUE(test_ds_->GetValues(key1, &values));
  EXPECT_EQ(size_t(1), values.size());
  EXPECT_EQ(make_pair(value1, signature1), values[0]);

  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key1, value1, signature1), 
																	 bptime::seconds(3600*24), false));
  values.clear();
  EXPECT_TRUE(test_ds_->GetValues(key1, &values));
  EXPECT_EQ(size_t(1), values.size());
  EXPECT_EQ(make_pair(value1, signature1), values[0]);
}

TEST_F(DataStoreTest, BEH_KAD_StoreInvalidData) {
  std::string value1(crypto::Hash<crypto::SHA512>("bb33"));
  std::string signature1(crypto::Hash<crypto::SHA512>(value1));
  std::string key1(crypto::Hash<crypto::SHA512>(value1));
  // invalid key
  EXPECT_FALSE(test_ds_->StoreValue(KeyValueSignature("", value1, signature1), 
                                    bptime::seconds(3600*24), false));
  // invalid value 
  EXPECT_FALSE(test_ds_->StoreValue(KeyValueSignature(key1, "", signature1), 
                                    bptime::seconds(3600*24), false));
 // invalid signature  
  EXPECT_FALSE(test_ds_->StoreValue(KeyValueSignature(key1, value1, ""), 
                                    bptime::seconds(3600*24), false));
  // invalid key,value & signature
  EXPECT_FALSE(test_ds_->StoreValue(KeyValueSignature("", "", ""), 
                                    bptime::seconds(3600*24), false));
  // invalid time to live
  EXPECT_FALSE(test_ds_->StoreValue(KeyValueSignature(key1, value1, signature1),
                                    bptime::seconds(0), false));
}

TEST_F(DataStoreTest, BEH_KAD_LoadExistingData) {
  // one value under a key
  std::string value1(crypto::Hash<crypto::SHA512>("oybbggjhhtytyerterter"));
  std::string key1(crypto::Hash<crypto::SHA512>(value1));
  std::string signature1(crypto::Hash<crypto::SHA512>(key1));
  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key1, value1, signature1), 
                                   bptime::seconds(3600*24), true));
  std::vector<std::pair<std::string, std::string>> values;
  EXPECT_TRUE(test_ds_->GetValues(key1, &values));
  EXPECT_EQ(size_t(1), values.size());
  EXPECT_EQ(make_pair(value1, signature1), values[0]);
  // multiple values under a key
  std::string key2 = crypto::Hash<crypto::SHA512>("erraaaaa4334223");
  std::string signature2 = crypto::Hash<crypto::SHA512>(key2);
  std::string value2_1;
  value2_1.reserve(3 * 1024 * 1024);  // big value 3MB
  std::string random_substring(RandomString(1024));
  for (int i = 0; i < 3 * 1024; ++i)
    value2_1 += random_substring;
  std::string value2_2 = RandomString(5);  // small value
  std::string value2_3 = crypto::Hash<crypto::SHA512>("vvvx12xxxzzzz3322");
  
  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key2, value2_1, signature2),
                                   bptime::seconds(3600*24), false));
  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key2, value2_2, signature2),
                                   bptime::seconds(3600*24), false));
  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key2, value2_3, signature2),
                                   bptime::seconds(3600*24), false));
  values.clear();
  EXPECT_TRUE(test_ds_->GetValues(key2, &values));
  EXPECT_EQ(size_t(3), values.size());
  int value_num = 0;
  for (size_t i = 0; i < values.size(); i++) {
    if ((values[i].first == value2_1) && (values[i].second == signature2))
      value_num++;
    else if ((values[i].first == value2_2) && (values[i].second == signature2))
      value_num++;
    else if ((values[i].first == value2_3) && (values[i].second == signature2))
      value_num++;
  }
  EXPECT_EQ(size_t(3), value_num);
  std::vector<std::pair<std::string, bool>> attr_key1, attr_key2;
  attr_key1 = test_ds_->LoadKeyAppendableAttr(key1);
  EXPECT_EQ(1, attr_key1.size());
  EXPECT_EQ(value1, attr_key1[0].first);
  EXPECT_TRUE(attr_key1[0].second);

  attr_key2 = test_ds_->LoadKeyAppendableAttr(key2);
  value_num = 0;
  for (size_t i = 0; i < attr_key2.size(); i++) {
    if (attr_key2[i].first == value2_1)
      value_num++;
    else if (attr_key2[i].first == value2_2)
      value_num++;
    else if (attr_key2[i].first == value2_3)
      value_num++;
    EXPECT_FALSE(attr_key2[i].second);
  }
  EXPECT_EQ(size_t(3), value_num);
}

TEST_F(DataStoreTest, BEH_KAD_LoadNonExistingData) {
  std::string key1(crypto::Hash<crypto::SHA512>("11222xc"));
  std::vector<std::pair<std::string, std::string>> values;
  EXPECT_FALSE(test_ds_->GetValues(key1, &values));
  EXPECT_TRUE(values.empty());
  std::vector<std::pair<std::string, bool>> attr_key;
  attr_key = test_ds_->LoadKeyAppendableAttr(key1);
  EXPECT_TRUE(attr_key.empty());
}

TEST_F(DataStoreTest, BEH_KAD_LoadEmptyKeyData) {
  std::vector<std::pair<std::string, std::string>> values;
  EXPECT_FALSE(test_ds_->GetValues("", &values));
  EXPECT_TRUE(values.empty());
  std::vector<std::pair<std::string, bool>> attr_key;
  attr_key = test_ds_->LoadKeyAppendableAttr("");
  EXPECT_TRUE(attr_key.empty());
}
TEST_F(DataStoreTest, BEH_KAD_HasKey) {
  KeyValueSignature key_value_signature1(RandomString(10),
                                         RandomString(10),
                                         RandomString(10));
  KeyValueSignature key_value_signature2(key_value_signature1.key, 
                                         RandomString(11),
                                         RandomString(11));
  KeyValueSignature key_value_signature3(RandomString(12), 
                                         key_value_signature2.value,
                                         RandomString(12));
  bptime::ptime expire_time(bptime::second_clock::local_time());
  expire_time += bptime::hours(20);
  bptime::ptime refresh_time = expire_time - bptime::hours(10);
  KeyValueTuple keyvalue1(key_value_signature1, expire_time, refresh_time,
                          false);
  KeyValueTuple keyvalue3(key_value_signature3, expire_time, refresh_time,
                          false);
  expire_time += bptime::millisec(10);
  KeyValueTuple keyvalue2(key_value_signature2, expire_time, refresh_time,
                          false);
  keyvalue3.delete_status = kMarkedForDeletion;

  GetKeyValueIndex().insert(keyvalue1);
  GetKeyValueIndex().insert(keyvalue2);
  GetKeyValueIndex().insert(keyvalue3);
  ASSERT_FALSE(test_ds_->HasKey(""));
  ASSERT_TRUE(test_ds_->HasKey(key_value_signature1.key));
  ASSERT_FALSE(test_ds_->HasKey(RandomString(11)));
  ASSERT_FALSE(test_ds_->HasKey(key_value_signature3.key));

}

TEST_F(DataStoreTest, BEH_KAD_DeleteValue) {
  KeyValueSignature key_value_signature1(RandomString(10),
                                         RandomString(10),
                                         RandomString(10));
  KeyValueSignature key_value_signature2(key_value_signature1.key,
                                         RandomString(11),
                                         RandomString(11));
  KeyValueSignature key_value_signature3(RandomString(10),
                                         key_value_signature2.value,
                                         RandomString(10));
 
  bptime::ptime expire_time(bptime::second_clock::local_time());
  expire_time += bptime::hours(20);
  bptime::ptime refresh_time = expire_time - bptime::hours(10); 
  KeyValueTuple keyvalue1(key_value_signature1, expire_time, refresh_time,
                          false);
  KeyValueTuple keyvalue3(key_value_signature3, expire_time, refresh_time,
                          false);
  KeyValueTuple keyvalue2(key_value_signature2, expire_time, refresh_time,
                          false);

  GetKeyValueIndex().insert(keyvalue1);
  GetKeyValueIndex().insert(keyvalue2);
  GetKeyValueIndex().insert(keyvalue3);
  
  ASSERT_EQ(size_t(3), GetKeyValueIndex().size());
  ASSERT_TRUE(test_ds_->DeleteValue(key_value_signature1.key,
                                    key_value_signature2.value));
  ASSERT_EQ(size_t(2), GetKeyValueIndex().size());
  EXPECT_TRUE(test_ds_->HasKey(key_value_signature1.key));
  EXPECT_TRUE(test_ds_->HasKey(key_value_signature3.key));
  ASSERT_TRUE(test_ds_->DeleteValue(key_value_signature1.key,
                                    key_value_signature1.value));
  ASSERT_EQ(size_t(1), GetKeyValueIndex().size());
  EXPECT_TRUE(test_ds_->HasKey(key_value_signature3.key));
  EXPECT_FALSE(test_ds_->HasKey(key_value_signature1.key));
  ASSERT_TRUE(test_ds_->DeleteValue(key_value_signature3.key,
                                    key_value_signature3.value));
  ASSERT_EQ(size_t(0), GetKeyValueIndex().size());
  EXPECT_FALSE(test_ds_->HasKey(key_value_signature2.key));
  EXPECT_FALSE(test_ds_->HasKey(key_value_signature3.key));

}
TEST_F(DataStoreTest, BEH_KAD_MutexTestWithMultipleThread) {
  boost::shared_ptr<boost::asio::io_service> asio_service(
      new boost::asio::io_service);
  boost::shared_ptr<boost::asio::io_service::work> work(
      new boost::asio::io_service::work(*asio_service));
  boost::thread_group asio_thread_group;
  for (int i = 0; i < 10; ++i) {
    asio_thread_group.create_thread(boost::bind(&boost::asio::io_service::run,
                                                asio_service));
  }
  KeyValueSignature key_value_signature(RandomString(10),
                                        RandomString(10),
                                        RandomString(10));
  std::vector<std::pair<std::string, std::string>> values, values1;
  this->MakeMultipleEntries();
  
  auto key_front =  key_value_from_front_.begin();
  for (int i = 0; i < kIterartorSize; ++i) {
    asio_service->post(boost::bind(&DataStore::DeleteValue, test_ds_,
                                   key_front->first,
                                   key_front->second));
    ++key_front;
  }
 
  auto k = key_value_from_end_.end();
  for (int i = 0; i < kIterartorSize; ++i) {
    --k;
    asio_service->post(boost::bind(&DataStore::DeleteValue, test_ds_,
                                   k->first, k->second));
  }
  for (int i = 0; i < kIterartorSize; ++i) { 
    asio_service->post(boost::bind(&DataStore::StoreValue, test_ds_,
                                   KeyValueSignature(RandomString(i*103),
                                   RandomString(i*107),
                                   RandomString(i*111)),
                                   bptime::seconds(1000), false));
  }
  asio_service->post(boost::bind(&DataStore::GetValues, test_ds_,
                                 k->first, &values));
  asio_service->post(boost::bind(&DataStore::MarkForDeletion, test_ds_,
                                 KeyValueSignature(k->first, k->second,
                                 RandomString(35)), RandomString(35)));
  ++k;
  asio_service->post(boost::bind(&DataStore::GetValues, test_ds_,
                                 k->first, &values1));
  auto s = key_value_from_mid_.begin();

  for (int i = 0; i < kIterartorSize; ++i) {
    asio_service->post(boost::bind(&DataStore::RefreshKeyValue, test_ds_,
                                   (*s), &(RandomString(35))));
    ++s;
  }
  for (int i = 0; i < kIterartorSize; ++i) {
    ++s;
    asio_service->post(boost::bind(&DataStore::UpdateValue, test_ds_,
                                   (*s),
                                   KeyValueSignature(RandomString(i*53),
                                   RandomString(i*59), RandomString(i*61)),
                                   bptime::seconds(1000), false));
  }
  for (int i = 0; i < kThreadBarrierSize; ++i) {
    asio_service->post(boost::bind(&DataStoreTest::CheckKey, this,
                                   key_front->first));
    asio_service->post(boost::bind(&DataStoreTest::CheckLoadKeyAppendableAttr,
                                   this, (*s).key));
    ++key_front;
    ++s;
  }
  work.reset();
  asio_thread_group.join_all();
  key_value_from_front_.clear();
  key_value_from_mid_.clear();
  key_value_from_end_.clear();
}
#if 0
TEST_F(DataStoreTest, BEH_KAD_UpdateValue) {
  std::string key1 = cry_obj_.Hash("663efsxx33d", "", crypto::STRING_STRING,
      false);
  std::string value1 = RandomString(500);
  boost::int32_t t_refresh1, t_refresh2, t_expire1, t_expire2, ttl1, ttl2;
  ttl1 = 3600*24;
  ttl2 = 3600*25;
  ASSERT_TRUE(test_ds_->StoreValue(KeyValueSignature(key1, value1, value1),
     bptime::seconds(ttl1), false));
  t_refresh1 = test_ds_->LastRefreshTime(key1, value1);
  t_expire1 = test_ds_->ExpireTime(key1, value1);
  ASSERT_NE(0, t_refresh1);
  ASSERT_NE(0, t_expire1);
  std::vector<std::string> values;
  ASSERT_TRUE(test_ds_->LoadItem(key1, &values));
  ASSERT_EQ(1, values.size());
  ASSERT_EQ(value1, values[0]);
  ASSERT_EQ(ttl1, test_ds_->TimeToLive(key1, value1));
  boost::this_thread::sleep(boost::posix_time::seconds(1));

  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, ttl2, false));
  t_refresh2 = test_ds_->LastRefreshTime(key1, value1);
  t_expire2 = test_ds_->ExpireTime(key1, value1);
  ASSERT_LT(t_refresh1, t_refresh2);
  ASSERT_LT(t_expire1, t_expire2);
  values.clear();
  ASSERT_TRUE(test_ds_->LoadItem(key1, &values));
  ASSERT_EQ(1, values.size());
  ASSERT_EQ(value1, values[0]);
  ASSERT_EQ(ttl2, test_ds_->TimeToLive(key1, value1));
}

TEST_F(DataStoreTest, BEH_KAD_DeleteKey) {
  // store one key
  std::string key1 = cry_obj_.Hash("hdvahyr54345t456d", "",
      crypto::STRING_STRING, false);
  std::string value1 = RandomString(100);
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, 3600*24, false));
  // store another key with 3 values
  std::string key2 = cry_obj_.Hash("hrerc4334cr", "", crypto::STRING_STRING,
      false);
  std::string value2_1 = RandomString(24);
  std::string value2_2 = RandomString(500);
  std::string value2_3 = cry_obj_.Hash("hneffddcx33xxx", "",
      crypto::STRING_STRING, false);
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_1, 3600*24, false));
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_2, 3600*24, false));
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_3, 3600*24, false));
  // there should be 2 keys
  std::set<std::string> keys;
  ASSERT_TRUE(test_ds_->Keys(&keys));
  ASSERT_EQ(2, keys.size());
  // delete one key
  ASSERT_TRUE(test_ds_->DeleteKey(key2));
  // there should be only one key left
  ASSERT_TRUE(test_ds_->Keys(&keys));
  ASSERT_EQ(1, keys.size());
  ASSERT_TRUE(keys.end() != keys.find(key1));
  // delete another key
  ASSERT_TRUE(test_ds_->DeleteKey(key1));
  ASSERT_TRUE(test_ds_->Keys(&keys));
  ASSERT_TRUE(keys.empty());
  // delete non-existing key
  ASSERT_FALSE(test_ds_->DeleteKey(key1));
}

TEST_F(DataStoreTest, BEH_KAD_DeleteItem) {
  // store one key
  std::string key1 = cry_obj_.Hash("vxxsdasde", "", crypto::STRING_STRING,
      false);
  std::string value1 = RandomString(200);
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, 3600*24, false));
  std::vector<std::string> values;
  ASSERT_TRUE(test_ds_->LoadItem(key1, &values));
  ASSERT_EQ(1, values.size());
  // store another key with 3 values
  std::string key2 = cry_obj_.Hash("vvxxxee1", "", crypto::STRING_STRING,
      false);
  std::string value2_1 = RandomString(10);
  std::string value2_2 = RandomString(2);
  std::string value2_3 = cry_obj_.Hash("jjrtfccvvdsss", "",
      crypto::STRING_STRING, false);

  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_1, 3600*24, false));
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_2, 3600*24, false));
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_3, 3600*24, false));
  ASSERT_TRUE(test_ds_->LoadItem(key2, &values));
  ASSERT_EQ(3, static_cast<int>(values.size()));
  // delete an item with key2 and value2_1
  ASSERT_TRUE(test_ds_->DeleteItem(key2, value2_1));
  ASSERT_TRUE(test_ds_->LoadItem(key2, &values));
  ASSERT_EQ(2, static_cast<int>(values.size()));
  // value2_1 should be gone
  int value_num = 0;
  for (size_t i = 0; i < values.size(); i++) {
    if (values[i] == value2_1)
      value_num++;
  }
  ASSERT_EQ(0, value_num);
  ASSERT_FALSE(test_ds_->DeleteItem(key2, value2_1));
  // delete an item with key1 and value1
  ASSERT_TRUE(test_ds_->DeleteItem(key1, value1));
  ASSERT_FALSE(test_ds_->LoadItem(key1, &values));
  ASSERT_TRUE(values.empty());
  ASSERT_FALSE(test_ds_->DeleteItem(key1, value1));
}
#endif
TEST_F(DataStoreTest, BEH_KAD_StoreMultipleValuesWithSameKey) {
  EXPECT_EQ(size_t(0), GetKeyValueIndex().size());
  std::string key = crypto::Hash<crypto::SHA512>("abc123vvd32sfdf");
  std::vector<KeyValueSignature> key_value_signatures;
  std::string random_string;
  random_string.reserve(1024);  //  1KB
  for (int j = 0; j < 10; ++j) {  
    std::string random_substring(RandomString(1024));
    for (int i = 0; i < 1024; ++i)
      random_string += random_substring;
    key_value_signatures.push_back(KeyValueSignature(key, random_string,
                                                     random_string));
    EXPECT_TRUE(test_ds_->StoreValue(key_value_signatures[j],
                                     bptime::seconds(3600*24), false));
    random_string.clear();
  }
  std::vector<std::pair<std::string, std::string>> values;
  EXPECT_TRUE(test_ds_->GetValues(key, &values));
  EXPECT_EQ(size_t(10), values.size());
  for (size_t j = 0; j < values.size(); j++) {
    EXPECT_TRUE((key_value_signatures[j].value == values[j].first) && 
                (key_value_signatures[j].signature == values[j].second));
  }
}

TEST_F(DataStoreTest, BEH_KAD_StoreMultipleKeysWithSameValue) {
  std::string value = crypto::Hash<crypto::SHA512>(RandomString(1024));
  std::string signature = crypto::Hash<crypto::SHA512>(RandomString(1024));
  std::vector<KeyValueSignature> key_value_signatures;
  std::string random_key;
  for (unsigned int j = 0; j < 10; j++) {  
    std::string random_substring(RandomString(1024));
  for (int i = 0; i < 1024; ++i)
    random_key += random_substring;
  key_value_signatures.push_back(KeyValueSignature(random_key, value, 
                                 signature));
  EXPECT_TRUE(test_ds_->StoreValue(key_value_signatures[j],
                                   bptime::seconds(3600*24), false));
  random_key.clear();
  } 
  std::vector<std::pair<std::string, std::string>> values;
  for (int i=0; i<10; i++){
    EXPECT_TRUE(test_ds_->GetValues(key_value_signatures[i].key, &values));
    EXPECT_EQ(1, values.size());
    EXPECT_TRUE((key_value_signatures[i].value == values[0].first) && 
                (key_value_signatures[i].signature == values[0].second));
    values.clear(); 	
  }
}

TEST_F(DataStoreTest, BEH_KAD_StoreMultipleValidInvalidData) {
  std::string random_string;
  std::vector<KeyValueSignature> key_value_signatures;
  for (int j = 0; j < 10; j++) {  
    std::string random_substring(RandomString(1024));
    for (int i = 0; i < 1024; ++i)
      random_string += random_substring;
    if (j%2) {
      key_value_signatures.push_back(KeyValueSignature(random_string,
                                  random_string, random_string));
      EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(random_string,
                                       random_string, random_string),
                                       bptime::seconds(3600*24), false));
    } else
      EXPECT_FALSE(test_ds_->StoreValue(KeyValueSignature("","",""),
                                        bptime::seconds(3600*24), false));
    random_string.clear();
  } 
  std::vector<std::pair<std::string, std::string>> values;
  for (auto it = key_value_signatures.begin(); 
    it<key_value_signatures.end();it++) {
    EXPECT_TRUE(test_ds_->GetValues((*it).key, &values));
    EXPECT_EQ(1, values.size());
    EXPECT_TRUE(((*it).value == values[0].first) && 
                ((*it).signature == values[0].second));
    values.clear();
  }
}

TEST_F(DataStoreTest, BEH_KAD_RefreshKeyValue) {
  std::string key1 = crypto::Hash<crypto::SHA512>("663efsxx33d");
  std::string value1 = RandomString(500);
  std::string signature1 = crypto::Hash<crypto::SHA512>(key1);
  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key1, value1, signature1),
                                   bptime::seconds(3600*24), false));
  KeyValueIndex::index<TagKeyValue>::type& index_by_key_value =
      GetKeyValueIndex().get<TagKeyValue>();
  
  auto it = index_by_key_value.find(boost::make_tuple(key1, value1));
  ASSERT_FALSE(it == index_by_key_value.end());
  bptime::ptime t_refresh1 = (*it).refresh_time;
  bptime::ptime t_expire1 = (*it).expire_time;
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_refresh1);
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_expire1);
  std::vector<std::pair<std::string, std::string>> values;
  EXPECT_TRUE(test_ds_->GetValues(key1, &values));
  ASSERT_EQ(1, values.size());
  EXPECT_EQ(value1, values[0].first);
  EXPECT_EQ(signature1, values[0].second);
  boost::this_thread::sleep(boost::posix_time::milliseconds(1500));
  // refreshing the value
  std::string ser_del_request;
  EXPECT_FALSE(test_ds_->RefreshKeyValue(KeyValueSignature ("key1", value1, 
                                                            signature1),
                                         &ser_del_request));
  EXPECT_FALSE(test_ds_->RefreshKeyValue(KeyValueSignature (key1, "value1", 
                                                            signature1),
                                         &ser_del_request));
  EXPECT_FALSE(test_ds_->RefreshKeyValue(KeyValueSignature (key1, value1, 
                                                            "signature1"),
                                         &ser_del_request));
  EXPECT_FALSE(test_ds_->RefreshKeyValue(KeyValueSignature ("key1", "value1", 
                                                            "signature1"),
                                         &ser_del_request));
  EXPECT_TRUE(test_ds_->RefreshKeyValue(KeyValueSignature (key1, value1, 
                                                           signature1),
                                         &ser_del_request));
  index_by_key_value = GetKeyValueIndex().get<TagKeyValue>();
  it = index_by_key_value.find(boost::make_tuple(key1, value1));
  ASSERT_FALSE(it == index_by_key_value.end());
  bptime::ptime t_refresh2 = (*it).refresh_time;
  bptime::ptime t_expire2 = (*it).expire_time;
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_refresh2);
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_expire2);
  EXPECT_LT(t_refresh1, t_refresh2);
  EXPECT_EQ(t_expire1, t_expire2);
  values.clear();
  EXPECT_TRUE(test_ds_->GetValues(key1, &values));
  ASSERT_EQ(1, values.size());
  EXPECT_EQ(value1, values[0].first);
  EXPECT_EQ(signature1, values[0].second);
}

TEST_F(DataStoreTest, BEH_KAD_RepublishKeyValue) {
  std::string key1 = crypto::Hash<crypto::SHA512>("663efsxx33d");
  std::string value1 = RandomString(500);
  std::string signature1 = crypto::Hash<crypto::SHA512>(key1);
  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key1, value1, signature1),
                                   bptime::seconds(3600*24), false));
  KeyValueIndex::index<TagKeyValue>::type& index_by_key_value =
      GetKeyValueIndex().get<TagKeyValue>();
  auto it = index_by_key_value.find(boost::make_tuple(key1, value1));
  ASSERT_FALSE(it == index_by_key_value.end());
  bptime::ptime t_refresh1 = (*it).refresh_time;
  bptime::ptime t_expire1 = (*it).expire_time;
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_refresh1);
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_expire1);
  std::vector<std::pair<std::string, std::string>> values;
  EXPECT_TRUE(test_ds_->GetValues(key1, &values));
  ASSERT_EQ(1, values.size());
  EXPECT_EQ(value1, values[0].first);
  EXPECT_EQ(signature1, values[0].second);
  boost::this_thread::sleep(boost::posix_time::milliseconds(1500));
  // republishing the value
  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key1, value1, signature1),
                                   bptime::seconds(3600*24), false));
  index_by_key_value = GetKeyValueIndex().get<TagKeyValue>();
  it = index_by_key_value.find(boost::make_tuple(key1, value1));
  ASSERT_FALSE(it == index_by_key_value.end());
  bptime::ptime t_refresh2 = (*it).refresh_time;
  bptime::ptime t_expire2 = (*it).expire_time;
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_refresh2);
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_expire2);
  ASSERT_LT(t_refresh1, t_refresh2);
  ASSERT_LT(t_expire1, t_expire2);
  values.clear();
  EXPECT_TRUE(test_ds_->GetValues(key1, &values));
  ASSERT_EQ(1, values.size());
  EXPECT_EQ(value1, values[0].first);
  EXPECT_EQ(signature1, values[0].second);
}
#if 0
TEST_F(DataStoreTest, FUNC_KAD_GetValuesToRefresh) {
  // data store with refresh time set to 3 seconds for test
  DataStore ds(3);
  std::vector<refresh_value> refvalues;
  std::vector<std::string> keys, values;
  for (boost::uint16_t i = 0; i < 7; i++) {
    keys.push_back(cry_obj_.Hash(boost::lexical_cast<std::string>(i), "",
        crypto::STRING_STRING, false));
    values.push_back(RandomString(500));
  }
  boost::int32_t ttl = 3600*24;
  for (boost::int16_t i = 0; i < 5; i++) {
    if (i == 1) {
      ASSERT_TRUE(ds.StoreItem(keys[i], values[i], -1, false));
    } else {
      if (i == 2) {
        ASSERT_TRUE(ds.StoreItem(keys[i], values[i]+"EXTRA", ttl, false));
      }
      ASSERT_TRUE(ds.StoreItem(keys[i], values[i], ttl, false));
    }
  }

  boost::this_thread::sleep(boost::posix_time::seconds(ds.t_refresh()+1));

  for (unsigned int i = 5; i < keys.size(); i++) {
    if (i == 6)
      ASSERT_TRUE(ds.StoreItem(keys[i], values[i], -1, false));
    else
      ASSERT_TRUE(ds.StoreItem(keys[i], values[i], ttl, false));
  }
  // refreshing key[0] so it does not apperat in keys to refresh
  std::string ser_del_request;
  ASSERT_TRUE(ds.RefreshItem(keys[0], values[0], &ser_del_request));
  refvalues = ds.ValuesToRefresh();
  for (size_t i = 0; i < refvalues.size(); i++) {
    ASSERT_NE(keys[0], refvalues[i].key_);
    ASSERT_NE(values[0], refvalues[i].value_);
  }
  for (size_t i = 5; i < keys.size(); i++) {
    bool found = false;
    for (size_t j = 0; j < refvalues.size(); j++) {
      if (keys[i] == refvalues[j].key_ && values[i] == refvalues[j].value_) {
        found = true;
        break;
      }
      ASSERT_FALSE(found);
    }
  }
  for (unsigned int i = 1; i < 4; i++) {
    bool found = false;
    boost::int32_t ttl_for_refresh = ttl+1;
    for (size_t j = 0; j < refvalues.size(); j++) {
      if (keys[i] == refvalues[j].key_ && values[i] == refvalues[j].value_) {
        found = true;
        ttl_for_refresh = refvalues[j].ttl_;
        ASSERT_EQ(NOT_DELETED, refvalues[j].del_status_);
        break;
      }
    }
    ASSERT_TRUE(found);
    if (i == 1)
      ASSERT_EQ(-1, ttl_for_refresh);
    else
      ASSERT_GE(ttl, ttl_for_refresh);
  }
}

TEST_F(DataStoreTest, FUNC_KAD_ExpiredValuesNotRefreshed) {
  // data store with refresh time set to 3 seconds for test
  DataStore ds(3);
  std::vector<refresh_value> refvalues;
  std::vector<std::string> keys, values;
  for (boost::int16_t i = 0; i < 3; i++) {
    keys.push_back(cry_obj_.Hash(boost::lexical_cast<std::string>(i), "",
        crypto::STRING_STRING, false));
    values.push_back(RandomString(500));
  }
  boost::uint32_t ttl = 3600*24;
  boost::uint32_t ttl_to_expire = ds.t_refresh() - 1;
  for (boost::int16_t i = 0; i < 3; i++) {
    if (i == 1)
      ASSERT_TRUE(ds.StoreItem(keys[i], values[i], ttl_to_expire, false));
    else
      ASSERT_TRUE(ds.StoreItem(keys[i], values[i], ttl, false));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(ds.t_refresh()+1));
  refvalues = ds.ValuesToRefresh();
  // only values[0] and values[2], should be in the values to refresh
  ASSERT_EQ(2, refvalues.size());
  bool missed_value = false;
  for (size_t i = 0; i < refvalues.size(); i++) {
    if (keys[0] != refvalues[i].key_ && values[0] != refvalues[i].value_ &&
        keys[2] != refvalues[i].key_ && values[2] != refvalues[i].value_) {
      missed_value = true;
      break;
    }
    ASSERT_GE(static_cast<int>(ttl), refvalues[i].ttl_);
  }
  ASSERT_FALSE(missed_value);
}

TEST_F(DataStoreTest, FUNC_KAD_DeleteExpiredValues) {
  std::vector<std::string> keys, values;
  std::vector<boost::int32_t> ttl;
  // creating 10 key/values
  for (boost::int16_t i = 0; i < 10; i++) {
    keys.push_back(boost::lexical_cast<std::string>(i));
    values.push_back(RandomString(100));
    ttl.push_back(i+5);  // TTL = i + 5 seconds
  }
  for (size_t i = 0; i < keys.size(); i++)
    test_ds_->StoreItem(keys[i], values[i], ttl[i], false);
  // waiting 9 seconds  values 0, 1, and 3 are expired and should be deleted
  boost::this_thread::sleep(boost::posix_time::seconds(4));
  // republishing value 2 with TTL 7
  ASSERT_TRUE(test_ds_->StoreItem(keys[2], values[2], ttl[2], false));
  // refreshing value 3 with TTL 8
  std::string ser_del_request;
  ASSERT_TRUE(test_ds_->RefreshItem(keys[3], values[3], &ser_del_request));
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  test_ds_->DeleteExpiredValues();
  boost::uint32_t now = GetEpochTime();
  std::set<std::string> rec_keys;
  ASSERT_TRUE(test_ds_->Keys(&rec_keys));
  ASSERT_EQ(keys.size()-3, rec_keys.size());
  for (std::set<std::string>::iterator it = rec_keys.begin();
       it != rec_keys.end(); it++) {
    std::string value;
    for (size_t j = 0; j < keys.size(); j++) {
      if (*it == keys[j]) {
        value = values[j];
        break;
      }
    }
    ASSERT_LE(now, test_ds_->ExpireTime(*it, value));
  }
  // checking correct keys have been deleted
  std::vector<std::string> del_keys;
  del_keys.push_back(keys[0]);
  del_keys.push_back(keys[1]);
  del_keys.push_back(keys[3]);
  for (size_t j = 0; j < del_keys.size(); j++) {
    ASSERT_TRUE(rec_keys.end() == rec_keys.find(del_keys[j]));
    std::vector<std::string> values;
    ASSERT_FALSE(test_ds_->LoadItem(del_keys[j], &values));
  }
}

TEST_F(DataStoreTest, FUNC_KAD_ValuesInfTTLDontExpire) {
  std::vector<std::string> keys, values;
  std::vector<boost::int32_t> ttl;
  // creating 10 key/values
  for (boost::int16_t i = 0; i < 5; i++) {
    keys.push_back(boost::lexical_cast<std::string>(i));
    values.push_back(RandomString(100));
    ttl.push_back(i+5);  // TTL = i + 5 seconds
  }
  // 5 have inf TTL
  for (boost::int16_t i = 5; i < 10; i++) {
    keys.push_back(boost::lexical_cast<std::string>(i));
    values.push_back(RandomString(100));
    ttl.push_back(-1);  // TTL = i + 5 seconds
  }
  for (size_t i = 0; i < keys.size(); i++)
    ASSERT_TRUE(test_ds_->StoreItem(keys[i], values[i], ttl[i], false));
  // waiting 12 seconds  values 0 - 4 have expired and should be deleted
  // other values don't expire, the have TTL = -1
  boost::this_thread::sleep(boost::posix_time::seconds(12));
  test_ds_->DeleteExpiredValues();
  std::set<std::string> rec_keys;
  ASSERT_TRUE(test_ds_->Keys(&rec_keys));
  ASSERT_EQ(keys.size()-5, rec_keys.size());
  for (std::set<std::string>::iterator it = rec_keys.begin();
       it != rec_keys.end(); it++) {
    std::string value;
    for (size_t j = 0; j < keys.size(); j++) {
      if (*it == keys[j]) {
        value = values[j];
        break;
      }
    }
    // expire time is 0
    ASSERT_EQ(0, test_ds_->ExpireTime(*it, value));
  }
  // checking correct keys have been deleted
  std::vector<std::string> del_keys;
  del_keys.push_back(keys[0]);
  del_keys.push_back(keys[1]);
  del_keys.push_back(keys[2]);
  del_keys.push_back(keys[3]);
  del_keys.push_back(keys[4]);
  for (size_t j = 0; j < del_keys.size(); j++) {
    ASSERT_TRUE(rec_keys.end() == rec_keys.find(del_keys[j]));
    std::vector<std::string> values;
    ASSERT_FALSE(test_ds_->LoadItem(del_keys[j], &values));
  }
}

TEST_F(DataStoreTest, BEH_KAD_ClearDataStore) {
  std::set<std::string> keys;
  // creating 10 key/values
  for (boost::int16_t i = 0; i < 10; i++) {
    std::string key = cry_obj_.Hash(boost::lexical_cast<std::string>(i), "",
        crypto::STRING_STRING, false);
    test_ds_->StoreItem(key, RandomString(100), 3600*24, false);
  }
  test_ds_->Keys(&keys);
  ASSERT_EQ(10, keys.size());
  test_ds_->Clear();
  keys.clear();
  test_ds_->Keys(&keys);
  ASSERT_EQ(0, keys.size());
}
#endif
TEST_F(DataStoreTest, FUNC_KAD_ExpiredValuesNotReturned) {
  std::string value = RandomString(100);
  std::string key = crypto::Hash<crypto::SHA512>(RandomString(5));
  std::string signature = crypto::Hash<crypto::SHA512>(RandomString(5));
  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key, value, signature), 
									                 bptime::seconds(3), false));   
  std::vector<std::pair<std::string, std::string>> values;
  EXPECT_TRUE(test_ds_->GetValues(key, &values));
  EXPECT_FALSE(values.empty());
  EXPECT_EQ(value, values[0].first);
  EXPECT_EQ(signature, values[0].second);
  values.clear();
  boost::this_thread::sleep(boost::posix_time::seconds(4));
  EXPECT_FALSE(test_ds_->GetValues(key, &values));
  EXPECT_TRUE(values.empty());

  std::string value2 = RandomString(100);
  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key, value, signature), 
									                 bptime::seconds(3), false));
  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key, value2, signature), 
									                 bptime::seconds(100), false));
  boost::this_thread::sleep(boost::posix_time::seconds(4));
  values.clear();
  EXPECT_TRUE(test_ds_->GetValues(key, &values));
  EXPECT_EQ(size_t(1), values.size());
  EXPECT_EQ(value2, values[0].first);
}

TEST_F(DataStoreTest, BEH_KAD_AllKeyValueTuplePrivateAttributes) {
  std::string value(RandomString(50));
  std::string key(crypto::Hash<crypto::SHA512>(RandomString(5)));
  std::string signature(RandomString(50));
  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key, value, signature), 
                                   bptime::seconds(100), false));
  KeyValueIndex::index<TagKeyValue>::type& index_by_key_value =
      GetKeyValueIndex().get<TagKeyValue>();
  auto it = index_by_key_value.find(boost::make_tuple(key, value));
  std::vector<std::pair<std::string, std::string>> values;
  EXPECT_TRUE(test_ds_->GetValues(key, &values));
  EXPECT_EQ(size_t(1), values.size());
  EXPECT_EQ(value, values[0].first);
  EXPECT_EQ(signature, values[0].second);
  
  bptime::ptime t_refresh1 = (*it).refresh_time;
  bptime::ptime t_expire1 = (*it).expire_time;
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_refresh1);
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_expire1);
  EXPECT_FALSE( (*it).expire_time.is_pos_infinity());
  EXPECT_EQ(kNotDeleted, (*it).delete_status);
  EXPECT_EQ(false, (*it).hashable);
  EXPECT_TRUE((*it).serialised_delete_request.empty());
  values.clear();
  std::string value2(RandomString(50));
  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key, value, signature), 
                                   bptime::seconds(bptime::pos_infin), false));
  it = index_by_key_value.find(boost::make_tuple(key, value));
  EXPECT_TRUE((*it).expire_time.is_pos_infinity());

  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key, value2, signature), 
                                   bptime::seconds(bptime::pos_infin), false));
  EXPECT_TRUE(test_ds_->GetValues(key, &values));
  ASSERT_EQ(size_t(2), values.size());
  EXPECT_EQ(value, values[0].first);
  EXPECT_EQ(value2, values[1].first);
  EXPECT_EQ(signature, values[0].second);
  EXPECT_EQ(signature, values[1].second);
  it = index_by_key_value.find(boost::make_tuple(key, value2));
  EXPECT_TRUE((*it).expire_time.is_pos_infinity());
}
#if 0
TEST_F(DataStoreTest, BEH_KAD_ItemsWithInfTTL) {
  std::string value(RandomString(50));
  std::string key(cry_obj_.Hash(RandomString(5), "",
      crypto::STRING_STRING, false));
  ASSERT_TRUE(test_ds_->StoreItem(key, value, -1, false));
  std::vector<std::string> rec_values;
  ASSERT_TRUE(test_ds_->LoadItem(key, &rec_values));
  ASSERT_EQ(1, rec_values.size());
  ASSERT_EQ(value, rec_values[0]);
  ASSERT_EQ(-1, test_ds_->TimeToLive(key, value));
  ASSERT_EQ(0, test_ds_->ExpireTime(key, value));
}
#endif 
TEST_F(DataStoreTest, BEH_KAD_ChangeDelStatus) {
  std::string value1(RandomString(100)), value2(RandomString(50)),
    value3(RandomString(150));
  std::string key1(crypto::Hash<crypto::SHA512>(RandomString(5)));
  std::string key2(crypto::Hash<crypto::SHA512>(RandomString(15)));
  std::string signature1(crypto::Hash<crypto::SHA512>(RandomString(5)));
  std::string signature2(crypto::Hash<crypto::SHA512>(RandomString(5)));
  std::string signature3(crypto::Hash<crypto::SHA512>(RandomString(5)));
  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key1, value1, signature1),
                                   bptime::seconds(1000), false));
  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key1, value2, signature2),
                                   bptime::seconds(1000), false));
  EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key2, value3, signature3),
                                   bptime::seconds(1000), false));
  std::vector<std::pair<std::string, std::string>> values;
  EXPECT_TRUE(test_ds_->GetValues(key1, &values));
  EXPECT_EQ(size_t(2), values.size());
  for (size_t i = 0; i < values.size(); ++i)
    if (values[i].first != value1 && values[i].first != value2)
      FAIL();
  values.clear();
  EXPECT_TRUE(test_ds_->GetValues(key2, &values));
  EXPECT_EQ(size_t(1), values.size());
  EXPECT_EQ(value3, values[0].first);
  EXPECT_EQ(signature3, values[0].second);
  values.clear();
  EXPECT_TRUE(test_ds_->MarkForDeletion(KeyValueSignature(key1, value2, 
                                                          signature2),
                                        "delete request"));
  EXPECT_TRUE(test_ds_->GetValues(key1, &values));
  ASSERT_EQ(size_t(1), values.size());
  EXPECT_EQ(value1, values[0].first);
  values.clear();
  EXPECT_TRUE(test_ds_->MarkForDeletion(KeyValueSignature(key2, value3, 
                                                          signature3),
                                        "delete request"));
  EXPECT_TRUE(test_ds_->MarkForDeletion(KeyValueSignature(key2, value3, 
                                                          signature3),
                                        "delete request"));
  EXPECT_FALSE(test_ds_->GetValues(key2, &values));
  EXPECT_TRUE(values.empty());
  EXPECT_FALSE(test_ds_->MarkForDeletion(KeyValueSignature("bad key", value2, 
                                                           signature2),
                                         "delete request"));
  values.clear();
  EXPECT_FALSE(test_ds_->GetValues("bad key", &values));
  EXPECT_TRUE(values.empty());
}
#if 0
TEST_F(DataStoreTest, FUNC_KAD_CheckDelStatusValuesToRefresh) {
  // data store with refresh time set to 3 seconds for test
  DataStore ds(3);
  std::vector<refresh_value> refvalues;
  std::vector<std::string> keys, values;
  for (boost::int16_t i = 0; i < 2; i++) {
    keys.push_back(cry_obj_.Hash(boost::lexical_cast<std::string>(i), "",
        crypto::STRING_STRING, false));
    values.push_back(RandomString(500));
  }
  ASSERT_TRUE(ds.StoreItem(keys[0], values[0], -1, false));
  ASSERT_TRUE(ds.StoreItem(keys[1], values[1], 3600*24, false));
  ASSERT_TRUE(ds.MarkForDeletion(keys[0], values[0], "delete request1"));
  ASSERT_TRUE(ds.MarkForDeletion(keys[1], values[1], "delete request2"));
  ASSERT_TRUE(ds.MarkAsDeleted(keys[0], values[0]));

  std::string ser_del_request;
  ASSERT_FALSE(ds.RefreshItem(keys[0], values[0], &ser_del_request));
  ASSERT_EQ(std::string("delete request1"), ser_del_request);
  ser_del_request.clear();
  ASSERT_FALSE(ds.RefreshItem(keys[1], values[1], &ser_del_request));
  ASSERT_EQ(std::string("delete request2"), ser_del_request);

  boost::this_thread::sleep(boost::posix_time::seconds(ds.t_refresh()+1));

  refvalues = ds.ValuesToRefresh();
  ASSERT_EQ(2, refvalues.size());
  for (size_t j = 0; j < refvalues.size(); j++) {
    if (keys[0] == refvalues[j].key_) {
      ASSERT_EQ(values[0], refvalues[j].value_);
      ASSERT_EQ(DELETED, refvalues[j].del_status_);
    } else if (keys[1] == refvalues[j].key_) {
      ASSERT_EQ(values[1], refvalues[j].value_);
      ASSERT_EQ(MARKED_FOR_DELETION, refvalues[j].del_status_);
    } else {
      FAIL();
    }
  }
}

TEST_F(DataStoreTest, BEH_KAD_CompareTTLWhenStoringMarkedForDelValues) {
  std::string value1(RandomString(50)), value2(RandomString(50));
  std::string key1(cry_obj_.Hash(RandomString(5), "",
      crypto::STRING_STRING, false));
  std::string key2(cry_obj_.Hash(RandomString(5), "",
      crypto::STRING_STRING, false));
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, -1, false));
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2, 3600, false));
  ASSERT_TRUE(test_ds_->MarkForDeletion(key1, value1, "delete request"));
  ASSERT_TRUE(test_ds_->MarkForDeletion(key2, value2, "delete request"));
  ASSERT_TRUE(test_ds_->MarkAsDeleted(key2, value2));
  std::vector<std::string> rec_values;
  ASSERT_FALSE(test_ds_->LoadItem(key1, &rec_values));
  ASSERT_FALSE(test_ds_->LoadItem(key2, &rec_values));

  // trying to republish key1, value1 with not infinite TTL
  ASSERT_FALSE(test_ds_->StoreItem(key1, value1, 1000, false));
  ASSERT_FALSE(test_ds_->LoadItem(key1, &rec_values));
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, -1, false));
  ASSERT_TRUE(test_ds_->LoadItem(key1, &rec_values));
  ASSERT_EQ(1, rec_values.size());
  ASSERT_EQ(value1, rec_values[0]);
  rec_values.clear();

  boost::this_thread::sleep(boost::posix_time::seconds(2));
  // trying to store with less TTL than the one left
  ASSERT_FALSE(test_ds_->StoreItem(key2, value2, 3597, false));
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2, 3600, false));
  ASSERT_TRUE(test_ds_->LoadItem(key2, &rec_values));
  ASSERT_EQ(1, rec_values.size());
  ASSERT_EQ(value2, rec_values[0]);
  rec_values.clear();

  ASSERT_TRUE(test_ds_->MarkForDeletion(key2, value2, "delete request"));
  ASSERT_FALSE(test_ds_->LoadItem(key2, &rec_values));
  // storing now key2 value2 with infinite ttl
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2, -1, false));
  ASSERT_TRUE(test_ds_->LoadItem(key2, &rec_values));
  ASSERT_EQ(1, rec_values.size());
  ASSERT_EQ(value2, rec_values[0]);
}

TEST_F(DataStoreTest, BEH_KAD_DeleteDelStatusExpiredValues) {
  std::string key(RandomString(5)), value(RandomString(50));
  ASSERT_TRUE(test_ds_->StoreItem(key, value, 3, false));
  std::set<std::string> keys;
  std::vector<std::string> values;
  ASSERT_TRUE(test_ds_->Keys(&keys));
  ASSERT_EQ(1, keys.size());
  ASSERT_TRUE(test_ds_->LoadItem(key, &values));
  ASSERT_EQ(1, values.size());
  ASSERT_EQ(value, values[0]);
  ASSERT_TRUE(test_ds_->MarkForDeletion(key, value, "delete request"));
  values.clear();
  ASSERT_FALSE(test_ds_->LoadItem(key, &values));
  keys.clear();
  boost::this_thread::sleep(boost::posix_time::seconds(4));
  test_ds_->DeleteExpiredValues();
  ASSERT_FALSE(test_ds_->LoadItem(key, &values));
  ASSERT_TRUE(test_ds_->Keys(&keys));
  ASSERT_TRUE(keys.empty());
}
#endif 
TEST_F(DataStoreTest, BEH_KAD_UpdateValues) {
  size_t total_values(5);
  for (size_t n = 0; n < total_values; ++n) {
    std::string key("key" + IntToString(n));
    std::string value("value" + IntToString(n));
    std::string signature("signature" + IntToString(n));
    EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key, value, signature), 
                                     bptime::seconds(3600*24), false)); 
  }
  EXPECT_EQ(total_values, GetKeyValueIndex().size());
  std::vector<std::pair<std::string, std::string>> values;
  EXPECT_TRUE(test_ds_->GetValues("key0", &values));
  EXPECT_EQ(size_t(1), values.size());
  EXPECT_EQ("value0", values[0].first);
  EXPECT_EQ("signature0", values[0].second);
  EXPECT_TRUE(test_ds_->UpdateValue(KeyValueSignature("key0", "value0",
                                                      "signature0"), 
                                    KeyValueSignature("key0","misbolas0",
                                                      "misbolas0"), 
                                    bptime::seconds(500), true));
  EXPECT_EQ(total_values, GetKeyValueIndex().size());
  values.clear();
  EXPECT_TRUE(test_ds_->GetValues("key0", &values));
  EXPECT_EQ(size_t(1), values.size());
  EXPECT_EQ("misbolas0", values[0].first);
  EXPECT_EQ("misbolas0", values[0].second);
  std::string key("key0");
  for (size_t a = 0; a < total_values; ++a) {
    std::string value("value_" + IntToString(a));
    std::string signature("signature_" + IntToString(a));
    EXPECT_TRUE(test_ds_->StoreValue(KeyValueSignature(key, value, signature), 
    bptime::seconds(3600*24), false));    
  }
  values.clear();
  EXPECT_TRUE(test_ds_->GetValues("key0", &values));
  EXPECT_EQ(size_t(6), values.size());
  //new value already existing under the kye 
  EXPECT_TRUE(test_ds_->UpdateValue(KeyValueSignature("key0", "value_2",
                                                       "signature_2"), 
                                     KeyValueSignature("key0","misbolas0", 
                                                       "misbolas0"),
			                               bptime::seconds(500), true));
  values.clear();
  EXPECT_TRUE(test_ds_->GetValues("key0", &values));
  EXPECT_EQ(size_t(5), values.size());
  //updating with same value  
  EXPECT_TRUE(test_ds_->UpdateValue(KeyValueSignature("key0", "value_3",
                                                       "signature_3"), 
                                     KeyValueSignature("key0","value_3", 
                                                       "signature_3"),
			                               bptime::seconds(500), true));
  values.clear();
  EXPECT_TRUE(test_ds_->GetValues("key0", &values));
  EXPECT_EQ(size_t(5), values.size());
  //Attempting to change key
  EXPECT_FALSE(test_ds_->UpdateValue(KeyValueSignature("key0", "value_3",
                                                       "signature_3"), 
                                     KeyValueSignature("key99","value_99", 
                                                       "signature_99"),
			                               bptime::seconds(30000), true));
  values.clear();
  EXPECT_TRUE(test_ds_->GetValues("key0", &values));
  EXPECT_EQ(size_t(5), values.size());
  EXPECT_TRUE(test_ds_->UpdateValue(KeyValueSignature("key0", "value_4", 
                                                      "signature_4"),
                                    KeyValueSignature("key0","bolotas0", 
                                                      "bolotas0"),
			                              bptime::seconds(500), true));
  values.clear();
  EXPECT_TRUE(test_ds_->GetValues("key0", &values));
  EXPECT_EQ(size_t(5), values.size());
  size_t count =std::count_if(values.begin(), values.end(), 
                              boost::bind(&DataStoreTest::findValue, this, _1, 
                                          std::make_pair("bolotas0",
                                                         "bolotas0")));
  EXPECT_EQ(size_t(1), count);
  // Invalid key/value/signature
  EXPECT_FALSE(test_ds_->UpdateValue(KeyValueSignature("key0", "bolotas0",
                                                       "bolotas0"), 
                                     KeyValueSignature("key0","", 
                                                       "signature_99"),
			                               bptime::seconds(500), true));
  EXPECT_FALSE(test_ds_->UpdateValue(KeyValueSignature("key0", "bolotas0",
                                                        "bolotas0"), 
                                     KeyValueSignature("key0","value_99", 
                                                       ""),
			                               bptime::seconds(500), true));
  EXPECT_FALSE(test_ds_->UpdateValue(KeyValueSignature("key0", "bolotas0",
                                                       "bolotas0"), 
                                     KeyValueSignature("key0", "", ""),
			                               bptime::seconds(500), true));
  EXPECT_FALSE(test_ds_->UpdateValue(KeyValueSignature("key0", "bolotas0",
                                                       "bolotas0"), 
                                     KeyValueSignature("","value_99", 
                                                       "signature_99"),
			                               bptime::seconds(500), true));
  values.clear();
  EXPECT_TRUE(test_ds_->GetValues("key0", &values));
  EXPECT_EQ(size_t(5), values.size());
}

}  // namespace test

}  // namespace kademlia

}  // namespace maidsafe
