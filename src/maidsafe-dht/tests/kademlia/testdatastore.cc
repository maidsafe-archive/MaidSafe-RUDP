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

#include <memory>
#include <string>
#include <vector>
#include "boost/cstdint.hpp"
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

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace kademlia {

namespace test {

typedef std::vector<std::pair<std::string, std::string>> KeyValuePairGroup;
const boost::uint16_t kIteratorSize = 23;
const boost::uint16_t kThreadBarrierSize = 5;

class DataStoreTest: public testing::Test {
 public:
  DataStoreTest()
      : thread_barrier_(new boost::barrier(kThreadBarrierSize)),
        thread_barrier_1_(new boost::barrier(kThreadBarrierSize)),
        data_store_(new kademlia::DataStore(bptime::seconds(3600))),
        key_value_index_(data_store_->key_value_index_),
        key_value_from_front_(),
        key_value_from_end_(),
        key_value_from_mid_(),
        crypto_keys_() {}
  KeyValueTuple MakeKVT(const crypto::RsaKeyPair &rsa_key_pair,
                        const size_t &value_size,
                        const bptime::time_duration &ttl) {
    std::string key = crypto::Hash<crypto::SHA512>(RandomString(1024));
    std::string value;
    value.reserve(value_size);
    std::string temp = RandomString((value_size > 1024) ? 1024 : value_size);
    while (value.size() < value_size)
      value += temp;
    value = value.substr(0, value_size);
    std::string signature = crypto::AsymSign(value, rsa_key_pair.private_key());
    bptime::ptime now = bptime::microsec_clock::universal_time();
    bptime::ptime expire_time = now + ttl;
    bptime::ptime refresh_time = now + bptime::minutes(30);
    std::string request = RandomString(1024);
    std::string req_sig = crypto::AsymSign(request, rsa_key_pair.private_key());
    return KeyValueTuple(KeyValueSignature(key, value, signature),
                         expire_time, refresh_time,
                         RequestAndSignature(request, req_sig), false);
  }
  bool FindValue(std::pair<std::string, std::string> element,
                 std::pair<std::string, std::string> value) {
    return ((element.first == value.first) && (element.second == value.second));
  }
  void CheckKey(const std::string &key) {
    thread_barrier_->wait();
    EXPECT_TRUE(data_store_->HasKey(key));
  }
  void MakeMultipleEntries() {
    for (int h = 0; h != 5; ++h) {
      crypto_keys_.push_back(crypto::RsaKeyPair());
      crypto_keys_.at(h).GenerateKeys(1024);
    }
    for (int i = 1; i < 1001; ++i) {
      bptime::ptime expire_time = bptime::microsec_clock::universal_time();
      expire_time += bptime::hours(20);
      bptime::ptime refresh_time = expire_time - bptime::hours(10);
      std::string key(RandomString(i * 7));
      std::string value(RandomString(i * 11));
      int crypto_key_index = RandomUint32() % crypto_keys_.size();
      std::string signature(crypto::AsymSign(value,
          crypto_keys_.at(crypto_key_index).private_key()));
      KeyValueSignature key_value_signature(key, value, signature);
      std::string request(RandomString(i * 3));
      std::string req_signature(crypto::AsymSign(request,
          crypto_keys_.at(crypto_key_index).private_key()));
      RequestAndSignature req_and_sig(make_pair(request, req_signature));
      data_store_->key_value_index_->insert(
          KeyValueTuple(key_value_signature, expire_time, refresh_time,
                        req_and_sig, false));
      if (i > 0 && i < 47)  // kIteratorSize * 2
        key_value_from_front_.push_back(make_pair(key, value));
      if (i > 500 && i < 570)  // kIteratorSize * 3
        key_value_from_mid_.push_back(key_value_signature);
      if (i > 942 && i < 990)  // kIteratorSize * 2
        key_value_from_end_.push_back(make_pair(key, value));
    }
  }

 protected:
  std::shared_ptr<boost::barrier> thread_barrier_, thread_barrier_1_;
  std::shared_ptr<DataStore> data_store_;
  std::shared_ptr<KeyValueIndex> key_value_index_;
  KeyValuePairGroup key_value_from_front_, key_value_from_end_;
  std::vector<KeyValueSignature> key_value_from_mid_;
  std::vector<crypto::RsaKeyPair> crypto_keys_;
 private:
  DataStoreTest(const DataStoreTest&);
  DataStoreTest &operator=(const DataStoreTest&);
};

TEST_F(DataStoreTest, BEH_KAD_StoreUnderEmptyKey) {
  EXPECT_EQ(0U, key_value_index_->size());
  for (int i = 0; i != 2; ++i) {
    crypto_keys_.push_back(crypto::RsaKeyPair());
    crypto_keys_.at(i).GenerateKeys(1024);
  }
  bptime::time_duration ttl(bptime::pos_infin);
  KeyValueTuple kvt1 = MakeKVT(crypto_keys_.at(0), 1024, ttl);
  KeyValueTuple kvt2 = MakeKVT(crypto_keys_.at(1), 5 * 1024 * 1024, ttl);
  EXPECT_TRUE(data_store_->StoreValue(kvt1.key_value_signature, ttl,
      kvt1.request_and_signature, crypto_keys_.at(0).public_key(), false));
  EXPECT_TRUE(data_store_->StoreValue(kvt2.key_value_signature, ttl,
      kvt2.request_and_signature, crypto_keys_.at(1).public_key(), false));
  EXPECT_EQ(2U, key_value_index_->size());
  EXPECT_EQ(1U, key_value_index_->count(kvt1.key()));
  EXPECT_EQ(1U, key_value_index_->count(kvt2.key()));
  KeyValuePairGroup values;
  EXPECT_TRUE(data_store_->GetValues(kvt1.key(), &values));
  EXPECT_EQ(1U, values.size());
  EXPECT_EQ(make_pair(kvt1.value(), kvt1.key_value_signature.signature),
            values.front());
  EXPECT_TRUE(data_store_->GetValues(kvt2.key(), &values));
  ASSERT_EQ(1U, values.size());
  EXPECT_EQ(make_pair(kvt2.value(), kvt2.key_value_signature.signature),
            values.front());
}

TEST_F(DataStoreTest, BEH_KAD_RefreshStoreUnderEmptyKey) {
  crypto::RsaKeyPair crypto_keys;
  crypto_keys.GenerateKeys(1024);
  bptime::time_duration ttl(bptime::pos_infin);
  KeyValueTuple kvt = MakeKVT(crypto_keys, 1024, ttl);
  EXPECT_TRUE(data_store_->StoreValue(kvt.key_value_signature, ttl,
      kvt.request_and_signature, crypto_keys.public_key(), true));

  KeyValuePairGroup values;
  EXPECT_TRUE(data_store_->GetValues(kvt.key(), &values));
  EXPECT_EQ(1U, values.size());
  EXPECT_EQ(make_pair(kvt.value(), kvt.key_value_signature.signature),
            values.front());
}

TEST_F(DataStoreTest, BEH_KAD_StoreUnderExistingKey) {
}

TEST_F(DataStoreTest, BEH_KAD_RefreshStoreUnderExistingKey) {
}

TEST_F(DataStoreTest, BEH_KAD_StoreExistingKeyValue) {
}

TEST_F(DataStoreTest, BEH_KAD_RefreshStoreExistingKeyValue) {
}

TEST_F(DataStoreTest, BEH_KAD_DeleteUnderEmptyKey) {
}

TEST_F(DataStoreTest, BEH_KAD_RefreshDeleteUnderEmptyKey) {
}

TEST_F(DataStoreTest, BEH_KAD_DeleteExistingKeyValue) {
}

TEST_F(DataStoreTest, BEH_KAD_RefreshDeleteExistingKeyValue) {
}


/*
TEST_F(DataStoreTest, BEH_KAD_StoreInvalidData) {
  std::string value1(crypto::Hash<crypto::SHA512>("bb33"));
  std::string signature1(crypto::Hash<crypto::SHA512>(value1));
  std::string key1(crypto::Hash<crypto::SHA512>(value1));
  // invalid key
  EXPECT_FALSE(data_store_->StoreValue(KeyValueSignature("", value1, signature1),
                                    bptime::seconds(3600*24), false));
  // invalid value
  EXPECT_FALSE(data_store_->StoreValue(KeyValueSignature(key1, "", signature1),
                                    bptime::seconds(3600*24), false));
  // invalid signature
  EXPECT_FALSE(data_store_->StoreValue(KeyValueSignature(key1, value1, ""),
                                    bptime::seconds(3600*24), false));
  // invalid key,value & signature
  EXPECT_FALSE(data_store_->StoreValue(KeyValueSignature("", "", ""),
                                    bptime::seconds(3600*24), false));
  // invalid time to live
  EXPECT_FALSE(data_store_->StoreValue(KeyValueSignature(key1, value1, signature1),
                                    bptime::seconds(0), false));
}

TEST_F(DataStoreTest, BEH_KAD_LoadExistingData) {
  // one value under a key
  std::string value1(crypto::Hash<crypto::SHA512>("oybbggjhhtytyerterter"));
  std::string key1(crypto::Hash<crypto::SHA512>(value1));
  std::string signature1(crypto::Hash<crypto::SHA512>(key1));
  EXPECT_TRUE(data_store_->StoreValue(KeyValueSignature(key1, value1, signature1),
                                   bptime::seconds(3600*24), true));
  KeyValuePairGroup values;
  EXPECT_TRUE(data_store_->GetValues(key1, &values));
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

  EXPECT_TRUE(data_store_->StoreValue(
      KeyValueSignature(key2, value2_1, signature2), bptime::seconds(3600*24),
      false));
  EXPECT_TRUE(data_store_->StoreValue(
      KeyValueSignature(key2, value2_2, signature2), bptime::seconds(3600*24),
      false));
  EXPECT_TRUE(data_store_->StoreValue(
      KeyValueSignature(key2, value2_3, signature2), bptime::seconds(3600*24),
      false));
  values.clear();
  EXPECT_TRUE(data_store_->GetValues(key2, &values));
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
  attr_key1 = data_store_->LoadKeyAppendableAttr(key1);
  EXPECT_EQ(1, attr_key1.size());
  EXPECT_EQ(value1, attr_key1[0].first);
  EXPECT_TRUE(attr_key1[0].second);

  attr_key2 = data_store_->LoadKeyAppendableAttr(key2);
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
  KeyValuePairGroup values;
  EXPECT_FALSE(data_store_->GetValues(key1, &values));
  EXPECT_TRUE(values.empty());
  std::vector<std::pair<std::string, bool>> attr_key;
  attr_key = data_store_->LoadKeyAppendableAttr(key1);
  EXPECT_TRUE(attr_key.empty());
}

TEST_F(DataStoreTest, BEH_KAD_LoadEmptyKeyData) {
  KeyValuePairGroup values;
  EXPECT_FALSE(data_store_->GetValues("", &values));
  EXPECT_TRUE(values.empty());
  std::vector<std::pair<std::string, bool>> attr_key;
  attr_key = data_store_->LoadKeyAppendableAttr("");
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

  key_value_index_->insert(keyvalue1);
  key_value_index_->insert(keyvalue2);
  key_value_index_->insert(keyvalue3);
  ASSERT_FALSE(data_store_->HasKey(""));
  ASSERT_TRUE(data_store_->HasKey(key_value_signature1.key));
  ASSERT_FALSE(data_store_->HasKey(RandomString(11)));
  ASSERT_FALSE(data_store_->HasKey(key_value_signature3.key));
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

  key_value_index_->insert(keyvalue1);
  key_value_index_->insert(keyvalue2);
  key_value_index_->insert(keyvalue3);

  ASSERT_EQ(size_t(3), key_value_index_->size());
  ASSERT_TRUE(data_store_->DeleteValue(key_value_signature1.key,
                                    key_value_signature2.value));
  ASSERT_EQ(size_t(2), key_value_index_->size());
  EXPECT_TRUE(data_store_->HasKey(key_value_signature1.key));
  EXPECT_TRUE(data_store_->HasKey(key_value_signature3.key));
  ASSERT_TRUE(data_store_->DeleteValue(key_value_signature1.key,
                                    key_value_signature1.value));
  ASSERT_EQ(size_t(1), key_value_index_->size());
  EXPECT_TRUE(data_store_->HasKey(key_value_signature3.key));
  EXPECT_FALSE(data_store_->HasKey(key_value_signature1.key));
  ASSERT_TRUE(data_store_->DeleteValue(key_value_signature3.key,
                                    key_value_signature3.value));
  ASSERT_EQ(size_t(0), key_value_index_->size());
  EXPECT_FALSE(data_store_->HasKey(key_value_signature2.key));
  EXPECT_FALSE(data_store_->HasKey(key_value_signature3.key));
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
  KeyValuePairGroup values, values1;
  this->MakeMultipleEntries();

  auto key_front =  key_value_from_front_.begin();
  for (int i = 0; i < kIteratorSize; ++i) {
    asio_service->post(boost::bind(&DataStore::DeleteValue, data_store_,
                                   key_front->first,
                                   key_front->second));
    ++key_front;
  }

  auto k = key_value_from_end_.end();
  for (int i = 0; i < kIteratorSize; ++i) {
    --k;
    asio_service->post(boost::bind(&DataStore::DeleteValue, data_store_,
                                   k->first, k->second));
  }
  for (int i = 0; i < kIteratorSize; ++i) {
    asio_service->post(boost::bind(&DataStore::StoreValue, data_store_,
                                   KeyValueSignature(RandomString(i*103),
                                   RandomString(i*107),
                                   RandomString(i*111)),
                                   bptime::seconds(1000), false));
  }
  asio_service->post(boost::bind(&DataStore::GetValues, data_store_,
                                 k->first, &values));
  asio_service->post(boost::bind(&DataStore::MarkForDeletion, data_store_,
                                 KeyValueSignature(k->first, k->second,
                                 RandomString(35)), RandomString(35)));
  ++k;
  asio_service->post(boost::bind(&DataStore::GetValues, data_store_,
                                 k->first, &values1));
  auto s = key_value_from_mid_.begin();

  for (int i = 0; i < kIteratorSize; ++i) {
    asio_service->post(boost::bind(&DataStore::RefreshKeyValue, data_store_,
                                   (*s), &(RandomString(35))));
    ++s;
  }
  for (int i = 0; i < kIteratorSize; ++i) {
    ++s;
    asio_service->post(boost::bind(&DataStore::UpdateValue, data_store_,
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

TEST_F(DataStoreTest, BEH_KAD_StoreMultipleValuesWithSameKey) {
  EXPECT_EQ(size_t(0), key_value_index_->size());
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
    EXPECT_TRUE(data_store_->StoreValue(key_value_signatures[j],
                                     bptime::seconds(3600*24), false));
    random_string.clear();
  }
  KeyValuePairGroup values;
  EXPECT_TRUE(data_store_->GetValues(key, &values));
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
  EXPECT_TRUE(data_store_->StoreValue(key_value_signatures[j],
                                   bptime::seconds(3600*24), false));
  random_key.clear();
  }
  KeyValuePairGroup values;
  for (int i = 0; i < 10; ++i) {
    EXPECT_TRUE(data_store_->GetValues(key_value_signatures[i].key, &values));
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
      EXPECT_TRUE(data_store_->StoreValue(KeyValueSignature(random_string,
                                       random_string, random_string),
                                       bptime::seconds(3600*24), false));
    } else {
      EXPECT_FALSE(data_store_->StoreValue(KeyValueSignature("", "", ""),
                                        bptime::seconds(3600*24), false));
    }
    random_string.clear();
  }
  KeyValuePairGroup values;
  for (auto it = key_value_signatures.begin(); it != key_value_signatures.end();
       ++it) {
    EXPECT_TRUE(data_store_->GetValues((*it).key, &values));
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
  EXPECT_TRUE(data_store_->StoreValue(KeyValueSignature(key1, value1, signature1),
                                   bptime::seconds(3600*24), false));
  KeyValueIndex::index<TagKeyValue>::type& index_by_key_value =
      key_value_index_->get<TagKeyValue>();

  auto it = index_by_key_value.find(boost::make_tuple(key1, value1));
  ASSERT_FALSE(it == index_by_key_value.end());
  bptime::ptime t_refresh1 = (*it).refresh_time;
  bptime::ptime t_expire1 = (*it).expire_time;
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_refresh1);
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_expire1);
  KeyValuePairGroup values;
  EXPECT_TRUE(data_store_->GetValues(key1, &values));
  ASSERT_EQ(1, values.size());
  EXPECT_EQ(value1, values[0].first);
  EXPECT_EQ(signature1, values[0].second);
  boost::this_thread::sleep(boost::posix_time::milliseconds(1500));
  // refreshing the value
  std::string ser_del_request;
  EXPECT_FALSE(data_store_->RefreshKeyValue(KeyValueSignature("key1", value1,
                                                           signature1),
                                         &ser_del_request));
  EXPECT_FALSE(data_store_->RefreshKeyValue(KeyValueSignature(key1, "value1",
                                                           signature1),
                                         &ser_del_request));
  EXPECT_FALSE(data_store_->RefreshKeyValue(KeyValueSignature(key1, value1,
                                                           "signature1"),
                                         &ser_del_request));
  EXPECT_FALSE(data_store_->RefreshKeyValue(KeyValueSignature("key1", "value1",
                                                           "signature1"),
                                         &ser_del_request));
  EXPECT_TRUE(data_store_->RefreshKeyValue(KeyValueSignature(key1, value1,
                                                          signature1),
                                         &ser_del_request));
  index_by_key_value = key_value_index_->get<TagKeyValue>();
  it = index_by_key_value.find(boost::make_tuple(key1, value1));
  ASSERT_FALSE(it == index_by_key_value.end());
  bptime::ptime t_refresh2 = (*it).refresh_time;
  bptime::ptime t_expire2 = (*it).expire_time;
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_refresh2);
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_expire2);
  EXPECT_LT(t_refresh1, t_refresh2);
  EXPECT_EQ(t_expire1, t_expire2);
  values.clear();
  EXPECT_TRUE(data_store_->GetValues(key1, &values));
  ASSERT_EQ(1, values.size());
  EXPECT_EQ(value1, values[0].first);
  EXPECT_EQ(signature1, values[0].second);
}

TEST_F(DataStoreTest, BEH_KAD_RepublishKeyValue) {
  std::string key1 = crypto::Hash<crypto::SHA512>("663efsxx33d");
  std::string value1 = RandomString(500);
  std::string signature1 = crypto::Hash<crypto::SHA512>(key1);
  EXPECT_TRUE(data_store_->StoreValue(KeyValueSignature(key1, value1, signature1),
                                   bptime::seconds(3600*24), false));
  KeyValueIndex::index<TagKeyValue>::type& index_by_key_value =
      key_value_index_->get<TagKeyValue>();
  auto it = index_by_key_value.find(boost::make_tuple(key1, value1));
  ASSERT_FALSE(it == index_by_key_value.end());
  bptime::ptime t_refresh1 = (*it).refresh_time;
  bptime::ptime t_expire1 = (*it).expire_time;
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_refresh1);
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_expire1);
  KeyValuePairGroup values;
  EXPECT_TRUE(data_store_->GetValues(key1, &values));
  ASSERT_EQ(1, values.size());
  EXPECT_EQ(value1, values[0].first);
  EXPECT_EQ(signature1, values[0].second);
  boost::this_thread::sleep(boost::posix_time::milliseconds(1500));
  // republishing the value
  EXPECT_TRUE(data_store_->StoreValue(KeyValueSignature(key1, value1, signature1),
                                   bptime::seconds(3600*24), false));
  index_by_key_value = key_value_index_->get<TagKeyValue>();
  it = index_by_key_value.find(boost::make_tuple(key1, value1));
  ASSERT_FALSE(it == index_by_key_value.end());
  bptime::ptime t_refresh2 = (*it).refresh_time;
  bptime::ptime t_expire2 = (*it).expire_time;
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_refresh2);
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_expire2);
  ASSERT_LT(t_refresh1, t_refresh2);
  ASSERT_LT(t_expire1, t_expire2);
  values.clear();
  EXPECT_TRUE(data_store_->GetValues(key1, &values));
  ASSERT_EQ(1, values.size());
  EXPECT_EQ(value1, values[0].first);
  EXPECT_EQ(signature1, values[0].second);
}

TEST_F(DataStoreTest, FUNC_KAD_ExpiredValuesNotReturned) {
  std::string value = RandomString(100);
  std::string key = crypto::Hash<crypto::SHA512>(RandomString(5));
  std::string signature = crypto::Hash<crypto::SHA512>(RandomString(5));
  EXPECT_TRUE(data_store_->StoreValue(KeyValueSignature(key, value, signature),
                                   bptime::seconds(3), false));
  KeyValuePairGroup values;
  EXPECT_TRUE(data_store_->GetValues(key, &values));
  EXPECT_FALSE(values.empty());
  EXPECT_EQ(value, values[0].first);
  EXPECT_EQ(signature, values[0].second);
  values.clear();
  boost::this_thread::sleep(boost::posix_time::seconds(4));
  EXPECT_FALSE(data_store_->GetValues(key, &values));
  EXPECT_TRUE(values.empty());

  std::string value2 = RandomString(100);
  EXPECT_TRUE(data_store_->StoreValue(KeyValueSignature(key, value, signature),
                                   bptime::seconds(3), false));
  EXPECT_TRUE(data_store_->StoreValue(KeyValueSignature(key, value2, signature),
                                   bptime::seconds(100), false));
  boost::this_thread::sleep(boost::posix_time::seconds(4));
  values.clear();
  EXPECT_TRUE(data_store_->GetValues(key, &values));
  EXPECT_EQ(size_t(1), values.size());
  EXPECT_EQ(value2, values[0].first);
}

TEST_F(DataStoreTest, BEH_KAD_AllKeyValueTuplePrivateAttributes) {
  std::string value(RandomString(50));
  std::string key(crypto::Hash<crypto::SHA512>(RandomString(5)));
  std::string signature(RandomString(50));
  EXPECT_TRUE(data_store_->StoreValue(KeyValueSignature(key, value, signature),
                                   bptime::seconds(100), false));
  KeyValueIndex::index<TagKeyValue>::type& index_by_key_value =
      key_value_index_->get<TagKeyValue>();
  auto it = index_by_key_value.find(boost::make_tuple(key, value));
  KeyValuePairGroup values;
  EXPECT_TRUE(data_store_->GetValues(key, &values));
  EXPECT_EQ(size_t(1), values.size());
  EXPECT_EQ(value, values[0].first);
  EXPECT_EQ(signature, values[0].second);

  bptime::ptime t_refresh1 = (*it).refresh_time;
  bptime::ptime t_expire1 = (*it).expire_time;
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_refresh1);
  EXPECT_LT(bptime::microsec_clock::universal_time(), t_expire1);
  EXPECT_FALSE((*it).expire_time.is_pos_infinity());
  EXPECT_EQ(kNotDeleted, (*it).delete_status);
  EXPECT_EQ(false, (*it).hashable);
  EXPECT_TRUE((*it).serialised_delete_request.empty());
  values.clear();
  std::string value2(RandomString(50));
  EXPECT_TRUE(data_store_->StoreValue(KeyValueSignature(key, value, signature),
                                   bptime::time_duration(bptime::pos_infin),
                                   false));
  it = index_by_key_value.find(boost::make_tuple(key, value));
  EXPECT_TRUE((*it).expire_time.is_pos_infinity());

  EXPECT_TRUE(data_store_->StoreValue(KeyValueSignature(key, value2, signature),
                                   bptime::time_duration(bptime::pos_infin),
                                   false));
  EXPECT_TRUE(data_store_->GetValues(key, &values));
  ASSERT_EQ(size_t(2), values.size());
  EXPECT_EQ(value, values[0].first);
  EXPECT_EQ(value2, values[1].first);
  EXPECT_EQ(signature, values[0].second);
  EXPECT_EQ(signature, values[1].second);
  it = index_by_key_value.find(boost::make_tuple(key, value2));
  EXPECT_TRUE((*it).expire_time.is_pos_infinity());
}

TEST_F(DataStoreTest, BEH_KAD_ChangeDelStatus) {
  std::string value1(RandomString(100)), value2(RandomString(50)),
    value3(RandomString(150));
  std::string key1(crypto::Hash<crypto::SHA512>(RandomString(5)));
  std::string key2(crypto::Hash<crypto::SHA512>(RandomString(15)));
  std::string signature1(crypto::Hash<crypto::SHA512>(RandomString(5)));
  std::string signature2(crypto::Hash<crypto::SHA512>(RandomString(5)));
  std::string signature3(crypto::Hash<crypto::SHA512>(RandomString(5)));
  EXPECT_TRUE(data_store_->StoreValue(KeyValueSignature(key1, value1, signature1),
                                   bptime::seconds(1000), false));
  EXPECT_TRUE(data_store_->StoreValue(KeyValueSignature(key1, value2, signature2),
                                   bptime::seconds(1000), false));
  EXPECT_TRUE(data_store_->StoreValue(KeyValueSignature(key2, value3, signature3),
                                   bptime::seconds(1000), false));
  KeyValuePairGroup values;
  EXPECT_TRUE(data_store_->GetValues(key1, &values));
  EXPECT_EQ(size_t(2), values.size());
  for (size_t i = 0; i < values.size(); ++i)
    if (values[i].first != value1 && values[i].first != value2)
      FAIL();
  values.clear();
  EXPECT_TRUE(data_store_->GetValues(key2, &values));
  EXPECT_EQ(size_t(1), values.size());
  EXPECT_EQ(value3, values[0].first);
  EXPECT_EQ(signature3, values[0].second);
  values.clear();
  EXPECT_TRUE(data_store_->MarkForDeletion(KeyValueSignature(key1, value2,
                                                          signature2),
                                        "delete request"));
  EXPECT_TRUE(data_store_->GetValues(key1, &values));
  ASSERT_EQ(size_t(1), values.size());
  EXPECT_EQ(value1, values[0].first);
  values.clear();
  EXPECT_TRUE(data_store_->MarkForDeletion(KeyValueSignature(key2, value3,
                                                          signature3),
                                        "delete request"));
  EXPECT_TRUE(data_store_->MarkForDeletion(KeyValueSignature(key2, value3,
                                                          signature3),
                                        "delete request"));
  EXPECT_FALSE(data_store_->GetValues(key2, &values));
  EXPECT_TRUE(values.empty());
  EXPECT_FALSE(data_store_->MarkForDeletion(KeyValueSignature("bad key", value2,
                                                           signature2),
                                         "delete request"));
  values.clear();
  EXPECT_FALSE(data_store_->GetValues("bad key", &values));
  EXPECT_TRUE(values.empty());
}
*/
}  // namespace test

}  // namespace kademlia

}  // namespace maidsafe
