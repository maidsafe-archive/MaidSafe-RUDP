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
                        const bptime::time_duration &ttl,
                        std::string key,
                        std::string value) {
    if (key.empty())
      key = crypto::Hash<crypto::SHA512>(RandomString(1024));
    if (value.empty()) {
      value.reserve(value_size);
      std::string temp = RandomString((value_size > 1024) ? 1024 : value_size);
      while (value.size() < value_size)
        value += temp;
      value = value.substr(0, value_size);
    }
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
  for (int i = 0; i != 3; ++i) {
    crypto_keys_.push_back(crypto::RsaKeyPair());
    crypto_keys_.at(i).GenerateKeys(1024);
  }
  bptime::time_duration ttl(bptime::pos_infin);
  KeyValueTuple kvt1 = MakeKVT(crypto_keys_.at(0), 1024, ttl, "", "");
  KeyValueTuple kvt2 = MakeKVT(crypto_keys_.at(1), 5242880, ttl, "", "");
  KeyValueTuple kvt3 = MakeKVT(crypto_keys_.at(2), 1024, ttl, "", "");
  EXPECT_TRUE(data_store_->StoreValue(kvt1.key_value_signature, ttl,
      kvt1.request_and_signature, crypto_keys_.at(0).public_key(), false));
  EXPECT_TRUE(data_store_->StoreValue(kvt2.key_value_signature, ttl,
      kvt2.request_and_signature, crypto_keys_.at(1).public_key(), false));
  EXPECT_TRUE(data_store_->StoreValue(kvt3.key_value_signature, ttl,
      kvt2.request_and_signature, crypto_keys_.at(2).public_key(), true));
  EXPECT_EQ(3U, key_value_index_->size());
  EXPECT_EQ(1U, key_value_index_->count(kvt1.key()));
  EXPECT_EQ(1U, key_value_index_->count(kvt2.key()));
  EXPECT_EQ(1U, key_value_index_->count(kvt3.key()));
  KeyValuePairGroup values;
  EXPECT_TRUE(data_store_->GetValues(kvt1.key(), &values));
  EXPECT_EQ(1U, values.size());
  EXPECT_EQ(make_pair(kvt1.value(), kvt1.key_value_signature.signature),
            values.front());
  EXPECT_TRUE(data_store_->GetValues(kvt2.key(), &values));
  ASSERT_EQ(1U, values.size());
  EXPECT_EQ(make_pair(kvt2.value(), kvt2.key_value_signature.signature),
            values.front());
  EXPECT_TRUE(data_store_->GetValues(kvt3.key(), &values));
  ASSERT_EQ(1U, values.size());
  EXPECT_EQ(make_pair(kvt3.value(), kvt3.key_value_signature.signature),
            values.front());
}

TEST_F(DataStoreTest, BEH_KAD_StoreInvalidData) {
  crypto::RsaKeyPair crypto_keys;
  crypto_keys.GenerateKeys(1024);
  bptime::time_duration ttl(bptime::pos_infin), bad_ttl(bptime::hours(0));
  KeyValueTuple kvt = MakeKVT(crypto_keys, 1024, ttl, "", "");

  // Invalid time to live
  EXPECT_FALSE(data_store_->StoreValue(kvt.key_value_signature, bad_ttl,
      kvt.request_and_signature, crypto_keys.public_key(), false));
  EXPECT_TRUE(key_value_index_->empty());
  KeyValuePairGroup values;
  values.push_back(std::make_pair("a", "b"));
  EXPECT_FALSE(data_store_->GetValues(kvt.key(), &values));
  EXPECT_TRUE(values.empty());

  // Invalid key
  kvt.key_value_signature.key.clear();
  EXPECT_FALSE(data_store_->StoreValue(kvt.key_value_signature, ttl,
      kvt.request_and_signature, crypto_keys.public_key(), false));
  EXPECT_TRUE(key_value_index_->empty());
  values.push_back(std::make_pair("a", "b"));
  EXPECT_FALSE(data_store_->GetValues(kvt.key(), &values));
  EXPECT_TRUE(values.empty());
}

TEST_F(DataStoreTest, BEH_KAD_StoreUnderExistingKey) {
  for (int i = 0; i != 2; ++i) {
    crypto_keys_.push_back(crypto::RsaKeyPair());
    crypto_keys_.at(i).GenerateKeys(1024);
  }
  bptime::time_duration ttl(bptime::pos_infin);
  KeyValueTuple kvt1 = MakeKVT(crypto_keys_.at(0), 1024, ttl, "", "");
  std::string common_key = kvt1.key_value_signature.key;
  KeyValueTuple kvt2 = MakeKVT(crypto_keys_.at(0), 1024, ttl, common_key, "");
  KeyValueTuple kvt3 = MakeKVT(crypto_keys_.at(0), 1024, ttl, common_key, "");
  KeyValueTuple kvt4 = MakeKVT(crypto_keys_.at(1), 1024, ttl, common_key, "");
  KeyValueTuple kvt5 = MakeKVT(crypto_keys_.at(1), 1024, ttl, common_key, "");

  // Initial key,value.
  EXPECT_TRUE(data_store_->StoreValue(kvt1.key_value_signature, ttl,
      kvt1.request_and_signature, crypto_keys_.at(0).public_key(), false));
  // Same key, different value, same signing private key, publish-type store.
  EXPECT_TRUE(data_store_->StoreValue(kvt2.key_value_signature, ttl,
      kvt2.request_and_signature, crypto_keys_.at(0).public_key(), false));
  // Same key, different value, same signing private key, refresh-type store.
  EXPECT_TRUE(data_store_->StoreValue(kvt3.key_value_signature, ttl,
      kvt3.request_and_signature, crypto_keys_.at(0).public_key(), true));
  // Same key, different value, different signing private key, publish-type
  // store.
  EXPECT_FALSE(data_store_->StoreValue(kvt4.key_value_signature, ttl,
      kvt4.request_and_signature, crypto_keys_.at(1).public_key(), false));
  // Same key, different value, different signing private key, refresh-type
  // store.
  EXPECT_FALSE(data_store_->StoreValue(kvt5.key_value_signature, ttl,
      kvt5.request_and_signature, crypto_keys_.at(1).public_key(), true));

  EXPECT_EQ(3U, key_value_index_->size());
  EXPECT_EQ(3U, key_value_index_->count(common_key));
  KeyValuePairGroup values;
  EXPECT_TRUE(data_store_->GetValues(common_key, &values));
  ASSERT_EQ(3U, values.size());

  EXPECT_EQ(make_pair(kvt1.value(), kvt1.key_value_signature.signature),
            values.at(0));
  EXPECT_NE(make_pair(kvt1.value(), kvt1.key_value_signature.signature),
            values.at(1));
  EXPECT_NE(make_pair(kvt1.value(), kvt1.key_value_signature.signature),
            values.at(2));

  EXPECT_NE(make_pair(kvt2.value(), kvt2.key_value_signature.signature),
            values.at(0));
  EXPECT_EQ(make_pair(kvt2.value(), kvt2.key_value_signature.signature),
            values.at(1));
  EXPECT_NE(make_pair(kvt2.value(), kvt2.key_value_signature.signature),
            values.at(2));

  EXPECT_NE(make_pair(kvt3.value(), kvt3.key_value_signature.signature),
            values.at(0));
  EXPECT_NE(make_pair(kvt3.value(), kvt3.key_value_signature.signature),
            values.at(1));
  EXPECT_EQ(make_pair(kvt3.value(), kvt3.key_value_signature.signature),
            values.at(2));

  EXPECT_NE(make_pair(kvt4.value(), kvt4.key_value_signature.signature),
            values.at(0));
  EXPECT_NE(make_pair(kvt4.value(), kvt4.key_value_signature.signature),
            values.at(1));
  EXPECT_NE(make_pair(kvt4.value(), kvt4.key_value_signature.signature),
            values.at(2));

  EXPECT_NE(make_pair(kvt5.value(), kvt5.key_value_signature.signature),
            values.at(0));
  EXPECT_NE(make_pair(kvt5.value(), kvt5.key_value_signature.signature),
            values.at(1));
  EXPECT_NE(make_pair(kvt5.value(), kvt5.key_value_signature.signature),
            values.at(2));
}

TEST_F(DataStoreTest, BEH_KAD_StoreExistingKeyValue) {
  for (int i = 0; i != 2; ++i) {
    crypto_keys_.push_back(crypto::RsaKeyPair());
    crypto_keys_.at(i).GenerateKeys(1024);
  }
  bptime::time_duration old_ttl(bptime::pos_infin), new_ttl(bptime::hours(24));
  KeyValueTuple old_kvt = MakeKVT(crypto_keys_.at(0), 1024, old_ttl, "", "");
  std::string common_key = old_kvt.key_value_signature.key;
  std::string common_value = old_kvt.key_value_signature.value;
  // Use different signing key
  KeyValueTuple new_bad_refresh_kvt =
      MakeKVT(crypto_keys_.at(1), 1024, new_ttl, common_key, common_value);
  // Use different signing key
  KeyValueTuple new_bad_store_kvt =
      MakeKVT(crypto_keys_.at(1), 1024, new_ttl, common_key, common_value);
  // Use original signing key
  KeyValueTuple new_good_refresh_kvt =
      MakeKVT(crypto_keys_.at(0), 1024, new_ttl, common_key, common_value);
  // Use original signing key
  KeyValueTuple new_good_store_kvt =
      MakeKVT(crypto_keys_.at(0), 1024, new_ttl, common_key, common_value);

  // Initial key,value.
  EXPECT_TRUE(data_store_->StoreValue(old_kvt.key_value_signature, old_ttl,
      old_kvt.request_and_signature, crypto_keys_.at(0).public_key(), false));
  ASSERT_EQ(1U, key_value_index_->size());
  std::string old_signature =
      (*key_value_index_->begin()).key_value_signature.signature;
  std::string old_request =
      (*key_value_index_->begin()).request_and_signature.first;
  std::string old_request_signature =
      (*key_value_index_->begin()).request_and_signature.second;
  bptime::ptime old_expire_time = (*key_value_index_->begin()).expire_time;
  bptime::ptime old_refresh_time = (*key_value_index_->begin()).refresh_time;
  bptime::ptime old_confirm_time = (*key_value_index_->begin()).confirm_time;

  // Same key, same value, different signing private key, refresh-type store.
  EXPECT_FALSE(data_store_->StoreValue(new_bad_refresh_kvt.key_value_signature,
      new_ttl, new_bad_refresh_kvt.request_and_signature,
      crypto_keys_.at(1).public_key(), true));
  ASSERT_EQ(1U, key_value_index_->size());
  EXPECT_EQ(old_signature,
            (*key_value_index_->begin()).key_value_signature.signature);
  EXPECT_EQ(old_request,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_EQ(old_request_signature,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(old_expire_time, (*key_value_index_->begin()).expire_time);
  EXPECT_EQ(old_refresh_time, (*key_value_index_->begin()).refresh_time);
  EXPECT_EQ(old_confirm_time, (*key_value_index_->begin()).confirm_time);
  EXPECT_FALSE((*key_value_index_->begin()).deleted);

  // Same key, same value, different signing private key, publish-type store.
  EXPECT_FALSE(data_store_->StoreValue(new_bad_store_kvt.key_value_signature,
      new_ttl, new_bad_store_kvt.request_and_signature,
      crypto_keys_.at(1).public_key(), false));
  ASSERT_EQ(1U, key_value_index_->size());
  EXPECT_EQ(old_signature,
            (*key_value_index_->begin()).key_value_signature.signature);
  EXPECT_EQ(old_request,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_EQ(old_request_signature,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(old_expire_time, (*key_value_index_->begin()).expire_time);
  EXPECT_EQ(old_refresh_time, (*key_value_index_->begin()).refresh_time);
  EXPECT_EQ(old_confirm_time, (*key_value_index_->begin()).confirm_time);
  EXPECT_FALSE((*key_value_index_->begin()).deleted);

  // Same key, same value, same signing private key, refresh-type store.
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_TRUE(data_store_->StoreValue(new_good_refresh_kvt.key_value_signature,
      new_ttl, new_good_refresh_kvt.request_and_signature,
      crypto_keys_.at(0).public_key(), true));
  ASSERT_EQ(1U, key_value_index_->size());
  EXPECT_EQ(old_signature,
            (*key_value_index_->begin()).key_value_signature.signature);
  EXPECT_EQ(old_request,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_EQ(old_request_signature,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(old_expire_time, (*key_value_index_->begin()).expire_time);
  bptime::ptime new_refresh_time = (*key_value_index_->begin()).refresh_time;
  EXPECT_LT(old_refresh_time, new_refresh_time);
  EXPECT_EQ(old_confirm_time, (*key_value_index_->begin()).confirm_time);
  EXPECT_FALSE((*key_value_index_->begin()).deleted);

  // Same key, same value, same signing private key, publish-type store.
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_TRUE(data_store_->StoreValue(new_good_store_kvt.key_value_signature,
      new_ttl, new_good_store_kvt.request_and_signature,
      crypto_keys_.at(0).public_key(), false));
  ASSERT_EQ(1U, key_value_index_->size());
  EXPECT_EQ(old_signature,
            (*key_value_index_->begin()).key_value_signature.signature);
  EXPECT_NE(old_request,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_NE(old_request_signature,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(new_good_store_kvt.request_and_signature.first,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_EQ(new_good_store_kvt.request_and_signature.second,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_GT(old_expire_time, (*key_value_index_->begin()).expire_time);
  EXPECT_LT(new_refresh_time, (*key_value_index_->begin()).refresh_time);
  EXPECT_LT(old_confirm_time, (*key_value_index_->begin()).confirm_time);
  EXPECT_FALSE((*key_value_index_->begin()).deleted);
}

TEST_F(DataStoreTest, BEH_KAD_StoreExistingDeletedKeyValue) {
  for (int i = 0; i != 2; ++i) {
    crypto_keys_.push_back(crypto::RsaKeyPair());
    crypto_keys_.at(i).GenerateKeys(1024);
  }
  bptime::time_duration old_ttl(bptime::pos_infin), new_ttl(bptime::hours(24));
  KeyValueTuple old_kvt = MakeKVT(crypto_keys_.at(0), 1024, old_ttl, "", "");
  std::string common_key = old_kvt.key_value_signature.key;
  std::string common_value = old_kvt.key_value_signature.value;
  // Use different signing key
  KeyValueTuple new_bad_refresh_kvt =
      MakeKVT(crypto_keys_.at(1), 1024, new_ttl, common_key, common_value);
  // Use different signing key
  KeyValueTuple new_bad_store_kvt =
      MakeKVT(crypto_keys_.at(1), 1024, new_ttl, common_key, common_value);
  // Use original signing key
  KeyValueTuple new_good_refresh_kvt =
      MakeKVT(crypto_keys_.at(0), 1024, new_ttl, common_key, common_value);
  // Use original signing key
  KeyValueTuple new_good_store_kvt =
      MakeKVT(crypto_keys_.at(0), 1024, new_ttl, common_key, common_value);

  // Initial key,value - mark as deleted.
  EXPECT_TRUE(data_store_->StoreValue(old_kvt.key_value_signature, old_ttl,
      old_kvt.request_and_signature, crypto_keys_.at(0).public_key(), false));
  EXPECT_TRUE(data_store_->DeleteValue(old_kvt.key_value_signature,
              old_kvt.request_and_signature, false));
  ASSERT_EQ(1U, key_value_index_->size());
  std::string old_signature =
      (*key_value_index_->begin()).key_value_signature.signature;
  std::string old_request =
      (*key_value_index_->begin()).request_and_signature.first;
  std::string old_request_signature =
      (*key_value_index_->begin()).request_and_signature.second;
  bptime::ptime old_expire_time = (*key_value_index_->begin()).expire_time;
  bptime::ptime old_refresh_time = (*key_value_index_->begin()).refresh_time;
  bptime::ptime old_confirm_time = (*key_value_index_->begin()).confirm_time;

  // Same key, same value, different signing private key, refresh-type store.
  EXPECT_FALSE(data_store_->StoreValue(new_bad_refresh_kvt.key_value_signature,
      new_ttl, new_bad_refresh_kvt.request_and_signature,
      crypto_keys_.at(1).public_key(), true));
  ASSERT_EQ(1U, key_value_index_->size());
  EXPECT_EQ(old_signature,
            (*key_value_index_->begin()).key_value_signature.signature);
  EXPECT_EQ(old_request,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_EQ(old_request_signature,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(old_expire_time, (*key_value_index_->begin()).expire_time);
  EXPECT_EQ(old_refresh_time, (*key_value_index_->begin()).refresh_time);
  EXPECT_EQ(old_confirm_time, (*key_value_index_->begin()).confirm_time);
  EXPECT_TRUE((*key_value_index_->begin()).deleted);

  // Same key, same value, different signing private key, publish-type store.
  EXPECT_FALSE(data_store_->StoreValue(new_bad_store_kvt.key_value_signature,
      new_ttl, new_bad_store_kvt.request_and_signature,
      crypto_keys_.at(1).public_key(), false));
  ASSERT_EQ(1U, key_value_index_->size());
  EXPECT_EQ(old_signature,
            (*key_value_index_->begin()).key_value_signature.signature);
  EXPECT_EQ(old_request,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_EQ(old_request_signature,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(old_expire_time, (*key_value_index_->begin()).expire_time);
  EXPECT_EQ(old_refresh_time, (*key_value_index_->begin()).refresh_time);
  EXPECT_EQ(old_confirm_time, (*key_value_index_->begin()).confirm_time);
  EXPECT_TRUE((*key_value_index_->begin()).deleted);

  // Same key, same value, same signing private key, refresh-type store.
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_FALSE(data_store_->StoreValue(new_good_refresh_kvt.key_value_signature,
      new_ttl, new_good_refresh_kvt.request_and_signature,
      crypto_keys_.at(0).public_key(), true));
  ASSERT_EQ(1U, key_value_index_->size());
  EXPECT_EQ(old_signature,
            (*key_value_index_->begin()).key_value_signature.signature);
  EXPECT_EQ(old_request,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_EQ(old_request_signature,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(old_expire_time, (*key_value_index_->begin()).expire_time);
  EXPECT_EQ(old_refresh_time, (*key_value_index_->begin()).refresh_time);
  EXPECT_EQ(old_confirm_time, (*key_value_index_->begin()).confirm_time);
  EXPECT_TRUE((*key_value_index_->begin()).deleted);

  // Same key, same value, same signing private key, publish-type store.
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_TRUE(data_store_->StoreValue(new_good_store_kvt.key_value_signature,
      new_ttl, new_good_store_kvt.request_and_signature,
      crypto_keys_.at(0).public_key(), false));
  ASSERT_EQ(1U, key_value_index_->size());
  EXPECT_EQ(old_signature,
            (*key_value_index_->begin()).key_value_signature.signature);
  EXPECT_NE(old_request,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_NE(old_request_signature,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(new_good_store_kvt.request_and_signature.first,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_EQ(new_good_store_kvt.request_and_signature.second,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_GT(old_expire_time, (*key_value_index_->begin()).expire_time);
  EXPECT_LT(old_refresh_time, (*key_value_index_->begin()).refresh_time);
  EXPECT_LT(old_confirm_time, (*key_value_index_->begin()).confirm_time);
  EXPECT_FALSE((*key_value_index_->begin()).deleted);
}

TEST_F(DataStoreTest, BEH_KAD_DeleteUnderEmptyKey) {
  crypto::RsaKeyPair crypto_keys;
  crypto_keys.GenerateKeys(1024);
  bptime::time_duration ttl(bptime::pos_infin);
  KeyValueTuple kvt1 = MakeKVT(crypto_keys, 1024, ttl, "", "");
  KeyValueTuple kvt2 = MakeKVT(crypto_keys, 1024, ttl, "", "");
  KeyValueTuple kvt3 = MakeKVT(crypto_keys, 1024, ttl, kvt1.key(), "");

  EXPECT_TRUE(data_store_->StoreValue(kvt1.key_value_signature, ttl,
      kvt1.request_and_signature, crypto_keys.public_key(), false));
  EXPECT_EQ(1U, key_value_index_->size());

  EXPECT_TRUE(data_store_->DeleteValue(kvt2.key_value_signature,
               kvt2.request_and_signature, false));
  EXPECT_EQ(1U, key_value_index_->size());

  EXPECT_TRUE(data_store_->DeleteValue(kvt2.key_value_signature,
               kvt2.request_and_signature, true));
  EXPECT_EQ(1U, key_value_index_->size());

  EXPECT_TRUE(data_store_->DeleteValue(kvt3.key_value_signature,
               kvt3.request_and_signature, false));
  EXPECT_EQ(1U, key_value_index_->size());

  EXPECT_TRUE(data_store_->DeleteValue(kvt3.key_value_signature,
               kvt3.request_and_signature, true));
  EXPECT_EQ(1U, key_value_index_->size());
}

TEST_F(DataStoreTest, BEH_KAD_DeleteExistingKeyValue) {
  for (int i = 0; i != 2; ++i) {
    crypto_keys_.push_back(crypto::RsaKeyPair());
    crypto_keys_.at(i).GenerateKeys(1024);
  }
  bptime::time_duration old_ttl(bptime::pos_infin), new_ttl(bptime::hours(24));
  KeyValueTuple old_kvt = MakeKVT(crypto_keys_.at(0), 1024, old_ttl, "", "");
  std::string common_key = old_kvt.key_value_signature.key;
  std::string common_value = old_kvt.key_value_signature.value;
  // Use different signing key
  KeyValueTuple new_bad_refresh_kvt =
      MakeKVT(crypto_keys_.at(1), 1024, new_ttl, common_key, common_value);
  // Use different signing key
  KeyValueTuple new_bad_delete_kvt =
      MakeKVT(crypto_keys_.at(1), 1024, new_ttl, common_key, common_value);
  // Use original signing key
  KeyValueTuple new_good_refresh_kvt =
      MakeKVT(crypto_keys_.at(0), 1024, new_ttl, common_key, common_value);
  // Use original signing key
  KeyValueTuple new_good_delete_kvt =
      MakeKVT(crypto_keys_.at(0), 1024, new_ttl, common_key, common_value);

  // Initial key,value.
  EXPECT_TRUE(data_store_->StoreValue(old_kvt.key_value_signature, old_ttl,
      old_kvt.request_and_signature, crypto_keys_.at(0).public_key(), false));
  ASSERT_EQ(1U, key_value_index_->size());
  std::string old_signature =
      (*key_value_index_->begin()).key_value_signature.signature;
  std::string old_request =
      (*key_value_index_->begin()).request_and_signature.first;
  std::string old_request_signature =
      (*key_value_index_->begin()).request_and_signature.second;
  bptime::ptime old_expire_time = (*key_value_index_->begin()).expire_time;
  bptime::ptime old_refresh_time = (*key_value_index_->begin()).refresh_time;
  bptime::ptime old_confirm_time = (*key_value_index_->begin()).confirm_time;

  // Same key, same value, different signing private key, refresh-type delete.
  EXPECT_FALSE(data_store_->DeleteValue(new_bad_refresh_kvt.key_value_signature,
               new_bad_refresh_kvt.request_and_signature, true));
  ASSERT_EQ(1U, key_value_index_->size());
  EXPECT_EQ(old_signature,
            (*key_value_index_->begin()).key_value_signature.signature);
  EXPECT_EQ(old_request,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_EQ(old_request_signature,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(old_expire_time, (*key_value_index_->begin()).expire_time);
  EXPECT_EQ(old_refresh_time, (*key_value_index_->begin()).refresh_time);
  EXPECT_EQ(old_confirm_time, (*key_value_index_->begin()).confirm_time);
  EXPECT_FALSE((*key_value_index_->begin()).deleted);

  // Same key, same value, different signing private key, publish-type delete.
  EXPECT_FALSE(data_store_->DeleteValue(new_bad_delete_kvt.key_value_signature,
               new_bad_delete_kvt.request_and_signature, false));
  ASSERT_EQ(1U, key_value_index_->size());
  EXPECT_EQ(old_signature,
            (*key_value_index_->begin()).key_value_signature.signature);
  EXPECT_EQ(old_request,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_EQ(old_request_signature,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(old_expire_time, (*key_value_index_->begin()).expire_time);
  EXPECT_EQ(old_refresh_time, (*key_value_index_->begin()).refresh_time);
  EXPECT_EQ(old_confirm_time, (*key_value_index_->begin()).confirm_time);
  EXPECT_FALSE((*key_value_index_->begin()).deleted);

  // Same key, same value, same signing private key, refresh-type delete,
  // confirm time not expired.
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_FALSE(data_store_->DeleteValue(
      new_good_refresh_kvt.key_value_signature,
      new_good_refresh_kvt.request_and_signature, true));
  ASSERT_EQ(1U, key_value_index_->size());
  EXPECT_EQ(old_signature,
            (*key_value_index_->begin()).key_value_signature.signature);
  EXPECT_EQ(old_request,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_EQ(old_request_signature,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(old_expire_time, (*key_value_index_->begin()).expire_time);
  EXPECT_EQ(old_refresh_time, (*key_value_index_->begin()).refresh_time);
  EXPECT_EQ(old_confirm_time, (*key_value_index_->begin()).confirm_time);
  EXPECT_FALSE((*key_value_index_->begin()).deleted);

  // Same key, same value, same signing private key, refresh-type delete,
  // confirm time expired.
  KeyValueTuple temp = *key_value_index_->begin();
  temp.confirm_time = bptime::microsec_clock::universal_time();
  key_value_index_->replace(key_value_index_->begin(), temp);
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_TRUE(data_store_->DeleteValue(
      new_good_refresh_kvt.key_value_signature,
      new_good_refresh_kvt.request_and_signature, true));
  ASSERT_EQ(1U, key_value_index_->size());
  EXPECT_EQ(old_signature,
            (*key_value_index_->begin()).key_value_signature.signature);
  EXPECT_NE(old_request,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_NE(old_request_signature,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(new_good_refresh_kvt.request_and_signature.first,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_EQ(new_good_refresh_kvt.request_and_signature.second,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(old_expire_time, (*key_value_index_->begin()).expire_time);
  bptime::ptime new_refresh_time = (*key_value_index_->begin()).refresh_time;
  bptime::ptime new_confirm_time = (*key_value_index_->begin()).confirm_time;
  EXPECT_LT(old_refresh_time, new_refresh_time);
  EXPECT_LT(old_confirm_time, new_confirm_time);
  EXPECT_TRUE((*key_value_index_->begin()).deleted);

  // Same key, same value, same signing private key, publish-type delete.
  temp = *key_value_index_->begin();
  temp.deleted = false;
  key_value_index_->replace(key_value_index_->begin(), temp);
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_TRUE(data_store_->DeleteValue(new_good_delete_kvt.key_value_signature,
              new_good_delete_kvt.request_and_signature, false));
  ASSERT_EQ(1U, key_value_index_->size());
  EXPECT_EQ(old_signature,
            (*key_value_index_->begin()).key_value_signature.signature);
  EXPECT_NE(old_request,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_NE(old_request_signature,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(new_good_delete_kvt.request_and_signature.first,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_EQ(new_good_delete_kvt.request_and_signature.second,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(old_expire_time, (*key_value_index_->begin()).expire_time);
  EXPECT_LT(old_refresh_time, (*key_value_index_->begin()).refresh_time);
  EXPECT_LT(old_confirm_time, (*key_value_index_->begin()).confirm_time);
  EXPECT_TRUE((*key_value_index_->begin()).deleted);
}

TEST_F(DataStoreTest, BEH_KAD_DeleteExistingDeletedKeyValue) {
  for (int i = 0; i != 2; ++i) {
    crypto_keys_.push_back(crypto::RsaKeyPair());
    crypto_keys_.at(i).GenerateKeys(1024);
  }
  bptime::time_duration old_ttl(bptime::pos_infin), new_ttl(bptime::hours(24));
  KeyValueTuple old_kvt = MakeKVT(crypto_keys_.at(0), 1024, old_ttl, "", "");
  std::string common_key = old_kvt.key_value_signature.key;
  std::string common_value = old_kvt.key_value_signature.value;
  // Use different signing key
  KeyValueTuple new_bad_refresh_kvt =
      MakeKVT(crypto_keys_.at(1), 1024, new_ttl, common_key, common_value);
  // Use different signing key
  KeyValueTuple new_bad_delete_kvt =
      MakeKVT(crypto_keys_.at(1), 1024, new_ttl, common_key, common_value);
  // Use original signing key
  KeyValueTuple new_good_refresh_kvt =
      MakeKVT(crypto_keys_.at(0), 1024, new_ttl, common_key, common_value);
  // Use original signing key
  KeyValueTuple new_good_delete_kvt =
      MakeKVT(crypto_keys_.at(0), 1024, new_ttl, common_key, common_value);

  // Initial key,value.
  EXPECT_TRUE(data_store_->StoreValue(old_kvt.key_value_signature, old_ttl,
      old_kvt.request_and_signature, crypto_keys_.at(0).public_key(), false));
  EXPECT_TRUE(data_store_->DeleteValue(old_kvt.key_value_signature,
                                       old_kvt.request_and_signature, false));
  ASSERT_EQ(1U, key_value_index_->size());
  std::string old_signature =
      (*key_value_index_->begin()).key_value_signature.signature;
  std::string old_request =
      (*key_value_index_->begin()).request_and_signature.first;
  std::string old_request_signature =
      (*key_value_index_->begin()).request_and_signature.second;
  bptime::ptime old_expire_time = (*key_value_index_->begin()).expire_time;
  bptime::ptime old_refresh_time = (*key_value_index_->begin()).refresh_time;
  bptime::ptime old_confirm_time = (*key_value_index_->begin()).confirm_time;
  EXPECT_TRUE((*key_value_index_->begin()).deleted);

  // Same key, same value, different signing private key, refresh-type delete.
  EXPECT_FALSE(data_store_->DeleteValue(new_bad_refresh_kvt.key_value_signature,
               new_bad_refresh_kvt.request_and_signature, true));
  ASSERT_EQ(1U, key_value_index_->size());
  EXPECT_EQ(old_signature,
            (*key_value_index_->begin()).key_value_signature.signature);
  EXPECT_EQ(old_request,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_EQ(old_request_signature,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(old_expire_time, (*key_value_index_->begin()).expire_time);
  EXPECT_EQ(old_refresh_time, (*key_value_index_->begin()).refresh_time);
  EXPECT_EQ(old_confirm_time, (*key_value_index_->begin()).confirm_time);
  EXPECT_TRUE((*key_value_index_->begin()).deleted);

  // Same key, same value, different signing private key, publish-type delete.
  EXPECT_FALSE(data_store_->DeleteValue(new_bad_delete_kvt.key_value_signature,
               new_bad_delete_kvt.request_and_signature, false));
  ASSERT_EQ(1U, key_value_index_->size());
  EXPECT_EQ(old_signature,
            (*key_value_index_->begin()).key_value_signature.signature);
  EXPECT_EQ(old_request,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_EQ(old_request_signature,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(old_expire_time, (*key_value_index_->begin()).expire_time);
  EXPECT_EQ(old_refresh_time, (*key_value_index_->begin()).refresh_time);
  EXPECT_EQ(old_confirm_time, (*key_value_index_->begin()).confirm_time);
  EXPECT_TRUE((*key_value_index_->begin()).deleted);

  // Same key, same value, same signing private key, refresh-type delete.
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_TRUE(data_store_->DeleteValue(
      new_good_refresh_kvt.key_value_signature,
      new_good_refresh_kvt.request_and_signature, true));
  ASSERT_EQ(1U, key_value_index_->size());
  EXPECT_EQ(old_signature,
            (*key_value_index_->begin()).key_value_signature.signature);
  EXPECT_EQ(old_request,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_EQ(old_request_signature,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(old_expire_time, (*key_value_index_->begin()).expire_time);
  bptime::ptime new_refresh_time = (*key_value_index_->begin()).refresh_time;
  EXPECT_LT(old_refresh_time, new_refresh_time);
  EXPECT_EQ(old_confirm_time, (*key_value_index_->begin()).confirm_time);
  EXPECT_TRUE((*key_value_index_->begin()).deleted);

  // Same key, same value, same signing private key, publish-type delete.
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  EXPECT_TRUE(data_store_->DeleteValue(new_good_delete_kvt.key_value_signature,
              new_good_delete_kvt.request_and_signature, false));
  ASSERT_EQ(1U, key_value_index_->size());
  EXPECT_EQ(old_signature,
            (*key_value_index_->begin()).key_value_signature.signature);
  EXPECT_NE(old_request,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_NE(old_request_signature,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(new_good_delete_kvt.request_and_signature.first,
            (*key_value_index_->begin()).request_and_signature.first);
  EXPECT_EQ(new_good_delete_kvt.request_and_signature.second,
            (*key_value_index_->begin()).request_and_signature.second);
  EXPECT_EQ(old_expire_time, (*key_value_index_->begin()).expire_time);
  EXPECT_LT(new_refresh_time, (*key_value_index_->begin()).refresh_time);
  EXPECT_LT(old_confirm_time, (*key_value_index_->begin()).confirm_time);
  EXPECT_TRUE((*key_value_index_->begin()).deleted);
}

TEST_F(DataStoreTest, BEH_KAD_HasKey) {
  crypto::RsaKeyPair crypto_keys;
  crypto_keys.GenerateKeys(1024);
  bptime::time_duration ttl(bptime::pos_infin);
  KeyValueTuple kvt1 = MakeKVT(crypto_keys, 1024, ttl, "", "");
  std::string common_key = kvt1.key_value_signature.key;
  KeyValueTuple kvt2 = MakeKVT(crypto_keys, 1024, ttl, common_key, "");

  EXPECT_FALSE(data_store_->HasKey(common_key));

  // Initial key,value.
  EXPECT_TRUE(data_store_->StoreValue(kvt1.key_value_signature, ttl,
      kvt1.request_and_signature, crypto_keys.public_key(), false));
  EXPECT_TRUE(data_store_->HasKey(common_key));

  // Same key, different value.
  EXPECT_TRUE(data_store_->StoreValue(kvt2.key_value_signature, ttl,
      kvt2.request_and_signature, crypto_keys.public_key(), false));
  EXPECT_TRUE(data_store_->HasKey(common_key));

  // Delete initial key,value
  EXPECT_TRUE(data_store_->DeleteValue(kvt1.key_value_signature,
              kvt1.request_and_signature, false));
  EXPECT_TRUE(data_store_->HasKey(common_key));

  // Delete subsequent key,value
  EXPECT_TRUE(data_store_->DeleteValue(kvt2.key_value_signature,
              kvt2.request_and_signature, false));
  EXPECT_TRUE(data_store_->HasKey(common_key));

  // Create unique key,values (no repeated keys)
  const size_t kTotalEntries(100);
  // Use std::set of keys to ensure uniqueness of keys
  std::set<std::string> keys;
  keys.insert(common_key);
  bool unique(false);
  for (size_t i = 0; i != kTotalEntries; ++i) {
    KeyValueTuple kvt = MakeKVT(crypto_keys, 1024, ttl, "", "");
    auto it = keys.insert(kvt.key_value_signature.key);
    unique = it.second;
    while (!unique) {
      kvt = MakeKVT(crypto_keys, 1024, ttl, "", "");
      it = keys.insert(kvt.key_value_signature.key);
      unique = it.second;
    }

    EXPECT_FALSE(data_store_->HasKey(kvt.key_value_signature.key));

    EXPECT_TRUE(data_store_->StoreValue(kvt.key_value_signature, ttl,
                kvt.request_and_signature, crypto_keys.public_key(), false));
    EXPECT_TRUE(data_store_->HasKey(kvt.key_value_signature.key));

    EXPECT_TRUE(data_store_->DeleteValue(kvt.key_value_signature,
                                         kvt.request_and_signature, false));
    EXPECT_TRUE(data_store_->HasKey(kvt.key_value_signature.key));
  }

  EXPECT_FALSE(data_store_->HasKey(""));

  EXPECT_TRUE(data_store_->HasKey(common_key));
  // Erase the first key,value
  auto itr_pair = key_value_index_->get<TagKey>().equal_range(common_key);
  key_value_index_->get<TagKey>().erase(itr_pair.first++);
  EXPECT_TRUE(data_store_->HasKey(common_key));

  // Erase the subsequent key,value
  key_value_index_->get<TagKey>().erase(itr_pair.first);
  EXPECT_FALSE(data_store_->HasKey(common_key));
}

TEST_F(DataStoreTest, BEH_KAD_GetValues) {
  crypto::RsaKeyPair crypto_keys;
  crypto_keys.GenerateKeys(1024);
  bptime::time_duration ttl(bptime::pos_infin);
  std::vector<KeyValueTuple> kvts;
  const size_t kTotalEntries(100), kRepeatedValues(13);
  kvts.reserve(kTotalEntries + kRepeatedValues);
  // Create first key
  kvts.push_back(MakeKVT(crypto_keys, 1024, ttl, "", ""));
  std::string common_key = kvts.at(0).key_value_signature.key;

  // Test on empty data_store
  std::vector<std::pair<std::string, std::string>> values;
  values.push_back(std::make_pair("a", "b"));
  EXPECT_FALSE(data_store_->GetValues(common_key, NULL));
  EXPECT_FALSE(data_store_->GetValues("", &values));
  EXPECT_TRUE(values.empty());
  values.push_back(std::make_pair("a", "b"));
  EXPECT_FALSE(data_store_->GetValues(common_key, &values));
  EXPECT_TRUE(values.empty());
  values.push_back(std::make_pair("a", "b"));

  // Store first key and create and store other values under same key
  EXPECT_TRUE(data_store_->StoreValue(kvts.at(0).key_value_signature, ttl,
      kvts.at(0).request_and_signature, crypto_keys.public_key(), false));
  std::string value = kvts.at(0).key_value_signature.value;
  for (size_t i = 1; i != kRepeatedValues; ++i) {
    value += "a";
    kvts.push_back(MakeKVT(crypto_keys, 0, ttl, common_key, value));
    EXPECT_TRUE(data_store_->StoreValue(kvts.at(i).key_value_signature, ttl,
        kvts.at(i).request_and_signature, crypto_keys.public_key(), false));
  }

  // Create unique key,values (no repeated keys)
  // Use std::set of keys to ensure uniqueness of keys
  std::set<std::string> keys;
  keys.insert(common_key);
  bool unique(false);
  for (size_t i = 0; i != kTotalEntries; ++i) {
    KeyValueTuple kvt = MakeKVT(crypto_keys, 1024, ttl, "", "");
    auto it = keys.insert(kvt.key_value_signature.key);
    unique = it.second;
    while (!unique) {
      kvt = MakeKVT(crypto_keys, 1024, ttl, "", "");
      it = keys.insert(kvt.key_value_signature.key);
      unique = it.second;
    }
    EXPECT_TRUE(data_store_->StoreValue(kvt.key_value_signature, ttl,
        kvt.request_and_signature, crypto_keys.public_key(), false));
    kvts.push_back(kvt);
  }

  // Retrieve values for first key
  EXPECT_TRUE(data_store_->GetValues(common_key, &values));
  ASSERT_EQ(kRepeatedValues, values.size());
  for (size_t i = 0; i != kRepeatedValues; ++i) {
    EXPECT_EQ(kvts.at(i).key_value_signature.value, values.at(i).first);
    EXPECT_EQ(kvts.at(i).key_value_signature.signature, values.at(i).second);
  }

  // Retrieve values for all other keys
  for (size_t i = kRepeatedValues; i != kvts.size(); ++i) {
    EXPECT_TRUE(data_store_->GetValues(kvts.at(i).key_value_signature.key,
                                       &values));
    ASSERT_EQ(1U, values.size());
    EXPECT_EQ(kvts.at(i).key_value_signature.value, values.at(0).first);
    EXPECT_EQ(kvts.at(i).key_value_signature.signature, values.at(0).second);
  }

  // Delete initial key,values
  for (size_t i = 0; i != kRepeatedValues - 1; ++i) {
    EXPECT_TRUE(data_store_->DeleteValue(kvts.at(i).key_value_signature,
                kvts.at(i).request_and_signature, false));
    EXPECT_TRUE(data_store_->GetValues(common_key, &values));
    ASSERT_EQ(kRepeatedValues - i - 1, values.size());
    for (size_t j = 0; j != kRepeatedValues - i - 1; ++j) {
      EXPECT_EQ(kvts.at(i + j + 1).key_value_signature.value,
                values.at(j).first);
      EXPECT_EQ(kvts.at(i + j + 1).key_value_signature.signature,
                values.at(j).second);
    }
  }
  EXPECT_TRUE(data_store_->DeleteValue(
              kvts.at(kRepeatedValues - 1).key_value_signature,
              kvts.at(kRepeatedValues - 1).request_and_signature, false));
  EXPECT_FALSE(data_store_->GetValues(common_key, &values));
  EXPECT_TRUE(values.empty());

  // Delete other key,value pairs
  for (size_t i = kRepeatedValues; i != kvts.size(); ++i) {
    values.push_back(std::make_pair("a", "b"));
    EXPECT_TRUE(data_store_->DeleteValue(kvts.at(i).key_value_signature,
                kvts.at(i).request_and_signature, false));
    EXPECT_FALSE(data_store_->GetValues(kvts.at(i).key_value_signature.key,
                                        &values));
    EXPECT_TRUE(values.empty());
  }
}
/*
TEST_F(DataStoreTest, BEH_KAD_Refresh) {
  crypto::RsaKeyPair crypto_keys;
  crypto_keys.GenerateKeys(1024);
  bptime::time_duration one_second(bptime::seconds(1));
  bptime::time_duration two_seconds(bptime::seconds(2));
  std::vector<KeyValueTuple> kvts, returned_kvts;
  const size_t kTotalEntries(100), kRepeatedValues(13);
  kvts.reserve(kTotalEntries + kRepeatedValues);
  // Create first key
  kvts.push_back(MakeKVT(crypto_keys, 1024, two_seconds, "", ""));
  std::string common_key = kvts.at(0).key_value_signature.key;

  // Test on empty data_store
  returned_kvts.push_back(MakeKVT(crypto_keys, 1, one_second, "", ""));
  data_store_->Refresh(NULL);
  data_store_->Refresh(&returned_kvts);
  EXPECT_TRUE(returned_kvts.empty());
  kvts.push_back(MakeKVT(crypto_keys, 1024, one_second, "", ""));

  // Store first key and create and store other values under same key
  EXPECT_TRUE(data_store_->StoreValue(kvts.at(0).key_value_signature,
      two_seconds, kvts.at(0).request_and_signature, crypto_keys.public_key(),
      false));
  std::string value = kvts.at(0).key_value_signature.value;
  for (size_t i = 1; i != kRepeatedValues; ++i) {
    value += "a";
    kvts.push_back(MakeKVT(crypto_keys, 0, ((i % 2) ? one_second : two_seconds),
                           common_key, value));
    EXPECT_TRUE(data_store_->StoreValue(kvts.at(i).key_value_signature,
        ((i % 2) ? one_second : two_seconds), kvts.at(i).request_and_signature,
        crypto_keys.public_key(), false));
  }

  // Create unique key,values (no repeated keys)
  // Use std::set of keys to ensure uniqueness of keys
  std::set<std::string> keys;
  keys.insert(common_key);
  bool unique(false);
  for (size_t i = 0; i != kTotalEntries; ++i) {
    KeyValueTuple kvt = MakeKVT(crypto_keys, 1024,
                                ((i % 2) ? one_second : two_seconds), "", "");
    auto it = keys.insert(kvt.key_value_signature.key);
    unique = it.second;
    while (!unique) {
      kvt = MakeKVT(crypto_keys, 1024, ((i % 2) ? one_second : two_seconds), "",
                    "");
      it = keys.insert(kvt.key_value_signature.key);
      unique = it.second;
    }
    EXPECT_TRUE(data_store_->StoreValue(kvt.key_value_signature,
        ((i % 2) ? one_second : two_seconds), kvt.request_and_signature,
        crypto_keys.public_key(), false));
    kvts.push_back(kvt);
  }

  // Call Refresh and check no values are erased or marked as deleted
  data_store_->Refresh(&returned_kvts);
  EXPECT_TRUE(returned_kvts.empty());
  kvts.push_back(MakeKVT(crypto_keys, 1024, one_second, "", ""));
  std::vector<std::pair<std::string, std::string>> values;
  EXPECT_TRUE(data_store_->GetValues(common_key, &values));
  EXPECT_EQ(kRepeatedValues, values.size());
  for (size_t i = kRepeatedValues; i != kvts.size(); ++i) {
    EXPECT_TRUE(data_store_->GetValues(kvts.at(i).key_value_signature.key,
                                       &values));
    EXPECT_EQ(1U, values.size());
  }
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
*/
}  // namespace test

}  // namespace kademlia

}  // namespace maidsafe
