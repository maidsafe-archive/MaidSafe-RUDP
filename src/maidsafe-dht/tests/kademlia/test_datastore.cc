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

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "boost/tr1/functional.hpp"
#include "boost/cstdint.hpp"
#include "boost/thread/thread.hpp"
#include "boost/thread/barrier.hpp"
#include "boost/lexical_cast.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"
#include "gtest/gtest.h"

#include "maidsafe/common/platform_config.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-dht/kademlia/config.h"
#include "maidsafe-dht/kademlia/datastore.h"

namespace arg = std::placeholders;
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
      : data_store_(new kademlia::DataStore(bptime::seconds(3600))),
        key_value_index_(data_store_->key_value_index_),
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
    std::string signature;
    while (signature.empty())
      signature = crypto::AsymSign(value, rsa_key_pair.private_key());
    bptime::ptime now = bptime::microsec_clock::universal_time();
    bptime::ptime expire_time = now + ttl;
    bptime::ptime refresh_time = now + bptime::minutes(30);
    std::string request = RandomString(1024);
    std::string req_sig;
    while (req_sig.empty())
      req_sig = crypto::AsymSign(request, rsa_key_pair.private_key());
    return KeyValueTuple(KeyValueSignature(key, value, signature),
                         expire_time, refresh_time,
                         RequestAndSignature(request, req_sig), false);
  }
  bool FindValue(std::pair<std::string, std::string> element,
                 std::pair<std::string, std::string> value) {
    return ((element.first == value.first) && (element.second == value.second));
  }

 protected:
  std::shared_ptr<DataStore> data_store_;
  std::shared_ptr<KeyValueIndex> key_value_index_;
  std::vector<crypto::RsaKeyPair> crypto_keys_;
 private:
  DataStoreTest(const DataStoreTest&);
  DataStoreTest &operator=(const DataStoreTest&);
};

TEST_F(DataStoreTest, BEH_KAD_StoreUnderEmptyKey) {
  EXPECT_EQ(0U, key_value_index_->size());
  for (int i = 0; i != 3; ++i) {
    crypto_keys_.push_back(crypto::RsaKeyPair());
    crypto_keys_.at(i).GenerateKeys(4096);
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
  crypto_keys.GenerateKeys(4096);
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
    crypto_keys_.at(i).GenerateKeys(4096);
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
    crypto_keys_.at(i).GenerateKeys(4096);
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
    crypto_keys_.at(i).GenerateKeys(4096);
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
  crypto_keys.GenerateKeys(4096);
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
    crypto_keys_.at(i).GenerateKeys(4096);
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
    crypto_keys_.at(i).GenerateKeys(4096);
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
  crypto_keys.GenerateKeys(4096);
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
  crypto_keys.GenerateKeys(4096);
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

TEST_F(DataStoreTest, BEH_KAD_Refresh) {
  crypto::RsaKeyPair crypto_keys;
  crypto_keys.GenerateKeys(4096);
  bptime::time_duration two_seconds(bptime::seconds(3));
  bptime::time_duration four_seconds(bptime::seconds(6));
  std::vector<KeyValueTuple> kvts, returned_kvts;
  const size_t kTotalEntries(100), kRepeatedValues(16);
  // kRepeatedValues must be a multiple of 2 for the test to succeed.
  ASSERT_EQ(0, kRepeatedValues % 2);
  kvts.reserve(kTotalEntries + kRepeatedValues);
  // Create first key
  kvts.push_back(MakeKVT(crypto_keys, 1024, four_seconds, "", ""));
  std::string common_key(kvts.at(0).key_value_signature.key);
  // Create other values under same key
  std::string value = kvts.at(0).key_value_signature.value;
  for (size_t i = 1; i != kRepeatedValues; ++i) {
    value += "a";
    kvts.push_back(MakeKVT(crypto_keys, 0,
                           ((i % 2) ? two_seconds : four_seconds),
                           common_key, value));
  }
  // Create unique key,values (no repeated keys)
  // Use std::set of keys to ensure uniqueness of keys
  std::set<std::string> keys;
  keys.insert(common_key);
  bool unique(false);
  for (size_t i = 0; i != kTotalEntries; ++i) {
    KeyValueTuple kvt = MakeKVT(crypto_keys, 1024,
                                ((i % 2) ? two_seconds : four_seconds), "", "");
    auto it = keys.insert(kvt.key_value_signature.key);
    unique = it.second;
    while (!unique) {
      kvt = MakeKVT(crypto_keys, 1024, ((i % 2) ? two_seconds : four_seconds),
                    "", "");
      it = keys.insert(kvt.key_value_signature.key);
      unique = it.second;
    }
    kvts.push_back(kvt);
  }
  // Test on empty data_store
  returned_kvts.push_back(MakeKVT(crypto_keys, 1, two_seconds, "", ""));
  data_store_->Refresh(NULL);
  data_store_->Refresh(&returned_kvts);
  ASSERT_TRUE(returned_kvts.empty());
  returned_kvts.push_back(MakeKVT(crypto_keys, 1024, two_seconds, "", ""));

  // Store first key and other values under same key
  ASSERT_TRUE(data_store_->StoreValue(
                  kvts.at(0).key_value_signature,
                  four_seconds, kvts.at(0).request_and_signature,
                  crypto_keys.public_key(),
                  false));
  for (size_t i = 1; i != kRepeatedValues; ++i) {
    ASSERT_TRUE(data_store_->StoreValue(kvts.at(i).key_value_signature,
        ((i % 2) ? two_seconds : four_seconds),
        kvts.at(i).request_and_signature, crypto_keys.public_key(), false));
  }
  // Store unique key,values (no repeated keys)
  for (size_t i = kRepeatedValues; i != (kTotalEntries + kRepeatedValues);
      ++i) {
    ASSERT_TRUE(data_store_->StoreValue(kvts.at(i).key_value_signature,
                                        ((i % 2) ? two_seconds : four_seconds),
                                        kvts.at(i).request_and_signature,
                                        crypto_keys.public_key(),
                                        false));
  }
  // Call Refresh and check no values are erased or marked as deleted
  data_store_->Refresh(&returned_kvts);
  ASSERT_TRUE(returned_kvts.empty());
  returned_kvts.push_back(MakeKVT(crypto_keys, 1024, two_seconds, "", ""));
  std::vector<std::pair<std::string, std::string>> values;
  ASSERT_TRUE(data_store_->GetValues(common_key, &values));
  ASSERT_EQ(kRepeatedValues, values.size());
  for (size_t i = kRepeatedValues; i != kvts.size(); ++i) {
    ASSERT_TRUE(data_store_->GetValues(kvts.at(i).key_value_signature.key,
                                       &values));
    ASSERT_EQ(1U, values.size());
  }

  // Sleep for 2 seconds then Refresh again
  boost::this_thread::sleep(two_seconds);
  data_store_->Refresh(&returned_kvts);
  ASSERT_TRUE(returned_kvts.empty());
  returned_kvts.push_back(MakeKVT(crypto_keys, 1024, two_seconds, "", ""));
  ASSERT_TRUE(data_store_->GetValues(common_key, &values));
  ASSERT_EQ(kRepeatedValues / 2, values.size());
  for (size_t i = 0; i < kvts.size() - kRepeatedValues; i += 2) {
    ASSERT_TRUE(data_store_->GetValues(
        kvts.at(i + kRepeatedValues).key_value_signature.key, &values));
    ASSERT_EQ(1U, values.size());
  }
  for (size_t i = 1; i < kvts.size() - kRepeatedValues; i += 2) {
    ASSERT_FALSE(data_store_->GetValues(
        kvts.at(i + kRepeatedValues).key_value_signature.key, &values));
    ASSERT_TRUE(values.empty());
  }
  ASSERT_EQ(kTotalEntries + kRepeatedValues, key_value_index_->size());

  // Sleep for 2 seconds then Refresh again
  boost::this_thread::sleep(two_seconds);
  data_store_->Refresh(&returned_kvts);
  ASSERT_TRUE(returned_kvts.empty());
  returned_kvts.push_back(MakeKVT(crypto_keys, 1024, two_seconds, "", ""));
  ASSERT_FALSE(data_store_->GetValues(common_key, &values));
  ASSERT_TRUE(values.empty());
  for (size_t i = 0; i != kvts.size() - kRepeatedValues; ++i) {
    ASSERT_FALSE(data_store_->GetValues(
        kvts.at(i + kRepeatedValues).key_value_signature.key, &values));
    ASSERT_TRUE(values.empty());
  }
  ASSERT_EQ(kTotalEntries + kRepeatedValues, key_value_index_->size());

  // Modify refresh times to allow Refresh to populate vector
  bptime::ptime now(bptime::microsec_clock::universal_time());
  auto it = key_value_index_->begin();
  for (size_t i = 0; i != (kTotalEntries + kRepeatedValues) / 2; ++i, ++it) {
    key_value_index_->modify(it,
           std::bind(&KeyValueTuple::UpdateStatus, arg::_1,
                     (*it).expire_time, now, now + kPendingConfirmDuration,
                     (*it).request_and_signature, (*it).deleted));
  }
  data_store_->Refresh(&returned_kvts);
  ASSERT_EQ((kTotalEntries + kRepeatedValues) / 2, returned_kvts.size());
  ASSERT_EQ(kTotalEntries + kRepeatedValues, key_value_index_->size());

  // Modify confirm times to allow Refresh to erase elements
  it = key_value_index_->begin();
  for (size_t i = 0; i != (kTotalEntries + kRepeatedValues) / 2; ++i, ++it) {
    key_value_index_->modify(it,
           std::bind(&KeyValueTuple::UpdateStatus, arg::_1,
                     (*it).expire_time, now + data_store_->refresh_interval(),
                     now, (*it).request_and_signature, (*it).deleted));
  }
  data_store_->Refresh(&returned_kvts);
  ASSERT_TRUE(returned_kvts.empty());
  ASSERT_EQ((kTotalEntries + kRepeatedValues) / 2, key_value_index_->size());
}

TEST_F(DataStoreTest, FUNC_KAD_MultipleThreads) {
  const size_t kThreadCount(10), kSigners(5), kEntriesPerSigner(123);
  const size_t kValuesPerEntry(4);

  IoServicePtr asio_service(new boost::asio::io_service);
  for (size_t i = 0; i != kSigners; ++i) {
    crypto_keys_.push_back(crypto::RsaKeyPair());
    crypto_keys_.at(i).GenerateKeys(4096);
  }

  // Prepare values for storing and deleting
  bptime::time_duration ttl(bptime::pos_infin);
  std::vector<std::pair<KeyValueTuple, std::string>> stored_kvts;
  std::vector<KeyValueTuple> stored_then_deleted_kvts;
  stored_kvts.reserve(kSigners * kEntriesPerSigner * kValuesPerEntry);
  stored_then_deleted_kvts.reserve(
      size_t(kSigners * kEntriesPerSigner * kValuesPerEntry * 0.2));
  // Use std::set of keys to ensure uniqueness of keys
  std::set<std::string> keys;
  bool unique(false);

  for (size_t signer = 0; signer != kSigners; ++signer) {
    const crypto::RsaKeyPair &crypto_keys(crypto_keys_.at(signer));

    for (size_t entry = 0; entry != kEntriesPerSigner; ++entry) {
      boost::uint32_t rand_num(RandomUint32());
      KeyValueTuple kvt =
          MakeKVT(crypto_keys, ((rand_num % 500) + 500), ttl, "", "");
      // Ensure key is unique
      auto it = keys.insert(kvt.key_value_signature.key);
      unique = it.second;
      while (!unique) {
        kvt = MakeKVT(crypto_keys, ((rand_num % 500) + 500), ttl, "", "");
        it = keys.insert(kvt.key_value_signature.key);
        unique = it.second;
      }
      // Store some now to allow later deletion
      if ((rand_num % kValuesPerEntry) == 0) {
        data_store_->StoreValue(kvt.key_value_signature, ttl,
            kvt.request_and_signature, crypto_keys.public_key(), false);
        stored_then_deleted_kvts.push_back(kvt);
      } else {
        stored_kvts.push_back(std::make_pair(kvt, crypto_keys.public_key()));
      }

      std::string common_key = kvt.key_value_signature.key;
      std::string value = kvt.key_value_signature.value;

      for (size_t i = 1; i != kValuesPerEntry; ++i) {
        value += "a";
        kvt = MakeKVT(crypto_keys, ((rand_num % 500) + 500), ttl, common_key,
                      value);
        // Store some now to allow later deletion
        if ((rand_num % kValuesPerEntry) == i) {
          data_store_->StoreValue(kvt.key_value_signature, ttl,
              kvt.request_and_signature, crypto_keys.public_key(), false);
          stored_then_deleted_kvts.push_back(kvt);
        } else {
          stored_kvts.push_back(std::make_pair(kvt, crypto_keys.public_key()));
        }
      }
    }
  }
  EXPECT_EQ(stored_then_deleted_kvts.size(), key_value_index_->size());

  // Create and enqueue test calls
  size_t returned_size(stored_then_deleted_kvts.size() + stored_kvts.size());
  std::vector<std::vector<std::pair<std::string, std::string>>> returned_values(  // NOLINT (Fraser)
      returned_size, std::vector<std::pair<std::string, std::string>>());  // NOLINT (Fraser)
  std::vector<std::function<bool()>> functors;
  functors.reserve(3 * returned_size);
  auto returned_itr = returned_values.begin();
  for (auto it = stored_then_deleted_kvts.begin();
       it != stored_then_deleted_kvts.end(); ++it, ++returned_itr) {
    functors.push_back(std::bind(&DataStore::DeleteValue, data_store_,
        (*it).key_value_signature, (*it).request_and_signature, false));
    functors.push_back(std::bind(&DataStore::HasKey, data_store_,
                       (*it).key_value_signature.key));
    functors.push_back(std::bind(&DataStore::GetValues, data_store_,
                       (*it).key_value_signature.key, &(*returned_itr)));
  }
  for (auto it = stored_kvts.begin(); it != stored_kvts.end();
       ++it, ++returned_itr) {
    const KeyValueTuple &kvt = (*it).first;
    const std::string &public_key = (*it).second;
    functors.push_back(std::bind(
        &DataStore::StoreValue, data_store_, kvt.key_value_signature, ttl,
        kvt.request_and_signature, public_key, false));
    functors.push_back(std::bind(&DataStore::HasKey, data_store_,
                                      kvt.key_value_signature.key));
    functors.push_back(std::bind(&DataStore::GetValues, data_store_,
                                      kvt.key_value_signature.key,
                                      &(*returned_itr)));
  }
  std::random_shuffle(functors.begin(), functors.end());

  std::vector<std::vector<KeyValueTuple>> returned_kvts(
      (functors.size() / kValuesPerEntry) + 1, std::vector<KeyValueTuple>());
  int count(0);
  for (auto it = functors.begin(); it != functors.end(); ++it, ++count) {
    asio_service->post(*it);
    if ((count % kValuesPerEntry) == 0) {
      asio_service->post(std::bind(&DataStore::Refresh, data_store_,
          &returned_kvts.at(count / kValuesPerEntry)));
    }
  }

  // Run threads
  boost::thread_group asio_thread_group;
  size_t(boost::asio::io_service::*fn)() = &boost::asio::io_service::run;
  for (size_t i = 0; i != kThreadCount; ++i) {
    asio_thread_group.create_thread(std::bind(fn, asio_service));
  }
  asio_thread_group.join_all();

  // Check results
  for (auto it = stored_then_deleted_kvts.begin();
       it != stored_then_deleted_kvts.end(); ++it) {
    const std::string &key = (*it).key_value_signature.key;
    EXPECT_TRUE(data_store_->HasKey(key));
    returned_values.front().push_back(std::make_pair("a", "b"));
    EXPECT_TRUE(data_store_->GetValues(key, &returned_values.front()));
    EXPECT_EQ(kValuesPerEntry - 1, returned_values.front().size());
  }
  for (auto it = stored_kvts.begin(); it != stored_kvts.end(); ++it) {
    const std::string &key = (*it).first.key_value_signature.key;
    EXPECT_TRUE(data_store_->HasKey(key));
    returned_values.front().clear();
    EXPECT_TRUE(data_store_->GetValues(key, &returned_values.front()));
    bool found(false);
    for (auto itr = returned_values.front().begin();
         itr != returned_values.front().end(); ++itr) {
      found = ((*it).first.key_value_signature.value == (*itr).first);
      if (found) {
        EXPECT_EQ((*it).first.key_value_signature.signature, (*itr).second);
        break;
      }
    }
    EXPECT_TRUE(found);
  }
}

}  // namespace test

}  // namespace kademlia

}  // namespace maidsafe
