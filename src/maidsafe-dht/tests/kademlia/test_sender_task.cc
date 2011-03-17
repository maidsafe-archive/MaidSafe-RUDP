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

#include "gtest/gtest.h"

#include "boost/thread/thread.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-dht/kademlia/datastore.h"
#include "maidsafe-dht/kademlia/securifier.h"
#include "maidsafe-dht/kademlia/sender_task.h"

namespace maidsafe {

namespace kademlia {

namespace test {

const boost::posix_time::seconds kNetworkDelay(2);

class Sender_TaskTest: public testing::Test {
 public:
  Sender_TaskTest()
      : info_(),
        sender_task_(new SenderTask),
        count_callback_1_(0),
        count_callback_2_(0),
        asio_service_(new boost::asio::io_service),
        asio_thread_group_() {
  }

  virtual void SetUp() {
  }

  KeyValueSignature MakeKVS(const crypto::RsaKeyPair &rsa_key_pair,
                            const size_t &value_size,
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
    return KeyValueSignature(key, value, signature);
  }

  bool HasDataInIndex(KeyValueSignature key_value_signature,
                      const RequestAndSignature request_signature,
                      const std::string public_key_id) {
    if (key_value_signature.key.empty() || key_value_signature.value.empty())
      return false;
    TaskIndex::index<TagKeyValuePair>::type& index_by_key_value =
      sender_task_->task_index_->get<TagKeyValuePair>();
    auto itr = index_by_key_value.
                   find(boost::make_tuple(key_value_signature.key,
                                          key_value_signature.value));
    if (itr == index_by_key_value.end())
      return false;
    return (((*itr).key_value_signature.signature ==
                key_value_signature.signature) &&
            ((*itr).request_signature == request_signature) &&
            ((*itr).public_key_id == public_key_id));
  }

  void TestTaskCallBack1(KeyValueSignature,
                         std::string,
                         transport::Info,
                         RequestAndSignature,
                         std::string,
                         std::string,
                         std::string) {
    ++count_callback_1_;
  }

  void TestTaskCallBack2(KeyValueSignature,
                         std::string,
                         transport::Info,
                         RequestAndSignature,
                         std::string,
                         std::string,
                         std::string) {
    ++count_callback_2_;
  }

  size_t GetSenderTaskSize() {
    return sender_task_->task_index_->size();
  }

  void ResetCallbackCount() {
    count_callback_2_ = 0;
    count_callback_1_ = 0;
  }

 protected:
  // Dummy function to imitate Securifier::GetPublicKeyAndValidation
  void GetPublicKeyAndValidation(const std::string & public_key_id,
      GetPublicKeyAndValidationCallback callback) {
    asio_thread_group_.create_thread(boost::bind(&boost::asio::io_service::run,
                                                 asio_service_));
    asio_service_->dispatch(boost::bind(&Sender_TaskTest::DummyFind,
                                        this, public_key_id, callback));
  }

  void DummyFind(const std::string &,
      GetPublicKeyAndValidationCallback callback) {
    // Imitating delay in lookup for kNetworkDelay seconds
    boost::this_thread::sleep(boost::posix_time::seconds(kNetworkDelay));
    callback("", "");
  }

  transport::Info info_;
  boost::shared_ptr<SenderTask> sender_task_;
  boost::uint16_t count_callback_1_, count_callback_2_;
  boost::shared_ptr<boost::asio::io_service> asio_service_;
  boost::thread_group asio_thread_group_;
};

TEST_F(Sender_TaskTest, BEH_KAD_AddTask) {
  crypto::RsaKeyPair crypto_key_data;
  crypto_key_data.GenerateKeys(1024);
  KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
  RequestAndSignature request_signature("message", "message_signature");
  TaskCallback task_cb = boost::bind(&Sender_TaskTest::TestTaskCallBack1, this,
                                     _1, "request", _2, _3, "response", _4, _5);
  bool is_new_id(true);
  // Invalid tasks
  EXPECT_FALSE(sender_task_->AddTask(KeyValueSignature("", "", ""), info_,
                                     request_signature, "public_key_id_1",
                                     task_cb, is_new_id));
  EXPECT_FALSE(sender_task_->AddTask(kvs, info_, RequestAndSignature("", ""),
                                     "public_key_id_1", task_cb, is_new_id));
  EXPECT_FALSE(HasDataInIndex(kvs, RequestAndSignature("", ""),
                              "public_key_id_1"));
  EXPECT_FALSE(sender_task_->AddTask(kvs, info_, request_signature, "", task_cb,
                                     is_new_id));
  EXPECT_FALSE(HasDataInIndex(kvs, request_signature, ""));
  EXPECT_FALSE(sender_task_->AddTask(kvs, info_, request_signature,
                                     "public_key_id_1", NULL, is_new_id));
  EXPECT_FALSE(HasDataInIndex(kvs, request_signature, "public_key_id_1"));
  // Valid task
  EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                                    "public_key_id_1", task_cb, is_new_id));
  EXPECT_TRUE(is_new_id);
  EXPECT_TRUE(HasDataInIndex(kvs, request_signature, "public_key_id_1"));
  EXPECT_EQ(size_t(1), GetSenderTaskSize());
  // Adding same task again
  EXPECT_FALSE(sender_task_->AddTask(kvs, info_, request_signature,
                                     "public_key_id_1", task_cb, is_new_id));
  EXPECT_FALSE(is_new_id);
  EXPECT_EQ(size_t(1), GetSenderTaskSize());

  // Adding new task with same key-value
  EXPECT_FALSE(sender_task_->AddTask(kvs, info_, request_signature,
                                     "public_key_id_2", task_cb, is_new_id));
  EXPECT_TRUE(is_new_id);
  EXPECT_FALSE(HasDataInIndex(kvs, request_signature, "public_key_id_2"));
  EXPECT_EQ(size_t(1), GetSenderTaskSize());

  { // Adding new task with same public key id
    crypto_key_data.GenerateKeys(1024);
    KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
    EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                                      "public_key_id_1", task_cb, is_new_id));
    EXPECT_FALSE(is_new_id);
    EXPECT_TRUE(HasDataInIndex(kvs, request_signature, "public_key_id_1"));
    EXPECT_EQ(size_t(2), GetSenderTaskSize());
  }
  // Adding new task with new public key id
  {
    crypto_key_data.GenerateKeys(1024);
    KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
    EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                                      "public_key_id_2", task_cb, is_new_id));
    EXPECT_TRUE(is_new_id);
    EXPECT_TRUE(HasDataInIndex(kvs, request_signature, "public_key_id_2"));
    EXPECT_EQ(size_t(3), GetSenderTaskSize());
  }
  // Adding new task with different callback
  {
    TaskCallback task_cb = boost::bind(&Sender_TaskTest::TestTaskCallBack2,
                                       this, _1, "request", _2, _3, "response",
                                       _4, _5);
    crypto_key_data.GenerateKeys(1024);
    KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
    EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                                      "public_key_id_1", task_cb, is_new_id));
    EXPECT_FALSE(is_new_id);
    EXPECT_TRUE(HasDataInIndex(kvs, request_signature, "public_key_id_1"));
    EXPECT_EQ(size_t(4), GetSenderTaskSize());
  }
}

TEST_F(Sender_TaskTest, BEH_KAD_SenderTaskCallback) {
  crypto::RsaKeyPair crypto_key_data;
  RequestAndSignature request_signature("message", "message_signature");
  TaskCallback task_cb_1 = boost::bind(&Sender_TaskTest::TestTaskCallBack1,
                                       this, _1, "request", _2, _3, "response",
                                       _4, _5);
  bool is_new_id(true);
  GetPublicKeyAndValidationCallback sender_task_cb_1 =
      boost::bind(&SenderTask::SenderTaskCallback, sender_task_,
                  "public_key_id_1", _1, _2);
  // Invalid data
  crypto_key_data.GenerateKeys(1024);
    KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
  ASSERT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                                    "public_key_id_1", task_cb_1, is_new_id));
  sender_task_->SenderTaskCallback("", "", "");
  EXPECT_EQ(size_t(1), GetSenderTaskSize());
  EXPECT_EQ(0u , count_callback_1_);
  // Valid data
  sender_task_->SenderTaskCallback("public_key_id_1", "public_key",
                                   "public_key_validation");
  EXPECT_EQ(size_t(0), GetSenderTaskSize());
  EXPECT_EQ(1u , count_callback_1_);
  ResetCallbackCount();
  // Adding multiple task
  for (int i = 1; i <= 10; ++i) {
    crypto_key_data.GenerateKeys(1024);
    KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
    EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                              "public_key_id_1", task_cb_1, is_new_id));
    EXPECT_TRUE(HasDataInIndex(kvs, request_signature, "public_key_id_1"));
    EXPECT_EQ(size_t(i), GetSenderTaskSize());
  }
  // Calling Securifier
  GetPublicKeyAndValidation("public_key_id_1", sender_task_cb_1);

  asio_thread_group_.join_all();
  EXPECT_EQ(10u, count_callback_1_);
  EXPECT_EQ(size_t(0), GetSenderTaskSize());
}

TEST_F(Sender_TaskTest, BEH_KAD_SenderTaskCallbackMulthiThreaded) {
  crypto::RsaKeyPair crypto_key_data;
  RequestAndSignature request_signature("message", "message_signature");
  TaskCallback task_cb_1 = boost::bind(&Sender_TaskTest::TestTaskCallBack1,
                                       this, _1, "request", _2, _3, "response",
                                       _4, _5);
  TaskCallback task_cb_2 = boost::bind(&Sender_TaskTest::TestTaskCallBack2,
                                       this, _1, "request", _2, _3, "response",
                                       _4, _5);
  bool is_new_id(true);
  boost::uint16_t i(0);
  // Tasks to be removed
  for (i = 0; i < 10; ++i) {
    crypto_key_data.GenerateKeys(1024);
    KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
    EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                                      "public_key_id_1", task_cb_1, is_new_id));
    EXPECT_TRUE(HasDataInIndex(kvs, request_signature, "public_key_id_1"));
    crypto_key_data.GenerateKeys(1024);
    kvs = MakeKVS(crypto_key_data, 1024, "", "");
    EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                                      "public_key_id_1", task_cb_2, is_new_id));
    EXPECT_TRUE(HasDataInIndex(kvs, request_signature, "public_key_id_1"));
    crypto_key_data.GenerateKeys(1024);
    kvs = MakeKVS(crypto_key_data, 1024, "", "");
    EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                                      "public_key_id_2", task_cb_1, is_new_id));
    EXPECT_TRUE(HasDataInIndex(kvs, request_signature, "public_key_id_2"));
    crypto_key_data.GenerateKeys(1024);
    kvs = MakeKVS(crypto_key_data, 1024, "", "");
    EXPECT_TRUE(sender_task_->AddTask(kvs, info_, request_signature,
                                      "public_key_id_2", task_cb_2, is_new_id));
    EXPECT_TRUE(HasDataInIndex(kvs, request_signature, "public_key_id_2"));
  }
  EXPECT_EQ(size_t(i * 4), GetSenderTaskSize());
  std::vector<KeyValueSignature> kvs_vector;
  // Tasks added and not removed
  for (i = 0; i < 3; ++i) {
    crypto_key_data.GenerateKeys(1024);
    KeyValueSignature kvs = MakeKVS(crypto_key_data, 1024, "", "");
    kvs_vector.push_back(kvs);
    asio_service_->post(boost::bind(&SenderTask::AddTask, sender_task_, kvs,
                                    info_, request_signature, "public_key_id_3",
                                    task_cb_1, is_new_id));
    crypto_key_data.GenerateKeys(1024);
    kvs = MakeKVS(crypto_key_data, 1024, "", "");
    kvs_vector.push_back(kvs);
    asio_service_->post(boost::bind(&SenderTask::AddTask, sender_task_, kvs,
                                    info_, request_signature, "public_key_id_4",
                                    task_cb_2, is_new_id));
  }
  // Calling SenderTaskCallback
  asio_service_->post(boost::bind(&SenderTask::SenderTaskCallback, sender_task_,
                                  "public_key_id_1", "public_key",
                                  "public_key_validation"));
  asio_service_->post(boost::bind(&SenderTask::SenderTaskCallback, sender_task_,
                                  "public_key_id_2", "public_key",
                                  "public_key_validation"));
  for (int j = 0; j < 8; ++j)
    asio_thread_group_.create_thread(boost::bind(&boost::asio::io_service::run,
                                     asio_service_));

  asio_thread_group_.join_all();
  EXPECT_EQ(20u , count_callback_1_);
  EXPECT_EQ(20u , count_callback_2_);
  ASSERT_EQ(size_t(i * 2), kvs_vector.size());
  for (size_t k = 0; k < kvs_vector.size(); ++k) {
    EXPECT_TRUE(HasDataInIndex(kvs_vector[k], request_signature,
                               "public_key_id_3") ||
                HasDataInIndex(kvs_vector[k], request_signature,
                               "public_key_id_4"));
  }
  EXPECT_EQ(size_t(i * 2), GetSenderTaskSize());
}

}  // namespace test_sender_task

}  // namespace kademlia

}  // namespace maidsafe
