/* Copyright (c) 2010 maidsafe.net limited
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

#include "maidsafe/distributed_network/operator.h"

#include <boost/progress.hpp>

#include <string>
#include <set>

#include "maidsafe/base/calllatertimer.h"
#include "maidsafe/base/crypto.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/distributed_network/mysqlppwrap.h"
#include "maidsafe/kademlia/knode-api.h"
#include "maidsafe/protobuf/kademlia_service_messages.pb.h"

namespace net_client {

Operator::Operator(boost::shared_ptr<kad::KNode> knode,
                   const std::string &public_key,
                   const std::string &private_key)
    : knode_(knode),
      wrap_(new MySqlppWrap()),
      halt_request_(false),
      operation_index_(0),
      random_operations_(0),
      fetch_count_(0),
      operation_map_(),
      values_map_(),
      op_map_mutex_(),
      values_map_mutex_(),
      timer_(new base::CallLaterTimer()),
      public_key_(public_key),
      private_key_(private_key),
      public_key_signature_() {
  crypto::Crypto co;
  public_key_signature_ = co.AsymSign(public_key_, "", private_key_,
                                      crypto::STRING_STRING);
  int result = wrap_->Init("kademlia_network_test", "127.0.0.1", "root",
                           "m41ds4f3", "kademliavalues");
  int vals(50);
  printf("Operator::Operator - DB init result: %d\n", result);
  {
    boost::progress_timer t;
    GenerateValues(vals);
  }

  printf("Operator::Operator - Done generating %d values\n", vals);
}

void Operator::GenerateValues(int size) {
  if (size%2 != 0)
    ++size;

  int split(size/2);

  // Generate hashable values
  std::set<std::string> values;
  for (int n = 0; n < split; ++n) {
    std::string random_value(base::RandomString(2000 + (n % 10) * 100));
    while (values.find(random_value) != values.end())
      random_value = base::RandomString(2000 + (n % 10) * 100);

    for (int a = 0; a < 10; ++a) {
      random_value += random_value;
    }

    values.insert(random_value);
    kad::SignedValue sv;
    sv.set_value(random_value);
    crypto::Crypto co;
    sv.set_value_signature(co.AsymSign(random_value, "", private_key_,
                                       crypto::STRING_STRING));
    std::string key(co.Hash(random_value, "", crypto::STRING_STRING, false));
    KeyValue kv(key, sv.SerializeAsString(), -1);
    values_map_.insert(kv);
  }

  // Generate non-hashable values
  values.clear();
  size_t limit(split);
  while (values.size() < limit) {
    boost::uint32_t values_for_key(base::RandomUint32()%10);
    while (size_t(values_for_key) + values.size() > limit)
      values_for_key = base::RandomUint32()%10;
    std::string key(base::RandomString(64));
    for (boost::uint32_t t = 0; t < values_for_key; ++t) {
      std::string random_value(base::RandomString(base::RandomUint32()%20000));
      while (values.find(random_value) != values.end())
        random_value = base::RandomString(base::RandomUint32()%20000);

      values.insert(random_value);
      kad::SignedValue sv;
      sv.set_value(random_value);
      crypto::Crypto co;
      sv.set_value_signature(co.AsymSign(random_value, "", private_key_,
                                         crypto::STRING_STRING));
      KeyValue kv(key, sv.SerializeAsString(), -1);
      values_map_.insert(kv);
    }
  }
}

void Operator::Run() {
  ScheduleInitialOperations();
//  timer_->AddCallLater(2 * 60 * 1000,
//                       boost::bind(&Operator::FetchKeyValuesFromDb, this));
  timer_->AddCallLater(30 * 1000,
                       boost::bind(&Operator::ChooseOperation, this));
}

void Operator::Halt() {}

void Operator::ScheduleInitialOperations() {
//  ValuesMap::iterator it = values_map_.begin();
//  for (int n = 0; n < 5; ++n) {
//    std::string key((*it).first);
//    ValueStatus vst((*it).second);
//    kad::SignedValue sv(vst.first);
//    timer_->AddCallLater((1 + n) * 1000,
//                         boost::bind(&Operator::StoreValue, this, key, sv));
//    ++it;
//  }
}

int Operator::ChooseOperation() {
  ++random_operations_;
//  boost::uint16_t op(base::RandomUint32() % 4);
//  switch (op) {
//    case 0: SendStore(); break;
//    case 1: SendFind(); break;
//    case 2: SendUpdate(); break;
//    case 3:
  SendDelete();
//  break;
//  }
  if (random_operations_ < 5)
    timer_->AddCallLater(30 * 1000,
                         boost::bind(&Operator::ChooseOperation, this));
  return 0;
}

void Operator::FetchKeyValuesFromDb() {
  std::vector<std::string> keys;
  wrap_->GetKeys(&keys);
  std::set<std::string> the_keys;
  std::random_shuffle(keys.begin(), keys.end());

  bool mine(false);
  if (KeyMine(keys[0]))
    mine = true;

  std::vector<std::string> values;
  int a = wrap_->GetValues(keys[0], &values);

  if (a == 0) {
    std::vector<kad::SignedValue> signed_values;
    signed_values.resize(values.size());
    for (size_t n = 0; n < values.size(); ++n)
      signed_values[n].ParseFromString(values[n]);
    FindValue(keys[0], signed_values, mine);
    ++fetch_count_;
  }

  if (fetch_count_ < 10)
    timer_->AddCallLater(20 * 1000,
                         boost::bind(&Operator::FetchKeyValuesFromDb, this));
}

bool Operator::KeyMine(const std::string&) {
  return false;
}

void Operator::SendStore() {
  std::vector<KeyValue> kv_vector;
  {
    boost::mutex::scoped_lock loch_tubleweed(values_map_mutex_);
    ValuesMapByStatus &vmbs_index = values_map_.get<by_status>();
    std::pair<ValuesMapByStatus::iterator, ValuesMapByStatus::iterator> p =
        vmbs_index.equal_range(-1);
    while (p.first != p.second) {
      if (!(*p.first).selected_for_op)
        kv_vector.push_back(*p.first);
      ++p.first;
    }
  }
  if (!kv_vector.empty()) {
    std::string key, value;
    std::random_shuffle(kv_vector.begin(), kv_vector.end());
    {
      boost::mutex::scoped_lock loch_tubleweed(values_map_mutex_);
      ValuesMapByKeyValue &vmbkv_index = values_map_.get<by_key_value>();
      ValuesMapByKeyValue::iterator it  =
          vmbkv_index.find(boost::tuple<std::string, std::string>(
                               kv_vector[0].key, kv_vector[0].value));
      if (it != vmbkv_index.end()) {
        KeyValue kv = *it;
        kv.selected_for_op = true;
      }
    }
    kad::SignedValue sv;
    sv.ParseFromString(kv_vector[0].value);
    StoreValue(kv_vector[0].key, sv);
  }
}

void Operator::SendFind() {
  ValuesMapByStatus &vmbs_index = values_map_.get<by_status>();
  std::pair<ValuesMapByStatus::iterator, ValuesMapByStatus::iterator> p =
      vmbs_index.equal_range(0);
  std::vector<KeyValue> kv_vector;
  while (p.first != p.second) {
    kv_vector.push_back(*p.first);
    ++p.first;
  }
  if (!kv_vector.empty()) {
    std::random_shuffle(kv_vector.begin(), kv_vector.end());
    ValuesMapByKey &vmbk_index = values_map_.get<by_valuemap_key>();
    std::pair<ValuesMapByKey::iterator, ValuesMapByKey::iterator> pvmbk =
        vmbk_index.equal_range(kv_vector[0].key);

    std::vector<kad::SignedValue> signed_values;
    while (pvmbk.first != pvmbk.second) {
      if ((*pvmbk.first).status == 0) {
        kad::SignedValue sv;
        sv.ParseFromString((*pvmbk.first).value);
        signed_values.push_back(sv);
      }
      ++pvmbk.first;
    }
    FindValue(kv_vector[0].key, signed_values, true);
  }
  timer_->AddCallLater(10 * 1000,
                       boost::bind(&Operator::SendFind, this));
}

void Operator::SendUpdate() {
  ValuesMapByStatus &vmbs_index = values_map_.get<by_status>();
  std::pair<ValuesMapByStatus::iterator, ValuesMapByStatus::iterator> p =
      vmbs_index.equal_range(0);
  std::vector<KeyValue> kv_vector;
  while (p.first != p.second) {
    kv_vector.push_back(*p.first);
    ++p.first;
  }
  if (!kv_vector.empty()) {
    std::random_shuffle(kv_vector.begin(), kv_vector.end());
    crypto::Crypto co;
    size_t count(0);
    while (HashableKeyPair(kv_vector[count].key, kv_vector[count].value, &co))
      ++count;
    kad::SignedValue sv;
    sv.ParseFromString(kv_vector[count].value);

    std::string random_value(base::RandomString(2270));
    for (int a = 0; a < 10; ++a) {
      random_value += random_value;
    }
    kad::SignedValue new_value;
    new_value.set_value(random_value);
    new_value.set_value_signature(co.AsymSign(new_value.value(), "",
                                              private_key_,
                                              crypto::STRING_STRING));
    UpdateValue(kv_vector[count].key, sv, new_value);
  }
}

void Operator::SendDelete() {
  ValuesMapByStatus &vmbs_index = values_map_.get<by_status>();
  std::pair<ValuesMapByStatus::iterator, ValuesMapByStatus::iterator> p =
      vmbs_index.equal_range(0);
  std::vector<KeyValue> kv_vector;
  while (p.first != p.second) {
    kv_vector.push_back(*p.first);
    ++p.first;
  }
  if (!kv_vector.empty()) {
    std::random_shuffle(kv_vector.begin(), kv_vector.end());
    kad::SignedValue sv;
    sv.ParseFromString(kv_vector[0].value);
    DeleteValue(kv_vector[0].key, sv);
  }
}

void Operator::StoreValue(const std::string &key, const kad::SignedValue &sv) {
  kad::SignedRequest request_signature;
  CreateRequestSignature(key, &request_signature);
  kad::KadId ki_key(key);
  knode_->StoreValue(ki_key, sv, request_signature, 24 * 60 * 60,
                     boost::bind(&Operator::StoreCallback, this, key, sv, _1));
}

void Operator::StoreCallback(const std::string &key,
                             const kad::SignedValue &sv,
                             const std::string &ser_result) {
  Operation op;
  kad::StoreResponse response;
  bool success(false);
  if (response.ParseFromString(ser_result))
    if (response.result())
      success = true;

  if (success) {
    int n = wrap_->Insert(key, sv.SerializeAsString());
    if (n == 0) {
      boost::mutex::scoped_lock loch_voil(values_map_mutex_);
      ValuesMapByKeyValue &vmbkv_index = values_map_.get<by_key_value>();
      ValuesMapByKeyValue::iterator it =
          vmbkv_index.find(
              boost::make_tuple(op.key, op.signed_value.SerializeAsString()));
      if (it != vmbkv_index.end()) {
        KeyValue kv = *it;
        kv.status = 0;
        kv.selected_for_op = false;
        vmbkv_index.replace(it, kv);
      } else {
        success = false;
      }
    } else {
      printf("\n\nWELL, JUST GO SIT ON A SPIKE, THEN\n\n");
    }
  }
}

void Operator::FindValue(const std::string&,
                         const std::vector<kad::SignedValue>&, bool) {
//  kad::KadId ki_key(key);
//  knode_->FindValue(ki_key, false,
//                    boost::bind(&Operator::FindValueCallback, this,
//                                _1, key, values, mine));
}

void Operator::FindValueCallback(const Operation &op,
                                 const std::string &ser_result,
                                 const std::vector<kad::SignedValue> &values,
                                 bool mine) {
  kad::FindResponse result_msg;
  bool success(true);
  if (!result_msg.ParseFromString(ser_result)) {
    success = false;
  } else if (!result_msg.result()) {
    success = false;
  } else if (size_t(result_msg.signed_values_size()) != values.size()) {
    success = false;
  } else {
    std::set<std::string> a, b, c, d;
    for (size_t y = 0; y < values.size(); ++y) {
      a.insert(values[y].value());
      b.insert(values[y].value_signature());
    }

    for (int n = 0; n < result_msg.signed_values_size(); ++n) {
      c.insert(result_msg.signed_values(n).value());
      d.insert(result_msg.signed_values(n).value_signature());
    }

    if (a != c || b != d) {
      success = false;
    } else if (mine) {
      int count = 0;
      boost::mutex::scoped_lock loch_voil(values_map_mutex_);
      ValuesMapByKeyValue &vmbkv_index = values_map_.get<by_key_value>();
      ValuesMapByKeyValue::iterator it;
      for (int n = 0; n < result_msg.signed_values_size(); ++n) {
         it = vmbkv_index.find(
                  boost::make_tuple(
                      op.key, result_msg.signed_values(n).SerializeAsString()));
        if (it != vmbkv_index.end()) {
          KeyValue kv = *it;
          ++kv.searches;
          kv.selected_for_op = false;
          vmbkv_index.replace(it, kv);
        } else {
          ++count;
        }
      }

      if (count != 0) {
        success = false;
      }
    }
  }
  printf("\nFindValueCallback DONE - %d\n\n", success);
  LogResult(op, kad::SignedValue(), success);
}

void Operator::DeleteValue(const std::string &key, const kad::SignedValue &sv) {
  kad::SignedRequest request_signature;
  CreateRequestSignature(key, &request_signature);
  kad::KadId ki_key(key);
  Operation op(key, sv, kDelete);
//  {
//    boost::mutex::scoped_lock loch_voil(op_map_mutex_);
//    std::pair<OperationMap::iterator, bool> p = operation_map_.insert(op);
//    if (!p.second)
//      printf("\n\nTHIS IS  WHY ONE SHOULD CHECK FOR INSERTION!!!!\n\n");
//    else
//      printf("Operator::DeleteValue - %s\n",
//             to_simple_string(op.start_time).c_str());
//  }
  knode_->DeleteValue(ki_key, sv, request_signature,
                      boost::bind(&Operator::DeleteValueCallback, this, op,
                                  _1));
}

void Operator::DeleteValueCallback(const Operation &op,
                                   const std::string &ser_result) {
  kad::DeleteResponse response;
  bool success(false);
  if (response.ParseFromString(ser_result))
    if (response.result())
      success = true;

  if (success) {
    int n = wrap_->Delete(op.key, op.signed_value.SerializeAsString());
    if (n == 0) {
      boost::mutex::scoped_lock loch_voil(values_map_mutex_);
      ValuesMapByKeyValue &vmbkv_index = values_map_.get<by_key_value>();
      ValuesMapByKeyValue::iterator it =
          vmbkv_index.find(
              boost::make_tuple(op.key, op.signed_value.SerializeAsString()));
      if (it != vmbkv_index.end()) {
        KeyValue kv = *it;
        kv.status = -1;
        kv.selected_for_op = false;
        vmbkv_index.replace(it, kv);
      } else {
        success = false;
      }
    }
  }
  LogResult(op, kad::SignedValue(), success);
}

void Operator::UpdateValue(const std::string &key,
                           const kad::SignedValue &old_value,
                           const kad::SignedValue &new_value) {
  kad::SignedRequest request_signature;
  CreateRequestSignature(key, &request_signature);
  kad::KadId ki_key(key);
  Operation op(key, old_value, kUpdate);
//  {
//    boost::mutex::scoped_lock loch_voil(op_map_mutex_);
//    std::pair<OperationMap::iterator, bool> p = operation_map_.insert(op);
//    if (!p.second)
//      printf("\n\nTHIS IS  WHY ONE SHOULD CHECK FOR INSERTION!!!!\n\n");
//    else
//      printf("Operator::UpdateValue - %s\n",
//             to_simple_string(op.start_time).c_str());
//  }
  knode_->UpdateValue(ki_key, old_value, new_value, request_signature,
                      24 * 60 * 60, boost::bind(&Operator::UpdateValueCallback,
                                                this, op, new_value, _1));
}

void Operator::UpdateValueCallback(const Operation &op,
                                   const kad::SignedValue &new_value,
                                   const std::string &ser_result) {
  kad::UpdateResponse response;
  bool success(false);
  if (response.ParseFromString(ser_result))
    if (response.result())
      success = true;

  std::string ser_old_value(op.signed_value.SerializeAsString());
  if (success) {
    int n = wrap_->Update(op.key, ser_old_value, new_value.SerializeAsString());
    if (n == 0) {
      boost::mutex::scoped_lock loch_voil(values_map_mutex_);
      ValuesMapByKeyValue &vmbkv_index = values_map_.get<by_key_value>();
      ValuesMapByKeyValue::iterator it =
          vmbkv_index.find(
              boost::make_tuple(op.key, op.signed_value.SerializeAsString()));
      if (it != vmbkv_index.end()) {
        KeyValue kv = *it;
        kv.status = 0;
        kv.selected_for_op = false;
        vmbkv_index.replace(it, kv);
      } else {
        success = false;
      }
    }
  }
  LogResult(op, new_value, success);
}

void Operator::FindKClosestNodes(const std::string &key) {
  kad::KadId ki_key(key);
  knode_->FindKClosestNodes(ki_key,
      boost::bind(&Operator::FindKClosestNodesCallback, this, key, _1));
}

void Operator::FindKClosestNodesCallback(const std::string&,
                                         const std::string &ser_result) {
  kad::FindResponse result_msg;
  if (!result_msg.ParseFromString(ser_result))
    return;

  if (!result_msg.result())
    return;

//  if (size_t(result_msg.signed_values_size()) != values.size())
//    return;

//  int count(0);
//  for (int n = 0; n < result_msg.signed_values_size(); ++n) {
//    if (values[n].value() != result_msg.signed_values(n).value() ||
//        values[n].value_signature() !=
//            result_msg.signed_values(n).value_signature())
//      ++count;
//  }

//  if (KeyMine(key)) {
//    boost::mutex::scoped_lock loch_voil(values_map_mutex_);
//    std::pair<ValuesMap::iterator, ValuesMap::iterator> p =
//        values_map_.equal_range(key);
//    while (p.first != p.second) {
//      ++(*p.first).second.second;
//      ++p.first;
//    }
//  }
}

void Operator::CreateRequestSignature(const std::string &key,
                                      kad::SignedRequest *request) {
  request->set_signer_id(knode_->node_id().String());
  request->set_public_key(public_key_);
  request->set_signed_public_key(public_key_signature_);
  crypto::Crypto co;
  request->set_signed_request(co.Hash(public_key_ + public_key_signature_ + key,
                                      "", crypto::STRING_STRING, true));
}

bool Operator::HashableKeyPair(const std::string &key, const std::string &value,
                               crypto::Crypto *co) {
  return key == co->Hash(value, "", crypto::STRING_STRING, false);
}

void Operator::LogResult(const Operation&, const kad::SignedValue&, bool) {}

}  // namespace net_client
