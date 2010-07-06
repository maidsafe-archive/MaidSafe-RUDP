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

#include "maidsafe/tests/benchmark/operations.h"

#include <boost/format.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/thread.hpp>
#include <boost/tokenizer.hpp>
#include <boost/lexical_cast.hpp>

#include <cassert>
#include <iomanip>
#include <iostream>  // NOLINT
#include <string>
#include <vector>

#include "maidsafe/protobuf/kademlia_service_messages.pb.h"
#include "maidsafe/maidsafe-dht.h"


namespace benchmark {

Operations::Operations(kad::KNode *node)
      : node_(node), cryobj_() {
  cryobj_.set_symm_algorithm(crypto::AES_256);
  cryobj_.set_hash_algorithm(crypto::SHA_512);
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
  public_key_ = kp.public_key();
  private_key_ = kp.private_key();
  public_key_signature_ = cryobj_.AsymSign(public_key_, "", private_key_,
                                           crypto::STRING_STRING);
}

void Operations::TestFindAndPing(const std::vector<kad::KadId> &nodes,
                                 const int &iterations) {
  std::vector<kad::Contact> contacts;
  {
    printf("Finding %d nodes...\n", nodes.size());

    base::Stats<boost::uint64_t> stats;
    boost::shared_ptr<CallbackData> data(new CallbackData());
    boost::mutex::scoped_lock lock(data->mutex);
    for (size_t i = 0; i < nodes.size(); ++i) {
      boost::uint64_t t = base::GetEpochMilliseconds();
      node_->GetNodeContactDetails(nodes[i], boost::bind(
          &Operations::GetNodeContactDetailsCallback, this, _1, data), false);
      while (static_cast<size_t>(data->returned_count) <= i)
        data->condition.wait(lock);
      stats.Add(base::GetEpochMilliseconds() - t);
      kad::Contact ctc;
      ctc.ParseFromString(data->content);
      contacts.push_back(ctc);
    }

    printf("Done: total %.2f s, min/avg/max %.2f/%.2f/%.2f s\n",
            stats.Sum() / 1000.0,
            stats.Min() / 1000.0,
            stats.Mean() / 1000.0,
            stats.Max() / 1000.0);
  }
  if (contacts.size() > 0) {
    printf("Pinging %d contacts, %d iterations...\n",
           contacts.size(), iterations);

    base::Stats<boost::uint64_t> stats;
    for (size_t i = 0; i < contacts.size(); ++i) {
      base::Stats<boost::uint64_t> it_stats;
      boost::shared_ptr<CallbackData> data(new CallbackData());
      boost::mutex::scoped_lock lock(data->mutex);
      for (int j = 0; j < iterations; ++j) {
        boost::uint64_t t = base::GetEpochMilliseconds();
        node_->Ping(contacts[i], boost::bind(
            &Operations::PingCallback, this, _1, data));
        while (data->returned_count <= j)
          data->condition.wait(lock);
        it_stats.Add(base::GetEpochMilliseconds() - t);
      }
      stats.Add(it_stats.Mean());
      printf(" Pinged contact %d, %02d/%02d times "
             "(total %.2f s, min/avg/max %.2f/%.2f/%.2f s)\n", i + 1,
             data->succeeded_count, data->returned_count,
             it_stats.Sum() / 1000.0,
             it_stats.Min() / 1000.0,
             it_stats.Mean() / 1000.0,
             it_stats.Max() / 1000.0);
    }

    printf("Done: min/avg/max %.2f/%.2f/%.2f s\n",
            stats.Min() / 1000.0,
            stats.Mean() / 1000.0,
            stats.Max() / 1000.0);
  } else {
    printf("No contacts for nodes found.\n");
  }
}

void Operations::TestStoreAndFind(const std::vector<kad::KadId> &nodes,
                                  const int &iterations, const bool &sign) {
  for (int val = 0; val < 4; ++val) {
    std::string size, value;
    switch (val) {
      case 0:
        value = base::RandomString(1 << 4);
        size = "16 byte";
        break;
      case 1:
        value = base::RandomString(1 << 10);
        size = "1 KB";
        break;
      case 2:
        value = base::RandomString(1 << 17);
        size = "128 KB";
        break;
      case 3:
        value = base::RandomString(1 << 20);
        size = "1 MB";
        break;
    }
    printf("Storing %s value on %d * k closest nodes, %d iterations...\n",
           size.c_str(), nodes.size(), iterations);


    base::Stats<boost::uint64_t> store_stats;
    for (size_t i = 0; i < nodes.size(); ++i) {
      base::Stats<boost::uint64_t> it_stats;
      boost::shared_ptr<CallbackData> data(new CallbackData());
      boost::mutex::scoped_lock lock(data->mutex);
      for (int j = 0; j < iterations; ++j) {
        kad::KadId mod =
            GetModId(val * iterations * nodes.size() + i * iterations + j);
        kad::KadId key(nodes[i] ^ mod);
        kad::SignedValue sig_val;
        kad::SignedRequest sig_req;
        if (sign) {
          std::string req_sig, ser_sig_val;
          req_sig = cryobj_.AsymSign(cryobj_.Hash(public_key_ +
              public_key_signature_ + key.String(), "",
              crypto::STRING_STRING, false), "", private_key_,
              crypto::STRING_STRING);
          sig_val.set_value(value);
          sig_val.set_value_signature(cryobj_.AsymSign(value, "",
              private_key_, crypto::STRING_STRING));
          ser_sig_val = sig_val.SerializeAsString();
          sig_req.set_signer_id(node_->node_id().String());
          sig_req.set_public_key(public_key_);
          sig_req.set_signed_public_key(public_key_signature_);
          sig_req.set_signed_request(req_sig);
        }
        boost::uint64_t t = base::GetEpochMilliseconds();
        if (sign) {
          node_->StoreValue(key, sig_val, sig_req, 86400, boost::bind(
              &Operations::StoreCallback, this, _1, data));
        } else {
          node_->StoreValue(key, value, 86400, boost::bind(
              &Operations::StoreCallback, this, _1, data));
        }
        while (data->returned_count <= j)
          data->condition.wait(lock);
        it_stats.Add(base::GetEpochMilliseconds() - t);
      }
      store_stats.Add(it_stats.Mean());
      printf(" Stored close to %d, %02d/%02d times "
             "(total %.2f s, min/avg/max %.2f/%.2f/%.2f s)\n", i + 1,
             data->succeeded_count, data->returned_count,
             it_stats.Sum() / 1000.0,
             it_stats.Min() / 1000.0,
             it_stats.Mean() / 1000.0,
             it_stats.Max() / 1000.0);
    }

    printf("Done: min/avg/max %.2f/%.2f/%.2f s\n",
           store_stats.Min() / 1000.0,
           store_stats.Mean() / 1000.0,
           store_stats.Max() / 1000.0);

    printf("Loading %s value from %d closest nodes, %d iterations...\n",
           size.c_str(), nodes.size(), iterations);

    base::Stats<boost::uint64_t> load_stats;
    for (size_t i = 0; i < nodes.size(); ++i) {
      base::Stats<boost::uint64_t> it_stats;
      boost::shared_ptr<CallbackData> data(new CallbackData());
      boost::mutex::scoped_lock lock(data->mutex);
      for (int j = 0; j < iterations; ++j) {
        kad::KadId mod =
            GetModId(val * iterations * nodes.size() + i * iterations + j);
        boost::uint64_t t = base::GetEpochMilliseconds();
        node_->FindValue(nodes[i] ^ mod, false, boost::bind(
            &Operations::FindValueCallback, this, _1, data));
        while (data->returned_count <= j)
          data->condition.wait(lock);
        it_stats.Add(base::GetEpochMilliseconds() - t);
      }
      load_stats.Add(it_stats.Mean());
      printf(" Loaded from %d, %02d/%02d times "
             "(total %.2f s, min/avg/max %.2f/%.2f/%.2f s)\n", i + 1,
             data->succeeded_count, data->returned_count,
             it_stats.Sum() / 1000.0,
             it_stats.Min() / 1000.0,
             it_stats.Mean() / 1000.0,
             it_stats.Max() / 1000.0);
    }

    printf("Done: min/avg/max %.2f/%.2f/%.2f s\n",
           load_stats.Min() / 1000.0,
           load_stats.Mean() / 1000.0,
           load_stats.Max() / 1000.0);
  }
}


void Operations::PingCallback(const std::string &result,
                              boost::shared_ptr<CallbackData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  data->content.clear();
  ++data->returned_count;
  kad::PingResponse msg;
  if (msg.ParseFromString(result) && msg.result() == kad::kRpcResultSuccess)
    ++data->succeeded_count;
  data->condition.notify_one();
}

void Operations::GetNodeContactDetailsCallback(const std::string &result,
                                  boost::shared_ptr<CallbackData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  data->content.clear();
  ++data->returned_count;
  kad::FindNodeResult msg;
  if (msg.ParseFromString(result) && msg.result() == kad::kRpcResultSuccess) {
    ++data->succeeded_count;
    data->content = msg.contact();
  }
  data->condition.notify_one();
}

void Operations::StoreCallback(const std::string &result,
                               boost::shared_ptr<CallbackData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  data->content.clear();
  ++data->returned_count;
  kad::StoreResponse msg;
  if (msg.ParseFromString(result) && msg.result() == kad::kRpcResultSuccess)
    ++data->succeeded_count;
  data->condition.notify_one();
}

void Operations::FindValueCallback(const std::string &result,
                                   boost::shared_ptr<CallbackData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  data->content.clear();
  ++data->returned_count;
  kad::FindResponse msg;
  if (msg.ParseFromString(result) && msg.result() == kad::kRpcResultSuccess &&
      (msg.values_size() > 0 || msg.signed_values_size() > 0))
    ++data->succeeded_count;
  data->condition.notify_one();
}

/**
 * Calculates a Kademlia ID with smallest possible distance from 000..000,
 * with a unique value for each (positive) iteration number.
 */
kad::KadId Operations::GetModId(int iteration) {
  int bits = kad::kKeySizeBits - 1;
  kad::KadId id;
  while (iteration > bits) {
    id = id ^ kad::KadId(bits);
    iteration -= (bits + 1);
    --bits;
  }
  return id ^ kad::KadId(iteration);
}

void Operations::PrintRpcTimings(const rpcprotocol::RpcStatsMap &rpc_timings) {
  std::cout << boost::format("Calls  RPC Name  %40t% min/avg/max\n");
  for (rpcprotocol::RpcStatsMap::const_iterator it = rpc_timings.begin();
       it != rpc_timings.end();
       ++it) {
    std::cout << boost::format("%1% : %2% %40t% %3% / %4% / %5% \n")
           % it->second.Size()
           % it->first.c_str()
           % it->second.Min()  // / 1000.0
           % it->second.Mean()  // / 1000.0
           % it->second.Max();  // / 1000.0;
  }
}

}  // namespace benchmark
