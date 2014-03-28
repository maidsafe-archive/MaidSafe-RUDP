/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

/*
 * @file  rudp_node_impl.cc
 * @brief Console commands to demo rudp stand alone node.
 * @date  2012-02-26
 */

#include "maidsafe/rudp/tests/rudp_node_impl.h"

#include <iostream>  // NOLINT
#include <utility>

#include "boost/format.hpp"
#include "boost/filesystem.hpp"
#ifdef __MSVC__
#pragma warning(push)
#pragma warning(disable : 4127)
#endif
#include "boost/tokenizer.hpp"
#ifdef __MSVC__
#pragma warning(pop)
#endif
#include "boost/lexical_cast.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace rudp {

namespace test {

RudpNode::RudpNode(std::vector<maidsafe::passport::Pmid> all_pmids, int identity_index,
                   int peer_identity_index, const std::string& peer)
    : all_pmids_(all_pmids),
      all_ids_(),
      identity_index_(identity_index),
      peer_identity_index_(peer_identity_index),
      bootstrap_peer_ep_(),
      asio_service_(Parameters::thread_count),
      nat_type_(NatType::kUnknown),
      transport_(new detail::Transport(asio_service_, nat_type_)),
      reply_(true),
      data_size_(256 * 1024),
      // TODO(dirvine) unused        data_rate_(1024 * 1024),
      result_arrived_(false),
      finish_(false),
      wait_mutex_(),
      wait_cond_var_(),
      mark_results_arrived_() {
  for (size_t i(0); i < (all_pmids_.size()); ++i)
    all_ids_.push_back(NodeId(all_pmids_[i].name().data));
  GetPeer(peer);

  std::vector<std::pair<NodeId, boost::asio::ip::udp::endpoint>> bootstrap_endpoints;
  bootstrap_endpoints.push_back(
      std::make_pair(NodeId(all_pmids[peer_identity_index_].name()->string()), bootstrap_peer_ep_));

  boost::asio::ip::udp::endpoint local_endpoint(GetLocalIp(),
                                                bootstrap_peer_ep_.port() == 9500 ? 9501 : 9500);
  NodeId chosen_id;
  transport_->Bootstrap(
      bootstrap_endpoints, NodeId(all_pmids[identity_index_].name().data.string()),
      std::shared_ptr<asymm::PublicKey>(
          new asymm::PublicKey(all_pmids_[identity_index_].public_key())),
      local_endpoint, false, boost::bind(&RudpNode::OnMessageSlot, this, _1),
      [this](const NodeId & peer_id, std::shared_ptr<detail::Transport> transport,
             bool temporary_connection, std::atomic<bool> & is_duplicate_normal_connection) {
        OnConnectionAddedSlot(peer_id, transport, temporary_connection,
                              is_duplicate_normal_connection);
      },
      boost::bind(&RudpNode::OnConnectionLostSlot, this, _1, _2, _3),
      boost::bind(&RudpNode::OnNatDetectionRequestedSlot, this, _1, _2, _3, _4), chosen_id);
  asio_service_.Start();
}

void RudpNode::OnMessageSlot(const std::string& /*message*/) {
  std::cout << "received a msg at : " << bptime::microsec_clock::universal_time() << std::endl;
  if (reply_)
    transport_->Send(NodeId(all_pmids_[peer_identity_index_].name().data.string()), "reply",
                     [](int /*result*/) {});
}

void RudpNode::OnConnectionAddedSlot(const NodeId& /*peer_id*/,
                                     std::shared_ptr<detail::Transport> /*transport*/,
                                     bool /*temporary_connection*/,
                                     std::atomic<bool> & /*is_duplicate_normal_connection*/) {
  std::cout << " connection added " << std::endl;
}

void RudpNode::OnConnectionLostSlot(const NodeId& /*peer_id*/,
                                    std::shared_ptr<detail::Transport> /*transport*/,
                                    bool /*temporary_connection*/) {
  std::cout << " connection lost " << std::endl;
}

void RudpNode::OnNatDetectionRequestedSlot(const Endpoint& /*this_local_endpoint*/,
                                           const NodeId& /*peer_id*/,
                                           const Endpoint& /*peer_endpoint*/,
                                           uint16_t& /*another_external_port*/) {
  std::cout << " nat detected " << std::endl;
}

void RudpNode::GetPeer(const std::string& peer) {
  size_t delim = peer.rfind(':');
  try {
    bootstrap_peer_ep_.port(static_cast<uint16_t>(atoi(peer.substr(delim + 1).c_str())));
    bootstrap_peer_ep_.address(boost::asio::ip::address::from_string(peer.substr(0, delim)));
    std::cout << "Going to connect to endpoint " << bootstrap_peer_ep_ << std::endl;
  }
  catch (...) {
    std::cout << "Could not parse IPv4 peer endpoint from " << peer << std::endl;
  }
}

void RudpNode::Run() {
  PrintUsage();

  while (!finish_) {
    std::cout << std::endl << std::endl << "Enter command > ";
    std::string cmdline;
    std::getline(std::cin, cmdline);
    {
      boost::mutex::scoped_lock lock(wait_mutex_);
      ProcessCommand(cmdline);
      //      wait_cond_var_.wait(lock, boost::bind(&Commands::ResultArrived, this));
      result_arrived_ = false;
    }
  }
}

void RudpNode::PrintUsage() {
  std::cout << "\thelp Print options.\n";
  std::cout << "\tsenddirect <num_msg> Send a msg to peer. -1 for infinite (Default 1)\n";
  std::cout << "\tdatasize <data_size> Set the data_size for the message.\n";
  std::cout << "\texit Exit application.\n";
}

void RudpNode::ProcessCommand(const std::string& cmdline) {
  if (cmdline.empty())
    return;

  std::string cmd;
  std::vector<std::string> args;
  try {
    boost::char_separator<char> sep(" ");
    boost::tokenizer<boost::char_separator<char>> tok(cmdline, sep);
    for (auto it = tok.begin(); it != tok.end(); ++it) {
      if (it == tok.begin())
        cmd = *it;
      else
        args.push_back(*it);
    }
  }
  catch (const std::exception& e) {
    LOG(kError) << "Error processing command: " << e.what();
  }

  if (cmd == "help") {
    PrintUsage();
  } else if (cmd == "senddirect") {
    std::string msg(RandomString(data_size_));
    std::cout << " sending msg : " << bptime::microsec_clock::universal_time() << std::endl;
    reply_ = false;
    transport_->Send(NodeId(all_pmids_[peer_identity_index_].name().data.string()), msg,
                     [](int /*result*/) {
      std::cout << " msg sent : " << bptime::microsec_clock::universal_time() << std::endl;
    });
  } else if (cmd == "datasize") {
    if (args.size() == 1)
      data_size_ = atoi(args[0].c_str());
    else
      std::cout << "Error : Try correct option" << std::endl;
  } else if (cmd == "exit") {
    std::cout << "Exiting application...\n";
    finish_ = true;
  } else {
    std::cout << "Invalid command : " << cmd << std::endl;
    PrintUsage();
  }
}

}  //  namespace test

}  //  namespace rudp

}  //  namespace maidsafe
