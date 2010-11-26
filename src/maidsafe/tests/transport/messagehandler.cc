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

#include "maidsafe/tests/transport/messagehandler.h"
#include "maidsafe/base/log.h"
#include "maidsafe/protobuf/rpcmessage.pb.h"
#include "maidsafe/transport/transportsignals.h"
#include "maidsafe/transport/udtconnection.h"

namespace  bs2 = boost::signals2;

namespace transport {

namespace test {

MessageHandler::MessageHandler(boost::shared_ptr<Signals> signals,
                               const std::string &message_handler_id,
                               bool display_stats)
    : signals_(signals),
      raw_messages_(),
      rpc_requests_(),
      rpc_responses_(),
      sent_results_(),
      received_results_(),
      managed_endpoint_messages_(),
      managed_endpoint_ids_(),
      lost_managed_endpoint_ids_(),
      message_handler_id_("MessageHandler " + message_handler_id),
      mutex_(),
      message_received_connection_(),
      rpc_request_received_connection_(),
      rpc_response_received_connection_(),
      managed_endpoint_received_connection_(),
      managed_endpoint_lost_connection_(),
      send_connection_(),
      receive_connection_(),
      stats_connection_() {
  message_received_connection_ = signals_->ConnectOnMessageReceived(
      boost::bind(&MessageHandler::OnMessageReceived, this, _1, _2, _3));
  rpc_request_received_connection_ = signals_->ConnectOnRpcRequestReceived(
      boost::bind(&MessageHandler::OnRpcMessageReceived, this, _1, _2, _3,
                  true));
  rpc_response_received_connection_ = signals_->ConnectOnRpcResponseReceived(
      boost::bind(&MessageHandler::OnRpcMessageReceived, this, _1, _2, _3,
                  false));
  managed_endpoint_received_connection_ =
      signals_->ConnectOnManagedEndpointReceived(boost::bind(
          &MessageHandler::OnManagedEndpointReceived, this, _1, _2));
  managed_endpoint_lost_connection_ = signals_->ConnectOnManagedEndpointLost(
      boost::bind(&MessageHandler::OnManagedEndpointLost, this, _1));
  send_connection_ = signals_->ConnectOnSend(
      boost::bind(&MessageHandler::OnResult, this, _1, _2, true));
  receive_connection_ = signals_->ConnectOnReceive(
      boost::bind(&MessageHandler::OnResult, this, _1, _2, false));
  if (display_stats) {
    stats_connection_ = signals_->ConnectOnStats(
        boost::bind(&MessageHandler::OnStats, this, _1));
  }
}

MessageHandler::~MessageHandler() {
  boost::mutex::scoped_lock lock(mutex_);
  message_received_connection_.disconnect();
  rpc_request_received_connection_.disconnect();
  rpc_response_received_connection_.disconnect();
  managed_endpoint_received_connection_.disconnect();
  managed_endpoint_lost_connection_.disconnect();
  send_connection_.disconnect();
  receive_connection_.disconnect();
  stats_connection_.disconnect();
}

void MessageHandler::OnMessageReceived(const std::string &message,
                                       const int &socket_id,
                                       const float &rtt) {
//  printf("%s - OnMessageReceived\n", message_handler_id_.c_str());
  boost::mutex::scoped_lock lock(mutex_);
  raw_messages_.push_back(boost::make_tuple(message, socket_id, rtt));
}

void MessageHandler::OnRpcMessageReceived(
    const rpcprotocol::RpcMessage &rpc_message,
    const int &socket_id,
    const float &rtt,
    bool is_request) {
/*
  if (is_request)
    printf("%s - OnRpcRequest (%i)\n", message_handler_id_.c_str(), socket_id);
  else
    printf("%s - OnRpcResponse (%i)\n", message_handler_id_.c_str(), socket_id);
*/
  boost::mutex::scoped_lock lock(mutex_);
//  if (!target_message_.empty() && message == target_message_)
//    ++messages_confirmed_;
  if (is_request)
    rpc_requests_.push_back(boost::make_tuple(rpc_message, socket_id, rtt));
  else
    rpc_responses_.push_back(boost::make_tuple(rpc_message, socket_id, rtt));
}

void MessageHandler::OnManagedEndpointReceived(
    const ManagedEndpointId &managed_endpoint_id,
    const ManagedEndpointMessage &message) {
//  printf("%s - OnManagedEndpointReceived\n", message_handler_id_.c_str());
  boost::mutex::scoped_lock lock(mutex_);
  managed_endpoint_messages_.push_back(boost::make_tuple(managed_endpoint_id,
                                                         message));
  managed_endpoint_ids_.insert(managed_endpoint_id);
}

void MessageHandler::OnManagedEndpointLost(
    const ManagedEndpointId &managed_endpoint_id) {
//  printf("%s - OnManagedEndpointLost\n", message_handler_id_.c_str());
  boost::mutex::scoped_lock lock(mutex_);
  managed_endpoint_ids_.erase(managed_endpoint_id);
  lost_managed_endpoint_ids_.insert(managed_endpoint_id);
}

void MessageHandler::OnResult(const int &socket_id,
                              const TransportCondition &result,
                              bool is_send) {
//  if (is_send)
//    printf("%s - OnSentResult\n", message_handler_id_.c_str());
//  else
//    printf("%s - OnReceivedResult\n", message_handler_id_.c_str());
  boost::mutex::scoped_lock lock(mutex_);
  if (is_send)
    sent_results_.push_back(boost::make_tuple(socket_id, result));
  else
    received_results_.push_back(boost::make_tuple(socket_id, result));
}

void MessageHandler::OnStats(boost::shared_ptr<SocketPerformanceStats> stats) {
//  printf("%s - OnStats\n", message_handler_id_.c_str());
  boost::shared_ptr<UdtStats> udt_stats =
      boost::static_pointer_cast<UdtStats>(stats);
  boost::mutex::scoped_lock lock(mutex_);
  if (udt_stats->udt_socket_type_ == UdtStats::kSend) {
    DLOG(INFO) << "\tSocket ID:         " << udt_stats->socket_id_ <<
        std::endl;
    DLOG(INFO) << "\tRTT:               " <<
        udt_stats->performance_monitor_.msRTT << " ms" << std::endl;
    DLOG(INFO) << "\tBandwidth:         " <<
        udt_stats->performance_monitor_.mbpsBandwidth << " Mbps" << std::endl;
    DLOG(INFO) << "\tTime elapsed:      " <<
        udt_stats->performance_monitor_.msTimeStamp << " ms" << std::endl;
    DLOG(INFO) << "\tSent:              " <<
        udt_stats->performance_monitor_.pktSentTotal << " packets" <<
        std::endl;
    DLOG(INFO) << "\tLost:              " <<
        udt_stats->performance_monitor_.pktSndLoss << " packets" << std::endl;
    DLOG(INFO) << "\tRetransmitted:     " <<
        udt_stats->performance_monitor_.pktRetrans << " packets" << std::endl;
    DLOG(INFO) << "\tACKs received:     " <<
        udt_stats->performance_monitor_.pktRecvACK << " packets" << std::endl;
    DLOG(INFO) << "\tNACKs received:    " <<
        udt_stats->performance_monitor_.pktRecvNAK << " packets" << std::endl;
    DLOG(INFO) << "\tSend rate:         " <<
        udt_stats->performance_monitor_.mbpsSendRate << " Mbps" << std::endl;
    DLOG(INFO) << "\tBusy send time:    " <<
        udt_stats->performance_monitor_.usSndDuration << " us" << std::endl;
    DLOG(INFO) << "\tSend period:       " <<
        udt_stats->performance_monitor_.usPktSndPeriod << " us" << std::endl;
    DLOG(INFO) << "\tFlow window:       " <<
        udt_stats->performance_monitor_.pktFlowWindow << " packets" <<
        std::endl;
    DLOG(INFO) << "\tCongestion window: " <<
        udt_stats->performance_monitor_.pktCongestionWindow << " packets" <<
        std::endl;
    DLOG(INFO) << "\tAvail send buffer: " <<
        udt_stats->performance_monitor_.byteAvailSndBuf << " bytes" <<
        std::endl;
    DLOG(INFO) << "\tAvail recv buffer: " <<
        udt_stats->performance_monitor_.byteAvailRcvBuf << " bytes" <<
        std::endl;
  } else {
    DLOG(INFO) << "\t\tSocket ID:         " << udt_stats->socket_id_ <<
        std::endl;
    DLOG(INFO) << "\t\tRTT:               " <<
        udt_stats->performance_monitor_.msRTT << " ms" << std::endl;
    DLOG(INFO) << "\t\tBandwidth:         " <<
        udt_stats->performance_monitor_.mbpsBandwidth << " Mbps" << std::endl;
    DLOG(INFO) << "\t\tTime elapsed:      " <<
        udt_stats->performance_monitor_.msTimeStamp << " ms" << std::endl;
    DLOG(INFO) << "\t\tReceived:          " <<
        udt_stats->performance_monitor_.pktRecv << " packets" << std::endl;
    DLOG(INFO) << "\t\tLost:              " <<
        udt_stats->performance_monitor_.pktRcvLoss << " packets" << std::endl;
    DLOG(INFO) << "\t\tACKs sent:         " <<
        udt_stats->performance_monitor_.pktSentACK << " packets" << std::endl;
    DLOG(INFO) << "\t\tNACKs sent:        " <<
        udt_stats->performance_monitor_.pktSentNAK << " packets" << std::endl;
    DLOG(INFO) << "\t\tReceive rate:      " <<
        udt_stats->performance_monitor_.mbpsRecvRate << " Mbps" << std::endl;
    DLOG(INFO) << "\t\tFlow window:       " <<
        udt_stats->performance_monitor_.pktFlowWindow << " packets" <<
        std::endl;
    DLOG(INFO) << "\t\tCongestion window: " <<
        udt_stats->performance_monitor_.pktCongestionWindow << " packets" <<
        std::endl;
    DLOG(INFO) << "\t\tAvail send buffer: " <<
        udt_stats->performance_monitor_.byteAvailSndBuf << " bytes" <<
        std::endl;
    DLOG(INFO) << "\t\tAvail recv buffer: " <<
        udt_stats->performance_monitor_.byteAvailRcvBuf << " bytes" <<
        std::endl;
  }
}

void MessageHandler::ClearContainers() {
  boost::mutex::scoped_lock lock(mutex_);
  raw_messages_.clear();
  rpc_requests_.clear();
  rpc_responses_.clear();
  sent_results_.clear();
  received_results_.clear();
  managed_endpoint_messages_.clear();
  managed_endpoint_ids_.clear();
  lost_managed_endpoint_ids_.clear();
}

MessageHandler::RawMessageList MessageHandler::raw_messages() {
  boost::mutex::scoped_lock lock(mutex_);
  return raw_messages_;
}

MessageHandler::RpcMessageList MessageHandler::rpc_requests() {
  boost::mutex::scoped_lock lock(mutex_);
  return rpc_requests_;
}

MessageHandler::RpcMessageList MessageHandler::rpc_responses() {
  boost::mutex::scoped_lock lock(mutex_);
  return rpc_responses_;
}

MessageHandler::MessageResultList MessageHandler::sent_results() {
  boost::mutex::scoped_lock lock(mutex_);
  return sent_results_;
}

MessageHandler::MessageResultList MessageHandler::received_results() {
  boost::mutex::scoped_lock lock(mutex_);
  return received_results_;
}

MessageHandler::ManagedEndpointMessageList
    MessageHandler::managed_endpoint_messages() {
  boost::mutex::scoped_lock lock(mutex_);
  return managed_endpoint_messages_;
}

std::set<ManagedEndpointId> MessageHandler::managed_endpoint_ids() {
  boost::mutex::scoped_lock lock(mutex_);
  return managed_endpoint_ids_;
}

std::set<ManagedEndpointId> MessageHandler::lost_managed_endpoint_ids() {
  boost::mutex::scoped_lock lock(mutex_);
  return lost_managed_endpoint_ids_;
}

}  // namespace test

}  // namespace transport
