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

#include "maidsafe/rpcprotocol/channelimpl.h"
#include "maidsafe/rpcprotocol/channel-api.h"
#include "maidsafe/transport/transporthandler-api.h"

namespace rpcprotocol {

Controller::Controller() : controller_pimpl_(new ControllerImpl) {}

Controller::~Controller() {}

void Controller::SetFailed(const std::string &str) {
  controller_pimpl_->SetFailed(str);
}

void Controller::Reset() {
  controller_pimpl_->Reset();
}

bool Controller::Failed() const {
  return controller_pimpl_->Failed();
}

std::string Controller::ErrorText() const {
  return controller_pimpl_->ErrorText();
}

void Controller::StartCancel() {
  controller_pimpl_->StartCancel();
}

bool Controller::IsCanceled() const {
  return controller_pimpl_->IsCanceled();
}

void Controller::NotifyOnCancel(google::protobuf::Closure* done) {
  controller_pimpl_->NotifyOnCancel(done);
}

void Controller::set_timeout(const boost::uint32_t &seconds) {
  controller_pimpl_->set_timeout(seconds);
}

boost::uint64_t Controller::timeout() const {
  return controller_pimpl_->timeout();
}

boost::uint64_t Controller::Duration() const {
  return controller_pimpl_->Duration();
}

void Controller::StartRpcTimer() {
  controller_pimpl_->StartRpcTimer();
}

void Controller::StopRpcTimer() {
  controller_pimpl_->StopRpcTimer();
}

void Controller::set_rtt(const float &rtt) {
  controller_pimpl_->set_rtt(rtt);
}

float Controller::rtt() const {
  return controller_pimpl_->rtt();
}

void Controller::set_transport_id(const boost::int16_t &transport_id) {
  controller_pimpl_->set_transport_id(transport_id);
}

boost::int16_t Controller::transport_id() const {
  return controller_pimpl_->transport_id();
}

void Controller::set_request_id(const boost::uint32_t &id) {
  return controller_pimpl_->set_request_id(id);
}

boost::uint32_t Controller::request_id() const {
  return controller_pimpl_->request_id();
}

void Controller::set_message_info(const std::string &service,
                                  const std::string &method) {
  controller_pimpl_->set_message_info(service, method);
}

void Controller::message_info(std::string *service, std::string *method) const {
  controller_pimpl_->message_info(service, method);
}

Channel::Channel(ChannelManager *channelmanager,
                 transport::TransportHandler *transport_handler)
    : pimpl_(new ChannelImpl(channelmanager, transport_handler)) {}

Channel::Channel(ChannelManager *channelmanager,
                 transport::TransportHandler *transport_handler,
                 const boost::int16_t &transport_id,
                 const std::string &remote_ip,
                 const boost::uint16_t &remote_port,
                 const std::string &local_ip,
                 const boost::uint16_t &local_port,
                 const std::string &rendezvous_ip,
                 const boost::uint16_t &rendezvous_port)
    : pimpl_(new ChannelImpl(channelmanager, transport_handler, transport_id,
                             remote_ip, remote_port, local_ip, local_port,
                             rendezvous_ip, rendezvous_port)) {}

Channel::~Channel() {}

void Channel::CallMethod(const google::protobuf::MethodDescriptor *method,
                         google::protobuf::RpcController *controller,
                         const google::protobuf::Message *request,
                         google::protobuf::Message *response,
                         google::protobuf::Closure *done) {
  pimpl_->CallMethod(method, controller, request, response, done);
}

void Channel::SetService(google::protobuf::Service* service) {
  pimpl_->SetService(service);
}

void Channel::HandleRequest(const RpcMessage &request,
                            const boost::uint32_t &connection_id,
                            const boost::int16_t &transport_id,
                            const float &rtt) {
  pimpl_->HandleRequest(request, connection_id, transport_id, rtt);
}

}  // namespace rpcprotocol
