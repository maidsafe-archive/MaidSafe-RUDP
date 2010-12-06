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

#include "maidsafe/rpcprotocol/channel-api.h"
#include "maidsafe/rpcprotocol/channelimpl.h"

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

void Controller::set_socket_id(const SocketId &socket_id) {
  controller_pimpl_->set_socket_id(socket_id);
}

SocketId Controller::socket_id() const {
  return controller_pimpl_->socket_id();
}

void Controller::set_method(const std::string &method) {
  controller_pimpl_->set_method(method);
}

std::string Controller::method() const {
  return controller_pimpl_->method();
}

void Controller::set_timeout(const boost::uint32_t &timeout) {
  controller_pimpl_->set_timeout(timeout);
}

boost::uint32_t Controller::timeout() const {
  return controller_pimpl_->timeout();
}

boost::shared_ptr<transport::Transport> Controller::transport() const {
  return controller_pimpl_->transport();
}

void Controller::set_connection(
    boost::shared_ptr<transport::Transport> transport) {
  controller_pimpl_->set_connection(transport);
}

Channel::Channel(boost::shared_ptr<ChannelManager> channel_manager)
    : pimpl_(new ChannelImpl(channel_manager)) {}

Channel::Channel(boost::shared_ptr<ChannelManager> channel_manager,
                 const IP &remote_ip, const Port &remote_port,
                 const IP &rendezvous_ip, const Port &rendezvous_port)
    : pimpl_(new ChannelImpl(channel_manager, remote_ip, remote_port,
                             rendezvous_ip,
                             rendezvous_port)) {}

Channel::~Channel() {}

void Channel::CallMethod(const google::protobuf::MethodDescriptor *method,
                         google::protobuf::RpcController *rpc_controller,
                         const google::protobuf::Message *request,
                         google::protobuf::Message *response,
                         google::protobuf::Closure *done) {
  pimpl_->CallMethod(method, rpc_controller, request, response, done);
}

void Channel::SetService(google::protobuf::Service* service) {
  pimpl_->SetService(service);
}

void Channel::HandleRequest(const rpcprotocol::RpcMessage &rpc_message,
                            const SocketId &socket_id,
                            const float &rtt) {
  pimpl_->HandleRequest(rpc_message, socket_id, rtt);
}

}  // namespace rpcprotocol
