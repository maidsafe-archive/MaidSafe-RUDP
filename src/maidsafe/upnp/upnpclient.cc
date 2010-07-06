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

#include "maidsafe/upnp/upnpclient.h"

#include <vector>

namespace upnp {

UpnpIgdClient::UpnpIgdClient() : pimpl_(new UpnpIgdClientImpl()) {}

UpnpIgdClient::~UpnpIgdClient() {}

bool UpnpIgdClient::IsAsync() {
  return pimpl_->IsAsync();
}

bool UpnpIgdClient::HasServices() {
  return pimpl_->HasServices();
}

bool UpnpIgdClient::InitControlPoint() {
  return pimpl_->InitControlPoint();
}

bool UpnpIgdClient::AddPortMapping(const int &port,
                                   const ProtocolType &protocol) {
  return pimpl_->AddPortMapping(PortMapping(port, protocol));
}

bool UpnpIgdClient::DeletePortMapping(const int &port,
                                      const ProtocolType &protocol) {
  return pimpl_->DeletePortMapping(port, protocol);
}

std::string UpnpIgdClient::GetExternalIpAddress() {
  return pimpl_->GetExternalIpAddress();
}

void UpnpIgdClient::SetNewMappingCallback(
       const upnp_callback &new_mapping_callback) {
  pimpl_->SetNewMappingCallback(new_mapping_callback);
}

void UpnpIgdClient::SetLostMappingCallback(
       const upnp_callback &lost_mapping_callback) {
  pimpl_->SetLostMappingCallback(lost_mapping_callback);
}

void UpnpIgdClient::SetFailedMappingCallback(
       const upnp_callback &failed_mapping_callback) {
  pimpl_->SetFailedMappingCallback(failed_mapping_callback);
}

}  // namespace upnp
