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

#ifndef MAIDSAFE_UPNP_MINIUPNPCLIENTIMPL_H_
#define MAIDSAFE_UPNP_MINIUPNPCLIENTIMPL_H_

// #define VERBOSE_DEBUG

#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <string>
#include <list>
#include <map>
#include "maidsafe/upnp/upnpcfg.h"
#include "maidsafe/libupnp/miniupnpc.h"
#include "maidsafe/base/calllatertimer.h"

namespace upnp {

// control point for a UPnP Internet Gateway Device (miniupnp implementation)
class UpnpIgdClientImpl {
 public:
  UpnpIgdClientImpl();
  ~UpnpIgdClientImpl();

  // returns true if the mapping functions use callbacks
  bool IsAsync();
  // returns true if suitable services have been found
  bool HasServices();

  // starts up the UPnP control point, including device discovery
  bool InitControlPoint();

  // schedules a port mapping for registration with known and future services
  bool AddPortMapping(const PortMapping &mapping);
  // checks, if the given mapping exists in the internal list
  bool PortMappingExists(const int &port, const ProtocolType &protocol,
                         std::list<PortMapping>::iterator &it);
  // removes the mapping from the internal list and all known services
  bool DeletePortMapping(const int &port, const ProtocolType &protocol);
  // removes all mappings
  bool DeleteAllPortMappings();

  // retrieves the external IP address from the device
  std::string GetExternalIpAddress();

  // register a function to be called when a mapping has been successful
  void SetNewMappingCallback(const upnp_callback &) {}
  // register a function to be called when all instances of a mapping are gone
  void SetLostMappingCallback(const upnp_callback &) {}
  // register a function to be called when a mapping couldn't be set up
  void SetFailedMappingCallback(const upnp_callback &) {}

 private:
  UpnpIgdClientImpl(const UpnpIgdClientImpl&);
  UpnpIgdClientImpl& operator=(const UpnpIgdClientImpl&);

  void DiscoverDevices();
  void RefreshCallback();

  bool is_initialised_;
  bool has_services_;

  UPNPUrls upnp_urls_;
  IGDdatas igd_data_;
  std::list<PortMapping> port_mappings_;
  base::CallLaterTimer timer_;
};

}  // namespace upnp

#endif  // MAIDSAFE_UPNP_MINIUPNPCLIENTIMPL_H_
