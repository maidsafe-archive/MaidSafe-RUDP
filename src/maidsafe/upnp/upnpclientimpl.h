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

#ifndef MAIDSAFE_UPNP_UPNPCLIENTIMPL_H_
#define MAIDSAFE_UPNP_UPNPCLIENTIMPL_H_

// #define VERBOSE_DEBUG

#include <upnp/upnp.h>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <string>
#include <list>
#include <map>
#include "upnp/upnpcfg.h"
#include "base/calllatertimer.h"

namespace upnp {

const char kIgdDeviceType[] =
  "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
const char kWanIpServiceType[] =
  "urn:schemas-upnp-org:service:WANIPConnection:1";
const char kWanPppServiceType[] =
  "urn:schemas-upnp-org:service:WANPPPConnection:1";

struct RootDevice;

struct Service {
  Service(): service_type(),
             service_id(),
             scpd_url(),
             control_url(),
             event_sub_url(),
             enabled(false),
             status_requested(false),
             subscription_requested(false),
             subscription_id(),
             subscription_expires(0),
             parent_root_device(NULL) {}
  std::string service_type;
  std::string service_id;
  std::string scpd_url;
  std::string control_url;
  std::string event_sub_url;

  bool enabled;
  bool status_requested;
  bool subscription_requested;
  std::string subscription_id;
  uint32_t subscription_expires;
  RootDevice* parent_root_device;
};

struct Device {
  Device(): device_type(),
            friendly_name(),
            manufacturer(),
            model_name(),
            unique_device_name(),
            services(),
            devices() {}
  std::string device_type;
  std::string friendly_name;
  std::string manufacturer;
  std::string model_name;
  std::string unique_device_name;

  std::list< boost::shared_ptr<Service> > services;
  std::list< boost::shared_ptr<Device> > devices;
};

struct RootDevice {
  RootDevice(const boost::shared_ptr<Device> &details_,
             const int &expires_,
             const std::string &location_): details(details_),
                                            expires(expires_),
                                            location(location_) {}
  boost::shared_ptr<Device> details;
  uint32_t expires;  // absolute timestamp!
  std::string location;
};

// control point for a UPnP Internet Gateway Device (libupnp implementation)
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
  // returns the ip address of the internal server listening for requests
  std::string GetServerIpAddress();
  // returns the port of the internal server listening for requests
  int GetServerPort();

  // schedules a port mapping for registration with known and future services
  bool AddPortMapping(const PortMapping &mapping);
  // checks, if the given mapping exists in the internal list
  bool PortMappingExists(const int &port, const ProtocolType &protocol,
                         std::list<PortMapping>::iterator &it);
  // removes the mapping from the internal list and all known services
  bool DeletePortMapping(const int &port, const ProtocolType &protocol);
  // removes all mappings
  bool DeleteAllPortMappings();

  // retrieves the external IP address from the first device (blocking)
  std::string GetExternalIpAddress();

  // callbacks for processing UPnP event notifications
  void ProcessDiscoveryEvent(Upnp_EventType event_type, Upnp_Discovery* event);
  void ProcessActionEvent(Upnp_Action_Complete* event);
  void ProcessChangeEvent(Upnp_Event* event);
  void ProcessSubscriptionEvent(Upnp_EventType event_type,
                                Upnp_Event_Subscribe* event);
  // main callback, called by upnplib
  static int EventCallback(Upnp_EventType event_type, void* event,
                           void* cookie);

  // register a function to be called when a mapping has been successful
  void SetNewMappingCallback(const upnp_callback &new_mapping_callback);
  // register a function to be called when all instances of a mapping are gone
  void SetLostMappingCallback(const upnp_callback &lost_mapping_callback);
  // register a function to be called when a mapping couldn't be set up
  void SetFailedMappingCallback(const upnp_callback &failed_mapping_callback);

 private:
  UpnpIgdClientImpl(const UpnpIgdClientImpl&);
  UpnpIgdClientImpl& operator=(const UpnpIgdClientImpl&);

  // initialises the UPnP SDK
  bool Init();
  // terminates the SDK
  void Finish();

  // registers the client with the SDK
  bool Register();
  // unregisters the client, unsubscribing all active subscriptions
  void UnRegister();

  // starts the search for suitable devices
  void DiscoverDevices();

  // extracts a device structure from an xml hierarchy
  bool ParseDeviceDescription(IXML_Node* node,
                              const boost::shared_ptr<Device> &device,
                              const std::string &location);
  // extracts a service structure from an xml hierarchy
  bool ParseServiceDescription(IXML_Node* node,
                               const boost::shared_ptr<Service> &service,
                               const std::string &location);

  // adds a unique root device to the internal list
  bool AddRootDevice(const boost::shared_ptr<Device> &device,
                     const uint32_t &expires, const std::string location);
  // checks, if a root device with the given ID exists in the internal list
  bool RootDeviceExists(const std::string &udn, const std::string location,
                        std::list<RootDevice>::iterator &it);
  // keeps the root device from expiring
  void UpdateRootDevice(RootDevice* rd, const uint32_t &expires);
  // removes the root device with the given ID
  bool DeleteRootDevice(const std::string &udn, const std::string location);

  // rebuilds list of relevant services
  void UpdateServicesCache();
  // renews mappings on active services, if needed
  void UpdatePortMappings();
  // sends request to find out whether service exists and is active
  void RequestServiceStatusInfo(const boost::shared_ptr<Service> &service);

  // retrieves service from cache list by its control URL
  bool GetCachedServiceByControlUrl(const std::string &url,
                                    boost::shared_ptr<Service> &service);
  // retrieves service from cache list by its subscription URL
  bool GetCachedServiceByEventSubUrl(const std::string &url,
                                     boost::shared_ptr<Service> &service);
  // retrieves service from cache list by its subscription ID
  bool GetCachedServiceBySubscriptionId(const std::string &sid,
                                        boost::shared_ptr<Service> &service);

  // creates/refreshes mapping-service relation
  bool AddPortMappingToService(const boost::shared_ptr<Service> &service,
                               PortMapping *mapping);
  // removes mapping-service relation
  bool DeletePortMappingFromService(const boost::shared_ptr<Service> &service,
                                    const PortMapping &mapping);
  // gets called periodically to refresh a mapping
  void RefreshPortMappingCallback(const int &port,
                                  const ProtocolType &protocol,
                                  const std::string &service_control_url);

  // void RefreshSubscriptionCallback(const std::string &subscription_id);

  // calls the callback for a new mapping
  void OnNewMapping(const int &port, const ProtocolType &protocol);
  // calls the callback for a lost mapping
  void OnLostMapping(const int &port, const ProtocolType &protocol);
  // calls the callback for a failed mapping
  void OnFailedMapping(const int &port, const ProtocolType &protocol);


  bool is_initialised_;
  bool is_registered_;
  UpnpClient_Handle handle_;
  boost::recursive_mutex mutex_;
  base::CallLaterTimer timer_;

  std::list<RootDevice> root_devices_;
  std::list<PortMapping> port_mappings_;
  std::list< boost::shared_ptr<Service> > services_cache_;

  upnp_callback new_mapping_callback_;
  upnp_callback lost_mapping_callback_;
  upnp_callback failed_mapping_callback_;
};

}  // namespace upnp

#endif  // MAIDSAFE_UPNP_UPNPCLIENTIMPL_H_
