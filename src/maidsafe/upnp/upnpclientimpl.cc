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

#include "upnp/upnpclientimpl.h"
#include <upnp/upnptools.h>
#include <boost/bind.hpp>
#include <boost/assert.hpp>
#include <vector>
#include "maidsafe/maidsafe-dht.h"
#include "maidsafe/utils.h"

// #define DEBUG

namespace upnp {

std::string ResolveUrl(const std::string &base_url,
                       const std::string &rel_url) {
  // hopefully enough to prevent buffer overflow in all cases...
  char *abs_url = new char[base_url.length() + 1 + rel_url.length()];
  if (UpnpResolveURL(base_url.c_str(), rel_url.c_str(), abs_url)
      == UPNP_E_SUCCESS) {
    std::string result(abs_url);
    delete[] abs_url;
    return result;
  } else {
    return rel_url;
  }
}

UpnpIgdClientImpl::UpnpIgdClientImpl()
  : is_initialised_(false), is_registered_(false), handle_(0), mutex_(),
    timer_(), root_devices_(), port_mappings_(), services_cache_() {}

UpnpIgdClientImpl::~UpnpIgdClientImpl() {
  {
    boost::recursive_mutex::scoped_lock guard(mutex_);
    timer_.CancelAll();
  }
  if (is_registered_) {
    DeleteAllPortMappings();
    UnRegister();
  }
  {
    boost::recursive_mutex::scoped_lock guard(mutex_);
    root_devices_.clear();
    Finish();
  }
}

bool UpnpIgdClientImpl::IsAsync() {
  return true;
}

bool UpnpIgdClientImpl::HasServices() {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  return services_cache_.size() > 0;
}

bool UpnpIgdClientImpl::InitControlPoint() {
  boost::recursive_mutex::scoped_lock guard(mutex_);

  if (!Init())
    return false;

  if (!Register())
    return false;

  DiscoverDevices();
  return true;
}

std::string UpnpIgdClientImpl::GetServerIpAddress() {
  if (is_initialised_)
    return UpnpGetServerIpAddress();
  else
    return "";
}

int UpnpIgdClientImpl::GetServerPort() {
  if (is_initialised_)
    return UpnpGetServerPort();
  else
    return 0;
}

bool UpnpIgdClientImpl::AddPortMapping(const PortMapping &mapping) {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  std::list<PortMapping>::iterator it;
  if (PortMappingExists(mapping.external_port, mapping.protocol, it))
    return false;

  port_mappings_.push_back(mapping);
  UpdatePortMappings();
  return true;
}

bool UpnpIgdClientImpl::PortMappingExists(
       const int &port, const ProtocolType &protocol,
       std::list<PortMapping>::iterator &it) {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  for (it = port_mappings_.begin(); it != port_mappings_.end(); ++it) {
    if ((*it).external_port == port &&
        (*it).protocol == protocol)
      return true;
  }
  return false;
}

bool UpnpIgdClientImpl::DeletePortMapping(const int &port,
                                          const ProtocolType &protocol) {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  std::list<PortMapping>::iterator it_pm;
  if (PortMappingExists(port, protocol, it_pm)) {
    if ((*it_pm).enabled) {
      for (std::list< boost::shared_ptr<Service> >::iterator it_srv =
             services_cache_.begin();
           it_srv != services_cache_.end(); ++it_srv) {
         DeletePortMappingFromService(*it_srv, *it_pm);
      }
    }
    port_mappings_.erase(it_pm);
    return true;
  }
  return false;
}

bool UpnpIgdClientImpl::DeleteAllPortMappings() {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  bool result = true;
  while (!port_mappings_.empty()) {
    result &= DeletePortMapping(port_mappings_.front().external_port,
                                port_mappings_.front().protocol);
  }
  return result;
}

std::string UpnpIgdClientImpl::GetExternalIpAddress() {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  if (!is_registered_ || !is_initialised_)
    return "";

  if (services_cache_.size() == 0)
    return "";

  boost::shared_ptr<Service> service = services_cache_.front();

  IXML_Document *action = UpnpMakeAction("GetExternalIPAddress",
    service->service_type.c_str(), 0, NULL);

  if (!action)
    return "";

  /* DOMString acdoc = ixmlPrintNode((IXML_Node *) action);
  printf("%s\n", acdoc);
  ixmlFreeDOMString(acdoc); */

  std::string ip("");

  IXML_Document* response = NULL;
  int res = UpnpSendAction(handle_,
                           service->control_url.c_str(),
                           service->service_type.c_str(),
                           NULL,
                           action,
                           &response);

  /* DOMString resdoc = ixmlPrintNode((IXML_Node *) response);
  printf("%s\n", resdoc);
  ixmlFreeDOMString(resdoc); */

  if (res == UPNP_E_SUCCESS) {
    IXML_Node* node = ixmlNode_getFirstChild(
      reinterpret_cast<IXML_Node*>(response));
    if (node) {
      std::string resp_name = base::StrToLwr(ixmlNode_getLocalName(node));
      node = ixmlNode_getFirstChild(node);
      if (resp_name == "getexternalipaddressresponse") {
        while (node) {
          std::string nodename = base::StrToLwr(ixmlNode_getLocalName(node));
          if (nodename == "newexternalipaddress") {
            if (ixmlNode_hasChildNodes(node)) {
              DOMString val = const_cast<DOMString>(
                ixmlNode_getNodeValue(ixmlNode_getFirstChild(node)));
              ip = val;
            }
          }
          node = ixmlNode_getNextSibling(node);
        }
      }
    }
  } else {
#ifdef DEBUG
    printf("UPnP error retrieving external IP address: %s (%d)\n",
           UpnpGetErrorMessage(res), res);
#endif
  }

  if (response)
    ixmlDocument_free(response);
  ixmlDocument_free(action);

  return ip;
}

bool UpnpIgdClientImpl::Init() {
  if (is_initialised_)
    return false;

  int init_result = UpnpInit(NULL, 0);

  if (init_result != UPNP_E_SUCCESS) {
#ifdef DEBUG
    printf("Error initialising UPnP: %s (%d)\n",
           UpnpGetErrorMessage(init_result), init_result);
#endif
    return false;
  }

  is_initialised_ = true;
#ifdef DEBUG
    printf("Initialised libupnp " UPNP_VERSION_STRING "\n");
#endif
  return true;
}

void UpnpIgdClientImpl::Finish() {
  is_initialised_ = is_registered_ = false;
  UpnpFinish();
}

bool UpnpIgdClientImpl::Register() {
  BOOST_ASSERT(is_initialised_);

  if (is_registered_)
    return false;

  int register_result = UpnpRegisterClient((Upnp_FunPtr) &EventCallback,
                                           this, &handle_);

  if (register_result != UPNP_E_SUCCESS) {
#ifdef DEBUG
    printf("Error registering UPnP client: %s (%d)\n",
           UpnpGetErrorMessage(register_result), register_result);
#endif
    return false;
  }

  is_registered_ = true;
  return true;
}

void UpnpIgdClientImpl::UnRegister() {
  BOOST_ASSERT(is_registered_ && is_initialised_);

  UpnpUnRegisterClient(handle_);
  handle_ = 0;
  is_registered_ = false;
}

void UpnpIgdClientImpl::DiscoverDevices() {
  BOOST_ASSERT(is_registered_ && is_initialised_);

  UpnpSearchAsync(handle_, kSearchTime, "upnp:rootdevice", this);
  UpnpSearchAsync(handle_, kSearchTime, kIgdDeviceType, this);
}

int UpnpIgdClientImpl::EventCallback(Upnp_EventType event_type, void* event,
                                     void* cookie) {
  // printf("UPnP event callback #%d\n", event_type);

  switch (event_type) {
    // Received by a control point when a new device or service is available.
    case UPNP_DISCOVERY_ADVERTISEMENT_ALIVE:
    // Received by a control point when a matching device or service responds.
    case UPNP_DISCOVERY_SEARCH_RESULT:
    // Received by a control point when a device or service shuts down.
    case UPNP_DISCOVERY_ADVERTISEMENT_BYEBYE:
      static_cast<UpnpIgdClientImpl*>(cookie)->
        ProcessDiscoveryEvent(event_type, static_cast<Upnp_Discovery*>(event));
      break;
    // Received by a control point when the search timeout expires.
    case UPNP_DISCOVERY_SEARCH_TIMEOUT:
      // Done searching. If a new device comes online, it will let us know.
#ifdef VERBOSE_DEBUG
      printf("UPnP device discovery finished.\n");
#endif
      break;


    // A UpnpSendActionAsync call completed.
    case UPNP_CONTROL_ACTION_COMPLETE:
      static_cast<UpnpIgdClientImpl*>(cookie)->
        ProcessActionEvent(static_cast<Upnp_Action_Complete*>(event));
      break;
    // A UpnpGetServiceVarStatus call completed.
    case UPNP_CONTROL_GET_VAR_COMPLETE:
#ifdef DEBUG
      printf("UPNP_CONTROL_GET_VAR_COMPLETE\n");
#endif
      break;

    // Received by a control point when an event arrives.
    case UPNP_EVENT_RECEIVED:
      static_cast<UpnpIgdClientImpl*>(cookie)->
        ProcessChangeEvent(static_cast<Upnp_Event*>(event));
      break;

    // A UpnpRenewSubscriptionAsync call completed.
    case UPNP_EVENT_RENEWAL_COMPLETE:
    // A UpnpSubscribeAsync call completed.
    case UPNP_EVENT_SUBSCRIBE_COMPLETE:
    // A UpnpUnSubscribeAsync call completed.
    case UPNP_EVENT_UNSUBSCRIBE_COMPLETE:
      static_cast<UpnpIgdClientImpl*>(cookie)->
        ProcessSubscriptionEvent(event_type,
                                 static_cast<Upnp_Event_Subscribe*>(event));
      break;

    // The auto-renewal of a client subscription failed.
    case UPNP_EVENT_AUTORENEWAL_FAILED:
#ifdef DEBUG
      printf("UPNP_EVENT_AUTORENEWAL_FAILED\n");
#endif
      break;

    // A client subscription has expired.
    case UPNP_EVENT_SUBSCRIPTION_EXPIRED:
#ifdef DEBUG
      printf("UPNP_EVENT_SUBSCRIPTION_EXPIRED\n");
#endif
      break;
  }

  return 0;
}

void UpnpIgdClientImpl::ProcessDiscoveryEvent(Upnp_EventType event_type,
                                              Upnp_Discovery* event) {
  if (!is_registered_ || !is_initialised_)
    return;

  if (event->ErrCode != UPNP_E_SUCCESS) {
#ifdef DEBUG
    printf("Error in UPnP discovery callback: %s (%d)\n",
           UpnpGetErrorMessage(event->ErrCode), event->ErrCode);
#endif
    return;
  }

  switch (event_type) {
    // Received by a control point when a new device or service is available.
    case UPNP_DISCOVERY_ADVERTISEMENT_ALIVE:
    // Received by a control point when a matching device or service responds.
    case UPNP_DISCOVERY_SEARCH_RESULT: {
#ifdef VERBOSE_DEBUG
      printf("UPnP device found: %s at %s\n", event->DeviceId, event->Location);
#endif
      uint32_t expires = base::get_epoch_time() +
                         static_cast<uint32_t>(event->Expires);

      // Don't download device description if known device, just update ttl
      {
        boost::recursive_mutex::scoped_lock guard(mutex_);
        std::list<RootDevice>::iterator it;
        if (RootDeviceExists(event->DeviceId, event->Location, it)) {
          // printf("!! skipped dl'ing desc doc from %s\n", event->Location);
          UpdateRootDevice(&(*it), expires);
          return;
        }
      }

      // Download device description
      IXML_Document *desc_doc = NULL;
      int download_result = UpnpDownloadXmlDoc(event->Location, &desc_doc);
      if (download_result != UPNP_E_SUCCESS) {
#ifdef DEBUG
        printf("Error obtaining UPnP device description: %s (%d)\n",
               UpnpGetErrorMessage(download_result), download_result);
#endif
        return;
      }  // else printf("!! downloaded desc doc from %s\n", event->Location);

      if (desc_doc) {  // * -> root -> device
        std::string location(event->Location);
        IXML_Node* node = ixmlNode_getFirstChild(
          reinterpret_cast<IXML_Node*>(desc_doc));
        if (node && base::StrToLwr(ixmlNode_getNodeName(node)) == "root") {
          node = ixmlNode_getFirstChild(node);
          while (node) {
            std::string nodename = base::StrToLwr(ixmlNode_getNodeName(node));
            if (nodename == "urlbase") {
              // deprecated; for backwards compatibility with UPnP 1.0
              if (ixmlNode_hasChildNodes(node)) {
                DOMString val = const_cast<DOMString>(
                  ixmlNode_getNodeValue(ixmlNode_getFirstChild(node)));
                location = val;
              }
            } else if (nodename == "device") {
              boost::shared_ptr<Device> device(new Device());
              if (ParseDeviceDescription(node, device, location)) {
                if (base::StrToLwr(device->device_type) ==
                    base::StrToLwr(kIgdDeviceType)) {  // IGDs only
                  AddRootDevice(device, expires, location);
                }  // else [add more dev types if needed]
              }
              node = NULL;  // only one root device allowed
            } else {
              node = ixmlNode_getNextSibling(node);
            }
          }
        }
        ixmlDocument_free(desc_doc);
      }
      } break;

    // Received by a control point when a device or service shuts down.
    case UPNP_DISCOVERY_ADVERTISEMENT_BYEBYE:
#ifdef VERBOSE_DEBUG
      printf("UPnP device went offline: %s\n", event->DeviceId);
#endif
      // Delete the vanished device
      DeleteRootDevice(event->DeviceId, event->Location);
      break;
  }
}

void UpnpIgdClientImpl::ProcessActionEvent(Upnp_Action_Complete* event) {
  if (!is_registered_ || !is_initialised_)
    return;

  if (event->ErrCode != UPNP_E_SUCCESS) {
#ifdef DEBUG
    printf("Error in UPnP action response callback: %s (%d)\n",
           UpnpGetErrorMessage(event->ErrCode), event->ErrCode);
#endif
    return;
  }

  boost::recursive_mutex::scoped_lock guard(mutex_);
  boost::shared_ptr<Service> service;
  if (GetCachedServiceByControlUrl(event->CtrlUrl, service)) {
//    DOMString acdoc = ixmlPrintNode((IXML_Node *) event->ActionRequest);
//    printf("%s\n", acdoc);
//    ixmlFreeDOMString(acdoc);
//    DOMString acdoc = ixmlPrintNode((IXML_Node *) event->ActionResult);
//    printf("%s\n", acdoc);
//    ixmlFreeDOMString(acdoc);
    if (event->ActionResult) {
      IXML_Node* node = ixmlNode_getFirstChild(
        reinterpret_cast<IXML_Node*>(event->ActionResult));
      if (node) {
        std::string resp_name = base::StrToLwr(ixmlNode_getLocalName(node));
        node = ixmlNode_getFirstChild(node);
        // needs separate functions for response handlers?
        if (resp_name == "getstatusinforesponse") {
          // we got a response for GetStatusInfo
          bool is_connected = false;
          service->status_requested = false;

          while (node) {
            std::string nodename = base::StrToLwr(ixmlNode_getLocalName(node));
            if (nodename == "newconnectionstatus") {
              if (ixmlNode_hasChildNodes(node)) {
                DOMString val = const_cast<DOMString>(
                  ixmlNode_getNodeValue(ixmlNode_getFirstChild(node)));
                if (val && base::StrToLwr(val) == "connected")
                  is_connected = true;
              }
            }
            node = ixmlNode_getNextSibling(node);
          }

          if (is_connected) {
            // this service is available
            service->enabled = true;
#ifdef DEBUG
            printf("UPnP service is active: %s\n",
                   service->service_type.c_str());
#endif
            if (!service->event_sub_url.empty()) {
              BOOST_ASSERT(service->parent_root_device);
              int res = UpnpSubscribeAsync(handle_,
                                           service->event_sub_url.c_str(),
                                           service->parent_root_device->expires
                                             - base::get_epoch_time(),
                                           (Upnp_FunPtr) &EventCallback,
                                           this);
              if (res == UPNP_E_SUCCESS) {
                service->subscription_requested = true;
                service->subscription_id = "";
              } else {
#ifdef DEBUG
                printf("Unable to subscribe to UPnP service: %s (%d)\n",
                       UpnpGetErrorMessage(res), res);
#endif
              }
            }

            UpdatePortMappings();
          }
        } else if (resp_name == "addportmappingresponse") {
          // we got a response for AddPortMapping
#ifdef DEBUG
          printf("Adding UPnP port mapping successfully completed.\n");
#endif
        } else if (resp_name == "deleteportmappingresponse") {
          // we got a response for DeletePortMapping
#ifdef DEBUG
          printf("Deleting UPnP port mapping successfully completed.\n");
#endif
        }  // else [add other response handlers]
      }
    }
  } else {
#ifdef DEBUG
    printf("Received UPnP action response for invalid service: %s\n",
           event->CtrlUrl);
#endif
  }

  // ixmlDocument_free(event->ActionRequest);
  // ixmlDocument_free(event->ActionResult);
}

void UpnpIgdClientImpl::ProcessChangeEvent(Upnp_Event* event) {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  if (!is_registered_ || !is_initialised_)
    return;

  /* printf("\nUPnP event received: SID=%s, EventKey=%d\n",
         event->Sid, event->EventKey);

  DOMString doc = ixmlPrintNode(
                    reinterpret_cast<IXML_Node *>(event->ChangedVariables));
  printf("%s\n\n", doc);
  ixmlFreeDOMString(doc); */

  bool update_needed = false;

  boost::shared_ptr<Service> service;
  if (GetCachedServiceBySubscriptionId(event->Sid, service)) {
    IXML_Node* node = ixmlNode_getFirstChild(
      reinterpret_cast<IXML_Node *>(event->ChangedVariables));
    if (node && ixmlNode_hasChildNodes(node) &&
        base::StrToLwr(ixmlNode_getLocalName(node)) == "propertyset") {
      node = ixmlNode_getFirstChild(node);
      while (node) {
        if (base::StrToLwr(ixmlNode_getLocalName(node)) == "property") {
          IXML_Node* node2 = ixmlNode_getFirstChild(node);
          while (node2) {
            std::string name = base::StrToLwr(ixmlNode_getLocalName(node2));
            std::string value = "";

            if (ixmlNode_hasChildNodes(node2)) {
              DOMString val = const_cast<DOMString>(
                ixmlNode_getNodeValue(ixmlNode_getFirstChild(node2)));
              if (val)
                value = val;
            }

            if (name == "connectionstatus") {
              bool is_connected = (base::StrToLwr(value) == "connected");
              if (service->enabled != is_connected) {
                service->enabled = is_connected;
                update_needed = true;
#ifdef DEBUG
                printf("UPnP service %s: %s\n",
                       service->enabled ? "enabled" : "disabled",
                       service->service_type.c_str());
#endif
              }
            }

            // printf("** [status] %s: %s\n", name.c_str(), value.c_str());

            node2 = ixmlNode_getNextSibling(node2);
          }
        }

        node = ixmlNode_getNextSibling(node);
      }
    }
  }

  if (update_needed)
    UpdatePortMappings();
}

void UpnpIgdClientImpl::ProcessSubscriptionEvent(Upnp_EventType event_type,
                                                 Upnp_Event_Subscribe* event) {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  if (!is_registered_ || !is_initialised_)
    return;

  if (event->ErrCode != UPNP_E_SUCCESS) {
#ifdef DEBUG
    printf("Error in UPnP subscription response callback: %s (%d)\n",
           UpnpGetErrorMessage(event->ErrCode), event->ErrCode);
#endif
    return;
  }

  boost::shared_ptr<Service> service;
  if (GetCachedServiceByEventSubUrl(event->PublisherUrl, service)) {
    switch (event_type) {
      // A UpnpSubscribeAsync call completed.
      case UPNP_EVENT_SUBSCRIBE_COMPLETE:
      // A UpnpRenewSubscriptionAsync call completed.
      case UPNP_EVENT_RENEWAL_COMPLETE:
        if (service->subscription_requested) {
          service->subscription_requested = false;
          service->subscription_id = event->Sid;
          service->subscription_expires = base::get_epoch_time() +
            static_cast<uint32_t>(event->TimeOut);
#ifdef DEBUG
          printf("(Re-)Subscribed to UPnP service:"
                 " %s (SID = %s, timeout in %d s)\n",
                 service->service_type.c_str(),
                 service->subscription_id.c_str(),
                 event->TimeOut);
#endif
          // schedule subscription renewal
/*          timer_.AddCallLater(
            //(kLeaseDuration - kRefreshThreshold) * 1000,
            15, // ...
            boost::bind(&UpnpIgdClientImpl::RefreshSubscriptionCallback,
                        this,
                        service->subscription_id)); */
        }
        break;

      // A UpnpUnSubscribeAsync call completed.
      case UPNP_EVENT_UNSUBSCRIBE_COMPLETE:
        if (service->subscription_id == event->Sid) {
          service->subscription_requested = false;
          service->subscription_id = "";
        }
        break;
    }
  }
}

bool UpnpIgdClientImpl::ParseDeviceDescription(IXML_Node* node,
       const boost::shared_ptr<Device> &device,
       const std::string &location) {
  // note: no mutex needed here
  if (!node)
    return false;

  bool res = false;

  node = ixmlNode_getFirstChild(node);
  while (node) {
    if (ixmlNode_getNodeType(node) == eELEMENT_NODE) {
      std::string name = base::StrToLwr(ixmlNode_getNodeName(node));
      std::string value = "";

      if (ixmlNode_hasChildNodes(node)) {
        DOMString val = const_cast<DOMString>(
          ixmlNode_getNodeValue(ixmlNode_getFirstChild(node)));
        if (val)
          value = val;

        res = true;
      }

      if (name == "devicetype") {
        device->device_type = value;
      } else if (name == "friendlyname") {
        device->friendly_name = value;
      } else if (name == "manufacturer") {
        device->manufacturer = value;
      } else if (name == "modelname") {
        device->model_name = value;
      } else if (name == "udn") {
        device->unique_device_name = base::StrToLwr(value);
      } else if (name == "devicelist") {
        IXML_Node* node2 = ixmlNode_getFirstChild(node);
        while (node2) {
          if (base::StrToLwr(ixmlNode_getNodeName(node2)) == "device") {
            boost::shared_ptr<Device> device2(new Device());
            if (ParseDeviceDescription(node2, device2, location)) {
              device->devices.push_back(device2);
            }  // else printf("!! Parsing device description failed!\n");
          }
          node2 = ixmlNode_getNextSibling(node2);
        }
      } else if (name == "servicelist") {
        IXML_Node* node2 = ixmlNode_getFirstChild(node);
        while (node2) {
          if (base::StrToLwr(ixmlNode_getNodeName(node2)) == "service") {
            boost::shared_ptr<Service> service(new Service());
            if (ParseServiceDescription(node2, service, location)) {
              device->services.push_back(service);
            }  // else printf("!! Parsing service description failed!\n");
          }
          node2 = ixmlNode_getNextSibling(node2);
        }
      }

      // printf("** [device] %s: %s\n", name.c_str(), value.c_str());
    }

    node = ixmlNode_getNextSibling(node);
  }
  return res;
}

bool UpnpIgdClientImpl::ParseServiceDescription(IXML_Node* node,
       const boost::shared_ptr<Service> &service,
       const std::string &location) {
  if (!node)
    return false;

  bool res = false;

  node = ixmlNode_getFirstChild(node);
  while (node) {
    if (ixmlNode_getNodeType(node) == eELEMENT_NODE) {
      std::string name = base::StrToLwr(ixmlNode_getNodeName(node));
      std::string value = "";

      if (ixmlNode_hasChildNodes(node)) {
        DOMString val = const_cast<DOMString>(
          ixmlNode_getNodeValue(ixmlNode_getFirstChild(node)));
        if (val)
          value = val;

        res = true;
      }

      if (name == "servicetype") {
        service->service_type = value;
      } else if (name == "serviceid") {
        service->service_id = value;
      } else if (name == "scpdurl") {
        service->scpd_url = ResolveUrl(location, value);
      } else if (name == "controlurl") {
        service->control_url = ResolveUrl(location, value);
      } else if (name == "eventsuburl") {
        service->event_sub_url = ResolveUrl(location, value);
      }

      // printf("** [service] %s: %s\n", name.c_str(), value.c_str());
    }

    node = ixmlNode_getNextSibling(node);
  }
  return res;
}

bool UpnpIgdClientImpl::AddRootDevice(const boost::shared_ptr<Device> &device,
                                      const uint32_t &expires,
                                      const std::string location) {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  std::list<RootDevice>::iterator it;
  if (RootDeviceExists(device->unique_device_name, location, it)) {
    UpdateRootDevice(&(*it), expires);
    return false;
  }

  // add new root device
  RootDevice rd(device, expires, location);
  root_devices_.push_back(rd);
#ifdef DEBUG
  printf("New UPnP device added: %s (%s at %s)\n",
         device->device_type.c_str(), device->unique_device_name.c_str(),
         location.c_str());
#endif
  UpdateServicesCache();
  return true;
}

bool UpnpIgdClientImpl::RootDeviceExists(const std::string &udn,
                                         const std::string location,
                                         std::list<RootDevice>::iterator &it) {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  for (it = root_devices_.begin(); it != root_devices_.end(); ++it) {
    if ((*it).details->unique_device_name == udn &&
        (*it).location == location)  // fix for linux-igd
      return true;
  }
  return false;
}

void UpnpIgdClientImpl::UpdateRootDevice(RootDevice* rd,
                                         const uint32_t &expires) {
  rd->expires = expires;
}

bool UpnpIgdClientImpl::DeleteRootDevice(const std::string &udn,
                                         const std::string location) {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  std::list<RootDevice>::iterator it;
  if (RootDeviceExists(udn, location, it)) {
    root_devices_.erase(it);
#ifdef DEBUG
    printf("UPnP device removed: %s at %s\n", udn.c_str(), location.c_str());
#endif
    UpdateServicesCache();
    UpdatePortMappings();
    return true;
  }
  return false;
}

void UpnpIgdClientImpl::UpdateServicesCache() {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  std::vector< boost::shared_ptr<Device> > dev_stack;

  services_cache_.clear();
  int num_srv_enabled = 0;  // only use locally!

  for (std::list<RootDevice>::iterator rdit = root_devices_.begin();
       rdit != root_devices_.end(); ++rdit) {
    dev_stack.push_back((*rdit).details);

    while (!dev_stack.empty()) {
      boost::shared_ptr<Device> curr_dev = dev_stack.back();
      dev_stack.pop_back();

  //    printf("curr_dev = %s (dev: %d, srv: %d)\n",
  //           curr_dev->friendly_name.c_str(),
  //           curr_dev->devices.size(),
  //           curr_dev->services.size());

      for (std::list< boost::shared_ptr<Device> >::iterator it =
             curr_dev->devices.begin();
           it != curr_dev->devices.end(); ++it) {
        dev_stack.push_back(*it);
      }

      for (std::list< boost::shared_ptr<Service> >::iterator it =
             curr_dev->services.begin();
           it != curr_dev->services.end(); ++it) {
        // printf("* service: %s\n", (*it)->service_type.c_str());
        if (base::StrToLwr((*it)->service_type) ==
              base::StrToLwr(kWanIpServiceType) ||
            base::StrToLwr((*it)->service_type) ==
              base::StrToLwr(kWanPppServiceType)) {
          // only add interesting services to cache
          services_cache_.push_back(*it);
          (*it)->parent_root_device = &(*rdit);
          if ((*it)->enabled) {
            ++num_srv_enabled;
          } else if (!(*it)->status_requested) {
            RequestServiceStatusInfo(*it);
          }
        }
      }
    }
  }

#ifdef VERBOSE_DEBUG
  printf("UPnP service cache update: %d of %d active\n",
         num_srv_enabled, services_cache_.size());
#endif
}

void UpnpIgdClientImpl::UpdatePortMappings() {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  if (!is_registered_ || !is_initialised_)
    return;

  for (std::list<PortMapping>::iterator it_pm = port_mappings_.begin();
             it_pm != port_mappings_.end(); ++it_pm) {
    int num = 0;
    for (std::list< boost::shared_ptr<Service> >::iterator it_srv =
           services_cache_.begin();
         it_srv != services_cache_.end(); ++it_srv) {
      if ((*it_srv)->enabled && AddPortMappingToService(*it_srv, &(*it_pm)))
        num++;
    }
    if (num == 0) {
      if ((*it_pm).enabled) {
        // callback for lost mapping
        OnLostMapping((*it_pm).external_port, (*it_pm).protocol);
#ifdef DEBUG
        printf("UPnP port mapping inactive: %s %d\n",
               (*it_pm).protocol == kTcp ? "TCP" : "UDP",
               (*it_pm).external_port);
#endif
      }
      (*it_pm).enabled = false;
      (*it_pm).last_refresh.clear();
    }
  }
}

void UpnpIgdClientImpl::RequestServiceStatusInfo(
       const boost::shared_ptr<Service> &service) {
  BOOST_ASSERT(is_registered_ && is_initialised_);
  boost::recursive_mutex::scoped_lock guard(mutex_);

  IXML_Document *action = UpnpMakeAction("GetStatusInfo",
                                         service->service_type.c_str(),
                                         0, NULL);
  if (!action) return;

//  DOMString acdoc = ixmlPrintNode((IXML_Node *) action);
//  printf("%s\n", acdoc);
//  ixmlFreeDOMString(acdoc);

  int res = UpnpSendActionAsync(handle_,
                                service->control_url.c_str(),
                                service->service_type.c_str(),
                                NULL,
                                action,
                                (Upnp_FunPtr) &EventCallback,
                                this);

  if (res == UPNP_E_SUCCESS) {
    service->status_requested = true;
  } else {
#ifdef DEBUG
    printf("Error sending UPnP action GetStatusInfo: %s (%d)\n",
           UpnpGetErrorMessage(res), res);
#endif
  }

  ixmlDocument_free(action);
}

bool UpnpIgdClientImpl::GetCachedServiceByControlUrl(const std::string &url,
       boost::shared_ptr<Service> &service) {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  for (std::list< boost::shared_ptr<Service> >::iterator it =
           services_cache_.begin();
       it != services_cache_.end(); ++it) {
    if ((*it)->control_url == url) {
      service = *it;
      return true;
    }
  }
  return false;
}

bool UpnpIgdClientImpl::GetCachedServiceByEventSubUrl(const std::string &url,
       boost::shared_ptr<Service> &service) {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  for (std::list< boost::shared_ptr<Service> >::iterator it =
           services_cache_.begin();
       it != services_cache_.end(); ++it) {
    if ((*it)->event_sub_url == url) {
      service = *it;
      return true;
    }
  }
  return false;
}

bool UpnpIgdClientImpl::GetCachedServiceBySubscriptionId(
       const std::string &sid, boost::shared_ptr<Service> &service) {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  for (std::list< boost::shared_ptr<Service> >::iterator it =
           services_cache_.begin();
       it != services_cache_.end(); ++it) {
    if ((*it)->subscription_id == sid) {
      service = *it;
      return true;
    }
  }
  return false;
}

bool UpnpIgdClientImpl::AddPortMappingToService(
       const boost::shared_ptr<Service> &service, PortMapping *mapping) {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  if (!is_registered_ || !is_initialised_)
    return false;

  if (!service->enabled) return false;

  if (mapping->last_refresh[service->control_url] >
      base::get_epoch_time() - kLeaseDuration + kRefreshThreshold) {
    // bail out, since we recently refreshed the mapping
    return true;
  }

  std::string protocol = (mapping->protocol == kUdp ? "UDP" : "TCP");
  std::string ip = GetServerIpAddress();

  IXML_Document *action = UpnpMakeAction("AddPortMapping",
    service->service_type.c_str(), 8,
    "NewRemoteHost",             "",
    "NewExternalPort",           base::itos(mapping->external_port).c_str(),
    "NewProtocol",               protocol.c_str(),
    "NewInternalPort",           base::itos(mapping->internal_port).c_str(),
    "NewInternalClient",         ip.c_str(),
    "NewEnabled",                "1",
    "NewPortMappingDescription", kClientName,
    "NewLeaseDuration",          base::itos(kLeaseDuration).c_str());

  if (!action) return false;

  /* DOMString acdoc = ixmlPrintNode((IXML_Node *) action);
  printf("%s\n", acdoc);
  ixmlFreeDOMString(acdoc); */

  bool success = false;

  // a sync call makes it easier to associate the response...
  IXML_Document* response = NULL;
  int res = UpnpSendAction(handle_,
                           service->control_url.c_str(),
                           service->service_type.c_str(),
                           NULL,
                           action,
                           &response);

  if (res == UPNP_E_SUCCESS) {
    if (!mapping->enabled) {
      // callback for new mapping
      OnNewMapping(mapping->external_port, mapping->protocol);
    }
    mapping->enabled = true;
    mapping->last_refresh[service->control_url] = base::get_epoch_time();
    success = true;
    timer_.AddCallLater((kLeaseDuration - kRefreshThreshold) * 1000,
                        boost::bind(
                          &UpnpIgdClientImpl::RefreshPortMappingCallback,
                          this,
                          mapping->external_port,
                          mapping->protocol,
                          service->control_url));
#ifdef DEBUG
    printf("Adding/refreshing UPnP port mapping (%s %d) successfully"
           " completed.\n", protocol.c_str(), mapping->external_port);
#endif
  } else {
    if (!mapping->enabled) {
      // ...if it were enabled and we lost it, we'd call OnLostMapping instead!
      OnFailedMapping(mapping->external_port, mapping->protocol);
    }
#ifdef DEBUG
    printf("Error sending UPnP action AddPortMapping: %s (%d)\n",
           UpnpGetErrorMessage(res), res);
    // TODO(Steve) deal with services only supporting infinite lease
#endif
  }

  if (response)
    ixmlDocument_free(response);
  ixmlDocument_free(action);

  return success;
}

bool UpnpIgdClientImpl::DeletePortMappingFromService(
       const boost::shared_ptr<Service> &service, const PortMapping &mapping) {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  if (!is_registered_ || !is_initialised_)
    return false;

  if (!service->enabled) return false;

  std::string protocol = (mapping.protocol == kUdp ? "UDP" : "TCP");
  std::string ip = GetServerIpAddress();

  IXML_Document *action = UpnpMakeAction("DeletePortMapping",
    service->service_type.c_str(), 3,
    "NewRemoteHost",             "",
    "NewExternalPort",           base::itos(mapping.external_port).c_str(),
    "NewProtocol",               protocol.c_str());

  if (!action) return false;

  /* DOMString acdoc = ixmlPrintNode(reinterpret_cast<IXML_Node *>(action));
  printf("%s\n", acdoc);
  ixmlFreeDOMString(acdoc); */

  bool success = false;
  /* int res = UpnpSendActionAsync(handle_,
                                service->control_url.c_str(),
                                service->service_type.c_str(),
                                NULL,
                                action,
                                (Upnp_FunPtr) &EventCallback,
                                this); */

  // use a sync call to hopefully avoid a deadlock on cleanup
  IXML_Document* response = NULL;
  int res = UpnpSendAction(handle_,
                           service->control_url.c_str(),
                           service->service_type.c_str(),
                           NULL,
                           action,
                           &response);

  if (res == UPNP_E_SUCCESS) {
    success = true;
#ifdef DEBUG
    printf("Successfully deleted UPnP port mapping: %s %d\n",
           protocol.c_str(), mapping.external_port);
#endif
  } else {
#ifdef DEBUG
    printf("Error sending UPnP action DeletePortMapping: %s (%d)\n",
           UpnpGetErrorMessage(res), res);
#endif
  }

  ixmlDocument_free(action);
  return success;
}

void UpnpIgdClientImpl::RefreshPortMappingCallback(
       const int &port, const ProtocolType &protocol,
       const std::string &service_control_url) {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  if (!is_registered_ || !is_initialised_)
    return;

  // check if mapping is still there
  std::list<PortMapping>::iterator it_pm;
  if (!PortMappingExists(port, protocol, it_pm))
    return;

  // check if service is still there
  boost::shared_ptr<Service> service;
  if (GetCachedServiceByControlUrl(service_control_url, service)) {
    // refresh mapping, this will reschedule this callback
    AddPortMappingToService(service, &(*it_pm));
  } else {
    UpdatePortMappings();
  }
}

/* void UpnpIgdClientImpl::RefreshSubscriptionCallback(
       const std::string &subscription_id) {
  boost::recursive_mutex::scoped_lock guard(mutex_);
  if (!is_registered_ || !is_initialised_)
    return;

  // check if service is still there
  boost::shared_ptr<Service> service;
  if (GetCachedServiceBySubscriptionId(subscription_id, service)) {
    // renew service subscription, rescheduling done in callback
    if (!service->subscription_requested) {
      int res = UpnpRenewSubscriptionAsync(
                  handle_,
                  20, // ...
                  const_cast<char*>(service->subscription_id.c_str()),
                  (Upnp_FunPtr) &EventCallback,
                  this);
      if (res == UPNP_E_SUCCESS) {
        service->subscription_requested = true;
      } else {
  #ifdef DEBUG
        printf("Unable to renew subscription to UPnP service: %s (%d)\n",
               UpnpGetErrorMessage(res), res);
  #endif
      }
    }
  } else {
    UpdatePortMappings();
  }
} */

void UpnpIgdClientImpl::SetNewMappingCallback(
       const upnp_callback &new_mapping_callback) {
  new_mapping_callback_ = new_mapping_callback;
}

void UpnpIgdClientImpl::SetLostMappingCallback(
       const upnp_callback &lost_mapping_callback) {
  lost_mapping_callback_ = lost_mapping_callback;
}

void UpnpIgdClientImpl::SetFailedMappingCallback(
       const upnp_callback &failed_mapping_callback) {
  failed_mapping_callback_ = failed_mapping_callback;
}

void UpnpIgdClientImpl::OnNewMapping(const int &port,
                                     const ProtocolType &protocol) {
  if (new_mapping_callback_)
    new_mapping_callback_(port, protocol);
}

void UpnpIgdClientImpl::OnLostMapping(const int &port,
                                      const ProtocolType &protocol) {
  if (lost_mapping_callback_)
    lost_mapping_callback_(port, protocol);
}

void UpnpIgdClientImpl::OnFailedMapping(const int &port,
                                        const ProtocolType &protocol) {
  if (failed_mapping_callback_)
    failed_mapping_callback_(port, protocol);
}

}  // namespace upnp
