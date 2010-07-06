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

Created by Julian Cain on 11/3/09.

*/

#include "maidsafe/base/network_interface.h"
#include "maidsafe/maidsafe-dht_config.h"  // NOLINT (Fraser) - This is needed
                                           // for preprocessor definitions

#if !defined (MAIDSAFE_WIN32)
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <netdb.h>
#endif

namespace base {

bool NetworkInterface::IsLocal(const boost::asio::ip::address & addr) {
  if (addr.is_v6()) {
    return addr.to_v6().is_link_local();
  } else {
    boost::asio::ip::address_v4 a4 = addr.to_v4();

    boost::uint32_t ip = a4.to_ulong();

    return (
        (ip & 0xff000000) == 0x0a000000 ||
        (ip & 0xfff00000) == 0xac100000 ||
        (ip & 0xffff0000) == 0xc0a80000);
  }

  return false;
}

bool NetworkInterface::IsLoopback(const boost::asio::ip::address & addr) {
  if (addr.is_v4()) {
    return addr.to_v4() == boost::asio::ip::address_v4::loopback();
  } else {
    return addr.to_v6() == boost::asio::ip::address_v6::loopback();
  }
}

bool NetworkInterface::IsMulticast(const boost::asio::ip::address & addr) {
  if (addr.is_v4()) {
    return addr.to_v4().is_multicast();
  } else {
    return addr.to_v6().is_multicast();
  }
}

bool NetworkInterface::IsAny(const boost::asio::ip::address & addr) {
  if (addr.is_v4()) {
    return addr.to_v4() == boost::asio::ip::address_v4::any();
  } else {
    /*  Currently only supporting IPv4 as IPv6 has yet to be tested */
    // TODO(Alec): Test system using IPv6 addresses
    return /*addr.to_v6() == boost::asio::ip::address_v6::any()*/true;
  }
}

boost::asio::ip::address NetworkInterface::InaddrToAddress(
    const in_addr * addr) {
  typedef boost::asio::ip::address_v4::bytes_type bytes_t;
  bytes_t b;
  std::memcpy(&b[0], addr, b.size());
  return boost::asio::ip::address_v4(b);
}

boost::asio::ip::address NetworkInterface::Inaddr6ToAddress(
    const in6_addr * addr) {
  typedef boost::asio::ip::address_v6::bytes_type bytes_t;
  bytes_t b;
  std::memcpy(&b[0], addr, b.size());
  return boost::asio::ip::address_v6(b);
}

boost::asio::ip::address NetworkInterface::SockaddrToAddress(
    const sockaddr * addr) {
  if (addr->sa_family == AF_INET) {
    in_addr address = (reinterpret_cast<const sockaddr_in*>(addr))->sin_addr;
    return InaddrToAddress(&address);
  } else if (addr->sa_family == AF_INET6) {
    in6_addr address = (reinterpret_cast<const sockaddr_in6*>(addr))->sin6_addr;
    return Inaddr6ToAddress(&address);
  }
  return boost::asio::ip::address();
}

#if (defined(MAIDSAFE_APPLE) || defined(MAIDSAFE_POSIX) || defined(__MACH__)) \
    && !defined(MAIDSAFE_LINUX)
static bool VerifySockaddr(sockaddr_in * sin) {
  return (sin->sin_len == sizeof(sockaddr_in) && sin->sin_family == AF_INET) ||
         (sin->sin_len == sizeof(sockaddr_in6) && sin->sin_family == AF_INET6);
}
#endif

boost::asio::ip::address NetworkInterface::LocalAddress() {
  boost::system::error_code ec;
  boost::asio::ip::address ret = boost::asio::ip::address_v4::any();

  const std::vector<NetworkInterface> & interfaces = LocalList(ec);

  std::vector<NetworkInterface>::const_iterator it = interfaces.begin();

  for (; it != interfaces.end(); ++it) {
    const boost::asio::ip::address & a = (*it).destination;

    // Skip loopback, multicast and any.
    if (IsLoopback(a)|| IsMulticast(a) || IsAny(a)) {
      continue;
    }

    // :NOTE: Other properties could be checked here such as the IFF_UP flag.

    // Prefer an ipv4 address over v6.
    if (a.is_v4()) {
      ret = a;
      break;
    }

    // If this one is not any then return it.
    if (ret != boost::asio::ip::address_v4::any()) {
      ret = a;
    }
  }

  return ret;
}

std::vector<NetworkInterface> NetworkInterface::LocalList(
    boost::system::error_code & ec) {
  std::vector<NetworkInterface> ret;

#if defined(MAIDSAFE_LINUX) || defined(MAIDSAFE_APPLE) || \
    defined(MAIDSAFE_POSIX) || defined(__MACH__)

  int s = socket(AF_INET, SOCK_DGRAM, 0);

  if (s < 0) {
    ec = boost::asio::error::fault;
    return ret;
  }

  ifconf ifc;
  char buf[1024];

  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;

  if (ioctl(s, SIOCGIFCONF, &ifc) < 0) {
    ec = boost::system::error_code(errno, boost::asio::error::system_category);

    close(s);

    return ret;
  }

  char *ifr = reinterpret_cast<char *>(ifc.ifc_req);

  int remaining = ifc.ifc_len;

  while (remaining) {
    const ifreq & item = *reinterpret_cast<ifreq *>(ifr);

    if (item.ifr_addr.sa_family == AF_INET ||
        item.ifr_addr.sa_family == AF_INET6) {
      NetworkInterface iface;

      iface.destination = SockaddrToAddress(&item.ifr_addr);

//      strcpy(iface.name, item.ifr_name);
      snprintf(iface.name, sizeof(iface.name), "%s", item.ifr_name);

      ifreq netmask = item;

      if (ioctl(s, SIOCGIFNETMASK, &netmask) < 0) {
        if (iface.destination.is_v6()) {
          iface.netmask = boost::asio::ip::address_v6::any();
        } else {
          ec = boost::system::error_code(errno,
                                         boost::asio::error::system_category);

          close(s);

          return ret;
        }
      } else {
        iface.netmask = SockaddrToAddress(&netmask.ifr_addr);
      }
      ret.push_back(iface);
    }

#if !defined(MAIDSAFE_LINUX)
    std::size_t if_size = item.ifr_addr.sa_len + IFNAMSIZ;
#else
    std::size_t if_size = sizeof(ifreq);
#endif
    ifr += if_size;
    remaining -= if_size;
  }

  close(s);

#elif defined(MAIDSAFE_WIN32)

  SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);

  if (static_cast<int>(s) == SOCKET_ERROR) {
    ec = boost::system::error_code(WSAGetLastError(),
                                   boost::asio::error::system_category);

    return ret;
  }

  INTERFACE_INFO buf[30];

  DWORD size;

  int err = WSAIoctl(s, SIO_GET_INTERFACE_LIST, 0, 0, buf, sizeof(buf), &size,
                     0, 0);

  if (err != 0) {
    ec = boost::system::error_code(WSAGetLastError(),
                                   boost::asio::error::system_category);

    closesocket(s);

    return ret;
  }

  closesocket(s);

  std::size_t n = size / sizeof(INTERFACE_INFO);

  NetworkInterface iface;

  for (std::size_t i = 0; i < n; ++i) {
    iface.destination = SockaddrToAddress(&buf[i].iiAddress.Address);

    iface.netmask = SockaddrToAddress(&buf[i].iiNetmask.Address);

    iface.name[0] = 0;

    if (iface.destination == boost::asio::ip::address_v4::any()) {
      continue;
    }
    ret.push_back(iface);
  }
#else
#error "Unsupported Device or Platform."
#endif
  return ret;
}

}  // namespace base
