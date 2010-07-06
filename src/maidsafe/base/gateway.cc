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

#include "maidsafe/base/gateway.h"

#if (defined(MAIDSAFE_APPLE) || defined(MAIDSAFE_POSIX) || defined(__MACH__)) \
    && !defined(MAIDSAFE_LINUX)
#include <net/route.h>
#include <sys/sysctl.h>
#include <boost/scoped_ptr.hpp>
#elif defined(MAIDSAFE_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif  // WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iphlpapi.h>
#elif defined(MAIDSAFE_LINUX)
#include <asm/types.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <boost/bind.hpp>

namespace base {

boost::asio::ip::address Gateway::DefaultRoute(
    boost::asio::io_service & ios,
    boost::system::error_code & ec) {
  std::vector<NetworkInterface> ret = Routes(ios, ec);
#if defined(MAIDSAFE_WIN32)
  std::vector<NetworkInterface>::iterator it = std::find_if(
      ret.begin(),
      ret.end(),
      boost::bind(
          &NetworkInterface::IsLoopback,
          boost::bind(&NetworkInterface::destination, _1)));
#else
  std::vector<NetworkInterface>::iterator it = std::find_if(
      ret.begin(),
      ret.end(),
      boost::bind(
          &NetworkInterface::destination, _1) == boost::asio::ip::address());
#endif
  if (it == ret.end()) {
        return boost::asio::ip::address();
  }
  return it->gateway;
}

#if (defined(MAIDSAFE_APPLE) || defined(MAIDSAFE_POSIX) || defined(__MACH__)) \
    && !defined(MAIDSAFE_LINUX)

inline int32_t RoundUp(int32_t val) {
  return ((val) > 0 ? (1 + (((val) - 1) | (sizeof(int32_t) - 1))) :
      sizeof(int32_t));
}

bool Gateway::ParseRtMsghdr(rt_msghdr * rtm, NetworkInterface & rt_if) {
  sockaddr * rti_info[RTAX_MAX];
  sockaddr * sa = reinterpret_cast<sockaddr*>(rtm + 1);

  for (unsigned int i = 0; i < RTAX_MAX; ++i) {
    if ((rtm->rtm_addrs & (1 << i)) == 0) {
      rti_info[i] = 0;
      continue;
    }

    rti_info[i] = sa;

    sa = reinterpret_cast<sockaddr*>(reinterpret_cast<char *>(sa) +
        RoundUp(sa->sa_len));
  }

  sa = rti_info[RTAX_GATEWAY];

  if (sa == 0 || rti_info[RTAX_DST] == 0 || rti_info[RTAX_NETMASK] == 0 ||
      (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)) {
    return false;
  }

  rt_if.gateway = NetworkInterface::SockaddrToAddress(rti_info[RTAX_GATEWAY]);

  rt_if.netmask = NetworkInterface::SockaddrToAddress(rti_info[RTAX_NETMASK]);

  rt_if.destination = NetworkInterface::SockaddrToAddress(rti_info[RTAX_DST]);

  if_indextoname(rtm->rtm_index, rt_if.name);

  return true;
}

#elif defined(MAIDSAFE_LINUX)

int Gateway::ReadNetlinkSock(int sock, char * buf, int len, int seq, int pid) {
  nlmsghdr * nl_hdr;

  int msg_len = 0;

  do {
    int read_len = recv(sock, buf, len - msg_len, 0);

    if (read_len < 0) {
      return -1;
    }

    nl_hdr = reinterpret_cast<nlmsghdr *>(buf);

    if ((NLMSG_OK(nl_hdr, static_cast<boost::uint32_t>(read_len)) == 0) ||
        (nl_hdr->nlmsg_type == NLMSG_ERROR)) {
      return -1;
    }

    if (nl_hdr->nlmsg_type == NLMSG_DONE) {
      break;
    }

    buf += read_len;

    msg_len += read_len;

    if ((nl_hdr->nlmsg_flags & NLM_F_MULTI) == 0) {
      break;
    }
  } while ((nl_hdr->nlmsg_seq != boost::uint32_t(seq)) ||
           (nl_hdr->nlmsg_pid != boost::uint32_t(pid)));

  return msg_len;
}

bool Gateway::ParseNlmsghdr(nlmsghdr * nl_hdr, NetworkInterface & rt_if) {
  rtmsg * rt_msg = reinterpret_cast<rtmsg *>(NLMSG_DATA(nl_hdr));

  if ((rt_msg->rtm_family != AF_INET) || (rt_msg->rtm_table != RT_TABLE_MAIN)) {
    return false;
  }

  int rt_len = RTM_PAYLOAD(nl_hdr);

  rtattr * rt_attr = reinterpret_cast<rtattr *>(RTM_RTA(rt_msg));

  for (; RTA_OK(rt_attr, rt_len); rt_attr = RTA_NEXT(rt_attr, rt_len)) {
    switch (rt_attr->rta_type) {
      case RTA_OIF:
        if_indextoname(*reinterpret_cast<int*>(RTA_DATA(rt_attr)), rt_if.name);
        break;
      case RTA_GATEWAY:
        rt_if.gateway = boost::asio::ip::address_v4(
            ntohl(*reinterpret_cast<u_int*>(RTA_DATA(rt_attr))));
        break;
      case RTA_DST:
        rt_if.destination = boost::asio::ip::address_v4(
            ntohl(*reinterpret_cast<u_int*>(RTA_DATA(rt_attr))));
        break;
    }
  }
  return true;
}

#endif

std::vector<NetworkInterface> Gateway::Routes(boost::asio::io_service&,
                                              boost::system::error_code &ec) {
  std::vector<NetworkInterface> ret;

#if (defined(MAIDSAFE_APPLE) || defined(MAIDSAFE_POSIX) || defined(__MACH__)) \
    && !defined(MAIDSAFE_LINUX)

  int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_UNSPEC, NET_RT_DUMP, 0 };

  std::size_t needed = 0;

  if (sysctl(mib, 6, 0, &needed, 0, 0) < 0) {
    ec = boost::system::error_code(errno, boost::asio::error::system_category);
    return std::vector<NetworkInterface>();
  }

  if (needed <= 0) {
    return std::vector<NetworkInterface>();
  }

  boost::scoped_ptr<char> buf(new char[needed]);

  if (sysctl(mib, 6, buf.get(), &needed, 0, 0) < 0) {
    ec = boost::system::error_code(errno, boost::asio::error::system_category);
    return std::vector<NetworkInterface>();
  }

  char * end = buf.get() + needed;

  rt_msghdr * rtm;

  for (char * next = buf.get(); next < end; next += rtm->rtm_msglen) {
    rtm = reinterpret_cast<rt_msghdr *>(next);

    if (rtm->rtm_version != RTM_VERSION) {
      continue;
    }

    NetworkInterface r;

    if (ParseRtMsghdr(rtm, r)) {
      ret.push_back(r);
    }
  }

#elif defined(MAIDSAFE_WIN32)

  HMODULE iphlp = LoadLibraryA("Iphlpapi.dll");

  if (!iphlp) {
    ec = boost::asio::error::operation_not_supported;
    return std::vector<NetworkInterface>();
  }

  typedef DWORD(WINAPI *GetAdaptersInfo_t)(PIP_ADAPTER_INFO, PULONG);

  GetAdaptersInfo_t GetAdaptersInfo =
      (GetAdaptersInfo_t)GetProcAddress(iphlp, "GetAdaptersInfo");

  if (!GetAdaptersInfo) {
    FreeLibrary(iphlp);
    ec = boost::asio::error::operation_not_supported;
    return std::vector<NetworkInterface>();
  }

  PIP_ADAPTER_INFO adapter_info = 0;

  ULONG out_buf_size = 0;

  if (GetAdaptersInfo(adapter_info, &out_buf_size) != ERROR_BUFFER_OVERFLOW) {
    FreeLibrary(iphlp);
    ec = boost::asio::error::operation_not_supported;
    return std::vector<NetworkInterface>();
  }

  adapter_info = new IP_ADAPTER_INFO[out_buf_size];

  if (GetAdaptersInfo(adapter_info, &out_buf_size) == NO_ERROR) {
    for (PIP_ADAPTER_INFO adapter = adapter_info; adapter != 0;
        adapter = adapter->Next) {
      NetworkInterface r;

      r.destination = boost::asio::ip::address::from_string(
          adapter->IpAddressList.IpAddress.String,
          ec);

      r.gateway =  boost::asio::ip::address::from_string(
          adapter->GatewayList.IpAddress.String,
          ec);

      r.netmask =  boost::asio::ip::address::from_string(
          adapter->IpAddressList.IpMask.String,
          ec);

      strncpy(r.name, adapter->AdapterName, sizeof(r.name));

      if (ec) {
        ec = boost::system::error_code();
        continue;
      }
      ret.push_back(r);
    }
  }

  delete adapter_info, adapter_info = 0;
  FreeLibrary(iphlp);

#elif defined(MAIDSAFE_LINUX)

  enum { kBufSize = 8192 };

  int sock = socket(PF_ROUTE, SOCK_DGRAM, NETLINK_ROUTE);

  if (sock < 0) {
    ec = boost::system::error_code(errno, boost::asio::error::system_category);
    return std::vector<NetworkInterface>();
  }

  int seq = 0;

  char msg[kBufSize];

  std::memset(msg, 0, kBufSize);

  nlmsghdr * nl_msg = reinterpret_cast<nlmsghdr*>(msg);

  nl_msg->nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
  nl_msg->nlmsg_type = RTM_GETROUTE;
  nl_msg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
  nl_msg->nlmsg_seq = seq++;
  nl_msg->nlmsg_pid = getpid();

  if (send(sock, nl_msg, nl_msg->nlmsg_len, 0) < 0) {
    ec = boost::system::error_code(errno, boost::asio::error::system_category);

    close(sock);

    return std::vector<NetworkInterface>();
  }

  int len = ReadNetlinkSock(sock, msg, kBufSize, seq, getpid());

  if (len < 0) {
    ec = boost::system::error_code(errno, boost::asio::error::system_category);

    close(sock);

    return std::vector<NetworkInterface>();
  }

  for (; NLMSG_OK(nl_msg, static_cast<boost::uint32_t>(len));
       nl_msg = NLMSG_NEXT(nl_msg, len)) {
    NetworkInterface intf;

    if (ParseNlmsghdr(nl_msg, intf)) {
      ret.push_back(intf);
    }
  }
  close(sock);

#endif
  return ret;
}

}  // namespace base
