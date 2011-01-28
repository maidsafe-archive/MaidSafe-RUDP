/*****************************************************************************
Copyright (c) 2001 - 2009, The Board of Trustees of the University of Illinois.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above
  copyright notice, this list of conditions and the
  following disclaimer.

* Redistributions in binary form must reproduce the
  above copyright notice, this list of conditions
  and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the University of Illinois
  nor the names of its contributors may be used to
  endorse or promote products derived from this
  software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/

/*****************************************************************************
written by
   Yunhong Gu, last updated 05/05/2009
*****************************************************************************/

#ifdef WIN32
   #include <winsock2.h>
   #include <ws2tcpip.h>
   #ifdef LEGACY_WIN32
      #include <wspiapi.h>
   #endif
#endif

#include <cstring>
#include "cache.h"
#include "core.h"

using namespace std;

bool CIPComp::operator()(const CInfoBlock* ib1, const CInfoBlock* ib2) const
{
   if (ib1->m_iIPversion != ib2->m_iIPversion)
      return (ib1->m_iIPversion < ib2->m_iIPversion);
   else if (ib1->m_iIPversion == AF_INET)
      return (ib1->m_piIP[0] > ib2->m_piIP[0]);
   else
   {
      for (int i = 0; i < 4; ++ i)
      {
         if (ib1->m_piIP[i] != ib2->m_piIP[i])
            return (ib1->m_piIP[i] > ib2->m_piIP[i]);
      }
      return false;
   }
}

bool CTSComp::operator()(const CInfoBlock* ib1, const CInfoBlock* ib2) const
{
   return (ib1->m_ullTimeStamp > ib2->m_ullTimeStamp);
}

CCache::CCache():
m_uiSize(1024),
m_sIPIndex(),
m_sTSIndex(),
m_Lock()
{
   #ifndef WIN32
      pthread_mutex_init(&m_Lock, NULL);
   #else
      m_Lock = CreateMutex(NULL, false, NULL);
   #endif
}

CCache::CCache(const unsigned int& size):
m_uiSize(size),
m_sIPIndex(),
m_sTSIndex(),
m_Lock()
{
   #ifndef WIN32
      pthread_mutex_init(&m_Lock, NULL);
   #else
      m_Lock = CreateMutex(NULL, false, NULL);
   #endif
}

CCache::~CCache()
{
   for (set<CInfoBlock*, CTSComp>::iterator i = m_sTSIndex.begin(); i != m_sTSIndex.end(); ++ i)
      delete *i;

   #ifndef WIN32
      pthread_mutex_destroy(&m_Lock);
   #else
      CloseHandle(m_Lock);
   #endif
}

void CCache::update(const sockaddr* addr, const int& ver, CInfoBlock* ib)
{
   CGuard cacheguard(m_Lock);

   CInfoBlock* newib = new CInfoBlock;
   convert(addr, ver, newib->m_piIP);
   newib->m_iIPversion = ver;

   set<CInfoBlock*, CIPComp>::iterator i = m_sIPIndex.find(newib);

   if (i != m_sIPIndex.end())
   {
      m_sTSIndex.erase(*i);
      delete *i;
      m_sIPIndex.erase(i);
   }

   newib->m_iRTT = ib->m_iRTT;
   newib->m_iBandwidth = ib->m_iBandwidth;
   newib->m_ullTimeStamp = CTimer::getTime();

   m_sIPIndex.insert(newib);
   m_sTSIndex.insert(newib);

   if (m_sTSIndex.size() > m_uiSize)
   {
      CInfoBlock* tmp = *m_sTSIndex.begin();
      m_sIPIndex.erase(tmp);
      m_sTSIndex.erase(m_sTSIndex.begin());
      delete tmp;
   }
}

int CCache::lookup(const sockaddr* addr, const int& ver, CInfoBlock* ib)
{
   CGuard cacheguard(m_Lock);

   convert(addr, ver, ib->m_piIP);
   ib->m_iIPversion = ver;

   set<CInfoBlock*, CIPComp>::iterator i = m_sIPIndex.find(ib);

   if (i == m_sIPIndex.end())
      return -1;

   ib->m_ullTimeStamp = (*i)->m_ullTimeStamp;
   ib->m_iRTT = (*i)->m_iRTT;
   ib->m_iBandwidth = (*i)->m_iBandwidth;

   return 1;
}

void CCache::convert(const sockaddr* addr, const int& ver, uint32_t* ip)
{
   if (ver == AF_INET)
   {
      ip[0] = ((sockaddr_in*)addr)->sin_addr.s_addr;
      ip[1] = ip[2] = ip[3] = 0;
   }
   else
   {
      memcpy((char*)ip, (char*)((sockaddr_in6*)addr)->sin6_addr.s6_addr, 16);
   }
}
