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


#ifndef MAIDSAFE_BASE_LOG_H_
#define MAIDSAFE_BASE_LOG_H_

  #ifdef HAVE_GLOG
  // For M$VC, we need to include windows.h which in turn includes WinGDI.h
  // which defines ERROR (which conflicts with Glog's ERROR definition)
    #ifdef __MSVC__
      #include <windows.h>
      #undef ERROR
    #endif
    #include <glog/logging.h>
  #else
    #include <iostream>  // NOLINT
    namespace google {
      inline void InitGoogleLogging(char*) {}  // NOLINT
    }  // namespace google

    class LogMessageVoidify {
      public:
    LogMessageVoidify() {}
    void operator &(std::ostream&) {}
    };

    #define LOG(severity) std::cerr
    #ifndef NDEBUG
      #define DLOG(severity) std::cerr
    #else
    #define DLOG(severity) true ? (void) 0 : LogMessageVoidify() & LOG(severity)
    #endif
  #endif

#endif  // MAIDSAFE_BASE_LOG_H_
