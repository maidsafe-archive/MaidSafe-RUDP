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

/*******************************************************************************
 * NOTE: This header should not be regarded as finalised until this notice is  *
 *       removed.                                                              *
 ******************************************************************************/

#ifndef MAIDSAFE_TRANSPORT_TRANSPORTCONDITIONS_H_
#define MAIDSAFE_TRANSPORT_TRANSPORTCONDITIONS_H_

namespace transport {

// TODO revise error code list
enum TransportCondition {
  kSuccess = 0,
  kError = -1,
  kRemoteUnreachable = -2,
  kNoConnection = -3,
  kNoNetwork = -4,
  kInvalidIP = -5,
  kInvalidPort = -6,
  kInvalidData = -7,
  kNoSocket = -8,
  kInvalidAddress = -9,
  kNoRendezvous = -10,
  kBehindFirewall = -11,
  kBindError = -12,
  kConnectError = -13,
  kAlreadyStarted = -14,
  kListenError = -15,
  kThreadResourceError = -16,
  kCloseSocketError = -17,
  kSendFailure = -18,
  kSendTimeout = -19,
  kSendStalled = -20,
  kSendParseFailure = -21,
  kSendSizeFailure = -22,
  kReceiveFailure = -23,
  kReceiveTimeout = -24,
  kReceiveStalled = -25,
  kReceiveParseFailure = -26,
  kReceiveSizeFailure = -27,
  kAddManagedEndpointError = -28,
  kAddManagedEndpointTimeout = -29,
  kSetOptionFailure = -30,
  kMessageSizeTooLarge = -31
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORTCONDITIONS_H_
