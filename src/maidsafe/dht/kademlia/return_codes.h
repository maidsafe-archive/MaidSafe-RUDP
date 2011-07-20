/* Copyright (c) 2011 maidsafe.net limited
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

#ifndef MAIDSAFE_DHT_KADEMLIA_RETURN_CODES_H_
#define MAIDSAFE_DHT_KADEMLIA_RETURN_CODES_H_

#include "maidsafe/dht/version.h"

#if MAIDSAFE_DHT_VERSION != 3002
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-dht library.
#endif


namespace maidsafe {
namespace dht {
namespace kademlia {

enum ReturnCode {
  // General
  kSuccess = 0,
  kGeneralError = -300001,
  kUndefined = -300002,
  kPendingResult = -300003,
  kFailedSignatureCheck = -300004,
  kInvalidPointer = -300005,
  kTimedOut = -300006,

  // DataStore
  kEmptyKey = -301001,
  kZeroTTL = -301002,
  kFailedToInsertKeyValue = -301003,
  kFailedToModifyKeyValue = -301004,
  kMarkedForDeletion = -301005,

  // RoutingTable
  kOwnIdNotIncludable = -302001,
  kFailedToUpdateLastSeenTime = -302002,
  kNotInBrotherBucket = -302003,
  kOutwithClosest = -302004,
  kFailedToInsertNewContact = -302005,
  kFailedToFindContact = -302006,
  kFailedToSetPublicKey = -302007,
  kFailedToUpdateRankInfo = -302008,
  kFailedToSetPreferredEndpoint = -302009,
  kFailedToIncrementFailedRpcCount = -302010,

  // Node
  kNoOnlineBootstrapContacts = -303001,
  kNotListening = -303002,
  kFindNodesFailed = -303003,
  kFoundTooFewNodes = -303004,
  kStoreTooFewNodes = -303005,
  kDeleteTooFewNodes = -303006,
  kUpdateTooFewNodes = -303007,
  kFailedToGetContact = -303008,
  kIterativeLookupFailed = -303009,
  kContactFailedToRespond = -303010,
  kValueAlreadyExists = -303011
};

}  // namespace kademlia
}  // namespace dht
}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_RETURN_CODES_H_
