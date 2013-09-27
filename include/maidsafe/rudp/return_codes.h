/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_RUDP_RETURN_CODES_H_
#define MAIDSAFE_RUDP_RETURN_CODES_H_

namespace maidsafe {

namespace rudp {

enum ReturnCode {
  kSuccess = 0,
  kNotBootstrapped = -350000,
  kFull = -350001,
  kNullParameter = -350002,
  kInvalidTransport = -350003,
  kInvalidConnection = -350004,
  kNotConnectable = -350005,
  kInvalidEndpoint = -350006,
  kConnectionAlreadyExists = -350007,
  kBootstrapConnectionAlreadyExists = -350008,
  kUnvalidatedConnectionAlreadyExists = -350009,
  kTransportStartFailure = -350010,
  kAlreadyStarted = -350011,
  kInvalidAddress = -350012,
  kEmptyValidationData = -350013,
  kSetOptionFailure = -350014,
  kBindError = -350015,
  kConnectError = -350016,
  kSendFailure = -350017,
  kMessageTooLarge = -350018,
  kPendingResult = -350019,
  kInvalidPublicKey = -350020,
  kPingFailed = -350021,
  kWontPingAlreadyConnected = -350022,
  kWontPingOurself = -350023,
  kConnectAttemptAlreadyRunning = -350024,
  kOwnId = -350025,
  kNoPendingConnectAttempt = -350026,
  kBootstrapUpgradeFailure = -350027,
  kInvalidParameter = -350028,
  kNoBootstrapEndpoints = -350029,
  kFailedToGetLocalAddress = -350030,
  kConnectionClosed = -350031,
  kFailedToEncryptMessage = -350032,

  // Upper limit of values for this enum.
  kReturnCodeLimit = -359999
};

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_RETURN_CODES_H_
