/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

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
