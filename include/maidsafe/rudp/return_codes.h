/*******************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of MaidSafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the licence   *
 *  file licence.txt found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of MaidSafe.net. *
 ******************************************************************************/

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
