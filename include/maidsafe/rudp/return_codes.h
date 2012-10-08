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
  kTransportStartFailure = -350008,
  kAlreadyStarted = -350009,
  kInvalidAddress = -350010,
  kEmptyValidationData = -350011,
  kSetOptionFailure = -350012,
  kBindError = -350013,
  kConnectError = -350014,
  kSendFailure = -350015,
  kMessageTooLarge = -350016,
  kPendingResult = -350017,
  kInvalidPublicKey = -350018,
  kPingFailed = -350019,
  kWontPingAlreadyConnected = -350020,
  kWontPingOurself = -350021,
  kConnectAttemptAlreadyRunning = -350022,
  kOwnId = -350023,
  kNoPendingConnectAttempt = -350024,
  kBootstrapUpgradeFailure = -350025,
  kInvalidParameter = -350026,
  kNoBootstrapEndpoints = -350027,
  kFailedToGetLocalAddress = -350028,
  kFailedToEncryptMessage = -350030,

  // Upper limit of values for this enum.
  kReturnCodeLimit = -359999
};

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_RETURN_CODES_H_
