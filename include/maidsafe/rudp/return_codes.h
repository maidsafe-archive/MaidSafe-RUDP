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
  kInvalidEndpoint = -350005,
  kConnectionAlreadyExists = -350006,
  kTransportStartFailure = -350007,
  kAlreadyStarted = -350008,
  kInvalidAddress = -350009,
  kEmptyValidationData = -350010,
  kSetOptionFailure = -350011,
  kBindError = -350012,
  kConnectError = -350013,
  kSendFailure = -350014,
  kMessageTooLarge = -350015,
  kPendingResult = -350016,
  kInvalidPublicKey = -350017,
  kPingFailed = -350018,
  kWontPingAlreadyConnected = -350019,
  kWontPingOurself = -350020,

  // Upper limit of values for this enum.
  kReturnCodeLimit = -359999
};

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_RETURN_CODES_H_
