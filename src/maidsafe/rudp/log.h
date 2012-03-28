/*******************************************************************************
 *  Copyright 2011 maidsafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 */

#ifndef MAIDSAFE_TRANSPORT_LOG_H_
#define MAIDSAFE_TRANSPORT_LOG_H_

#include "maidsafe/common/log.h"

#undef LOG
#define LOG(severity) MAIDSAFE_LOG(transport, severity)

#endif  // MAIDSAFE_TRANSPORT_LOG_H_

