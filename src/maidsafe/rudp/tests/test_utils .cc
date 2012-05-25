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

#include "maidsafe/rudp/tests/test_utils.h"

#include<set>

namespace maidsafe {

namespace rudp {

namespace test {

uint16_t GetRandomPort() {
  static std::set<uint16_t> already_used_ports;
  bool unique(false);
  uint16_t port(0);
  do {
    port = (RandomUint32() % 48126) + 1025;
    unique = (already_used_ports.insert(port)).second;
  } while (!unique);
  return port;
}

}  // namespace test

}  // namespace rudp

}  // namespace maidsafe
