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

#include "maidsafe/common/test.h"

int main(int argc, char **argv) {
  maidsafe::log::FilterMap filter;
  filter["*"] = maidsafe::log::kVerbose;
  return ExecuteMain(argc, argv, filter, true, maidsafe::log::ColourMode::kFullLine);
}
