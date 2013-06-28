/* Copyright 2013 MaidSafe.net limited

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

/*
* @file  rudp_node.cc
* @brief Runs Rudp Node.
* @date  2013-02-26
*/

#include <signal.h>
#include "boost/filesystem.hpp"
#include "boost/program_options.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/tests/rudp_node_impl.h"

namespace bptime = boost::posix_time;
namespace fs = boost::filesystem;
namespace po = boost::program_options;
namespace ma = maidsafe::asymm;

struct PortRange {
  PortRange(uint16_t first, uint16_t second)
      : first(first), second(second) {}
  uint16_t first;
  uint16_t second;
};

namespace {

// This function is needed to avoid use of po::bool_switch causing MSVC warning C4505:
// 'boost::program_options::typed_value<bool>::name' : unreferenced local function has been removed.
#ifdef MAIDSAFE_WIN32
void UseUnreferenced() {
  auto dummy = po::typed_value<bool>(nullptr);
  (void)dummy;
}
#endif

// volatile bool ctrlc_pressed(false);
// reported unused (dirvine)
// void CtrlCHandler(int /*a*/) {
//   ctrlc_pressed = true;
// }

}  // unnamed namespace

fs::path GetPathFromProgramOption(const std::string &option_name,
                                  po::variables_map *variables_map,
                                  bool is_dir,
                                  bool create_new_if_absent) {
  fs::path option_path;
  if (variables_map->count(option_name))
    option_path = variables_map->at(option_name).as<std::string>();
  if (option_path.empty())
    return fs::path();

  boost::system::error_code ec;
  if (!fs::exists(option_path, ec) || ec) {
    if (!create_new_if_absent) {
      LOG(kError) << "GetPathFromProgramOption - Invalid " << option_name << ", " << option_path
                  << " doesn't exist or can't be accessed (" << ec.message() << ")";
      return fs::path();
    }

    if (is_dir) {  // Create new dir
      fs::create_directories(option_path, ec);
      if (ec) {
        LOG(kError) << "GetPathFromProgramOption - Unable to create new dir " << option_path << " ("
                    << ec.message() << ")";
        return fs::path();
      }
    } else {  // Create new file
      if (option_path.has_filename()) {
        try {
          std::ofstream ofs(option_path.c_str());
        }
        catch(const std::exception &e) {
          LOG(kError) << "GetPathFromProgramOption - Exception while creating new file: "
                      << e.what();
          return fs::path();
        }
      }
    }
  }

  if (is_dir) {
    if (!fs::is_directory(option_path, ec) || ec) {
      LOG(kError) << "GetPathFromProgramOption - Invalid " << option_name << ", " << option_path
                  << " is not a directory (" << ec.message() << ")";
      return fs::path();
    }
  } else {
    if (!fs::is_regular_file(option_path, ec) || ec) {
      LOG(kError) << "GetPathFromProgramOption - Invalid " << option_name << ", " << option_path
                  << " is not a regular file (" << ec.message() << ")";
      return fs::path();
    }
  }

  LOG(kInfo) << "GetPathFromProgramOption - " << option_name << " is " << option_path;
  return option_path;
}

int main(int argc, char **argv) {
  maidsafe::log::Logging::Instance().Initialise(argc, argv);

  try {
    int peer_identity_index, identity_index;
    boost::system::error_code error_code;
    po::options_description options_description("Options");
    options_description.add_options()
        ("help,h", "Print options.")
        ("identity_index,i", po::value<int>(&identity_index)->default_value(-1),
            "Entry from keys file to use as ID (starts from 0)")
        ("peer_identity_index,r", po::value<int>(&peer_identity_index)->default_value(-1),
            "Entry from keys file to use as ID (starts from 0)")
        ("peer,p", po::value<std::string>()->default_value(""), "Endpoint of bootstrap peer")
        ("pmids_path",
            po::value<std::string>()->default_value(
                fs::path(fs::temp_directory_path(error_code) / "pmids_list.dat").string()),
            "Path to pmid file");

    po::variables_map variables_map;
//     po::store(po::parse_command_line(argc, argv, options_description),
//               variables_map);
    po::store(po::command_line_parser(argc, argv).options(options_description).allow_unregistered().
                                                  run(), variables_map);
    po::notify(variables_map);

    if (variables_map.count("help")) {
      std::cout << options_description << std::endl;
      return 0;
    }

    // Load fob list
    std::vector<maidsafe::passport::Pmid> all_pmids;
    boost::filesystem::path pmids_path(GetPathFromProgramOption(
        "pmids_path", &variables_map, false, true));
    if (fs::exists(pmids_path, error_code)) {
      all_pmids = maidsafe::passport::detail::ReadPmidList(pmids_path);
      std::cout << "Loaded " << all_pmids.size() << " fobs." << std::endl;
      if (static_cast<uint32_t>(identity_index) >= all_pmids.size() || identity_index < 0) {
        std::cout << "ERROR : index exceeds fob pool -- pool has "
                  << all_pmids.size() << " fobs, while identity_index is "
                  << identity_index << std::endl;
        return 0;
      }
      if (static_cast<uint32_t>(peer_identity_index) >= all_pmids.size() ||
          peer_identity_index < 0) {
        std::cout << "ERROR : index exceeds fob pool -- pool has "
                  << all_pmids.size() << " fobs, while peer_identity_index is "
                  << peer_identity_index << std::endl;
        return 0;
      }
    }

    std::string peer(variables_map.at("peer").as<std::string>());
    maidsafe::rudp::test::RudpNode rudp_node(all_pmids, identity_index,
                                             peer_identity_index, peer);
    rudp_node.Run();
    std::cout << "Node stopped successfully." << std::endl;
  }
  catch(const std::exception &e) {
    std::cout << "Error: " << e.what() << std::endl;
    return -1;
  }
  return 0;
}
