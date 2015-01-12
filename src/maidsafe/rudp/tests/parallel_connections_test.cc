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


#include <type_traits>
#include <atomic>
#include <chrono>
#include <future>
#include <functional>
#include <limits>
#include <vector>
#include <sstream>

#include "asio/use_future.hpp"
#include "maidsafe/rudp/managed_connections.h"
#include "maidsafe/rudp/tests/histogram.h"

#ifndef WIN32
extern "C" char** environ;
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4127)  // conditional expression is constant
#pragma warning(disable : 4267)  // conversion of size_t to int (Boost.Process bug)
#pragma warning(disable : 4702)  // unreachable code
#endif
#include "boost/process.hpp"
#include "boost/iostreams/stream.hpp"
#ifdef _MSC_VER
#pragma warning(pop)
#endif
#ifndef WIN32
#include "boost/asio/posix/stream_descriptor.hpp"
#endif

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/error.h"
#include "maidsafe/common/make_unique.h"

#include "maidsafe/rudp/core/multiplexer.h"
#include "maidsafe/rudp/core/session.h"
#include "maidsafe/rudp/core/socket.h"
#include "maidsafe/rudp/tests/test_utils.h"
#include "maidsafe/rudp/tests/get_within.h"
#include "maidsafe/rudp/return_codes.h"
#include "maidsafe/rudp/connection_manager.h"
#include "maidsafe/rudp/transport.h"
#include "maidsafe/rudp/utils.h"

#define ASSERT_THROW_CODE(expr, CODE) \
  try { expr; GTEST_FAIL() << "Expected to throw"; } \
  catch (std::system_error e) { ASSERT_EQ(e.code(), CODE) << "Exception: " << e.what(); }

namespace args = std::placeholders;
namespace Asio = boost::asio;
namespace bptime = boost::posix_time;
namespace ip = asio::ip;
using minutes      = std::chrono::minutes;
using seconds      = std::chrono::seconds;
using milliseconds = std::chrono::milliseconds;

namespace maidsafe {

namespace rudp {

namespace test {

class ParallelConnectionsTest : public testing::Test {
 public:
  ParallelConnectionsTest()
      : node_(999),
        nodes_(),
// FIXME: Explain why we do this apple stuff?
#ifndef MAIDSAFE_APPLE
        bootstrap_endpoints_()
  { }
#else
        bootstrap_endpoints_(),
        rlimit_() {
    SetNumberOfOpenFiles(2048);
  }
#endif

  ~ParallelConnectionsTest() {
#ifdef MAIDSAFE_APPLE
    setrlimit(RLIMIT_NOFILE, &rlimit_);
#endif
  }

 protected:
  Node node_;
  std::vector<NodePtr> nodes_;
  std::vector<Contact> bootstrap_endpoints_;

#ifdef MAIDSAFE_APPLE
  struct rlimit rlimit_;

  void SetNumberOfOpenFiles(unsigned int open_files) {
    getrlimit(RLIMIT_NOFILE, &rlimit_);
    if (rlimit_.rlim_cur >= open_files)
      return;

    struct rlimit limit;
    limit.rlim_cur = open_files;
    limit.rlim_max = open_files;
    setrlimit(RLIMIT_NOFILE, &limit);
  }
#endif
};

// Unfortunately disabled on Windows as ASIO and NT refuses to work well with anonymous pipe handles
// (think win32 exception throws in the kernel, you are about right)
#ifdef WIN32
struct input_watcher {
  typedef HANDLE native_handle_type;
};
#else
struct input_watcher {
  Asio::io_service& _service;
  Asio::posix::stream_descriptor _h;

 public:
  typedef Asio::posix::stream_descriptor::native_handle_type native_handle_type;

 private:
  Asio::deadline_timer _timer;
  std::unique_ptr<Asio::io_service::work> _work;
  void _init(bool doTimer) {
    _h.async_read_some(Asio::null_buffers(),
                       std::bind(&input_watcher::data_available, this, std::placeholders::_1));
    if (doTimer) {
      _timer.async_wait(std::bind(&input_watcher::timed_out, this, std::placeholders::_1));
    }
  }

 protected:
  virtual void data_available(const boost::system::error_code&) = 0;
  virtual void timed_out(const boost::system::error_code&) { cancel(); };
  input_watcher(Asio::io_service& service, native_handle_type h)
      : _service(service),
        _h(service, h),
        _timer(service),
        _work(maidsafe::make_unique<Asio::io_service::work>(service)) {
    _init(false);
  }
  input_watcher(Asio::io_service& service, native_handle_type h, boost::posix_time::ptime timeout)
      : _service(service),
        _h(service, h),
        _timer(service, timeout),
        _work(maidsafe::make_unique<Asio::io_service::work>(service)) {
    _init(true);
  }
  input_watcher(Asio::io_service& service, native_handle_type h,
                boost::posix_time::time_duration timeout)
      : _service(service),
        _h(service, h),
        _timer(service, timeout),
        _work(maidsafe::make_unique<Asio::io_service::work>(service)) {
    _init(true);
  }

 public:
  ~input_watcher() { _h.release(); }
  Asio::io_service& service() { return _service; }
  native_handle_type handle() { return _h.native(); }
  Asio::deadline_timer& timer() { return _timer; }
  void cancel() {
    _h.cancel();
    _timer.cancel();
    _work.reset();
  }
};
#endif
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4706)  // assignment within conditional expression
#endif

using sstream = std::stringstream;

template<class T>
static std::string to_string(const std::vector<T>& v) {
  return std::string(v.begin(), v.end());
}

// Poor man's LL parser.
static char parse_one_of(sstream& ss, std::string allowed) {
  sstream::int_type result = ss.peek();

  if (result == sstream::traits_type::eof()) {
    throw std::runtime_error("expected one of \"" + allowed + "\" got eof");
  }

  if (allowed.find(result) == std::string::npos) {
    throw std::runtime_error("expected one of \"" + allowed + "\" got " +
                             static_cast<char>(result));
  }

  ss.get();

  return result;
}

template<class P>
static std::vector<typename std::result_of<P(sstream&)>::type>
parse_kleene(sstream& ss, const P& p) {
  std::vector<typename std::result_of<P(sstream&)>::type> result;

  try {
    while (true) { result.push_back(p(ss)); }
  } catch(...) {}

  return result;
}

static std::vector<char> parse_hex(sstream& ss) {
  return parse_kleene(ss, [&](sstream& ss)
                             { return parse_one_of(ss, "0123456789abcdefABCDEF"); });
}

static uint16_t parse_port(sstream& ss) {
  auto chars = parse_kleene(ss, [&](sstream& ss) { return parse_one_of(ss, "0123456789"); });
  return atoi(to_string(chars).c_str());
}

static asio::ip::address parse_address(sstream& ss) {
  auto parser = [&](sstream& ss) { return parse_one_of(ss, "0123456789."); };
  return asio::ip::address::from_string(to_string(parse_kleene(ss, parser)));
}

static NodeId parse_node_id(sstream& ss) {
  return NodeId(HexDecode(to_string(parse_hex(ss))));
}

static asymm::PublicKey parse_public_key(sstream& ss) {
  auto decoded = HexDecode(to_string(parse_hex(ss)));
  return Parse<asymm::PublicKey>(std::vector<unsigned char>(decoded.begin(), decoded.end()));
}

static asio::ip::udp::endpoint parse_endpoint(sstream& ss) {
  auto addr = parse_address(ss);
  parse_one_of(ss, ":");
  auto port = parse_port(ss);
  return asio::ip::udp::endpoint(addr, port);
}

static Contact parse_contact(sstream& ss) {
  auto node_id  = parse_node_id(ss);
  parse_one_of(ss, ":");
  auto endpoint = parse_endpoint(ss);
  parse_one_of(ss, ":");
  auto public_key = parse_public_key(ss);
  return Contact(node_id, endpoint, public_key);
}

static std::string serialize(const asio::ip::udp::endpoint& e) {
  return e.address().to_string() + ":" + std::to_string(e.port());
}

static std::string serialize(const NodeId& id) {
  return HexEncode(id.string());
}

static std::string serialize(const asymm::PublicKey& key) {
  return HexEncode(to_string(Serialise(key)));
}

static std::string serialize(const Contact& c) {
  auto node_id     = serialize(c.id);
  auto endpoint    = serialize(c.endpoint_pair.local);
  auto public_key  = serialize(c.public_key);
  auto contact_str = node_id + ":" + endpoint + ":" + public_key + ";";
  return contact_str;
}

static std::string serialize(const EndpointPair& eps) {
  return serialize(eps.local) + "," + serialize(eps.external);
}

static EndpointPair parse_endpoint_pair(sstream& ss) {
  auto local = parse_endpoint(ss);
  parse_one_of(ss, ",");
  auto external = parse_endpoint(ss);
  return EndpointPair(local, external);
}

static std::vector<Contact> parse_contacts(sstream& ss) {
  return parse_kleene(ss, [&](sstream& ss) {
      auto contact = parse_contact(ss);
      parse_one_of(ss, ";");
      return contact;
      });
}


TEST_F(ParallelConnectionsTest, FUNC_API_500ParallelConnectionsWorker) {
  const char* endpoints = std::getenv("MAIDSAFE_RUDP_PARALLEL_CONNECTIONS_BOOTSTRAP_ENDPOINTS");
  if (!endpoints) { return; }

  try {
    std::stringstream ss(endpoints);
    bootstrap_endpoints_ = parse_contacts(ss);
  } catch (const std::exception& e) {
    GTEST_FAIL() << "Problem parsing contacts: " << e.what();
  }

  std::string line;
  do {
    if (!std::getline(std::cin, line)) {
      std::cout << "ERROR: Couldn't read from parent so exiting." << std::endl;
      abort();
    }
  } while (line.compare(0, 8, "NODE_ID:"));
  if (line[line.size() - 1] == 13)
    line.resize(line.size() - 1);
  const size_t my_id = atoi(line.substr(9).c_str());
  Node node(static_cast<int>(my_id));

  std::cout << "NODE_ID: " << serialize(node.node_id()) << ","
                           << serialize(node.public_key()) << std::endl;

  NodeId peer_node_id;
  Contact chosen_node;
  ASSERT_NO_THROW(chosen_node = get_within(node.Bootstrap(bootstrap_endpoints_), seconds(30)));

  std::atomic<bool> sender_thread_done(false);
  std::mutex lock;
  std::vector<NodeId> peer_node_ids;
  size_t peer_node_ids_idx = 0, messages_sent = 0;
  std::thread sender_thread([&] {
    static std::string bleh(1500, 'n');
    while (!sender_thread_done) {
      // FIXME: Why sleep?
      std::this_thread::sleep_for(milliseconds(20));
      std::lock_guard<decltype(lock)> g(lock);
      if (peer_node_ids_idx < peer_node_ids.size()) {
        try {
          get_within(node.Send(peer_node_ids[peer_node_ids_idx], bleh), minutes(10));
        } catch (const std::exception& e) {
          GTEST_FAIL() << "Failed sending: " << e.what();
        }
        ++messages_sent;
      }
      if (++peer_node_ids_idx >= peer_node_ids.size())
        peer_node_ids_idx = 0;
    }
  });

  try {
    for (;;) {
      if (!std::getline(std::cin, line)) {
        std::cout << "ERROR: Couldn't read from parent due to state=" << std::cin.rdstate()
                  << " so exiting." << std::endl;
        abort();
      }
      if (line[line.size() - 1] == 13)
        line.resize(line.size() - 1);
      if (!line.compare("QUIT"))
        break;
      if (!line.compare(0, 13, "ENDPOINT_FOR:")) {
        NodeId peer_node_id(line.substr(14), NodeId::EncodingType::kHex);

        EndpointPair empty_endpoint_pair, this_endpoint_pair;

        ASSERT_NO_THROW(this_endpoint_pair
            = get_within(node.GetAvailableEndpoints(peer_node_id), seconds(10)));

        std::cout << "ENDPOINT: " << serialize(this_endpoint_pair) << std::endl;
      } else if (!line.compare(0, 8, "CONNECT:")) {
        std::stringstream ss(line.substr(9));
        Contact peer_contact;
        ASSERT_NO_THROW(peer_contact = parse_contact(ss));
        get_within(node.Add(peer_contact), minutes(1));
        std::cout << "CONNECTED: " << serialize(peer_contact.id) << std::endl;
        std::lock_guard<decltype(lock)> g(lock);
        peer_node_ids.push_back(peer_contact.id);
      } else if (!line.compare(0, 5, "STATS")) {
        std::lock_guard<decltype(lock)> g(lock);
        std::cout << "STATS: " << messages_sent << std::endl;
      }
    }
  } catch (const std::exception& e) {
    std::cout << "ERROR: Saw exception '" << e.what() << "' so exiting." << std::endl;
  }
  sender_thread_done = true;
  sender_thread.join();
}

TEST_F(ParallelConnectionsTest, FUNC_API_500ParallelConnections) {
  size_t node_count = 23, messages_sent_count = 100000;
  const char* node_count_env = std::getenv("MAIDSAFE_RUDP_TEST_PARALLEL_CONNECTIONS_NODE_COUNT");
  if (node_count_env)
    node_count = atoi(node_count_env);
  const char* messages_sent_count_env =
      std::getenv("MAIDSAFE_RUDP_TEST_PARALLEL_CONNECTIONS_MESSAGE_COUNT");
  if (messages_sent_count_env)
    messages_sent_count = atoi(messages_sent_count_env);
  const auto self_path = ThisExecutablePath();
  typedef boost::filesystem::path::string_type native_string;
  const std::vector<native_string> args{
      self_path.native(),
#ifdef WIN32
      L"--gtest_filter=ParallelConnectionsTest.FUNC_API_500ParallelConnectionsWorker"
#else
      "--gtest_filter=ParallelConnectionsTest.FUNC_API_500ParallelConnectionsWorker"
#endif
  };

  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));
#ifdef WIN32
  native_string endpoints(
      L"MAIDSAFE_RUDP_PARALLEL_CONNECTIONS_BOOTSTRAP_ENDPOINTS=");
#else
  native_string endpoints(
      "MAIDSAFE_RUDP_PARALLEL_CONNECTIONS_BOOTSTRAP_ENDPOINTS=");
#endif
  for (auto& i : bootstrap_endpoints_) {
    auto contact = serialize(i);
    endpoints.append(native_string(contact.begin(), contact.end()));
  }
  std::vector<native_string> env{endpoints};
// Boost.Process won't inherit environment at the same time as do custom env,
// so manually propagate our current environment into the custom environment.
// Failure to propagate environment causes child processes to fail due to CryptoPP
// refusing to initialise.
#ifdef WIN32
  for (const TCHAR* e = GetEnvironmentStrings(); *e; e++) {
    env.push_back(e);
    while (*e != 0)
      e++;
  }
#else
  for (char** e = environ; *e; ++e)
    env.push_back(*e);
#endif
  auto getline = [](std::istream & is, input_watcher::native_handle_type h, std::string & str)
      -> std::istream & {
#ifdef WIN32
    // Unfortunately Win32 anonymous pipe handles are a very special not-entirely-working
    // form of HANDLE, indeed I personally never ever use them as named pipe handles work
    // better, albeit not without their quirks/bugs either.
    //
    // So here I'm simply going to wait on the handle with timeout. I've wasted two days on
    // debugging this already, sometimes the easy hack way is better than the right way ...
    str.clear();
    for (;;) {
      char c;
      if (is.rdbuf()->in_avail()) {
        is.get(c);
      } else {
        if (WAIT_TIMEOUT == WaitForSingleObject(h, 30000)) {
          is.setstate(std::ios::badbit);
          return is;
        }
        is.get(c);
      }
      if (c == 10)
        break;
      else
        str.push_back(c);
    }
#else
    Asio::io_service service;
    str.clear();
    for (;;) {
      char c;
      if (is.rdbuf()->in_avail()) {
        is.get(c);
      } else {
        // Wait no more than ten seconds for something to turn up
        struct watcher : input_watcher {
          bool have_data;
          watcher(Asio::io_service& service, input_watcher::native_handle_type h)
              : input_watcher(service, h, boost::posix_time::seconds(30)), have_data(false) {}
          virtual void data_available(const boost::system::error_code& ec) {
            if (!ec)
              have_data = true;
            cancel();
          }
        } w(service, h);
        service.run();
        if (!w.have_data) {
          is.setstate(std::ios::badbit);
          return is;
        }
        is.get(c);
      }
      if (c == 10)
        break;
      else
        str.push_back(c);
    }
#endif
    if (str[str.size() - 1] == 13)
      str.resize(str.size() - 1);
    return is;
  };

  std::vector<boost::process::child> children;
  // Try to make sure that we don't ever leave zombie child processes around
  struct child_deleter {
    void operator()(boost::iostreams::stream<boost::iostreams::file_descriptor_sink>* c) const {
      *c << "QUIT" << std::endl;
      delete c;
    }
  };
  std::vector<
      std::pair<std::unique_ptr<boost::iostreams::stream<boost::iostreams::file_descriptor_source>>,
                std::unique_ptr<boost::iostreams::stream<boost::iostreams::file_descriptor_sink>,
                                child_deleter>>> childpipes;
  children.reserve(node_count);
  childpipes.reserve(node_count);
  try {
    for (size_t n = 0; n < node_count; n++) {
      boost::system::error_code ec;
      auto childin = boost::process::create_pipe(), childout = boost::process::create_pipe();
      boost::iostreams::file_descriptor_sink sink(childin.sink, boost::iostreams::close_handle);
      boost::iostreams::file_descriptor_source source(childout.source,
                                                      boost::iostreams::close_handle);
      children.push_back(boost::process::execute(boost::process::initializers::run_exe(self_path),
                                                 boost::process::initializers::set_args(args),
                                                 boost::process::initializers::set_env(env),
                                                 boost::process::initializers::bind_stdin(source),
                                                 boost::process::initializers::bind_stdout(sink),
                                                 boost::process::initializers::set_on_error(ec)));
      if (ec) {
        GTEST_FAIL() << "Failed to launch child " << n << " due to error code " << ec << ".";
        return;
      }
      childpipes.push_back(std::make_pair(
          maidsafe::make_unique<boost::iostreams::stream<boost::iostreams::file_descriptor_source>>(
              childin.source, boost::iostreams::never_close_handle),
          std::unique_ptr<boost::iostreams::stream<boost::iostreams::file_descriptor_sink>,
                          child_deleter>(
              new boost::iostreams::stream<boost::iostreams::file_descriptor_sink>(
                  childout.sink,
                  boost::iostreams::never_close_handle))  // libstdc++ hasn't implemented the custom
                                                          // deleter implicit conversions for some
                                                          // weird reason
          ));                                             // NOLINT (Niall)
      *childpipes.back().second << "NODE_ID: " << n << std::endl;
    }
    // Prepare to connect node_count nodes to one another, making node_count*(node_count-1) total
    // connections
    std::vector<std::pair<size_t, size_t>> execution_order;
    std::vector<NodeId> child_nodeids;
    std::vector<asymm::PublicKey> child_nodekeys;
    child_nodeids.reserve(node_count);
    child_nodekeys.reserve(node_count);
    for (size_t n = 0; n < node_count; n++) {
      boost::iostreams::stream<boost::iostreams::file_descriptor_source>& is = *childpipes[n].first;
      for (;;) {
        std::string line;
        // ASIO gets upset if the pipe isn't opened on the other side, so use getline for this round
        if (!std::getline(is, line)) {
          GTEST_FAIL() << "Failed to read from child " << n << ".";
          return;
        }
        if (line[line.size() - 1] == 13)
          line.resize(line.size() - 1);
        if (!line.compare(0, 6, "ERROR:")) {
          GTEST_FAIL() << "Failed to launch child " << n << " due to " << line << ".";
          return;
        }
        if (!line.compare(0, 8, "NODE_ID:")) {
          std::stringstream ss(line.substr(9));
          child_nodeids.push_back(parse_node_id(ss));
          parse_one_of(ss, ",");
          child_nodekeys.push_back(parse_public_key(ss));
          break;
        } else if (line[0] != '[' && !strstr(line.c_str(), "Google Test filter")) {
          std::cout << "Child " << n << " sends me unknown line '" << line << "'" << std::endl;
        }
      }
      for (size_t i = 0; i < n; i++) {
        execution_order.push_back(std::make_pair(n, i));
      }
    }
    // child_nodeids[n] contains a map of child processes to NodeId
    // child_endpoints[n][i*2] is the endpoint of childprocess n to childprocess i
    // child_endpoints[n][i*2+1] is the endpoint of childprocess i to childprocess n
    std::vector<std::vector<EndpointPair>> child_endpoints;
    child_endpoints.resize(node_count);
    for (auto& i : child_endpoints)
      i.resize((node_count - 1) * 2);
    // We need execution order to maximise distance between each x,x and y,y in each (x,y) pair
    // such that concurrency is maximised. That is the CPU instruction scheduling problem which
    // requires the solution of an unbalanced graph via iterating rebalancing according to longest
    // path analysis, and it has O(N!) complexity with a non-trivial implementation. So here is a
    // poorer quality O(N^2) complexity alternative with a much simpler implementation. It doesn't
    // produce perfect ordering, but it's close enough and doesn't require more code than the whole
    // of this test case.
    {
      std::deque<std::pair<size_t, size_t>> list(std::make_move_iterator(execution_order.begin()),
                                                 std::make_move_iterator(execution_order.end())),
          prevline, line;
      execution_order.clear();
      std::reverse(list.begin(), list.end());
      do {
        prevline = std::move(line);
        // Choose a starting value as far away as possible from any collision in the previous line
        if (prevline.empty()) {
          line.push_back(std::move(list.back()));
          list.pop_back();
        } else {
          do {
            prevline.pop_front();
            for (auto it = list.begin(); it != list.end(); ++it) {
              bool bad = false;
              for (auto& b : prevline) {
                if (it->first == b.first || it->second == b.first || it->first == b.second ||
                    it->second == b.second) {
                  bad = true;
                  break;
                }
              }
              if (!bad) {
                line.push_back(std::move(*it));
                list.erase(it);
                break;
              }
            }
          } while (line.empty());
        }
        // Append all values not colliding into this line
        for (auto it = list.begin(); it != list.end();) {
          bool bad = false;
          for (auto& b : line) {
            if (it->first == b.first || it->second == b.first || it->first == b.second ||
                it->second == b.second) {
              bad = true;
              break;
            }
          }
          if (!bad) {
            line.push_back(std::move(*it));
            it = list.erase(it);
          } else {
            ++it;
          }
        }
        // Copy line into output
        execution_order.insert(execution_order.end(), line.begin(), line.end());
      } while (!list.empty());
    }
    // std::cout << "Execution order will be: ";
    // for (auto& o : execution_order)
    //   std::cout << "[" << o.first << ", " << o.second << "], ";
    // std::cout << std::endl;
    size_t connection_count = 0;
    for (auto& o : execution_order) {
      EndpointPair endpoint;
      size_t n, i;
      std::tie(n, i) = o;
      boost::iostreams::stream<boost::iostreams::file_descriptor_sink>& os1 = *childpipes[n].second;
      boost::iostreams::stream<boost::iostreams::file_descriptor_sink>& os2 = *childpipes[i].second;
      os1 << "ENDPOINT_FOR: " << child_nodeids[i].ToStringEncoded(NodeId::EncodingType::kHex)
          << std::endl;
      os2 << "ENDPOINT_FOR: " << child_nodeids[n].ToStringEncoded(NodeId::EncodingType::kHex)
          << std::endl;
      // std::cout << "Asking child " << n << " for endpoint to child " << i << std::endl;
      // std::cout << "Asking child " << i << " for endpoint to child " << n << std::endl;
      auto drain_endpoint = [&](size_t a) {
        boost::iostreams::stream<boost::iostreams::file_descriptor_source>& is =
            *childpipes[a].first;
        // std::cout << "drain_endpoint(" << a << ")" << std::endl;
        for (;;) {
          std::string line;
          if (!getline(is, is->handle(), line)) {
            return false;
          }
          if (!line.compare(0, 9, "ENDPOINT:")) {
            try {
              std::stringstream ss(line.substr(10));
              endpoint = parse_endpoint_pair(ss);
            } catch (const std::exception& e) {
              std::cerr << "ERROR: Couldn't parse " << line << " so exiting: " << e.what();
              return false;
            }
            return true;
          } else if (line[0] != '[') {
            std::cout << "Child " << a << " sends me unknown line '" << line << "'\n";
          }
        }
      };
      if (!drain_endpoint(n)) {
        GTEST_FAIL() << "Failed to read from child " << n << ".";
        return;
      }
      child_endpoints[n][i * 2] = endpoint;
      if (!drain_endpoint(i)) {
        GTEST_FAIL() << "Failed to read from child " << i << ".";
        return;
      }
      child_endpoints[n][i * 2 + 1] = endpoint;

      Contact c1(child_nodeids[i], child_endpoints[n][i*2+1], child_nodekeys[i]);
      Contact c2(child_nodeids[n], child_endpoints[n][i*2],   child_nodekeys[n]);
      os1 << "CONNECT: " << serialize(c1) << std::endl;
      os2 << "CONNECT: " << serialize(c2) << std::endl;

      auto drain_connect = [&](size_t a) {
        boost::iostreams::stream<boost::iostreams::file_descriptor_source>& is =
            *childpipes[a].first;
        for (;;) {
          std::string line;
          if (!getline(is, is->handle(), line)) {
            return false;
          }
          if (!line.compare(0, 10, "CONNECTED:")) {
            // std::cout << "Child " << a << " is connected to " << line.substr(11) << std::endl;
            ++connection_count;
            return true;
          } else if (line[0] != '[') {
            std::cout << "Child " << a << " sends me unknown line '" << line << "'" << std::endl;
          }
        }
      };
      if (!drain_connect(n)) {
        GTEST_FAIL() << "Failed to read from child " << n << ".";
        return;
      }
      if (!drain_connect(i)) {
        GTEST_FAIL() << "Failed to read from child " << i << ".";
        return;
      }
    }

    std::cout << node_count << " nodes connected with " << connection_count << " connections."
              << std::endl;

    size_t messages_sent = 0;
    do {
      std::this_thread::sleep_for(std::chrono::seconds(5));
      for (auto& childpipe : childpipes) {
        boost::iostreams::stream<boost::iostreams::file_descriptor_sink>& os = *childpipe.second;
        os << "STATS" << std::endl;
      }
      messages_sent = 0;
      size_t n = 0;

      for (auto& childpipe : childpipes) {
        boost::iostreams::stream<boost::iostreams::file_descriptor_source>& is = *childpipe.first;
        for (;;) {
          std::string line;
          if (!getline(is, is->handle(), line)) {
            GTEST_FAIL() << "Failed to read from child " << n << ".";
            return;
          }
          if (!line.compare(0, 6, "STATS:")) {
            messages_sent += atoi(line.substr(7).c_str());
            break;
          } else if (line[0] != '[') {
            std::cout << "Child " << n << " sends me unknown line '" << line << "'" << std::endl;
          }
        }
        ++n;
      }
      std::cout << "Children have now sent " << messages_sent << " messages." << std::endl;
    } while (messages_sent < messages_sent_count);
  } catch (const std::exception& e) {
    GTEST_FAIL() << "Exception thrown '" << e.what() << "'.";
  }

  // Shutdown children
  childpipes.clear();
  for (size_t n = 0; n < node_count; n++) {
    boost::system::error_code ec;
    // std::cout << "Waiting for child " << n << " to exit" << std::endl;
    boost::process::wait_for_exit(children[n], ec);
  }
}
#ifdef _MSC_VER
#pragma warning(pop)
#endif

}  // namespace test

}  // namespace rudp

}  // namespace maidsafe
