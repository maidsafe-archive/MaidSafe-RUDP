#ifndef _MAIDSFAFE_TEST_GET_WITHIN_H_
#define _MAIDSFAFE_TEST_GET_WITHIN_H_

#include <chrono>
#include <future>

namespace maidsafe {

// Wait for the future to finish within the duration time or throw exception.
template<class FutureT>
auto get_within(FutureT&& future, std::chrono::steady_clock::duration duration)
    -> decltype(future.get())
{
  if (future.wait_for(duration) == std::future_status::ready) {
    return future.get();
  } else {
    throw std::system_error(asio::error::timed_out);
  }
}

} // maidsafe namespace

#endif // ifndef _MAIDSFAFE_TEST_GET_WITHIN_H_
