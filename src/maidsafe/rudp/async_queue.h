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

#ifndef MAIDSAFE_RUDP_ASYNC_QUEUE_H_
#define MAIDSAFE_RUDP_ASYNC_QUEUE_H_

#include <mutex>
#include <queue>
#include "asio/async_result.hpp"

namespace maidsafe {

namespace __detail {
  namespace helper {
    template <int... Is>
    struct index {};

    template <int N, int... Is>
    struct gen_seq : gen_seq<N - 1, N - 1, Is...> {};

    template <int... Is>
    struct gen_seq<0, Is...> : index<Is...> {};
  }

  template <class F, typename... Args, int... Is>
  inline constexpr auto
  apply_tuple(F&& f, const std::tuple<Args...>& tup, helper::index<Is...>)
    -> decltype(f(std::get<Is>(tup)...)) {
    return f(std::get<Is>(tup)...);
  }

  template <class F, typename... Args>
  inline constexpr auto
  apply_tuple(F&& f, const std::tuple<Args...>& tup)
    -> decltype(apply_tuple(f, tup, helper::gen_seq<sizeof...(Args)>{})) {
    return apply_tuple( std::forward<F>(f), tup
                      , helper::gen_seq<sizeof...(Args)>{});
  }
}  // namespace __detail

template<class... Args> class async_queue {
  using handler_type = std::function<void(Args...)>;
  using tuple_type   = std::tuple<Args...>;

 public:
  template<class... Params>
  void push(Params&&... args) {
    handler_type handler;

    {
      std::lock_guard<std::mutex> lock(mutex);

      if (handlers.empty()) {
        return values.emplace(std::forward<Params>(args)...);
      }

      handler = std::move(handlers.front());
      handlers.pop();
    }

    handler(std::forward<Params>(args)...);
  }

  template <typename CompletionToken>
  typename asio::async_result
            <typename asio::handler_type
              < typename std::decay<CompletionToken>::type
              , void(Args...)>::type
            >::type
  async_pop(CompletionToken&& token) {
    using HT = typename asio::handler_type
                 < typename std::decay<CompletionToken>::type
                 , void(Args...)
                 >::type;

    HT handler = std::forward<decltype(token)>(token);

    asio::async_result<HT> result(handler);

    tuple_type tuple;

    {
      std::lock_guard<std::mutex> lock(mutex);

      if (values.empty()) {
        handlers.emplace(std::move(handler));
        return result.get();
      }

      tuple = std::move(values.front());
      values.pop();
    }

    __detail::apply_tuple(std::move(handler), tuple);

    return result.get();
  }

 private:
  std::mutex               mutex;
  std::queue<handler_type> handlers;
  std::queue<tuple_type>   values;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_ASYNC_QUEUE_H_
