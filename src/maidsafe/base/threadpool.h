/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*******************************************************************************
 * NOTE: This header is unlikely to have any breaking changes applied.         *
 *       However, it should not be regarded as finalised until this notice is  *
 *       removed.                                                              *
 ******************************************************************************/

#ifndef MAIDSAFE_BASE_THREADPOOL_H_
#define MAIDSAFE_BASE_THREADPOOL_H_

#include <boost/asio.hpp>
#include <boost/concept_check.hpp>
#include <boost/function.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/thread.hpp>
#include <queue>
#include <vector>

namespace base {

namespace test {
}  // namespace test

class Threadpool {
 public:
  explicit Threadpool(const boost::uint8_t &poolsize);
  ~Threadpool();
  typedef boost::function<void()> VoidFunctor;
  // we may add this method plus the private run now method later
  // template <typename T>
  // AddTask (io_service_.post(
  //    boost::bind( &Threadpool::Run<T>, this, function )
  bool EnqueueTask(const VoidFunctor &functor);
 private:
  //     template <typename T>
  //     void Run(T function) {
  //   An Object
  //       function(Object); // use shared pointer to object to do this properly
  //     }
  // no copy or assign for thread safety (functors)
  Threadpool(const Threadpool&);
  Threadpool &operator=(const Threadpool&);
  boost::asio::io_service io_service_;
  boost::shared_ptr<boost::asio::io_service::work> work_;
  boost::thread_group thread_group_;
};

}  // namespace base

#endif  // MAIDSAFE_BASE_THREADPOOL_H_
