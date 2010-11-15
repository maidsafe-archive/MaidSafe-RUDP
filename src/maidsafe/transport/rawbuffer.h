/* Copyright (c) 2010 maidsafe.net limited
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

#ifndef MAIDSAFE_TRANSPORT_RAWBUFFER_H_
# define MAIDSAFE_TRANSPORT_RAWBUFFER_H_

# include <memory>

namespace transport {

class RawBuffer {
public:
  RawBuffer() : storage_(0),
                max_size_(0),
                size_(0) {}

  ~RawBuffer() {
    ::operator delete(storage_);
  }

  char* Allocate(std::size_t bytes) {
    if (!storage_ || bytes > max_size_) {
      ::operator delete(storage_);
      storage_ = ::operator new(bytes);
      max_size_ = bytes;
    }
    size_ = bytes;
    return (char*)storage_;
  }

  std::size_t Size() const {
    return size_;
  }

  char* Data() {
    return (char*)storage_;
  }

private:
  RawBuffer(const RawBuffer&);
  RawBuffer& operator=(const RawBuffer&);

  void* storage_;
  std::size_t max_size_;
  std::size_t size_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_RAWBUFFER_H_
