#ifndef UTILS_H
#define UTILS_H

#include <nan.h>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/vsc_data.h>

namespace utils {
  Nan::MaybeLocal<v8::Object> VirgilBufferToNodeBuffer(vsc_buffer_t* buffer);
  vsc_data_t NodeBufferToVirgilData(v8::Local<v8::Value> value);
}

#endif
