#include "utils.h"

Nan::MaybeLocal<v8::Object> utils::VirgilBufferToNodeBuffer(vsc_buffer_t* buffer) {
  size_t buffer_len = vsc_buffer_len(buffer);
  char* data = new char[buffer_len];
  std::memcpy(data, vsc_buffer_bytes(buffer), buffer_len);
  return Nan::NewBuffer(data, buffer_len);
}

vsc_data_t utils::NodeBufferToVirgilData(v8::Local<v8::Value> value) {
  return vsc_data_from_str(node::Buffer::Data(value), node::Buffer::Length(value));
}
