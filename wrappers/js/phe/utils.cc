#include "utils.h"

Nan::MaybeLocal<v8::Object> utils::GetNodeBuffer(vsc_buffer_t* buffer) {
  size_t capacity = vsc_buffer_capacity(buffer);
  char* data = new char[capacity];
  std::memcpy(data, vsc_buffer_bytes(buffer), capacity);
  return Nan::NewBuffer(data, capacity);
}

vsc_data_t utils::NodeBufferToVirgilData(v8::Local<v8::Value> value) {
  return vsc_data_from_str(node::Buffer::Data(value), node::Buffer::Length(value));
}
