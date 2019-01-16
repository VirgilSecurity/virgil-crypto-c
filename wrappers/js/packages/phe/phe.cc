#include <nan.h>

#include "client.h"
#include "server.h"

void InitAll(v8::Local<v8::Object> exports) {
  Client::Init(exports);
  Server::Init(exports);
}

NODE_MODULE(addon, InitAll)
