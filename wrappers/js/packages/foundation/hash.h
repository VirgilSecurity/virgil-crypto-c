#ifndef HASH_H
#define HASH_H

#include <nan.h>
#include <virgil/crypto/foundation/vscf_impl.h>

class Hash : public Nan::ObjectWrap {
public:
  virtual vscf_impl_t* GetImplementation();
};

#endif
