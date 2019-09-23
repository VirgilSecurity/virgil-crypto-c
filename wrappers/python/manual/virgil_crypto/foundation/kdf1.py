from virgil_crypto.common._c_bridge import Data, Buffer
from virgil_crypto.foundation._c_bridge._vscf_kdf1 import VscfKdf1


class Kdf1(object):

    def __init__(self, hash_alg):
        self._lib_vscf_kdf1 = VscfKdf1()
        self._kdf1 = self._lib_vscf_kdf1.vscf_kdf1_new()
        self.set_hash(hash_alg)

    def __delete__(self, instance):
        self._lib_vscf_kdf1.vscf_kdf1_delete(self._kdf1)

    def set_hash(self, hash_alg):
        self._lib_vscf_kdf1.vscf_kdf1_use_hash(self._kdf1, hash_alg._c_impl)

    def derive(self, data, key_len):
        d_data = Data(data)
        key = Buffer(key_len)
        self._lib_vscf_kdf1.vscf_kdf1_derive(self._kdf1, d_data.data, key_len, key.c_buffer)
        return key.get_bytes()
