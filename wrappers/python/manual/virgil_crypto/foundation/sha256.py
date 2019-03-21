from virgil_crypto.common._c_bridge import Buffer, Data
from virgil_crypto.foundation._c_bridge._vscf_sha256 import VscfSha256, VscfSha256Constants


class SHA256(object):

    def __init__(self):
        self._lib_vscf_sha256 = VscfSha256()
        self._sha = self._lib_vscf_sha256.vscf_sha256_new()
        self.constants = VscfSha256Constants
        self._c_impl = self._lib_vscf_sha256.vscf_sha256_impl(self._sha)

    def __delete__(self, instance):
        self._lib_vscf_sha256.vscf_sha256_delete(self._sha)

    def hash(self, data):
        digest = Buffer(self.constants.DIGEST_LEN)
        d_data = Data(data)
        self._lib_vscf_sha256.vscf_sha256_hash(d_data.data, digest.c_buffer)
        return digest.get_bytes()

    def start(self):
        self._lib_vscf_sha256.vscf_sha256_start(self._sha)

    def update(self, data):
        d_data = Data(data)
        self._lib_vscf_sha256.vscf_sha256_update(self._sha, d_data.data)

    def finish(self):
        digest = Buffer(self.constants.DIGEST_LEN)
        self._lib_vscf_sha256.vscf_sha256_finish(self._sha, digest.c_buffer)
        return digest.get_bytes()
