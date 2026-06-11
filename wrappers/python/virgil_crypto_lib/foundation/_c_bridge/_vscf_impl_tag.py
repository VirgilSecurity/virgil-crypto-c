# Copyright (C) 2015-2026 Virgil Security, Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


from ctypes import *
from virgil_crypto_lib.foundation._c_bridge import vscf_aes128_kw_t
from virgil_crypto_lib.foundation._c_bridge import vscf_aes256_cbc_t
from virgil_crypto_lib.foundation._c_bridge import vscf_aes256_gcm_t
from virgil_crypto_lib.foundation._c_bridge import vscf_aes256_kw_t
from virgil_crypto_lib.foundation._c_bridge import vscf_alg_info_der_deserializer_t
from virgil_crypto_lib.foundation._c_bridge import vscf_alg_info_der_serializer_t
from virgil_crypto_lib.foundation._c_bridge import vscf_asn1rd_t
from virgil_crypto_lib.foundation._c_bridge import vscf_asn1wr_t
from virgil_crypto_lib.foundation._c_bridge import vscf_cipher_alg_info_t
from virgil_crypto_lib.foundation._c_bridge import vscf_compound_key_alg_t
from virgil_crypto_lib.foundation._c_bridge import vscf_compound_key_alg_info_t
from virgil_crypto_lib.foundation._c_bridge import vscf_compound_private_key_t
from virgil_crypto_lib.foundation._c_bridge import vscf_compound_public_key_t
from virgil_crypto_lib.foundation._c_bridge import vscf_ctr_drbg_t
from virgil_crypto_lib.foundation._c_bridge import vscf_curve25519_t
from virgil_crypto_lib.foundation._c_bridge import vscf_ecc_t
from virgil_crypto_lib.foundation._c_bridge import vscf_ecc_alg_info_t
from virgil_crypto_lib.foundation._c_bridge import vscf_ecc_private_key_t
from virgil_crypto_lib.foundation._c_bridge import vscf_ecc_public_key_t
from virgil_crypto_lib.foundation._c_bridge import vscf_ed25519_t
from virgil_crypto_lib.foundation._c_bridge import vscf_entropy_accumulator_t
from virgil_crypto_lib.foundation._c_bridge import vscf_fake_random_t
from virgil_crypto_lib.foundation._c_bridge import vscf_falcon_t
from virgil_crypto_lib.foundation._c_bridge import vscf_hash_based_alg_info_t
from virgil_crypto_lib.foundation._c_bridge import vscf_hkdf_t
from virgil_crypto_lib.foundation._c_bridge import vscf_hmac_t
from virgil_crypto_lib.foundation._c_bridge import vscf_hybrid_key_alg_t
from virgil_crypto_lib.foundation._c_bridge import vscf_hybrid_key_alg_info_t
from virgil_crypto_lib.foundation._c_bridge import vscf_hybrid_private_key_t
from virgil_crypto_lib.foundation._c_bridge import vscf_hybrid_public_key_t
from virgil_crypto_lib.foundation._c_bridge import vscf_kdf1_t
from virgil_crypto_lib.foundation._c_bridge import vscf_kdf2_t
from virgil_crypto_lib.foundation._c_bridge import vscf_key_asn1_deserializer_t
from virgil_crypto_lib.foundation._c_bridge import vscf_key_asn1_serializer_t
from virgil_crypto_lib.foundation._c_bridge import vscf_key_material_rng_t
from virgil_crypto_lib.foundation._c_bridge import vscf_message_info_der_serializer_t
from virgil_crypto_lib.foundation._c_bridge import vscf_ml_dsa_t
from virgil_crypto_lib.foundation._c_bridge import vscf_ml_kem_t
from virgil_crypto_lib.foundation._c_bridge import vscf_pbe_alg_info_t
from virgil_crypto_lib.foundation._c_bridge import vscf_pkcs5_pbes2_t
from virgil_crypto_lib.foundation._c_bridge import vscf_pkcs5_pbkdf2_t
from virgil_crypto_lib.foundation._c_bridge import vscf_pkcs8_serializer_t
from virgil_crypto_lib.foundation._c_bridge import vscf_random_padding_t
from virgil_crypto_lib.foundation._c_bridge import vscf_raw_private_key_t
from virgil_crypto_lib.foundation._c_bridge import vscf_raw_public_key_t
from virgil_crypto_lib.foundation._c_bridge import vscf_rsa_t
from virgil_crypto_lib.foundation._c_bridge import vscf_rsa_private_key_t
from virgil_crypto_lib.foundation._c_bridge import vscf_rsa_public_key_t
from virgil_crypto_lib.foundation._c_bridge import vscf_salted_kdf_alg_info_t
from virgil_crypto_lib.foundation._c_bridge import vscf_sec1_serializer_t
from virgil_crypto_lib.foundation._c_bridge import vscf_seed_entropy_source_t
from virgil_crypto_lib.foundation._c_bridge import vscf_sha224_t
from virgil_crypto_lib.foundation._c_bridge import vscf_sha256_t
from virgil_crypto_lib.foundation._c_bridge import vscf_sha384_t
from virgil_crypto_lib.foundation._c_bridge import vscf_sha512_t
from virgil_crypto_lib.foundation._c_bridge import vscf_simple_alg_info_t
from virgil_crypto_lib._libs import LowLevelLibs
from virgil_crypto_lib.foundation._c_bridge import vscf_impl_t


class VscfImplTag(object):
    LL = LowLevelLibs()
    LIB = LL.foundation

    @classmethod
    def get_type(cls, impl):
        VSCF_IMPL_TAG_T = {
            1: ["Aes128Kw", vscf_aes128_kw_t],
            2: ["Aes256Cbc", vscf_aes256_cbc_t],
            3: ["Aes256Gcm", vscf_aes256_gcm_t],
            4: ["Aes256Kw", vscf_aes256_kw_t],
            5: ["AlgInfoDerDeserializer", vscf_alg_info_der_deserializer_t],
            6: ["AlgInfoDerSerializer", vscf_alg_info_der_serializer_t],
            7: ["Asn1rd", vscf_asn1rd_t],
            8: ["Asn1wr", vscf_asn1wr_t],
            9: ["CipherAlgInfo", vscf_cipher_alg_info_t],
            10: ["CompoundKeyAlg", vscf_compound_key_alg_t],
            11: ["CompoundKeyAlgInfo", vscf_compound_key_alg_info_t],
            12: ["CompoundPrivateKey", vscf_compound_private_key_t],
            13: ["CompoundPublicKey", vscf_compound_public_key_t],
            14: ["CtrDrbg", vscf_ctr_drbg_t],
            15: ["Curve25519", vscf_curve25519_t],
            16: ["Ecc", vscf_ecc_t],
            17: ["EccAlgInfo", vscf_ecc_alg_info_t],
            18: ["EccPrivateKey", vscf_ecc_private_key_t],
            19: ["EccPublicKey", vscf_ecc_public_key_t],
            20: ["Ed25519", vscf_ed25519_t],
            21: ["EntropyAccumulator", vscf_entropy_accumulator_t],
            22: ["FakeRandom", vscf_fake_random_t],
            23: ["Falcon", vscf_falcon_t],
            24: ["HashBasedAlgInfo", vscf_hash_based_alg_info_t],
            25: ["Hkdf", vscf_hkdf_t],
            26: ["Hmac", vscf_hmac_t],
            27: ["HybridKeyAlg", vscf_hybrid_key_alg_t],
            28: ["HybridKeyAlgInfo", vscf_hybrid_key_alg_info_t],
            29: ["HybridPrivateKey", vscf_hybrid_private_key_t],
            30: ["HybridPublicKey", vscf_hybrid_public_key_t],
            31: ["Kdf1", vscf_kdf1_t],
            32: ["Kdf2", vscf_kdf2_t],
            33: ["KeyAsn1Deserializer", vscf_key_asn1_deserializer_t],
            34: ["KeyAsn1Serializer", vscf_key_asn1_serializer_t],
            35: ["KeyMaterialRng", vscf_key_material_rng_t],
            36: ["MessageInfoDerSerializer", vscf_message_info_der_serializer_t],
            37: ["MlDsa", vscf_ml_dsa_t],
            38: ["MlKem", vscf_ml_kem_t],
            39: ["PbeAlgInfo", vscf_pbe_alg_info_t],
            40: ["Pkcs5Pbes2", vscf_pkcs5_pbes2_t],
            41: ["Pkcs5Pbkdf2", vscf_pkcs5_pbkdf2_t],
            42: ["Pkcs8Serializer", vscf_pkcs8_serializer_t],
            43: ["RandomPadding", vscf_random_padding_t],
            44: ["RawPrivateKey", vscf_raw_private_key_t],
            45: ["RawPublicKey", vscf_raw_public_key_t],
            46: ["Rsa", vscf_rsa_t],
            47: ["RsaPrivateKey", vscf_rsa_private_key_t],
            48: ["RsaPublicKey", vscf_rsa_public_key_t],
            49: ["SaltedKdfAlgInfo", vscf_salted_kdf_alg_info_t],
            50: ["Sec1Serializer", vscf_sec1_serializer_t],
            51: ["SeedEntropySource", vscf_seed_entropy_source_t],
            52: ["Sha224", vscf_sha224_t],
            53: ["Sha256", vscf_sha256_t],
            54: ["Sha384", vscf_sha384_t],
            55: ["Sha512", vscf_sha512_t],
            56: ["SimpleAlgInfo", vscf_simple_alg_info_t]
        }
        tag = cls.vscf_impl_tag(impl)

        mod = __import__("virgil_crypto_lib.foundation", fromlist=[VSCF_IMPL_TAG_T[tag][0]])
        klass = getattr(mod, VSCF_IMPL_TAG_T[tag][0])
        return klass, VSCF_IMPL_TAG_T[tag][1]

    @classmethod
    def vscf_impl_tag(cls, impl):
        vscf_impl_tag = cls.LIB.vscf_impl_tag
        vscf_impl_tag.argtypes = [POINTER(vscf_impl_t)]
        vscf_impl_tag.restype = c_int
        return vscf_impl_tag(impl)
