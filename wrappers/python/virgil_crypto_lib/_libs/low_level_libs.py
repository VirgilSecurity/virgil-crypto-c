# Copyright (C) 2015-2019 Virgil Security, Inc.
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
import os
import platform


class LowLevelLibs(object):

    SHARED_OBJECT_EXTENSIONS = {
        "Linux": "so",
        "Darwin": "dylib",
        "Windows": "dll"
    }

    LIB_PREFIXES = {
        "Linux": "libvsc",
        "Darwin": "libvsc",
        "Windows": "vsc"
    }

    def __init__(self):
        """Create underlying C context."""
        self.__lib_path = os.path.dirname(os.path.realpath(__file__))
        self.common = CDLL(os.path.join(self.__lib_path, "{0}_common.{1}".format(
            self.LIB_PREFIXES[platform.system()],
            self.SHARED_OBJECT_EXTENSIONS[platform.system()]))
        )

        self.foundation = CDLL(os.path.join(self.__lib_path, "{0}_foundation.{1}").format(
            self.LIB_PREFIXES[platform.system()],
            self.SHARED_OBJECT_EXTENSIONS[platform.system()])
        )

        self.phe = CDLL(os.path.join(self.__lib_path, "{0}_phe.{1}".format(
            self.LIB_PREFIXES[platform.system()],
            self.SHARED_OBJECT_EXTENSIONS[platform.system()]))
        )

        if platform.system() != "Windows":
            self.pythia = CDLL(os.path.join(self.__lib_path, "{0}_pythia.{1}".format(
                self.LIB_PREFIXES[platform.system()],
                self.SHARED_OBJECT_EXTENSIONS[platform.system()]))
            )

        self.ratchet = CDLL(os.path.join(self.__lib_path, "{0}_ratchet.{1}".format(
            self.LIB_PREFIXES[platform.system()],
            self.SHARED_OBJECT_EXTENSIONS[platform.system()]))
        )
