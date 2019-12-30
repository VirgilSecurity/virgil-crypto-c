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
from abc import *


class Padding(object):
    """Provide an interface to add and remove data padding."""
    __metaclass__ = ABCMeta

    @abstractmethod
    def configure(self, params):
        """Set new padding parameters."""
        raise NotImplementedError()

    @abstractmethod
    def padded_data_len(self, data_len):
        """Return length in bytes of a data with a padding."""
        raise NotImplementedError()

    @abstractmethod
    def __len__(self):
        """Return an actual number of padding in bytes.
        Note, this method might be called right before "finish data processing"."""
        raise NotImplementedError()

    @abstractmethod
    def len_max(self):
        """Return a maximum number of padding in bytes."""
        raise NotImplementedError()

    @abstractmethod
    def start_data_processing(self):
        """Prepare the algorithm to process data."""
        raise NotImplementedError()

    @abstractmethod
    def process_data(self, data):
        """Only data length is needed to produce padding later.
        Return data that should be further proceeded."""
        raise NotImplementedError()

    @abstractmethod
    def finish_data_processing(self):
        """Accomplish data processing and return padding."""
        raise NotImplementedError()

    @abstractmethod
    def start_padded_data_processing(self):
        """Prepare the algorithm to process padded data."""
        raise NotImplementedError()

    @abstractmethod
    def process_padded_data(self, data):
        """Process padded data.
        Return filtered data without padding."""
        raise NotImplementedError()

    @abstractmethod
    def finish_padded_data_processing_out_len(self):
        """Return length in bytes required hold output of the method
        "finish padded data processing"."""
        raise NotImplementedError()

    @abstractmethod
    def finish_padded_data_processing(self):
        """Accomplish padded data processing and return left data without a padding."""
        raise NotImplementedError()
