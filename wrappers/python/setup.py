# Copyright (C) 2015-2020 Virgil Security, Inc.
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


from setuptools import setup, find_packages
from virgil_crypto_lib import __version__, __author__
from setuptools.dist import Distribution


class BinaryDistribution(Distribution):

    def has_ext_modules(self):
        return True

    def is_pure(self):
        return False


setup(
    name="virgil-crypto-lib",
    version=__version__,
    distclass=BinaryDistribution,
    packages=find_packages(exclude=["doc-source"]),
    package_data={"virgil_crypto_lib": [
        "tests/*",
        "_libs/*"
    ]},
    include_package_data=True,
    zip_safe=False,
    author=__author__,
    author_email="support@virgilsecurity.com",
    url="https://virgilsecurity.com",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Intended Audience :: Developers",
        "Programming Language :: C",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "Topic :: Software Development :: Libraries :: Python Modules"
        ],
    project_urls={
        "Documentation": "https://developer.virgilsecurity.com",
        "Source": "https://github.com/VirgilSecurity/virgil-crypto-c",
        "Tracker": "https://github.com/VirgilSecurity/virgil-crypto-c/issues"
    },
    license="BSD 3-Clause",
    description="""
    This library is designed to be small, flexible and convenient wrapper for a variety crypto algorithms.
    """,
    long_description="""
    This library is designed to be a small, flexible and convenient wrapper for a variety of crypto algorithms. So it can be used in a small microcontroller as well as in a high load server application. Also, it provides several custom hybrid algorithms that combine different crypto algorithms to solve common complex cryptographic problems in an easy way. This eliminates the requirement for developers to have strong cryptographic skills.

    The library is available for different platforms and contains wrappers for other languages.
    """
)
