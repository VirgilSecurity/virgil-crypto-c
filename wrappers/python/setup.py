from setuptools import setup, find_packages
from virgil_crypto_lib import __version__, __author__

setup(
    name="virgil-crypto-lib",
    version=__version__,
    packages=find_packages(exclude=["doc-source"]),
    package_data={"virgil_crypto_lib": [
        "tests/*",
        "_libs/*"
    ]},
    author=__author__,
    author_email="support@virgilsecurity.com",
    url="https://virgilsecurity.com/",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Security :: Cryptography",
        ],
    license="BSD",
    description="""
    Virgil Crypto Lib v5
    """,
    long_description="""
    Virgil Crypto Lib v5
    """
)
