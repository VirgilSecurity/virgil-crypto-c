{
    "targets": [
        {
            "target_name": "foundation",
            "sources": [
                "foundation.cc",
                "hash.h",
                "kdf.h",
                "kdf1.cc",
                "kdf1.h",
                "sha256.cc",
                "sha256.h",
                "utils.cc",
                "utils.h"
            ],
            "include_dirs" : [
                "<!(node -e \"require('nan')\")",
                "/usr/local/include"
            ],
            "libraries": [
                "/usr/local/lib/libmbedcrypto.a",
                "/usr/local/lib/libvsc_common.a",
                "/usr/local/lib/libvsc_foundation.a"
            ]
        }
    ]
}
