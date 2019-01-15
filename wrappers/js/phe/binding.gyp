{
    "targets": [
        {
            "target_name": "phe",
            "sources": [
                "phe.cc",
                "client.cc",
                "client.h",
                "server.cc",
                "server.h",
                "utils.cc",
                "utils.h"
            ],
            "include_dirs" : [
                "<!(node -e \"require('nan')\")",
                "/usr/local/include"
            ],
            "libraries": [
                "/usr/local/lib/libmbedcrypto.a",
                "/usr/local/lib/libprotobuf-nanopb.a",
                "/usr/local/lib/libvsc_common.a",
                "/usr/local/lib/libvsc_foundation.a",
                "/usr/local/lib/libvsc_phe.a",
                "/usr/local/lib/libvsc_phe_pb.a"
            ]
        }
    ]
}
