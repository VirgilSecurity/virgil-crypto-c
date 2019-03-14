{
    "targets": [
        {
            "target_name": "foundation",
            "sources": [
                "index.cc"
            ],
            "include_dirs" : [
                "<!(node -e \"require('nan')\")"
            ],
            "libraries": []
        },
        {
            "target_name": "phe",
            "sources": [
                "index.cc"
            ],
            "include_dirs" : [
                "<!(node -e \"require('nan')\")"
            ],
            "libraries": []
        },
        {
            "target_name": "pythia",
            "sources": [
                "index.cc"
            ],
            "include_dirs" : [
                "<!(node -e \"require('nan')\")"
            ],
            "libraries": []
        },
        {
            "target_name": "ratchet",
            "sources": [
                "index.cc"
            ],
            "include_dirs" : [
                "<!(node -e \"require('nan')\")"
            ],
            "libraries": []
        }
    ]
}
