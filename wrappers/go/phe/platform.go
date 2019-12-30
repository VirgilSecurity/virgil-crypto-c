package phe

// #cgo darwin CFLAGS: -I${SRCDIR}/../pkg/darwin_amd64/include/
// #cgo darwin LDFLAGS: -L${SRCDIR}/../pkg/darwin_amd64/lib -lvsc_phe -lvsc_phe_pb -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #cgo linux CFLAGS: -I${SRCDIR}/../pkg/linux_amd64/include/
// #cgo linux LDFLAGS: -L${SRCDIR}/../pkg/linux_amd64/lib -lvsc_phe -lvsc_phe_pb -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #cgo windows CFLAGS: -I${SRCDIR}/../pkg/windows_amd64/include/
// #cgo windows LDFLAGS: -L${SRCDIR}/../pkg/windows_amd64/lib -lvsc_phe -lvsc_phe_pb -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
import "C"

