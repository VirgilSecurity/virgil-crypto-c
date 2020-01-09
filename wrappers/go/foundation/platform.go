package foundation

// #cgo darwin CFLAGS: -I${SRCDIR}/../pkg/darwin_amd64/include/
// #cgo darwin LDFLAGS: -L${SRCDIR}/../pkg/darwin_amd64/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -lround5 -lfalcon -lkeccak
// #cgo linux CFLAGS: -I${SRCDIR}/../pkg/linux_amd64/include/
// #cgo linux LDFLAGS: -L${SRCDIR}/../pkg/linux_amd64/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -lround5 -lfalcon -lkeccak -lpthread
// #cgo windows CFLAGS: -I${SRCDIR}/../pkg/windows_amd64/include/
// #cgo windows LDFLAGS: -L${SRCDIR}/../pkg/windows_amd64/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -lround5 -lfalcon -lkeccak
import "C"

