package foundation

// #cgo darwin CFLAGS: -I${SRCDIR}/../pkg/darwin_amd64/include/
// #cgo darwin LDFLAGS: -L${SRCDIR}/../pkg/darwin_amd64/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -lround5 -lfalcon
// #cgo linux,!legacy CFLAGS: -I${SRCDIR}/../pkg/linux_amd64/include/
// #cgo linux,!legacy LDFLAGS: -L${SRCDIR}/../pkg/linux_amd64/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -lround5 -lfalcon -lpthread
// #cgo linux,legacy CFLAGS: -I${SRCDIR}/../pkg/linux_amd64__legacy_os/include/
// #cgo linux,legacy LDFLAGS: -L${SRCDIR}/../pkg/linux_amd64__legacy_os/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -lround5 -lfalcon -lpthread
// #cgo windows CFLAGS: -I${SRCDIR}/../pkg/windows_amd64/include/
// #cgo windows LDFLAGS: -L${SRCDIR}/../pkg/windows_amd64/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -lround5 -lfalcon
import "C"

