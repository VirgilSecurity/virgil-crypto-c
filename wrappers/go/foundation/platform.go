package foundation

// #cgo darwin,amd64 CFLAGS: -I${SRCDIR}/../pkg/darwin_amd64/include/
// #cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/../pkg/darwin_amd64/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -lround5 -lfalcon
// #cgo darwin,arm64 CFLAGS: -I${SRCDIR}/../pkg/darwin_arm64/include/
// #cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/../pkg/darwin_arm64/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -lround5 -lfalcon
// #cgo linux,amd64,!legacy CFLAGS: -I${SRCDIR}/../pkg/linux_amd64/include/
// #cgo linux,amd64,!legacy LDFLAGS: -L${SRCDIR}/../pkg/linux_amd64/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -lround5 -lfalcon -lpthread
// #cgo linux,amd64,legacy CFLAGS: -I${SRCDIR}/../pkg/linux_amd64__legacy_os/include/
// #cgo linux,amd64,legacy LDFLAGS: -L${SRCDIR}/../pkg/linux_amd64__legacy_os/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -lround5 -lfalcon -lpthread
// #cgo linux,arm64 CFLAGS: -I${SRCDIR}/../pkg/linux_arm64/include/
// #cgo linux,arm64 LDFLAGS: -L${SRCDIR}/../pkg/linux_arm64/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -lround5 -lfalcon -lpthread
// #cgo windows CFLAGS: -I${SRCDIR}/../pkg/windows_amd64/include/
// #cgo windows LDFLAGS: -L${SRCDIR}/../pkg/windows_amd64/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -lround5 -lfalcon
import "C"

