package sdk_comm_kit

// #cgo darwin CFLAGS: -I${SRCDIR}/../../pkg/darwin_amd64/include/
// #cgo darwin LDFLAGS: -L${SRCDIR}/../../pkg/darwin_amd64/lib -lvsc_comm_kit -lvsc_comm_kit_pb -lvsc_keyknox_sdk -lvsc_brainkey_sdk -lvsc_core_sdk -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -ljson-c -lfalcon -lround5 -lcurl
// #cgo linux,!legacy CFLAGS: -I${SRCDIR}/../../pkg/linux_amd64/include/
// #cgo linux,!legacy LDFLAGS: -L${SRCDIR}/../../pkg/linux_amd64/lib -lvsc_comm_kit -lvsc_comm_kit_pb -lvsc_keyknox_sdk -lvsc_brainkey_sdk -lvsc_core_sdk -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -ljson-c -lfalcon -lround5 -lcurl
// #cgo linux,legacy CFLAGS: -I${SRCDIR}/../../pkg/linux_amd64__legacy_os/include/
// #cgo linux,legacy LDFLAGS: -L${SRCDIR}/../../pkg/linux_amd64__legacy_os/lib -lvsc_comm_kit -lvsc_comm_kit_pb -lvsc_keyknox_sdk -lvsc_brainkey_sdk -lvsc_core_sdk -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -ljson-c -lfalcon -lround5 -lcurl
// #cgo windows CFLAGS: -I${SRCDIR}/../../pkg/windows_amd64/include/
// #cgo windows LDFLAGS: -L${SRCDIR}/../../pkg/windows_amd64/lib -lvsc_comm_kit -lvsc_comm_kit_pb -lvsc_keyknox_sdk -lvsc_brainkey_sdk -lvsc_core_sdk -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -ljson-c -lfalcon -lround5 -lcurl
import "C"
