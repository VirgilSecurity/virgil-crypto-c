package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Provide DER deserializer of algorithm information.
*/
type AlgInfoDerDeserializer struct {
    IAlgInfoDeserializer
    cCtx *C.vscf_alg_info_der_deserializer_t /*ct10*/
}

func (obj *AlgInfoDerDeserializer) SetAsn1Reader (asn1Reader IAsn1Reader) {
    C.vscf_alg_info_der_deserializer_release_asn1_reader(obj.cCtx)
    C.vscf_alg_info_der_deserializer_use_asn1_reader(obj.cCtx, (*C.vscf_impl_t)(asn1Reader.ctx()))
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *AlgInfoDerDeserializer) SetupDefaults () {
    C.vscf_alg_info_der_deserializer_setup_defaults(obj.cCtx)

    return
}

/*
* Deserialize by using internal ASN.1 reader.
* Note, that caller code is responsible to reset ASN.1 reader with
* an input buffer.
*/
func (obj *AlgInfoDerDeserializer) DeserializeInplace () (IAlgInfo, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_alg_info_der_deserializer_deserialize_inplace(obj.cCtx, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *AlgInfoDerDeserializer) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewAlgInfoDerDeserializer () *AlgInfoDerDeserializer {
    ctx := C.vscf_alg_info_der_deserializer_new()
    return &AlgInfoDerDeserializer {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAlgInfoDerDeserializerWithCtx (ctx *C.vscf_alg_info_der_deserializer_t /*ct10*/) *AlgInfoDerDeserializer {
    return &AlgInfoDerDeserializer {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAlgInfoDerDeserializerCopy (ctx *C.vscf_alg_info_der_deserializer_t /*ct10*/) *AlgInfoDerDeserializer {
    return &AlgInfoDerDeserializer {
        cCtx: C.vscf_alg_info_der_deserializer_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (obj *AlgInfoDerDeserializer) clear () {
    C.vscf_alg_info_der_deserializer_delete(obj.cCtx)
}

/*
* Deserialize algorithm from the data.
*/
func (obj *AlgInfoDerDeserializer) Deserialize (data []byte) (IAlgInfo, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_alg_info_der_deserializer_deserialize(obj.cCtx, dataData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}
