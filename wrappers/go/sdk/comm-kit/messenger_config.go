package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Contains messenger configuration.
*/
type MessengerConfig struct {
    cCtx *C.vssq_messenger_config_t /*ct2*/
}
const (
    MessengerConfigKUrlMessenger string = "https://messenger.virgilsecurity.com"
    MessengerConfigKUrlContactDiscovery string = "https://disco.virgilsecurity.com"
    MessengerConfigKUrlEjabberd string = "xmpp.virgilsecurity.com"
)

/* Handle underlying C context. */
func (obj *MessengerConfig) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessengerConfig() *MessengerConfig {
    ctx := C.vssq_messenger_config_new()
    obj := &MessengerConfig {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessengerConfig).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessengerConfigWithCtx(pointer unsafe.Pointer) *MessengerConfig {
    ctx := (*C.vssq_messenger_config_t /*ct2*/)(pointer)
    obj := &MessengerConfig {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessengerConfig).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessengerConfigCopy(pointer unsafe.Pointer) *MessengerConfig {
    ctx := (*C.vssq_messenger_config_t /*ct2*/)(pointer)
    obj := &MessengerConfig {
        cCtx: C.vssq_messenger_config_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*MessengerConfig).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *MessengerConfig) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *MessengerConfig) delete() {
    C.vssq_messenger_config_delete(obj.cCtx)
}

/*
* Create object with required fields.
*/
func NewMessengerConfigWith(messengerUrl string, contactDiscoveryUrl string, ejabberdUrl string) *MessengerConfig {
    messengerUrlChar := C.CString(messengerUrl)
    defer C.free(unsafe.Pointer(messengerUrlChar))
    messengerUrlStr := C.vsc_str_from_str(messengerUrlChar)
    contactDiscoveryUrlChar := C.CString(contactDiscoveryUrl)
    defer C.free(unsafe.Pointer(contactDiscoveryUrlChar))
    contactDiscoveryUrlStr := C.vsc_str_from_str(contactDiscoveryUrlChar)
    ejabberdUrlChar := C.CString(ejabberdUrl)
    defer C.free(unsafe.Pointer(ejabberdUrlChar))
    ejabberdUrlStr := C.vsc_str_from_str(ejabberdUrlChar)

    proxyResult := /*pr4*/C.vssq_messenger_config_new_with(messengerUrlStr, contactDiscoveryUrlStr, ejabberdUrlStr)

    runtime.KeepAlive(messengerUrl)

    runtime.KeepAlive(contactDiscoveryUrl)

    runtime.KeepAlive(ejabberdUrl)

    obj := &MessengerConfig {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*MessengerConfig).Delete)
    return obj
}

/*
* Set path to the custom CA bundle.
*/
func (obj *MessengerConfig) SetCaBundle(caBundle string) {
    caBundleChar := C.CString(caBundle)
    defer C.free(unsafe.Pointer(caBundleChar))
    caBundleStr := C.vsc_str_from_str(caBundleChar)

    C.vssq_messenger_config_set_ca_bundle(obj.cCtx, caBundleStr)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(caBundle)

    return
}

/*
* Return URL of the Messenger backend (main service).
*/
func (obj *MessengerConfig) MessengerUrl() string {
    proxyResult := /*pr4*/C.vssq_messenger_config_messenger_url(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return URL of the Messenger Contact Discovery service.
*/
func (obj *MessengerConfig) ContactDiscoveryUrl() string {
    proxyResult := /*pr4*/C.vssq_messenger_config_contact_discovery_url(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return URL of the Messenger Ejabberd service.
*/
func (obj *MessengerConfig) EjabberdUrl() string {
    proxyResult := /*pr4*/C.vssq_messenger_config_ejabberd_url(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return path to the custom CA bundle.
*/
func (obj *MessengerConfig) CaBundle() string {
    proxyResult := /*pr4*/C.vssq_messenger_config_ca_bundle(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}
