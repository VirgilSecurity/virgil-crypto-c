package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"

type context interface {

	/* Get C context */
	Ctx() uintptr
}
