package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"


/*
* Utility class for working with Unix time / Epoch time /  POSIX time.
*/
type UnixTime struct {
}

/*
* Returns current timestamp.
*/
func UnixTimeNow() uint {
    proxyResult := /*pr4*/C.vssc_unix_time_now()

    return uint(proxyResult) /* r9 */
}

/*
* Returns distance between now and given timestamp.
*
* Note, always return non-negative value.
*/
func UnixTimeDistanceFromNow(toTimestamp uint) uint {
    proxyResult := /*pr4*/C.vssc_unix_time_distance_from_now((C.size_t)(toTimestamp)/*pa10*/)

    return uint(proxyResult) /* r9 */
}
