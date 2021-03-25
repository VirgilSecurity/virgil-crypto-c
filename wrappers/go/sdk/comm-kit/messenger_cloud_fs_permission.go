package sdk_comm_kit

import "C"

/*
* Set of file/folder permissions within the Cloud FS.
*/
type MessengerCloudFsPermission int
const (
    /*
    * Users with this permission can perform next operations:
    * - folder: create, delete, read, update, share.
    * - file: create, delete, read, update, share.
    */
    MessengerCloudFsPermissionAdmin MessengerCloudFsPermission = 1
    /*
    * Users with this permission can perform next operations:
    * - folder: ??.
    * - file: ??.
    */
    MessengerCloudFsPermissionUser MessengerCloudFsPermission = 2
)
