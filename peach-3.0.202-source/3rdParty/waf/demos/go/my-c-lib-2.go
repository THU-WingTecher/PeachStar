package foo

/*
 #cgo LDFLAGS: -lmy-c-lib

 #include "my-c-lib.h"
 #include <stdlib.h>
*/
import "C"
import "unsafe"

func MyBye(msg string) {
	c_msg := C.CString(msg)
	defer C.free(unsafe.Pointer(c_msg))
	C.my_c_bye(c_msg)
}
