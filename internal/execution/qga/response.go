package qga

import (
	"encoding/json"
)

var qgaResponseFields = map[string]bool{"return": false, "error": false}
var qgaErrorFields = map[string]bool{"class": false, "desc": false}
var qgaStartFields = map[string]bool{"pid": false}
var qgaStatusFields = map[string]bool{
	"exited": false, "exitcode": false, "signal": false,
	"out-data": false, "err-data": false,
	"out-truncated": false, "err-truncated": false,
}
var qgaWriteFields = map[string]bool{"count": false, "eof": false}

// decodeQGAReturn preserves QGA's optional status members without accepting
// duplicate/case-alias keys or nulls that encoding/json would turn into zeroes.
// Input is already bounded and the outer envelope has been checked.
func decodeQGAReturn(raw []byte, result any) bool {
	switch result.(type) {
	case *guestExecStart:
		return decodeExactObject(raw, result, qgaStartFields)
	case *guestExecStatus:
		return decodeObject(raw, result, qgaStatusFields, []string{"exited"})
	case *int64: // guest-file-open's handle
		var handle int64
		if json.Unmarshal(raw, &handle) != nil || handle <= 0 {
			return false
		}
		*result.(*int64) = handle
		return true
	case *guestFileWrite:
		return decodeObject(raw, result, qgaWriteFields, []string{"count"})
	case nil: // guest-file-close / guest-file-flush return an empty object
		return decodeExactObject(raw, new(struct{}), map[string]bool{})
	default:
		return false
	}
}

type guestFileWrite struct {
	Count int64 `json:"count"`
	EOF   bool  `json:"eof"`
}
