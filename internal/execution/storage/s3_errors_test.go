package storage

import (
	"errors"
	"fmt"
	"testing"

	"github.com/minio/minio-go/v7"
)

func TestS3MissingKeyUsesProtocolCode(t *testing.T) {
	missing := minio.ErrorResponse{Code: "NoSuchKey", Message: "The specified key does not exist."}
	for _, err := range []error{missing, &missing, fmt.Errorf("read object: %w", missing)} {
		if !isNoSuchKey(err) {
			t.Fatal("missing key protocol response was not recognized")
		}
	}
	for _, err := range []error{nil, errors.New("NoSuchKey in arbitrary text"), minio.ErrorResponse{Code: "AccessDenied", Message: "NoSuchKey"}} {
		if isNoSuchKey(err) {
			t.Fatal("non-missing response was treated as missing evidence")
		}
	}
}
