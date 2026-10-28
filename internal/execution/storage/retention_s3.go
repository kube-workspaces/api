package storage

import (
	"context"
	"strings"

	"github.com/minio/minio-go/v7"
)

func (s *s3Recording) DeleteRecording(ctx context.Context, recordingID string, limit int) (bool, error) {
	if err := validateID("recording id", recordingID); err != nil {
		return false, err
	}
	if limit < 1 || limit > 256 {
		return false, ErrConflict
	}
	// Deleting current objects in a versioned bucket would merely create
	// markers and leave old sensitive versions behind. Do not claim cleanup
	// completed, or silently change the bucket's operator-owned policy.
	versioning, err := s.client.GetBucketVersioning(ctx, s.bucket)
	if err != nil {
		return false, err
	}
	if versioning.Status != "" {
		return false, ErrConflict
	}
	listCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	prefix := recordingPrefix + "/" + recordingID + "/"
	count := 0
	for object := range s.client.ListObjects(listCtx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if object.Err != nil {
			return false, object.Err
		}
		if !strings.HasPrefix(object.Key, prefix) {
			return false, ErrConflict
		}
		if count == limit {
			return false, nil
		}
		if err := s.client.RemoveObject(ctx, s.bucket, object.Key, minio.RemoveObjectOptions{}); err != nil {
			return false, err
		}
		count++
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// Versioning cannot return to an unversioned state after being enabled.
	// Detect an operator policy change during this deletion batch as well.
	versioning, err = s.client.GetBucketVersioning(ctx, s.bucket)
	if err != nil {
		return false, err
	}
	if versioning.Status != "" {
		return false, ErrConflict
	}
	return true, nil
}
