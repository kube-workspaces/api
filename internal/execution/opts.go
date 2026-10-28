package execution

import "github.com/kube-workspaces/api/internal/execution/storage"

// StorageOptions translates the validated deployment configuration into the
// decoupled storage options. It never enables admission on its own: callers
// must Open the store and require Ready before permitting execution.
func (c StorageConfig) StorageOptions() storage.Options {
	return storage.Options{
		Mode:              string(c.Mode),
		EphemeralDir:      c.EphemeralDir,
		EphemeralMaxBytes: c.EphemeralMaxBytes,
		DatabaseURL:       c.DatabaseURL,
		S3: storage.S3Options{
			Endpoint:       c.S3.Endpoint,
			Region:         c.S3.Region,
			Bucket:         c.S3.Bucket,
			CAFile:         c.S3.CAFile,
			AccessKey:      c.S3.AccessKey,
			SecretKey:      c.S3.SecretKey,
			ForcePathStyle: c.S3.ForcePathStyle,
			CreateBucket:   c.S3.CreateBucket,
		},
		RecordingKey:          c.RecordingKey(),
		PreviousRecordingKeys: c.PreviousRecordingKeys(),
		KeyID:                 c.KeyID,
	}
}
