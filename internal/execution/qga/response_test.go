package qga

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func responseBridge(raw []byte, transportErr error) *Bridge {
	bridge, _ := NewBridge(func(context.Context, string, string, string, []string, []byte) ([]byte, []byte, error) {
		return raw, nil, transportErr
	})
	return bridge
}

func TestQGARejectsAmbiguousEnvelopesAndRefusals(t *testing.T) {
	for name, raw := range map[string]string{
		"null":                  `null`,
		"missing-result":        `{}`,
		"null-return":           `{"return":null}`,
		"null-error":            `{"error":null}`,
		"both":                  `{"return":{"pid":7},"error":{"class":"GenericError","desc":"private-qga-marker"}}`,
		"return-and-null-error": `{"return":{"pid":7},"error":null}`,
		"duplicate-return":      `{"return":{"pid":1},"return":{"pid":7}}`,
		"escaped-duplicate":     `{"return":{"pid":1},"\u0072eturn":{"pid":7}}`,
		"duplicate-error":       `{"error":{"class":"GenericError","desc":"a"},"error":{"class":"GenericError","desc":"b"}}`,
		"case-alias":            `{"Return":{"pid":7}}`,
		"unknown-field":         `{"return":{"pid":7},"private-qga-marker":true}`,
		"trailing-object":       `{"return":{"pid":7}} {}`,
		"trailing-content":      `{"return":{"pid":7}} private-qga-marker`,
		"missing-class":         `{"error":{"desc":"private-qga-marker"}}`,
		"missing-description":   `{"error":{"class":"private-qga-marker"}}`,
		"null-description":      `{"error":{"class":"GenericError","desc":null}}`,
		"duplicate-class":       `{"error":{"class":"a","class":"private-qga-marker","desc":"b"}}`,
		"description-alias":     `{"error":{"class":"GenericError","Desc":"private-qga-marker"}}`,
		"empty-error":           `{"error":{}}`,
		"oversized":             strings.Repeat(" ", maxQGAResponseBytes) + `{"return":{"pid":7}}`,
		"invalid-utf8":          "{\"error\":{\"class\":\"GenericError\",\"desc\":\"\xff\"}}",
	} {
		t.Run(name, func(t *testing.T) {
			var started guestExecStart
			err := responseBridge([]byte(raw), nil).qga(context.Background(), testTarget(), "guest-exec", nil, &started)
			var refusal *qgaRefusal
			if !errors.Is(err, ErrTransport) || errors.As(err, &refusal) || strings.Contains(err.Error(), "private-qga-marker") {
				t.Fatalf("ambiguous reply became authoritative or leaked: %v", err)
			}
		})
	}
}

func TestQGARefusalAndTransportDiagnosticsAreSanitized(t *testing.T) {
	var started guestExecStart
	bridge := responseBridge([]byte(`{"error":{"class":"private-qga-marker","desc":"private-qga-marker"}}`), nil)
	err := bridge.qga(context.Background(), testTarget(), "guest-exec", nil, &started)
	var refusal *qgaRefusal
	if !errors.As(err, &refusal) || strings.Contains(err.Error(), "private-qga-marker") {
		t.Fatalf("well-formed refusal lost classification or leaked content: %v", err)
	}
	err = responseBridge(nil, errors.New("private-qga-marker")).qga(context.Background(), testTarget(), "guest-exec", nil, &started)
	if !errors.Is(err, ErrTransport) || strings.Contains(err.Error(), "private-qga-marker") {
		t.Fatalf("transport error lost classification or leaked content: %v", err)
	}
}

func TestBridgeAmbiguousSpawnReplyRemainsUnknown(t *testing.T) {
	for _, raw := range []string{
		`{"return":{"pid":7},"error":{"class":"GenericError","desc":"private-qga-marker"}}`,
		`{"error":{"class":"GenericError","desc":"private-qga-marker"},"return":{"pid":7}}`,
		`{"return":{"pid":7},"return":{"pid":0}}`,
		`{"error":{"class":"GenericError","desc":null}}`,
	} {
		guest := newFakeExec(successRunnerResult())
		starts, polls := 0, 0
		bridge, _ := NewBridge(func(ctx context.Context, namespace, pod, container string, args []string, stdin []byte) ([]byte, []byte, error) {
			var request struct {
				Execute string `json:"execute"`
			}
			if err := json.Unmarshal(stdin, &request); err != nil {
				t.Fatal(err)
			}
			if request.Execute == "guest-exec" {
				starts++
				return []byte(raw), nil, nil
			}
			if request.Execute == "guest-exec-status" {
				polls++
			}
			return guest.run(ctx, namespace, pod, container, args, stdin)
		})
		result, err := bridge.Run(context.Background(), testTarget(), "exec_ambiguous", []byte(`{"grant":"protected","request":{}}`), []byte(`{"version":1,"keys":["public"]}`), 20)
		if result != nil || !errors.Is(err, ErrTransport) || errors.Is(err, ErrNotStarted) || strings.Contains(err.Error(), "private-qga-marker") {
			t.Fatalf("ambiguous spawn result became not-started/success or leaked: %+v %v", result, err)
		}
		if starts != 1 || polls != 0 || len(guest.files[dataDirPath+`\qga-request-exec_ambiguous.json`]) != 0 {
			t.Fatal("ambiguous spawn was rerun, polled without a trusted PID or retained its envelope")
		}
	}
}

func TestQGAReturnSchemasRejectZeroValueCoercionAndDuplicateMembers(t *testing.T) {
	for name, test := range map[string]struct {
		raw    string
		result func() any
	}{
		"duplicate-pid":      {`{"pid":0,"pid":7}`, func() any { return new(guestExecStart) }},
		"null-pid":           {`{"pid":null}`, func() any { return new(guestExecStart) }},
		"missing-pid":        {`{}`, func() any { return new(guestExecStart) }},
		"pid-case-alias":     {`{"PID":7}`, func() any { return new(guestExecStart) }},
		"missing-exited":     {`{"exitcode":0}`, func() any { return new(guestExecStatus) }},
		"null-exited":        {`{"exited":null}`, func() any { return new(guestExecStatus) }},
		"duplicate-exited":   {`{"exited":false,"exited":true,"exitcode":0}`, func() any { return new(guestExecStatus) }},
		"duplicate-exit":     {`{"exited":true,"exitcode":1,"exitcode":0}`, func() any { return new(guestExecStatus) }},
		"null-truncation":    {`{"exited":true,"exitcode":0,"out-truncated":null}`, func() any { return new(guestExecStatus) }},
		"null-exit":          {`{"exited":true,"exitcode":null}`, func() any { return new(guestExecStatus) }},
		"status-alias":       {`{"Exited":true,"exitcode":0}`, func() any { return new(guestExecStatus) }},
		"status-unknown":     {`{"exited":true,"exitcode":0,"private-qga-marker":1}`, func() any { return new(guestExecStatus) }},
		"count-null":         {`{"count":null}`, func() any { return new(guestFileWrite) }},
		"count-missing":      {`{}`, func() any { return new(guestFileWrite) }},
		"count-duplicate":    {`{"count":0,"count":7}`, func() any { return new(guestFileWrite) }},
		"eof-null":           {`{"count":7,"eof":null}`, func() any { return new(guestFileWrite) }},
		"handle-null":        {`null`, func() any { return new(int64) }},
		"handle-nonpositive": {`0`, func() any { return new(int64) }},
		"close-nonempty":     {`{"private-qga-marker":true}`, func() any { return nil }},
		"close-array":        {`[]`, func() any { return nil }},
	} {
		t.Run(name, func(t *testing.T) {
			err := responseBridge([]byte(`{"return":`+test.raw+`}`), nil).qga(context.Background(), testTarget(), "test", nil, test.result())
			if !errors.Is(err, ErrTransport) || strings.Contains(err.Error(), "private-qga-marker") {
				t.Fatalf("invalid typed reply escaped: %v", err)
			}
		})
	}
	for _, test := range []struct {
		raw    string
		result any
	}{
		{`{"pid":7}`, new(guestExecStart)},
		{`{"exited":false}`, new(guestExecStatus)},
		{`{"exited":true,"exitcode":0,"out-data":"","err-data":"","out-truncated":false,"err-truncated":false}`, new(guestExecStatus)},
		{`{"exited":true,"signal":9}`, new(guestExecStatus)},
		{`{"count":7}`, new(guestFileWrite)},
		{`{"count":7,"eof":false}`, new(guestFileWrite)},
		{`7`, new(int64)},
		{`{}`, nil},
	} {
		if err := responseBridge([]byte(`{"return":`+test.raw+`}`), nil).qga(context.Background(), testTarget(), "test", nil, test.result); err != nil {
			t.Fatalf("valid QGA optional-member contract rejected: %s %v", test.raw, err)
		}
	}
}

func FuzzQGAResponse(f *testing.F) {
	f.Add([]byte(`{"return":{"pid":7}}`))
	f.Add([]byte(`{"error":{"class":"GenericError","desc":"private-qga-marker"}}`))
	f.Add([]byte(`{"return":{"pid":0},"return":{"pid":7}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var started guestExecStart
		err := responseBridge(raw, nil).qga(context.Background(), testTarget(), "guest-exec", nil, &started)
		if err != nil {
			var refusal *qgaRefusal
			if (!errors.Is(err, ErrTransport) && !errors.As(err, &refusal)) || strings.Contains(err.Error(), "private-qga-marker") {
				t.Fatalf("unclassified or unsanitized response error: %v", err)
			}
		}
	})
}
