package history

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func testSettings(dir string) Settings {
	return Settings{
		Enable:             true,
		Store:              filepath.Join(dir, "record-connections.db"),
		RetentionDays:      7,
		CheckpointInterval: time.Hour,
		IgnoreInternal:     true,
		AgentID:            "local",
		PushInterval:       time.Hour,
	}
}

func start(t *testing.T, st Settings, snapshot func() []Record) {
	t.Helper()
	Configure(st, snapshot)
	t.Cleanup(func() { Configure(Settings{}, nil) })
}

func TestFinalBytesAndClosedStick(t *testing.T) {
	start(t, testSettings(t.TempDir()), nil)
	base := Record{
		ID:          "c1",
		Start:       "2020-01-01T00:00:00.000000000+08:00",
		LastUpdated: "2020-01-01T00:00:00.000000000+08:00",
		Download:    10,
		Upload:      1,
		Chains:      `["GROUP","node"]`,
		Host:        "example.com",
	}
	Observe(true, base)
	closed := base
	closed.Download = 50
	closed.Upload = 4
	closed.Closed = 1
	closed.LastUpdated = "2020-01-01T00:00:01.000000000+08:00"
	Observe(true, closed)
	late := base
	late.Download = 20
	late.Upload = 2
	late.Closed = 0
	late.LastUpdated = "2020-01-01T00:00:02.000000000+08:00"
	Observe(true, late)
	Flush()

	rec, ok, err := current.load("c1")
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if rec.Download != 50 || rec.Upload != 4 || rec.Closed != 1 {
		t.Fatalf("got download=%d upload=%d closed=%d", rec.Download, rec.Upload, rec.Closed)
	}
	if rec.AgentID != "local" || rec.Host != "example.com" {
		t.Fatalf("metadata lost: %+v", rec)
	}
}

func TestIgnoreInternal(t *testing.T) {
	start(t, testSettings(t.TempDir()), nil)
	Observe(false, Record{
		ID:          "dns",
		Start:       "2020-01-01T00:00:00.000000000+08:00",
		LastUpdated: "2020-01-01T00:00:00.000000000+08:00",
	})
	Flush()
	_, ok, err := current.load("dns")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("internal connection was stored")
	}
}

func TestChainsReversedAndJSONFields(t *testing.T) {
	meta := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.HTTP,
		Host:    "example.com",
		Process: "curl",
	}
	rec := FromConnection("id", time.Unix(0, 0), 2, 3, []string{"node", "GROUP"}, "DOMAIN", "example.com", meta, 1)
	if rec.Chains != `["GROUP","node"]` {
		t.Fatalf("chains: %s", rec.Chains)
	}
	if rec.Host != "example.com" || rec.Process != "curl" || rec.Network != "tcp" || rec.ConnType != "HTTP" || rec.Closed != 1 {
		t.Fatalf("record: %+v", rec)
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"id", "download", "upload", "last_updated", "conn_type", "source_ip", "closed", "agent_id", "rule_payload", "sniff_host"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("missing json field %s", key)
		}
	}
}

func TestCheckpointThenClose(t *testing.T) {
	start(t, testSettings(t.TempDir()), func() []Record {
		return []Record{{
			ID:          "live",
			Download:    3,
			Upload:      1,
			Start:       "2020-01-01T00:00:00.000000000+08:00",
			LastUpdated: "2020-01-01T00:00:00.000000000+08:00",
			Closed:      0,
			Host:        "live.example",
		}}
	})
	CheckpointNow()
	rec, ok, err := current.load("live")
	if err != nil || !ok {
		t.Fatalf("checkpoint load: ok=%v err=%v", ok, err)
	}
	if rec.Download != 3 || rec.Closed != 0 || rec.AgentID != "local" {
		t.Fatalf("checkpoint record: %+v", rec)
	}
	Observe(true, Record{
		ID:          "live",
		Download:    9,
		Upload:      2,
		Start:       "2020-01-01T00:00:00.000000000+08:00",
		LastUpdated: "2020-01-01T00:00:05.000000000+08:00",
		Closed:      1,
		Host:        "live.example",
	})
	Flush()
	rec, _, err = current.load("live")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Download != 9 || rec.Closed != 1 {
		t.Fatalf("after close: %+v", rec)
	}
}

func TestPushCursor(t *testing.T) {
	var got syncPackage
	var healthy bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/health":
			if !healthy {
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		case "/api/v1/sync":
			if r.Header.Get("Authorization") != "Bearer secret" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	st := testSettings(t.TempDir())
	st.PushURL = srv.URL
	st.PushToken = "secret"
	st.AgentID = "mi14"
	start(t, st, nil)

	before, beforeID, err := current.cursor()
	if err != nil {
		t.Fatal(err)
	}
	Observe(true, Record{
		ID:          "a",
		Download:    1,
		Upload:      1,
		Start:       "2020-01-01T00:00:00.000000000+08:00",
		LastUpdated: "2099-01-01T00:00:01.000000000+08:00",
		Closed:      1,
		Chains:      `["GROUP","node"]`,
	})
	Observe(true, Record{
		ID:          "b",
		Download:    2,
		Upload:      2,
		Start:       "2020-01-01T00:00:00.000000000+08:00",
		LastUpdated: "2099-01-01T00:00:02.000000000+08:00",
		Closed:      0,
		Chains:      `["GROUP","node"]`,
	})
	Flush()

	if err = current.pushOnce(); err == nil {
		t.Fatal("expected health failure")
	}
	after, afterID, err := current.cursor()
	if err != nil {
		t.Fatal(err)
	}
	if after != before || afterID != beforeID {
		t.Fatalf("cursor moved on failure: %s %s -> %s %s", before, beforeID, after, afterID)
	}

	healthy = true
	if err = current.pushOnce(); err != nil {
		t.Fatal(err)
	}
	if got.AgentID != "mi14" || len(got.Connections) != 2 {
		t.Fatalf("package: %+v", got)
	}
	if got.Connections[0].ID != "a" || got.Connections[1].ID != "b" {
		t.Fatalf("order: %+v", got.Connections)
	}
	if got.Connections[0].Chains != `["GROUP","node"]` || got.Connections[0].Closed != 1 {
		t.Fatalf("payload: %+v", got.Connections[0])
	}
	ts, id, err := current.cursor()
	if err != nil {
		t.Fatal(err)
	}
	if ts != "2099-01-01T00:00:02.000000000+08:00" || id != "b" {
		t.Fatalf("cursor: %s %s", ts, id)
	}
}

func TestRetentionKeepsUnsynced(t *testing.T) {
	st := testSettings(t.TempDir())
	st.PushURL = "http://127.0.0.1:1"
	st.RetentionDays = 7
	start(t, st, nil)

	old := time.Now().AddDate(0, 0, -30).Format(timeLayout)
	cursor := "2020-06-01T00:00:00.000000000+08:00"
	if err := current.advance(cursor, "synced"); err != nil {
		t.Fatal(err)
	}
	Observe(true, Record{ID: "synced", Start: old, LastUpdated: cursor, Closed: 1})
	Observe(true, Record{ID: "pending", Start: old, LastUpdated: "2099-01-01T00:00:00.000000000+08:00", Closed: 1})
	fresh := time.Now().Format(timeLayout)
	Observe(true, Record{ID: "fresh", Start: fresh, LastUpdated: cursor, Closed: 1})
	Flush()
	if _, err := current.cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := current.load("synced"); err != nil || ok {
		t.Fatalf("synced old row still present: ok=%v err=%v", ok, err)
	}
	if _, ok, err := current.load("pending"); err != nil || !ok {
		t.Fatalf("unsynced row missing: ok=%v err=%v", ok, err)
	}
	if _, ok, err := current.load("fresh"); err != nil || !ok {
		t.Fatalf("fresh row missing: ok=%v err=%v", ok, err)
	}
}
