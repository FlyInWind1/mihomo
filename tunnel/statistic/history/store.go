package history

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"

	_ "modernc.org/sqlite"
)

const (
	queueSize    = 4096
	flushEvery   = 200 * time.Millisecond
	flushBatch   = 100
	pushBatch    = 1000
	cleanupEvery = time.Hour
)

// Settings is the runtime form of the record-connections config block.
type Settings struct {
	Enable             bool
	Store              string
	RetentionDays      int
	CheckpointInterval time.Duration
	IgnoreInternal     bool
	PushURL            string
	PushToken          string
	AgentID            string
	PushInterval       time.Duration
}

type service struct {
	settings Settings
	snapshot func() []Record

	db   *sql.DB
	dbMu sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
	in     chan Record
	flush  chan chan struct{}
	snap   chan chan struct{}
	wg     sync.WaitGroup
}

var (
	mu      sync.Mutex
	current *service
)

// Configure opens or replaces the local history store. A nil snapshot skips checkpoints.
func Configure(st Settings, snapshot func() []Record) {
	mu.Lock()
	old := current
	current = nil
	mu.Unlock()
	if old != nil {
		old.cancel()
		old.wg.Wait()
		_ = old.db.Close()
	}
	if !st.Enable {
		if old != nil {
			log.Infoln("[RecordConnections] disabled")
		}
		return
	}
	if st.Store == "" {
		log.Warnln("[RecordConnections] store path is empty")
		return
	}
	if err := os.MkdirAll(filepath.Dir(st.Store), 0o755); err != nil {
		log.Warnln("[RecordConnections] create store dir failed: %s", err.Error())
		return
	}
	db, err := sql.Open("sqlite", sqliteDSN(st.Store))
	if err != nil {
		log.Warnln("[RecordConnections] open %s failed: %s", st.Store, err.Error())
		return
	}
	db.SetMaxOpenConns(1)
	if err = db.Ping(); err != nil {
		_ = db.Close()
		log.Warnln("[RecordConnections] open %s failed: %s", st.Store, err.Error())
		return
	}
	if err = migrate(db); err != nil {
		_ = db.Close()
		log.Warnln("[RecordConnections] migrate %s failed: %s", st.Store, err.Error())
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	svc := &service{
		settings: st,
		snapshot: snapshot,
		db:       db,
		ctx:      ctx,
		cancel:   cancel,
		in:       make(chan Record, queueSize),
		flush:    make(chan chan struct{}),
		snap:     make(chan chan struct{}),
	}
	svc.wg.Add(2)
	go svc.loop()
	go svc.pushLoop()

	mu.Lock()
	current = svc
	mu.Unlock()
	log.Infoln(
		"[RecordConnections] recording to %s retention=%dd checkpoint=%s ignore-internal=%v",
		st.Store,
		st.RetentionDays,
		formatDuration(st.CheckpointInterval),
		st.IgnoreInternal,
	)
	if st.PushURL != "" {
		log.Infoln(
			"[RecordConnections] push to %s agent=%s interval=%s",
			st.PushURL,
			st.AgentID,
			formatDuration(st.PushInterval),
		)
	}
}

// Observe enqueues one connection when recording is on.
// pushToManager is false for mihomo's own DNS dials.
func Observe(pushToManager bool, rec Record) {
	mu.Lock()
	svc := current
	mu.Unlock()
	if svc == nil {
		return
	}
	if svc.settings.IgnoreInternal && !pushToManager {
		return
	}
	rec.AgentID = svc.settings.AgentID
	select {
	case <-svc.ctx.Done():
		return
	case svc.in <- rec:
		if rec.Closed != 0 {
			log.Debugln(
				"[RecordConnections] closed %s %s:%s --> %s up=%d down=%d",
				rec.Network,
				rec.SourceIP,
				rec.SourcePort,
				recordTarget(rec),
				rec.Upload,
				rec.Download,
			)
		}
	}
}

// Flush waits until records queued so far are written. Tests use it.
func Flush() {
	mu.Lock()
	svc := current
	mu.Unlock()
	if svc == nil {
		return
	}
	done := make(chan struct{})
	select {
	case <-svc.ctx.Done():
	case svc.flush <- done:
		<-done
	}
}

// CheckpointNow writes the current snapshot. Tests use it.
func CheckpointNow() {
	mu.Lock()
	svc := current
	mu.Unlock()
	if svc == nil {
		return
	}
	done := make(chan struct{})
	select {
	case <-svc.ctx.Done():
	case svc.snap <- done:
		<-done
	}
}

func (s *service) loop() {
	defer s.wg.Done()
	flushTick := time.NewTicker(flushEvery)
	defer flushTick.Stop()
	checkpointC := s.ticker(s.settings.CheckpointInterval)
	cleanupC := s.ticker(cleanupEvery)
	var batch []Record
	write := func() {
		batch = append(batch, drain(s.in)...)
		if len(batch) == 0 {
			return
		}
		var closed int
		for _, rec := range batch {
			if rec.Closed != 0 {
				closed++
			}
		}
		if err := s.upsert(batch); err != nil {
			log.Warnln("[RecordConnections] write failed: %s", err.Error())
		} else {
			log.Debugln("[RecordConnections] wrote %d records (%d closed)", len(batch), closed)
		}
		batch = nil
	}
	for {
		select {
		case <-s.ctx.Done():
			write()
			return
		case rec := <-s.in:
			batch = append(batch, rec)
			if len(batch) >= flushBatch {
				write()
			}
		case <-flushTick.C:
			write()
		case done := <-s.flush:
			write()
			close(done)
		case done := <-s.snap:
			batch = append(batch, s.logSnapshot(s.takeSnapshot())...)
			write()
			close(done)
		case <-checkpointC:
			batch = append(batch, s.logSnapshot(s.takeSnapshot())...)
		case <-cleanupC:
			removed, err := s.cleanup()
			if err != nil {
				log.Warnln("[RecordConnections] cleanup failed: %s", err.Error())
			} else if removed > 0 {
				log.Debugln("[RecordConnections] removed %d expired records", removed)
			}
		}
	}
}

func drain(in <-chan Record) []Record {
	var extra []Record
	for {
		select {
		case rec := <-in:
			extra = append(extra, rec)
		default:
			return extra
		}
	}
}

func (s *service) takeSnapshot() []Record {
	if s.snapshot == nil {
		return nil
	}
	recs := s.snapshot()
	for i := range recs {
		recs[i].AgentID = s.settings.AgentID
	}
	return recs
}

func (s *service) logSnapshot(recs []Record) []Record {
	if len(recs) > 0 {
		log.Debugln("[RecordConnections] checkpoint %d live connections", len(recs))
	}
	return recs
}

func recordTarget(rec Record) string {
	if rec.Host != "" {
		return rec.Host
	}
	if rec.DestinationIP != "" {
		return rec.DestinationIP
	}
	return rec.RemoteDestination
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "off"
	}
	return d.String()
}

// Accept reports whether this connection should be stored.
func Accept(pushToManager bool) bool {
	mu.Lock()
	svc := current
	mu.Unlock()
	if svc == nil {
		return false
	}
	if svc.settings.IgnoreInternal && !pushToManager {
		return false
	}
	return true
}

func (s *service) ticker(d time.Duration) <-chan time.Time {
	if d <= 0 {
		return nil
	}
	t := time.NewTicker(d)
	go func() {
		<-s.ctx.Done()
		t.Stop()
	}()
	return t.C
}

func sqliteDSN(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := url.URL{
		Scheme:   "file",
		Path:     p,
		RawQuery: "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)",
	}
	return u.String()
}

func migrate(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS connections (
			id TEXT PRIMARY KEY,
			conn_download INTEGER,
			conn_upload INTEGER,
			last_updated TEXT,
			start TEXT,
			network TEXT,
			type TEXT,
			source_ip TEXT,
			destination_ip TEXT,
			source_geoip TEXT,
			destination_geoip TEXT,
			source_ip_asn TEXT,
			destination_ip_asn TEXT,
			source_port TEXT,
			destination_port TEXT,
			inbound_ip TEXT,
			inbound_port TEXT,
			inbound_name TEXT,
			inbound_user TEXT,
			host TEXT,
			dns_mode TEXT,
			uid INTEGER,
			process TEXT,
			process_path TEXT,
			special_proxy TEXT,
			special_rules TEXT,
			remote_destination TEXT,
			dscp INTEGER,
			sniff_host TEXT,
			chains TEXT,
			rule TEXT,
			rule_payload TEXT,
			agent_id TEXT,
			closed INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_connections_last_updated_id ON connections(last_updated, id)`,
		`CREATE TABLE IF NOT EXISTS sync_state (
			id INTEGER PRIMARY KEY,
			last_sync_time TEXT,
			last_connection_id TEXT
		)`,
		`INSERT OR IGNORE INTO sync_state (id, last_sync_time, last_connection_id) VALUES (1, datetime('now'), '')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *service) upsert(recs []Record) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
		INSERT INTO connections (
			id, conn_download, conn_upload, last_updated, start, network, type,
			source_ip, destination_ip, source_geoip, destination_geoip, source_ip_asn,
			destination_ip_asn, source_port, destination_port, inbound_ip, inbound_port,
			inbound_name, inbound_user, host, dns_mode, uid, process, process_path,
			special_proxy, special_rules, remote_destination, dscp, sniff_host, chains,
			rule, rule_payload, agent_id, closed
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			conn_download=MAX(conn_download, excluded.conn_download),
			conn_upload=MAX(conn_upload, excluded.conn_upload),
			last_updated=MAX(last_updated, excluded.last_updated),
			closed=MAX(closed, excluded.closed),
			start=excluded.start,
			network=excluded.network,
			type=excluded.type,
			source_ip=excluded.source_ip,
			destination_ip=excluded.destination_ip,
			source_geoip=excluded.source_geoip,
			destination_geoip=excluded.destination_geoip,
			source_ip_asn=excluded.source_ip_asn,
			destination_ip_asn=excluded.destination_ip_asn,
			source_port=excluded.source_port,
			destination_port=excluded.destination_port,
			inbound_ip=excluded.inbound_ip,
			inbound_port=excluded.inbound_port,
			inbound_name=excluded.inbound_name,
			inbound_user=excluded.inbound_user,
			host=excluded.host,
			dns_mode=excluded.dns_mode,
			uid=excluded.uid,
			process=excluded.process,
			process_path=excluded.process_path,
			special_proxy=excluded.special_proxy,
			special_rules=excluded.special_rules,
			remote_destination=excluded.remote_destination,
			dscp=excluded.dscp,
			sniff_host=excluded.sniff_host,
			chains=excluded.chains,
			rule=excluded.rule,
			rule_payload=excluded.rule_payload,
			agent_id=excluded.agent_id
	`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, rec := range recs {
		if _, err = stmt.Exec(
			rec.ID, rec.Download, rec.Upload, rec.LastUpdated, rec.Start, rec.Network, rec.ConnType,
			rec.SourceIP, rec.DestinationIP, rec.SourceGeoIP, rec.DestinationGeoIP, rec.SourceIPASN,
			rec.DestinationIPASN, rec.SourcePort, rec.DestinationPort, rec.InboundIP, rec.InboundPort,
			rec.InboundName, rec.InboundUser, rec.Host, rec.DNSMode, rec.UID, rec.Process, rec.ProcessPath,
			rec.SpecialProxy, rec.SpecialRules, rec.RemoteDestination, rec.DSCP, rec.SniffHost, rec.Chains,
			rec.Rule, rec.RulePayload, rec.AgentID, rec.Closed,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *service) cleanup() (int64, error) {
	if s.settings.RetentionDays < 0 {
		return 0, nil
	}
	cutoff := time.Now().AddDate(0, 0, -s.settings.RetentionDays).Format(timeLayout)
	q := `DELETE FROM connections WHERE start < ?`
	if s.settings.PushURL != "" {
		q = `DELETE FROM connections WHERE start < ? AND (
			last_updated < (SELECT last_sync_time FROM sync_state WHERE id = 1)
			OR (
				last_updated = (SELECT last_sync_time FROM sync_state WHERE id = 1)
				AND id <= COALESCE((SELECT last_connection_id FROM sync_state WHERE id = 1), '')
			)
		)`
	}
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	res, err := s.db.Exec(q, cutoff)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (s *service) pending(limit int) ([]Record, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	rows, err := s.db.Query(`
		SELECT
			id, conn_download, conn_upload, last_updated, start,
			network, type, source_ip, destination_ip,
			source_geoip, destination_geoip, source_ip_asn, destination_ip_asn,
			source_port, destination_port, inbound_ip, inbound_port,
			inbound_name, inbound_user, host, dns_mode, uid, process,
			process_path, special_proxy, special_rules, remote_destination,
			dscp, sniff_host, chains, rule, rule_payload, agent_id, closed
		FROM connections
		WHERE last_updated > (SELECT last_sync_time FROM sync_state WHERE id = 1)
			OR (
				last_updated = (SELECT last_sync_time FROM sync_state WHERE id = 1)
				AND id > COALESCE((SELECT last_connection_id FROM sync_state WHERE id = 1), '')
			)
		ORDER BY last_updated ASC, id ASC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var recs []Record
	for rows.Next() {
		var rec Record
		if err = rows.Scan(
			&rec.ID, &rec.Download, &rec.Upload, &rec.LastUpdated, &rec.Start,
			&rec.Network, &rec.ConnType, &rec.SourceIP, &rec.DestinationIP,
			&rec.SourceGeoIP, &rec.DestinationGeoIP, &rec.SourceIPASN, &rec.DestinationIPASN,
			&rec.SourcePort, &rec.DestinationPort, &rec.InboundIP, &rec.InboundPort,
			&rec.InboundName, &rec.InboundUser, &rec.Host, &rec.DNSMode, &rec.UID, &rec.Process,
			&rec.ProcessPath, &rec.SpecialProxy, &rec.SpecialRules, &rec.RemoteDestination,
			&rec.DSCP, &rec.SniffHost, &rec.Chains, &rec.Rule, &rec.RulePayload, &rec.AgentID, &rec.Closed,
		); err != nil {
			return nil, err
		}
		recs = append(recs, rec)
	}
	return recs, rows.Err()
}

func (s *service) advance(lastUpdated, id string) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	_, err := s.db.Exec(
		`UPDATE sync_state SET last_sync_time = ?, last_connection_id = ? WHERE id = 1`,
		lastUpdated, id,
	)
	return err
}

func (s *service) cursor() (string, string, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	var ts, id string
	err := s.db.QueryRow(`SELECT last_sync_time, last_connection_id FROM sync_state WHERE id = 1`).Scan(&ts, &id)
	return ts, id, err
}

func (s *service) load(id string) (Record, bool, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	var rec Record
	err := s.db.QueryRow(`
		SELECT
			id, conn_download, conn_upload, last_updated, start,
			network, type, source_ip, destination_ip,
			source_geoip, destination_geoip, source_ip_asn, destination_ip_asn,
			source_port, destination_port, inbound_ip, inbound_port,
			inbound_name, inbound_user, host, dns_mode, uid, process,
			process_path, special_proxy, special_rules, remote_destination,
			dscp, sniff_host, chains, rule, rule_payload, agent_id, closed
		FROM connections WHERE id = ?`, id).Scan(
		&rec.ID, &rec.Download, &rec.Upload, &rec.LastUpdated, &rec.Start,
		&rec.Network, &rec.ConnType, &rec.SourceIP, &rec.DestinationIP,
		&rec.SourceGeoIP, &rec.DestinationGeoIP, &rec.SourceIPASN, &rec.DestinationIPASN,
		&rec.SourcePort, &rec.DestinationPort, &rec.InboundIP, &rec.InboundPort,
		&rec.InboundName, &rec.InboundUser, &rec.Host, &rec.DNSMode, &rec.UID, &rec.Process,
		&rec.ProcessPath, &rec.SpecialProxy, &rec.SpecialRules, &rec.RemoteDestination,
		&rec.DSCP, &rec.SniffHost, &rec.Chains, &rec.Rule, &rec.RulePayload, &rec.AgentID, &rec.Closed,
	)
	if err == sql.ErrNoRows {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	return rec, true, nil
}
