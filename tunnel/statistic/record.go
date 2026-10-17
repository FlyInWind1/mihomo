package statistic

import (
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic/history"
)

// ConfigureHistory starts or stops connection recording from the record-connections config.
func ConfigureHistory(s history.Settings) {
	history.Configure(s, snapshotActive)
}

func snapshotActive() []history.Record {
	var recs []history.Record
	DefaultManager.Range(func(c Tracker) bool {
		switch t := c.(type) {
		case *tcpTracker:
			if history.Accept(t.pushToManager) {
				recs = append(recs, history.FromConnection(t.ID(), t.Start, t.UploadTotal.Load(), t.DownloadTotal.Load(), []string(t.Chains()), t.Rule, t.RulePayload, t.Metadata, 0))
			}
		case *udpTracker:
			if history.Accept(t.pushToManager) {
				recs = append(recs, history.FromConnection(t.ID(), t.Start, t.UploadTotal.Load(), t.DownloadTotal.Load(), []string(t.Chains()), t.Rule, t.RulePayload, t.Metadata, 0))
			}
		}
		return true
	})
	return recs
}

func observeClosed(pushToManager bool, id string, start time.Time, upload, download int64, chains C.Chain, rule, payload string, meta *C.Metadata) {
	history.Observe(pushToManager, history.FromConnection(id, start, upload, download, []string(chains), rule, payload, meta, 1))
}
