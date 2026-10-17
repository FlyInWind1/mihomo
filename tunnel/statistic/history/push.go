package history

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/metacubex/mihomo/log"
)

func (s *service) pushLoop() {
	defer s.wg.Done()
	if s.settings.PushURL == "" {
		return
	}
	interval := s.settings.PushInterval
	if interval <= 0 {
		interval = time.Minute
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-tick.C:
			if err := s.pushOnce(); err != nil {
				log.Warnln("[RecordConnections] push failed: %s", err.Error())
			}
		}
	}
}

func (s *service) pushOnce() error {
	if s.settings.PushURL == "" {
		return nil
	}
	if err := s.health(); err != nil {
		return err
	}
	for {
		recs, err := s.pending(pushBatch)
		if err != nil {
			return err
		}
		if len(recs) == 0 {
			return nil
		}
		if err = s.post(recs); err != nil {
			return err
		}
		last := recs[len(recs)-1]
		if err = s.advance(last.LastUpdated, last.ID); err != nil {
			return err
		}
		if len(recs) < pushBatch {
			return nil
		}
	}
}

func (s *service) health() error {
	req, err := http.NewRequest(http.MethodGet, joinAPI(s.settings.PushURL, "/api/v1/health"), nil)
	if err != nil {
		return err
	}
	resp, err := pushClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("master health %s", resp.Status)
	}
	return nil
}

func (s *service) post(recs []Record) error {
	body, err := json.Marshal(syncPackage{
		AgentID:     s.settings.AgentID,
		Connections: recs,
		Timestamp:   time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, joinAPI(s.settings.PushURL, "/api/v1/sync"), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.settings.PushToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.settings.PushToken)
	}
	resp, err := pushClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("master sync %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

func joinAPI(base, path string) string {
	return strings.TrimRight(base, "/") + path
}

var pushClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		Proxy: nil,
	},
}
