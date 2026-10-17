package history

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// timeLayout is fixed-width RFC3339 so lexicographic order matches time order.
const timeLayout = "2006-01-02T15:04:05.000000000Z07:00"

// Record matches the tracker ConnectionRecord JSON sent to the master.
type Record struct {
	ID                string `json:"id"`
	Download          int64  `json:"download"`
	Upload            int64  `json:"upload"`
	LastUpdated       string `json:"last_updated"`
	Start             string `json:"start"`
	Network           string `json:"network"`
	ConnType          string `json:"conn_type"`
	SourceIP          string `json:"source_ip"`
	DestinationIP     string `json:"destination_ip"`
	SourceGeoIP       string `json:"source_geoip"`
	DestinationGeoIP  string `json:"destination_geoip"`
	SourceIPASN       string `json:"source_ip_asn"`
	DestinationIPASN  string `json:"destination_ip_asn"`
	SourcePort        string `json:"source_port"`
	DestinationPort   string `json:"destination_port"`
	InboundIP         string `json:"inbound_ip"`
	InboundPort       string `json:"inbound_port"`
	InboundName       string `json:"inbound_name"`
	InboundUser       string `json:"inbound_user"`
	Host              string `json:"host"`
	DNSMode           string `json:"dns_mode"`
	UID               int64  `json:"uid"`
	Process           string `json:"process"`
	ProcessPath       string `json:"process_path"`
	SpecialProxy      string `json:"special_proxy"`
	SpecialRules      string `json:"special_rules"`
	RemoteDestination string `json:"remote_destination"`
	DSCP              int64  `json:"dscp"`
	SniffHost         string `json:"sniff_host"`
	Chains            string `json:"chains"`
	Rule              string `json:"rule"`
	RulePayload       string `json:"rule_payload"`
	AgentID           string `json:"agent_id"`
	Closed            int64  `json:"closed"`
}

type syncPackage struct {
	AgentID     string    `json:"agent_id"`
	Connections []Record  `json:"connections"`
	Timestamp   time.Time `json:"timestamp"`
}

func nowStamp() string {
	return time.Now().Format(timeLayout)
}

// FromConnection copies a live connection. chains uses mihomo order
// (outbound at index 0) and is reversed before it is stored.
func FromConnection(id string, start time.Time, upload, download int64, chains []string, rule, rulePayload string, meta *C.Metadata, closed int64) Record {
	rec := Record{
		ID:               id,
		Download:         download,
		Upload:           upload,
		LastUpdated:      nowStamp(),
		Start:            start.Format(timeLayout),
		Chains:           reversedChains(chains),
		Rule:             rule,
		RulePayload:      rulePayload,
		Closed:           closed,
		SourceGeoIP:      "[]",
		DestinationGeoIP: "[]",
	}
	if meta == nil {
		return rec
	}
	rec.Network = meta.NetWork.String()
	rec.ConnType = meta.Type.String()
	rec.SourceIP = addrString(meta.SrcIP)
	rec.DestinationIP = addrString(meta.DstIP)
	rec.SourceGeoIP = jsonArray(meta.SrcGeoIP)
	rec.DestinationGeoIP = jsonArray(meta.DstGeoIP)
	rec.SourceIPASN = meta.SrcIPASN
	rec.DestinationIPASN = meta.DstIPASN
	rec.SourcePort = strconv.FormatUint(uint64(meta.SrcPort), 10)
	rec.DestinationPort = strconv.FormatUint(uint64(meta.DstPort), 10)
	rec.InboundIP = addrString(meta.InIP)
	rec.InboundPort = strconv.FormatUint(uint64(meta.InPort), 10)
	rec.InboundName = meta.InName
	rec.InboundUser = meta.InUser
	rec.Host = meta.Host
	rec.DNSMode = meta.DNSMode.String()
	rec.UID = int64(meta.Uid)
	rec.Process = meta.Process
	rec.ProcessPath = meta.ProcessPath
	rec.SpecialProxy = meta.SpecialProxy
	rec.SpecialRules = meta.SpecialRules
	rec.RemoteDestination = meta.RemoteDst
	rec.DSCP = int64(meta.DSCP)
	rec.SniffHost = meta.SniffHost
	return rec
}

func reversedChains(chains []string) string {
	cp := append([]string(nil), chains...)
	for i, j := 0, len(cp)-1; i < j; i, j = i+1, j-1 {
		cp[i], cp[j] = cp[j], cp[i]
	}
	raw, err := json.Marshal(cp)
	if err != nil {
		return "[]"
	}
	return string(raw)
}

func jsonArray(v []string) string {
	if v == nil {
		v = []string{}
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(raw)
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}
