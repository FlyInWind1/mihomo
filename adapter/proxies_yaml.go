package adapter

import (
	"fmt"

	"github.com/metacubex/mihomo/common/orderedmap"

	"go.yaml.in/yaml/v3"
)

// ProxyMappings is a proxies list. nameserver-policy is unmarshaled as an
// ordered map, same as dns.nameserver-policy.
type ProxyMappings []map[string]any

func (m *ProxyMappings) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode && node.Tag == "!!null" {
		*m = nil
		return nil
	}
	if node.Kind != yaml.SequenceNode {
		return fmt.Errorf("proxies must be a sequence")
	}
	proxies := make([]map[string]any, len(node.Content))
	for i, item := range node.Content {
		var proxy map[string]any
		if err := item.Decode(&proxy); err != nil {
			return err
		}
		if err := decodeProxyNameserverPolicy(item, proxy); err != nil {
			return err
		}
		proxies[i] = proxy
	}
	*m = proxies
	return nil
}

func decodeProxyNameserverPolicy(item *yaml.Node, proxy map[string]any) error {
	if proxy == nil || item.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(item.Content); i += 2 {
		var key string
		if err := item.Content[i].Decode(&key); err != nil {
			return err
		}
		if key != "nameserver-policy" || item.Content[i+1].Kind != yaml.MappingNode {
			continue
		}
		policy := orderedmap.New[string, any]()
		if err := item.Content[i+1].Decode(policy); err != nil {
			return err
		}
		proxy[key] = policy
	}
	// A merged key is already expanded into the map and is not a mapping node here.
	if raw, ok := proxy["nameserver-policy"].(map[string]any); ok {
		policy := orderedmap.New[string, any]()
		for key, value := range raw {
			policy.Set(key, value)
		}
		proxy["nameserver-policy"] = policy
	}
	return nil
}
