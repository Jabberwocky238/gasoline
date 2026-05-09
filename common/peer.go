package common

import "container/list"

// Peer is a stub kept solely so the vendored allowedips.go reference
// implementation compiles. The operator's routing table lives in
// device/operator/vnet_routing_map.go and does not use this type.
type Peer struct {
	trieEntries list.List
}
