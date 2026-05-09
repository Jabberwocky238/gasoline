package operator

import "github.com/jabberwocky238/gasoline/common"

// PeerClientTable represents a table of clients connected to this operator.
type PeerClientTable struct {
	indexTable *common.IndexTable[PeerClient]
}
