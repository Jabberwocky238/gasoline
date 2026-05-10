package control

// CordinatorDisconnect tells the operator to tear down the
// CordinatorController targeting Endpoint, if any.
type CordinatorDisconnect struct {
	Endpoint string `json:"endpoint"`
}

func (CordinatorDisconnect) opMarker() {}
func (CordinatorDisconnect) Kind() Kind { return KindCordinatorDisconnect }
