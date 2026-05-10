package control

// CordinatorConnect tells the operator to dial a remote cordinator at
// Endpoint and start a CordinatorController against it.
type CordinatorConnect struct {
	Endpoint string `json:"endpoint"`
}

func (CordinatorConnect) opMarker() {}
func (CordinatorConnect) Kind() Kind { return KindCordinatorConnect }
