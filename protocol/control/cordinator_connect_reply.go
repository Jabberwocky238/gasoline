package control

// CordinatorConnectReply is sent by the cordinator in response to a
// successful CordinatorConnect. Peers is the cordinator's current
// view of every operator already attached (UUID + underlay endpoint),
// so the new operator can preload its PeerTable instead of waiting
// for separate PeerJoin events to arrive.
type CordinatorConnectReply struct {
	Peers []PeerJoin `json:"peers"`
}

func (CordinatorConnectReply) opMarker() {}
func (CordinatorConnectReply) Kind() Kind { return KindCordinatorConnectReply }
