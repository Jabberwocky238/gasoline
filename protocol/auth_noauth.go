package protocol

type NoAuthClient struct{}

func (a *NoAuthClient) Type() HandshakeType                    { return NoAuth }
func (a *NoAuthClient) Respond(_ []byte) ([]byte, error)       { return nil, nil }

type NoAuthServer struct{}

func (a *NoAuthServer) Type() HandshakeType                                    { return NoAuth }
func (a *NoAuthServer) GenerateChallenge() ([]byte, error)                     { return nil, nil }
func (a *NoAuthServer) VerifyResponse(_ [16]byte, _, _ []byte) error           { return nil }
