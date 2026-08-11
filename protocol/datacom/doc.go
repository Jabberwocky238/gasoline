// Package datacom is the gasoline client<->operator data-communication layer.
// It bundles the three pieces that share the post-handshake noise.Session and
// the on-wire framing they all seal under:
//
//   - assign        — the CONTROL plane: a two-phase-commit exchange that hands
//     the client an overlay IP + SessionID after authentication
//     (ServerAssign / ClientAssign).
//   - dataframe     — the DATA-PLANE frame: SessionTag||Counter||AEAD, the
//     envelope every IP packet travels in between a CE and a PE
//     (Seal / ParseHeader / Open).
//   - message       — the operator<->operator envelope (MessageTransport) plus
//     the in-band data-control messages (Ping/Pong, PrefixChanged,
//     Shutdown, Stats, …).
//
// They were merged into one package because they are one protocol surface: the
// same session keys, the same AEAD, the same addressing types. Each retains its
// own AAD domain-separation constant (aadAssign / aadData) so a frame from one
// plane can never be opened as another.
package datacom
