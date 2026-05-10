// Package cordinator is the central authority for VNet configuration
// (routes + auth) and the broadcast hub for connected operators.
//
// It exposes a single HTTP listener with two surfaces:
//
//	REST under /api/vnet (path-based vni):
//	  GET    /api/vnet                            list all VNets
//	  GET    /api/vnet/{vni}                      one VNet's state
//	  GET    /api/vnet/{vni}/routes               list bindings
//	  PUT    /api/vnet/{vni}/routes               body: {cid,prefix}     -> set
//	  DELETE /api/vnet/{vni}/routes/{cid}                                -> del
//	  PUT    /api/vnet/{vni}/auth                 body: {spec}           -> replace
//	  POST   /api/vnet/{vni}/auth/patch           body: {type?,add,remove} -> merge
//
//	Websocket:
//	  GET    /ws                                  one connection per operator
//
// REST mutations are applied to the in-memory tables and broadcast to
// every connected operator as one binary websocket frame per event,
// using protocol/control's wire format: Kind(1B) + Op.Encode().
//
// Today's broadcasts:
//
//	control.RouteUpsert  (vni, cid, prefix, ownerUUID=zero)
//	control.RouteRemove  (vni, cid)
//
// Auth mutations are NOT broadcast yet — there is no Auth control.Op
// and no operator-side handler. PUT/PATCH on /api/vnet/{vni}/auth
// updates cordinator state only.
package cordinator

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/protocol"
	"github.com/jabberwocky238/gasoline/protocol/control"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/websocket"
)

// vnetState is the per-VNI authoritative table.
type vnetState struct {
	mu          sync.RWMutex
	routes      map[protocol.CID_Ty]netip.Prefix
	authType    string            // "noauth" | "hmac" | "userpass" | ""
	authEntries map[string]string // id->secret (hmac) or user->hash (userpass)
}

func newVnetState() *vnetState {
	return &vnetState{
		routes:      make(map[protocol.CID_Ty]netip.Prefix),
		authEntries: make(map[string]string),
	}
}

// Cordinator owns per-VNI state and the set of connected operator
// websockets.
type Cordinator struct {
	addr string

	vnetsMu sync.RWMutex
	vnets   map[protocol.VNI_Ty]*vnetState

	opsMu sync.Mutex
	ops   map[*websocket.Conn]struct{}

	server *http.Server
	lctx   *common.LogContext
}

// New returns an unstarted Cordinator that will listen on addr (e.g.
// ":8080" or "127.0.0.1:8080") when Start is called.
func New(addr string) *Cordinator {
	return &Cordinator{
		addr:  addr,
		vnets: make(map[protocol.VNI_Ty]*vnetState),
		ops:   make(map[*websocket.Conn]struct{}),
		lctx:  common.NewLogContext(nil, log.New()),
	}
}

// Start binds the HTTP listener and serves REST + websocket.
func (c *Cordinator) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/vnet", c.handleVnetList)
	mux.HandleFunc("GET /api/vnet/{vni}", c.handleVnetGet)
	mux.HandleFunc("GET /api/vnet/{vni}/routes", c.handleRoutesList)
	mux.HandleFunc("PUT /api/vnet/{vni}/routes", c.handleRoutesPut)
	mux.HandleFunc("DELETE /api/vnet/{vni}/routes/{cid}", c.handleRoutesDel)
	mux.HandleFunc("PUT /api/vnet/{vni}/auth", c.handleAuthPut)
	mux.HandleFunc("POST /api/vnet/{vni}/auth/patch", c.handleAuthPatch)
	mux.Handle("/ws", websocket.Handler(c.handleWS))

	c.server = &http.Server{
		Addr:              c.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ln, err := net.Listen("tcp", c.addr)
	if err != nil {
		return fmt.Errorf("cordinator: listen %s: %w", c.addr, err)
	}
	c.lctx.Log().Infof("cordinator: serving on %s", ln.Addr())
	go func() {
		if err := c.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			c.lctx.Log().Errorf("cordinator: serve: %v", err)
		}
	}()
	return nil
}

// Close shuts the HTTP server and disconnects every operator.
func (c *Cordinator) Close() error {
	c.lctx.Cancel()

	c.opsMu.Lock()
	for conn := range c.ops {
		_ = conn.Close()
	}
	c.ops = make(map[*websocket.Conn]struct{})
	c.opsMu.Unlock()

	if c.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = c.server.Shutdown(ctx)
	}
	return nil
}

// --------------- REST: state ---------------

type vnetSummary struct {
	VNI        protocol.VNI_Ty `json:"vni"`
	RouteCount int             `json:"routeCount"`
	AuthSpec   string          `json:"authSpec"`
}

type routeEntry struct {
	CID    string `json:"cid"`
	Prefix string `json:"prefix"`
}

type routePutBody struct {
	CID    string `json:"cid"`
	Prefix string `json:"prefix"`
}

type authPutBody struct {
	Spec string `json:"spec"`
}

type authPatchBody struct {
	Type   string            `json:"type,omitempty"` // required only when no auth set yet
	Add    map[string]string `json:"add,omitempty"`
	Remove []string          `json:"remove,omitempty"`
}

func (c *Cordinator) handleVnetList(w http.ResponseWriter, r *http.Request) {
	c.vnetsMu.RLock()
	out := make([]vnetSummary, 0, len(c.vnets))
	for vni, v := range c.vnets {
		out = append(out, c.summarizeVNI(vni, v))
	}
	c.vnetsMu.RUnlock()
	writeJSON(w, out)
}

func (c *Cordinator) handleVnetGet(w http.ResponseWriter, r *http.Request) {
	vni, err := parseVNI(r.PathValue("vni"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	v := c.lookupVNI(vni)
	if v == nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, c.summarizeVNI(vni, v))
}

func (c *Cordinator) summarizeVNI(vni protocol.VNI_Ty, v *vnetState) vnetSummary {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return vnetSummary{VNI: vni, RouteCount: len(v.routes), AuthSpec: serializeAuth(v.authType, v.authEntries)}
}

// --------------- REST: routes ---------------

func (c *Cordinator) handleRoutesList(w http.ResponseWriter, r *http.Request) {
	vni, err := parseVNI(r.PathValue("vni"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	v := c.lookupVNI(vni)
	if v == nil {
		http.NotFound(w, r)
		return
	}
	v.mu.RLock()
	out := make([]routeEntry, 0, len(v.routes))
	for cid, pfx := range v.routes {
		out = append(out, routeEntry{CID: cid.FormatCID(), Prefix: pfx.String()})
	}
	v.mu.RUnlock()
	writeJSON(w, out)
}

func (c *Cordinator) handleRoutesPut(w http.ResponseWriter, r *http.Request) {
	vni, err := parseVNI(r.PathValue("vni"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var body routePutBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	cid, err := parseCID(body.CID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pfx, err := netip.ParsePrefix(body.Prefix)
	if err != nil {
		http.Error(w, "invalid prefix: "+err.Error(), http.StatusBadRequest)
		return
	}

	v := c.ensureVNI(vni)
	v.mu.Lock()
	v.routes[cid] = pfx
	v.mu.Unlock()

	c.broadcastOp(&control.RouteUpsert{VNI: vni, CID: cid, Prefix: pfx})
	w.WriteHeader(http.StatusNoContent)
}

func (c *Cordinator) handleRoutesDel(w http.ResponseWriter, r *http.Request) {
	vni, err := parseVNI(r.PathValue("vni"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cidHex := r.PathValue("cid")
	cid, err := parseCID(cidHex)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	v := c.lookupVNI(vni)
	if v == nil {
		http.NotFound(w, r)
		return
	}
	v.mu.Lock()
	_, existed := v.routes[cid]
	delete(v.routes, cid)
	v.mu.Unlock()
	if !existed {
		http.NotFound(w, r)
		return
	}
	c.broadcastOp(&control.RouteRemove{VNI: vni, CID: cid})
	w.WriteHeader(http.StatusNoContent)
}

// --------------- REST: auth ---------------

func (c *Cordinator) handleAuthPut(w http.ResponseWriter, r *http.Request) {
	vni, err := parseVNI(r.PathValue("vni"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var body authPutBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.Spec == "" {
		http.Error(w, "spec must not be empty", http.StatusBadRequest)
		return
	}
	typ, entries, err := parseAuth(body.Spec)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	v := c.ensureVNI(vni)
	v.mu.Lock()
	v.authType = typ
	v.authEntries = entries
	spec := serializeAuth(v.authType, v.authEntries)
	v.mu.Unlock()

	// auth changes are not broadcast yet (no control.Op for auth).
	_ = spec
	w.WriteHeader(http.StatusNoContent)
}

func (c *Cordinator) handleAuthPatch(w http.ResponseWriter, r *http.Request) {
	vni, err := parseVNI(r.PathValue("vni"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var body authPatchBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}

	v := c.ensureVNI(vni)
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.authType == "" {
		if body.Type == "" {
			http.Error(w, "type is required when no auth is currently set", http.StatusBadRequest)
			return
		}
		switch body.Type {
		case "noauth", "hmac", "userpass":
			v.authType = body.Type
		default:
			http.Error(w, "type must be noauth|hmac|userpass", http.StatusBadRequest)
			return
		}
	} else if body.Type != "" && body.Type != v.authType {
		http.Error(w, fmt.Sprintf("type mismatch: existing %s", v.authType), http.StatusBadRequest)
		return
	}

	for k, val := range body.Add {
		v.authEntries[k] = val
	}
	for _, k := range body.Remove {
		delete(v.authEntries, k)
	}

	// auth changes are not broadcast yet (no control.Op for auth).
	_ = serializeAuth(v.authType, v.authEntries)
	w.WriteHeader(http.StatusNoContent)
}

// --------------- Websocket: operator connections ---------------

func (c *Cordinator) handleWS(ws *websocket.Conn) {
	c.opsMu.Lock()
	c.ops[ws] = struct{}{}
	c.opsMu.Unlock()

	logger := c.lctx.Log().WithField("op", ws.RemoteAddr().String())
	logger.Info("operator connected")

	c.snapshotTo(ws)

	buf := make([]byte, 1024)
	for {
		if _, err := ws.Read(buf); err != nil {
			break
		}
	}

	c.opsMu.Lock()
	delete(c.ops, ws)
	c.opsMu.Unlock()
	logger.Info("operator disconnected")
}

// snapshotTo replays the current per-VNI route table to a freshly
// connected operator as control.RouteUpsert events (JSON-per-line).
func (c *Cordinator) snapshotTo(ws *websocket.Conn) {
	c.vnetsMu.RLock()
	defer c.vnetsMu.RUnlock()
	for vni, v := range c.vnets {
		v.mu.RLock()
		for cid, pfx := range v.routes {
			c.writeOp(ws, &control.RouteUpsert{VNI: vni, CID: cid, Prefix: pfx})
		}
		v.mu.RUnlock()
	}
}

// broadcastOp encodes op once as JSON and writes the resulting line to
// every connected operator. Failed writes drop the offending connection.
func (c *Cordinator) broadcastOp(op control.Op) {
	body, err := control.MarshalJSON(op)
	if err != nil {
		c.lctx.Log().Errorf("broadcast: marshal %T: %v", op, err)
		return
	}
	body = append(body, '\n')

	c.opsMu.Lock()
	conns := make([]*websocket.Conn, 0, len(c.ops))
	for conn := range c.ops {
		conns = append(conns, conn)
	}
	c.opsMu.Unlock()

	for _, conn := range conns {
		if _, err := conn.Write(body); err != nil {
			c.lctx.Log().Debugf("broadcast: drop %s: %v", conn.RemoteAddr(), err)
			_ = conn.Close()
			c.opsMu.Lock()
			delete(c.ops, conn)
			c.opsMu.Unlock()
		}
	}
}

// writeOp encodes one op as JSON + '\n' and writes it to ws.
func (c *Cordinator) writeOp(ws *websocket.Conn, op control.Op) {
	body, err := control.MarshalJSON(op)
	if err != nil {
		c.lctx.Log().Errorf("writeOp: marshal %T: %v", op, err)
		return
	}
	body = append(body, '\n')
	_, _ = ws.Write(body)
}

// --------------- helpers ---------------

func (c *Cordinator) lookupVNI(vni protocol.VNI_Ty) *vnetState {
	c.vnetsMu.RLock()
	defer c.vnetsMu.RUnlock()
	return c.vnets[vni]
}

func (c *Cordinator) ensureVNI(vni protocol.VNI_Ty) *vnetState {
	c.vnetsMu.Lock()
	defer c.vnetsMu.Unlock()
	v, ok := c.vnets[vni]
	if !ok {
		v = newVnetState()
		c.vnets[vni] = v
	}
	return v
}

func parseVNI(s string) (protocol.VNI_Ty, error) {
	if s == "" {
		return 0, fmt.Errorf("vni: missing")
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("vni %q: %v", s, err)
	}
	return protocol.VNI_Ty(v), nil
}

// parseCID decodes a CID. Decimal by default; "0x..." for hex.
func parseCID(s string) (protocol.CID_Ty, error) { return protocol.ParseCID(s) }

// parseAuth splits an auth spec string into (type, entries).
//
//	"noauth"               -> ("noauth",   nil)
//	"hmac:id:secret;..."   -> ("hmac",     map{id: secret, ...})
//	"userpass:user:hash"   -> ("userpass", map{user: hash, ...})
func parseAuth(spec string) (string, map[string]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "noauth" {
		return "noauth", map[string]string{}, nil
	}
	prefix, body, ok := strings.Cut(spec, ":")
	if !ok {
		return "", nil, fmt.Errorf("auth spec %q: missing prefix", spec)
	}
	switch prefix {
	case "hmac", "userpass":
	default:
		return "", nil, fmt.Errorf("auth spec %q: unknown type %q", spec, prefix)
	}
	entries := make(map[string]string)
	for _, e := range strings.Split(body, ";") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		k, v, ok := strings.Cut(e, ":")
		if !ok {
			return "", nil, fmt.Errorf("auth spec %q: bad entry %q (want key:value)", spec, e)
		}
		entries[k] = v
	}
	return prefix, entries, nil
}

// serializeAuth is the inverse of parseAuth. Entries are emitted in
// sorted key order so the output is stable across map iterations.
func serializeAuth(typ string, entries map[string]string) string {
	switch typ {
	case "":
		return ""
	case "noauth":
		return "noauth"
	}
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+":"+entries[k])
	}
	return typ + ":" + strings.Join(parts, ";")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
