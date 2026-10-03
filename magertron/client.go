// Package magertron is a small client for building agents on Magertron™:
// credentials and the token exchange, the tool catalogue, governed tool calls
// with idempotency keys, and the refusal-handling rules from the Agent
// Developer Guide.
//
// It has no dependencies outside the standard library.
package magertron

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Options configures a Client.
type Options struct {
	// GatewayURL is the Magertron gateway, e.g. https://mcp.acme.com. Tool
	// calls go here so the gateway can govern them.
	GatewayURL string

	// ControlURL is the Magertron API (token exchange, catalogue). Defaults to
	// GatewayURL, which is right for most deployments.
	ControlURL string

	// InsecureSkipVerify disables TLS certificate verification. ONLY for a
	// test cluster with a self-signed certificate: with it on, anyone on the
	// network path can read your tokens.
	InsecureSkipVerify bool

	// Timeout for each HTTP request. Default 60s.
	Timeout time.Duration
}

// Client talks to one Magertron deployment. Safe for concurrent use.
type Client struct {
	gateway string
	control string
	http    *http.Client

	mu       sync.Mutex
	sessions map[sessionKey]string // -> Mcp-Session-Id or statelessSession
}

// New creates a Client. TLS is verified unless opts.InsecureSkipVerify is set.
func New(opts Options) (*Client, error) {
	if opts.GatewayURL == "" {
		return nil, errors.New("magertron: GatewayURL is required")
	}
	if opts.ControlURL == "" {
		opts.ControlURL = opts.GatewayURL
	}
	if opts.Timeout == 0 {
		opts.Timeout = 60 * time.Second
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if opts.InsecureSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit opt-in for test clusters
	}
	return &Client{
		gateway:  strings.TrimRight(opts.GatewayURL, "/"),
		control:  strings.TrimRight(opts.ControlURL, "/"),
		http:     &http.Client{Timeout: opts.Timeout, Transport: tr},
		sessions: make(map[sessionKey]string),
	}, nil
}

// HTTPClient returns the client's HTTP client, so other legs (your directory,
// the model) share the same TLS decision.
func (c *Client) HTTPClient() *http.Client { return c.http }

func (c *Client) controlURL(path string) string { return c.control + path }
func (c *Client) toolURL(ns, server string) string {
	return fmt.Sprintf("%s/mcp/%s/%s/", c.gateway, ns, server)
}

// do sends one request and returns status and body. It never logs headers.
func (c *Client) do(ctx context.Context, method, url string, hdr http.Header, body []byte,
	respHdr *http.Header) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if respHdr != nil {
		*respHdr = resp.Header
	}
	return resp.StatusCode, raw, err
}

// ── Turn ids ────────────────────────────────────────────────────────────────

type turnKey struct{}

// WithTurnID tags every call made with ctx as part of one conversational turn.
// The platform then groups a model call and the tool calls it produced into
// one unit in the audit and the chargeback. Optional.
func WithTurnID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, turnKey{}, id)
}

// TurnID returns the turn id set with WithTurnID, or "".
func TurnID(ctx context.Context) string {
	s, _ := ctx.Value(turnKey{}).(string)
	return s
}

// NewID returns a random UUID (v4), for turn ids and idempotency keys.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ── Catalogue ────────────────────────────────────────────────────────────────

// Tool is one callable tool, with enough context to route a call back to it.
type Tool struct {
	Namespace   string
	Server      string
	Name        string
	Description string
	InputSchema json.RawMessage
	Allowed     bool // the platform's verdict for the principal that fetched the catalogue
}

// Catalog lists the tools visible to cred's principal, with a per-tool verdict.
//
// When your agent acts for a person, pass a credential for the PERSON alone,
// not the delegated one: "what can this person do?" is the useful question,
// and every call is gated anyway, so nothing becomes reachable by being listed.
func (c *Client) Catalog(ctx context.Context, cred Credential) ([]Tool, error) {
	var raw []byte
	err := c.withRetries(ctx, cred, func(tok string) (int, []byte, error) {
		h := http.Header{}
		h.Set("Authorization", "Bearer "+tok)
		h.Set("Accept", "application/json")
		s, b, err := c.do(ctx, http.MethodGet, c.controlURL("/api/v1/portal/catalog"), h, nil, nil)
		raw = b
		return s, b, err
	})
	if err != nil {
		return nil, err
	}
	type tool struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Access      string          `json:"access"`
		InputSchema json.RawMessage `json:"input_schema"`
	}
	type server struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Tools     []tool `json:"tools"`
	}
	var servers []server
	if json.Unmarshal(raw, &servers) != nil || len(servers) == 0 {
		var wrapped struct {
			Servers []server `json:"servers"`
			Catalog []server `json:"catalog"`
		}
		if err := json.Unmarshal(raw, &wrapped); err != nil {
			return nil, fmt.Errorf("catalog: unexpected response: %w", err)
		}
		servers = append(wrapped.Servers, wrapped.Catalog...)
	}
	var out []Tool
	for _, s := range servers {
		for _, t := range s.Tools {
			out = append(out, Tool{
				Namespace: s.Namespace, Server: s.Name, Name: t.Name,
				Description: t.Description, InputSchema: t.InputSchema,
				Allowed: strings.EqualFold(t.Access, "allowed"),
			})
		}
	}
	return out, nil
}

// ── Tool calls ───────────────────────────────────────────────────────────────

const statelessSession = "-stateless-"

// Sessions are per principal: a session opened as one identity is never
// reused by another.
type sessionKey struct {
	cred       Credential
	ns, server string
}

// CallTool invokes a tool through the gateway and returns the JSON-RPC result.
//
// cred is the credential the call is made with: your agent's own, or a
// delegated Exchange (Subject = the person, Actor = your agent).
//
// Every call carries a fresh Idempotency-Key, reused on each retry of that
// call, so a call retried after a network failure is metered once.
// Refusals are returned as *Refusal; retries follow the guide's rules.
func (c *Client) CallTool(ctx context.Context, cred Credential, t Tool, args json.RawMessage) (json.RawMessage, error) {
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	sid, err := c.session(ctx, cred, t.Namespace, t.Server)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]any{"name": t.Name, "arguments": args},
	})
	idemKey := NewID() // one per logical call, fixed across its retries
	var raw []byte
	err = c.withRetries(ctx, cred, func(tok string) (int, []byte, error) {
		h := c.mcpHeaders(ctx, tok)
		h.Set("Idempotency-Key", idemKey)
		if sid != statelessSession {
			h.Set("Mcp-Session-Id", sid)
		}
		s, b, err := c.do(ctx, http.MethodPost, c.toolURL(t.Namespace, t.Server), h, body, nil)
		raw = b
		return s, b, err
	})
	if err != nil {
		return nil, err
	}
	frame, ok := jsonRPCFrame(raw)
	if !ok {
		return nil, fmt.Errorf("tools/call: unexpected response: %s", truncate(string(raw), 200))
	}
	if len(frame.Error) > 0 {
		return nil, fmt.Errorf("tool %s returned an error: %s", t.Name, truncate(string(frame.Error), 300))
	}
	return frame.Result, nil
}

// session opens (or reuses) an MCP session for cred's principal on ns/server.
func (c *Client) session(ctx context.Context, cred Credential, ns, server string) (string, error) {
	key := sessionKey{cred, ns, server}
	c.mu.Lock()
	sid := c.sessions[key]
	c.mu.Unlock()
	if sid != "" {
		return sid, nil
	}
	initBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{` +
		`"protocolVersion":"2025-03-26","capabilities":{},` +
		`"clientInfo":{"name":"magertron-agent-example","version":"0.1"}}}`)
	var hdr http.Header
	var raw []byte
	var status int
	// Authenticate the handshake exactly like the call: a session opened as one
	// principal and used as another is a seam nobody can explain.
	err := c.withRetries(ctx, cred, func(tok string) (int, []byte, error) {
		s, b, err := c.do(ctx, http.MethodPost, c.toolURL(ns, server), c.mcpHeaders(ctx, tok), initBody, &hdr)
		raw, status = b, s
		return s, b, err
	})
	if err != nil {
		return "", err
	}
	sid = hdr.Get("Mcp-Session-Id")
	if sid == "" {
		// Some servers are stateless and issue no session id. HTTP 200 with a
		// JSON-RPC result means live; anything else is a failure.
		if f, ok := jsonRPCFrame(raw); ok && status == http.StatusOK && len(f.Result) > 0 && len(f.Error) == 0 {
			sid = statelessSession
		} else {
			return "", fmt.Errorf("initialize %s/%s: no session id (HTTP %d): %s",
				ns, server, status, truncate(string(raw), 200))
		}
	} else {
		tok, err := cred.Token(ctx)
		if err != nil {
			return "", err
		}
		h := c.mcpHeaders(ctx, tok)
		h.Set("Mcp-Session-Id", sid)
		if _, _, err := c.do(ctx, http.MethodPost, c.toolURL(ns, server), h,
			[]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), nil); err != nil {
			return "", fmt.Errorf("notifications/initialized: %w", err)
		}
	}
	c.mu.Lock()
	c.sessions[key] = sid
	c.mu.Unlock()
	return sid, nil
}

func (c *Client) mcpHeaders(ctx context.Context, tok string) http.Header {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json, text/event-stream")
	if id := TurnID(ctx); id != "" {
		h.Set("X-Magertron-Turn-Id", id)
	}
	return h
}

// ── Retry rules (Agent Developer Guide §6) ──────────────────────────────────

const (
	maxNetworkRetries = 2
	maxShedRetries    = 3
)

// withRetries runs send with a current token and applies the retry rules:
//
//	403 "No permission for"  once, after Refresh (the roles may be stale)
//	429 "PDP at capacity"    up to 3 times, exponential backoff with jitter
//	network error            up to 2 times (callers keep their idempotency key)
//	anything else            returned as a *Refusal, never retried
func (c *Client) withRetries(ctx context.Context, cred Credential, send func(tok string) (int, []byte, error)) error {
	tok, err := cred.Token(ctx)
	if err != nil {
		return err
	}
	refreshed := false
	shed, netFail := 0, 0
	for {
		status, body, err := send(tok)
		if err != nil {
			if ctx.Err() != nil || netFail >= maxNetworkRetries {
				return err
			}
			netFail++
			if werr := sleep(ctx, backoff(netFail)); werr != nil {
				return werr
			}
			continue
		}
		if status/100 == 2 {
			return nil
		}
		r := Classify(status, body)
		switch {
		case r.Kind == KindStaleRoles && !refreshed:
			refreshed = true
			if tok, err = cred.Refresh(ctx); err != nil {
				return err
			}
			continue
		case r.Kind == KindLoadShed && shed < maxShedRetries:
			shed++
			if werr := sleep(ctx, backoff(shed)); werr != nil {
				return werr
			}
			continue
		}
		return r
	}
}

func backoff(attempt int) time.Duration {
	base := time.Duration(250*(1<<attempt)) * time.Millisecond
	j, _ := rand.Int(rand.Reader, big.NewInt(int64(base/2)+1))
	return base + time.Duration(j.Int64())
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ── JSON-RPC helpers ─────────────────────────────────────────────────────────

type rpcFrame struct {
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

// jsonRPCFrame parses a JSON-RPC response from a plain JSON body or from the
// first SSE "data:" line that carries one.
func jsonRPCFrame(raw []byte) (rpcFrame, bool) {
	var f rpcFrame
	s := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(s, "{") {
		for _, line := range strings.Split(s, "\n") {
			if after, ok := strings.CutPrefix(strings.TrimSpace(line), "data:"); ok {
				if json.Unmarshal([]byte(strings.TrimSpace(after)), &f) == nil &&
					(len(f.Result) > 0 || len(f.Error) > 0) {
					return f, true
				}
			}
		}
		return f, false
	}
	if json.Unmarshal([]byte(s), &f) != nil {
		return f, false
	}
	return f, len(f.Result) > 0 || len(f.Error) > 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
