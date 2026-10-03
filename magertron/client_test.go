package magertron

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeJWT builds an unsigned token with the given exp. Only the payload matters
// here: the client reads exp for cache timing and never verifies.
func fakeJWT(exp time.Time, sub string) string {
	p, _ := json.Marshal(map[string]any{"sub": sub, "exp": exp.Unix()})
	return "e30." + base64.RawURLEncoding.EncodeToString(p) + ".sig"
}

type fakeGateway struct {
	mu        sync.Mutex
	exchanges []map[string]string
	calls     []http.Header
	// script for tools/call responses, consumed in order
	script []func(w http.ResponseWriter)
	tok    int
}

func (f *fakeGateway) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/token/exchange", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		_ = json.NewDecoder(r.Body).Decode(&m)
		f.mu.Lock()
		f.exchanges = append(f.exchanges, m)
		f.tok++
		n := f.tok
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fakeJWT(time.Now().Add(5*time.Minute), fmt.Sprintf("tok-%d", n)),
			"expires_in":   300,
		})
	})
	mux.HandleFunc("GET /api/v1/portal/catalog", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"namespace":"mcp-prod","name":"time","tools":[
			{"name":"now","access":"allowed","input_schema":{"type":"object"}},
			{"name":"set","access":"denied"}]}]`)
	})
	mux.HandleFunc("POST /mcp/mcp-prod/time/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case strings.Contains(string(body), `"initialize"`):
			// stateless server: 200 + result, no session header, SSE framing
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-03-26\"}}\n\n")
		case strings.Contains(string(body), `"tools/call"`):
			f.mu.Lock()
			f.calls = append(f.calls, r.Header.Clone())
			var step func(http.ResponseWriter)
			if len(f.script) > 0 {
				step, f.script = f.script[0], f.script[1:]
			}
			f.mu.Unlock()
			if step != nil {
				step(w)
				return
			}
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"12:00"}]}}`)
		default:
			t.Errorf("unexpected body %s", body)
		}
	})
	return mux
}

func newTest(t *testing.T, f *fakeGateway) (*Client, *Exchange) {
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	c, err := New(Options{GatewayURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	ex := &Exchange{Client: c, Subject: StaticToken("person-token"), Actor: StaticToken("agent-token")}
	return c, ex
}

func TestClassify(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   Kind
	}{
		{403, "No permission for MCPServer/ViewLogs in 'mcp-prod'. Principal 'x' has roles []", KindStaleRoles},
		{403, "tool-approval: pending review", KindToolApproval},
		{403, "on-behalf-of principal 'ops-admin' holds a non-delegable role (system:platform-admin): an agent may not act for an administrator", KindNonDelegable},
		{429, "Spend limit reached for mcp-prod/exa: usage $10.00 has reached the $10.00 limit; a platform-admin override is required to resume traffic", KindSpendLimit},
		{429, "Budget threshold reached for mcp-prod/exa: usage $90.00 has reached 90.00% of the $100.00 commitment (limit $90.00); a platform-admin override is required to resume traffic", KindSpendLimit},
		{429, "PDP at capacity — request shed before evaluation. This is load shedding, not a policy decision; retry shortly.", KindLoadShed},
		{401, "", KindUnauthorized},
		{500, "boom", KindOther},
	}
	for _, c := range cases {
		if got := Classify(c.status, []byte(c.body)).Kind; got != c.want {
			t.Errorf("Classify(%d, %q) = %v, want %v", c.status, c.body, got, c.want)
		}
	}
}

func TestDelegatedExchangeSendsSubjectAndActor(t *testing.T) {
	f := &fakeGateway{}
	_, ex := newTest(t, f)
	if _, err := ex.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := ex.Token(context.Background()); err != nil { // cached
		t.Fatal(err)
	}
	if len(f.exchanges) != 1 {
		t.Fatalf("exchanges = %d, want 1 (second call should hit the cache)", len(f.exchanges))
	}
	got := f.exchanges[0]
	if got["subject_token"] != "person-token" || got["actor_token"] != "agent-token" ||
		got["subject_token_type"] == "" || got["actor_token_type"] == "" {
		t.Errorf("exchange request = %v", got)
	}
}

func TestEmptyTokenFailsFast(t *testing.T) {
	f := &fakeGateway{}
	c, _ := newTest(t, f)
	ex := &Exchange{Client: c, Subject: StaticToken("")}
	if _, err := ex.Token(context.Background()); err == nil {
		t.Fatal("expected an error for an empty subject token")
	}
	if len(f.exchanges) != 0 {
		t.Fatal("an empty token must never reach the exchange")
	}
}

func TestCatalog(t *testing.T) {
	f := &fakeGateway{}
	c, ex := newTest(t, f)
	tools, err := c.Catalog(context.Background(), ex)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 2 || !tools[0].Allowed || tools[1].Allowed {
		t.Fatalf("tools = %+v", tools)
	}
}

func callNow(t *testing.T, c *Client, ex *Exchange) (json.RawMessage, error) {
	t.Helper()
	return c.CallTool(WithTurnID(context.Background(), "turn-1"), ex,
		Tool{Namespace: "mcp-prod", Server: "time", Name: "now"}, nil)
}

func TestStaleRolesRetriedOnceWithFreshTokenSameKey(t *testing.T) {
	f := &fakeGateway{script: []func(http.ResponseWriter){
		func(w http.ResponseWriter) {
			w.WriteHeader(403)
			fmt.Fprint(w, "No permission for MCPServer/Invoke in 'mcp-prod'. Principal 'a' has roles [r]")
		},
	}}
	c, ex := newTest(t, f)
	if _, err := callNow(t, c, ex); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(f.calls))
	}
	if f.calls[0].Get("Authorization") == f.calls[1].Get("Authorization") {
		t.Error("retry after a stale-roles 403 must use a re-exchanged token")
	}
	if f.calls[0].Get("Idempotency-Key") == "" || f.calls[0].Get("Idempotency-Key") != f.calls[1].Get("Idempotency-Key") {
		t.Error("a retry must carry the same Idempotency-Key")
	}
	if f.calls[0].Get("X-Magertron-Turn-Id") != "turn-1" {
		t.Error("turn id not sent")
	}
	if f.calls[0].Get("Mcp-Session-Id") != "" {
		t.Error("a stateless server must not receive Mcp-Session-Id")
	}
}

func TestStaleRolesNotRetriedTwice(t *testing.T) {
	deny := func(w http.ResponseWriter) {
		w.WriteHeader(403)
		fmt.Fprint(w, "No permission for MCPServer/Invoke in 'mcp-prod'. Principal 'a' has roles [r]")
	}
	f := &fakeGateway{script: []func(http.ResponseWriter){deny, deny, deny}}
	c, ex := newTest(t, f)
	_, err := callNow(t, c, ex)
	r, ok := err.(*Refusal)
	if !ok || r.Kind != KindStaleRoles {
		t.Fatalf("err = %v, want a stale-roles Refusal", err)
	}
	if len(f.calls) != 2 {
		t.Fatalf("calls = %d, want exactly 2 (one retry)", len(f.calls))
	}
}

func TestSpendLimitNeverRetried(t *testing.T) {
	f := &fakeGateway{script: []func(http.ResponseWriter){func(w http.ResponseWriter) {
		w.WriteHeader(429)
		fmt.Fprint(w, "Spend limit reached for mcp-prod/time: usage $1.00 has reached the $1.00 limit; a platform-admin override is required to resume traffic")
	}}}
	c, ex := newTest(t, f)
	_, err := callNow(t, c, ex)
	if r, ok := err.(*Refusal); !ok || r.Kind != KindSpendLimit {
		t.Fatalf("err = %v", err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(f.calls))
	}
}

func TestLoadShedRetriedWithSameKey(t *testing.T) {
	shed := func(w http.ResponseWriter) {
		w.WriteHeader(429)
		fmt.Fprint(w, "PDP at capacity — request shed before evaluation. This is load shedding, not a policy decision; retry shortly.")
	}
	f := &fakeGateway{script: []func(http.ResponseWriter){shed, shed}}
	c, ex := newTest(t, f)
	out, err := callNow(t, c, ex)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "12:00") {
		t.Fatalf("result = %s", out)
	}
	if len(f.calls) != 3 {
		t.Fatalf("calls = %d, want 3", len(f.calls))
	}
	k := f.calls[0].Get("Idempotency-Key")
	for _, h := range f.calls {
		if h.Get("Idempotency-Key") != k {
			t.Fatal("Idempotency-Key changed across retries")
		}
	}
}

func TestDistinctCallsGetDistinctKeys(t *testing.T) {
	f := &fakeGateway{}
	c, ex := newTest(t, f)
	for i := 0; i < 2; i++ {
		if _, err := callNow(t, c, ex); err != nil {
			t.Fatal(err)
		}
	}
	if f.calls[0].Get("Idempotency-Key") == f.calls[1].Get("Idempotency-Key") {
		t.Fatal("two different calls must not share an Idempotency-Key")
	}
}

func TestTLSVerifiedByDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler()) // self-signed
	defer srv.Close()
	c, _ := New(Options{GatewayURL: srv.URL})
	ex := &Exchange{Client: c, Subject: StaticToken("x")}
	if _, err := ex.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected a certificate error by default, got %v", err)
	}
}
