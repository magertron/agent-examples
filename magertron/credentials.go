package magertron

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Credential supplies the bearer token for a request.
//
// Token returns a token valid right now, refreshing it if needed. Refresh
// discards any cached token and obtains a new one: call it once after a
// KindStaleRoles refusal, because a re-exchange reads the principal's roles
// fresh.
type Credential interface {
	Token(ctx context.Context) (string, error)
	Refresh(ctx context.Context) (string, error)
}

// TokenSource produces a raw token: a Magertron-issued service-account or
// person token (Path A) or an access token from your directory (Path B).
type TokenSource func(ctx context.Context) (string, error)

// StaticToken returns the same token every time. Use it for a TokenSource, or
// as a Credential for a quick test with a raw service-account token. Prefer
// Exchange for real use: a raw token keeps the roles it was created with.
func StaticToken(tok string) TokenSource {
	return func(context.Context) (string, error) {
		if strings.TrimSpace(tok) == "" {
			// An empty token produces "Authorization: Bearer" and a 401 that
			// reads like a permissions problem. Fail here instead.
			return "", errors.New("token is empty")
		}
		return tok, nil
	}
}

// ClientCredentials fetches an access token from your directory with the OAuth
// client-credentials grant (Path B). audience must be the exchange audience
// your platform team gave you — a label stamped into the token, not a URL that
// is called.
func ClientCredentials(hc *http.Client, tokenURL, clientID, clientSecret, audience string) TokenSource {
	return func(ctx context.Context) (string, error) {
		body, _ := json.Marshal(map[string]string{
			"grant_type":    "client_credentials",
			"client_id":     clientID,
			"client_secret": clientSecret,
			"audience":      audience,
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewReader(body))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			return "", fmt.Errorf("directory token request: %w", err)
		}
		defer resp.Body.Close()
		var out struct {
			AccessToken string `json:"access_token"`
		}
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		if resp.StatusCode/100 != 2 {
			// The directory's own error, verbatim: "invalid_client" and
			// "access_denied" are different problems.
			return "", fmt.Errorf("directory returned %d: %s", resp.StatusCode, strings.TrimSpace(buf.String()))
		}
		if err := json.Unmarshal(buf.Bytes(), &out); err != nil || out.AccessToken == "" {
			return "", errors.New("directory response carried no access_token")
		}
		return out.AccessToken, nil
	}
}

// Exchange is a Credential that trades tokens at Magertron's token exchange for
// a short-lived Magertron token, and caches it until shortly before it expires.
//
//   - Subject only: your agent acting as itself. Subject is your service-account
//     token (Path A) or your directory token (Path B).
//   - Subject + Actor: your agent acting FOR a person. Subject is the PERSON's
//     token, Actor is YOURS. The RFC's names read backwards; reversing them
//     produces a call that looks delegated and is not.
type Exchange struct {
	Client  *Client     // the Magertron client the exchange is sent through
	Subject TokenSource // who the call is FOR
	Actor   TokenSource // who is ACTING; nil when the agent acts as itself

	mu      sync.Mutex
	cached  string
	expires time.Time
}

// refreshMargin is long enough that a token cannot expire in flight between
// the cache check and the gateway reading it.
const refreshMargin = 30 * time.Second

func (e *Exchange) Token(ctx context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cached != "" && time.Now().Add(refreshMargin).Before(e.expires) {
		return e.cached, nil
	}
	return e.exchangeLocked(ctx)
}

func (e *Exchange) Refresh(ctx context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cached = ""
	return e.exchangeLocked(ctx)
}

func (e *Exchange) exchangeLocked(ctx context.Context) (string, error) {
	subject, err := e.Subject(ctx)
	if err != nil {
		return "", fmt.Errorf("subject token: %w", err)
	}
	req := map[string]string{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":      subject,
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
	}
	if e.Actor != nil {
		actor, err := e.Actor(ctx)
		if err != nil {
			// Never fall back to the subject alone: that silently turns a
			// delegated call into a different principal's call.
			return "", fmt.Errorf("actor token: %w", err)
		}
		req["actor_token"] = actor
		req["actor_token_type"] = "urn:ietf:params:oauth:token-type:jwt"
	}
	body, _ := json.Marshal(req)
	status, raw, err := e.Client.do(ctx, http.MethodPost, e.Client.controlURL("/api/v1/token/exchange"),
		nil, body, nil)
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	if status/100 != 2 {
		return "", Classify(status, raw)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.AccessToken == "" {
		return "", errors.New("token exchange response carried no access_token")
	}
	// Prefer the token's own exp: it is the value the gateway enforces.
	ttl := time.Duration(out.ExpiresIn) * time.Second
	if exp, ok := jwtExpiry(out.AccessToken); ok {
		ttl = time.Until(exp)
	}
	if ttl <= 0 {
		return "", errors.New("token exchange returned a token that is already expired")
	}
	e.cached, e.expires = out.AccessToken, time.Now().Add(ttl)
	return e.cached, nil
}

// static adapts a TokenSource to a Credential with nothing to refresh.
type static struct{ src TokenSource }

// Static wraps a TokenSource as a Credential without exchanging it. Useful for
// a first test; see StaticToken for why Exchange is the better default.
func Static(src TokenSource) Credential { return &static{src} }

func (s *static) Token(ctx context.Context) (string, error)   { return s.src(ctx) }
func (s *static) Refresh(ctx context.Context) (string, error) { return s.src(ctx) }

// jwtExpiry reads exp from a JWT WITHOUT verifying it. Safe only because it is
// used for cache timing, never for a decision: the gateway verifies the
// signature, and a wrong exp here causes an early refresh, not a trust failure.
func jwtExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp == 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}
