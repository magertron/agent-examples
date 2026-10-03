package magertron

import (
	"fmt"
	"net/http"
	"strings"
)

// Kind classifies a refusal by what the caller should DO about it, not by its
// HTTP status. Two 403s can need opposite handling: one is fixed by fetching a
// fresh token, the other by a human approving a tool.
type Kind int

const (
	// KindOther is any refusal not listed below. Not retried.
	KindOther Kind = iota

	// KindUnauthorized is a 401: the credential was missing, malformed or
	// expired. Check that the token is non-empty before suspecting the platform.
	KindUnauthorized

	// KindStaleRoles is a 403 that names the roles the principal holds. A token
	// carries the roles its principal had when it was minted, so a permission
	// granted since then does not reach it. Retried ONCE, after re-exchanging.
	KindStaleRoles

	// KindToolApproval is a 403 because the tool's definition is waiting for a
	// human to review it. Retrying cannot help.
	KindToolApproval

	// KindNonDelegable is a 403 because the person holds a role an agent may
	// never act for (an administrator). Permanent by design.
	KindNonDelegable

	// KindSpendLimit is a 429 because the server's spend limit or budget
	// threshold is reached. A platform admin must lift it; do not retry.
	KindSpendLimit

	// KindLoadShed is a 429 sent before any policy decision was made. The only
	// 429 worth retrying, with backoff.
	KindLoadShed
)

func (k Kind) String() string {
	switch k {
	case KindUnauthorized:
		return "unauthorized"
	case KindStaleRoles:
		return "stale-roles"
	case KindToolApproval:
		return "tool-approval"
	case KindNonDelegable:
		return "non-delegable"
	case KindSpendLimit:
		return "spend-limit"
	case KindLoadShed:
		return "load-shed"
	default:
		return "other"
	}
}

// Refusal is a request the platform declined. Message is the platform's own
// text, verbatim: it names the cause, and paraphrasing it loses that.
type Refusal struct {
	Status  int
	Kind    Kind
	Message string
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("magertron refused (HTTP %d, %s): %s", r.Status, r.Kind, r.Message)
}

// Classify turns a non-2xx response into a Refusal. The match strings are the
// platform's documented messages (Agent Developer Guide §9).
func Classify(status int, body []byte) *Refusal {
	msg := strings.TrimSpace(string(body))
	r := &Refusal{Status: status, Message: msg}
	switch {
	case status == http.StatusUnauthorized:
		r.Kind = KindUnauthorized
	case status == http.StatusTooManyRequests && strings.Contains(msg, "PDP at capacity"):
		r.Kind = KindLoadShed
	case status == http.StatusTooManyRequests &&
		(strings.Contains(msg, "Spend limit reached") || strings.Contains(msg, "Budget threshold reached")):
		r.Kind = KindSpendLimit
	case status == http.StatusForbidden && strings.Contains(msg, "tool-approval:"):
		r.Kind = KindToolApproval
	case status == http.StatusForbidden && strings.Contains(msg, "non-delegable role"):
		r.Kind = KindNonDelegable
	case status == http.StatusForbidden && strings.Contains(msg, "No permission for"):
		r.Kind = KindStaleRoles
	default:
		r.Kind = KindOther
	}
	return r
}
