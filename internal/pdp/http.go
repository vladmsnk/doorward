package pdp

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/schema"
)

// EvaluationPath is the AuthZEN 1.0 access evaluation endpoint.
const EvaluationPath = "/access/v1/evaluation"

// MaxRequestSize bounds an evaluation request.
const MaxRequestSize = 64 << 10

// Client is a point of enforcement allowed to ask for decisions: the bearer
// token it presents, and who it is in the records.
type Client struct {
	Token string
	PEP   v0.PEP
}

// Response is the AuthZEN evaluation response. Decision is true only for
// an allowed call; Context says why.
type Response struct {
	Decision bool            `json:"decision"`
	Context  ResponseContext `json:"context"`
}

// ResponseContext is what a point of enforcement needs to act on a
// decision: the record's ID, the outcome, the reasons for a refusal, the
// approval request for a held call, and what an allowed call drew.
type ResponseContext struct {
	ID         string          `json:"id,omitempty"`
	Outcome    v0.Outcome      `json:"outcome,omitempty"`
	Reasons    []v0.Reason     `json:"reasons,omitempty"`
	Approval   *v0.ApprovalRef `json:"approval,omitempty"`
	ActionHash string          `json:"action_hash,omitempty"`
	Limits     []v0.LimitUse   `json:"limits,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// Handler serves the evaluation endpoint to the given clients. With no
// client configured, it refuses every request and says why.
func (p *PDP) Handler(clients []Client) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+EvaluationPath, func(w http.ResponseWriter, r *http.Request) {
		if len(clients) == 0 {
			writeJSON(w, http.StatusServiceUnavailable, Response{Context: ResponseContext{Error: "no point of enforcement is configured; start serve with --pep ID=TOKEN"}})
			return
		}
		pep, ok := authenticate(r, clients)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="doorward-pdp"`)
			writeJSON(w, http.StatusUnauthorized, Response{Context: ResponseContext{Error: "a point of enforcement's token is required"}})
			return
		}
		req, err := readRequest(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, Response{Context: ResponseContext{Error: err.Error()}})
			return
		}
		// One span per evaluation, continuing the caller's trace; the record
		// carries the same trace ID.
		ctx := propagation.TraceContext{}.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := p.tracer().Start(ctx, "doorward.evaluation", trace.WithSpanKind(trace.SpanKindServer))
		defer span.End()
		tid := traceID(r)
		if sc := span.SpanContext(); sc.HasTraceID() {
			tid = sc.TraceID().String()
		}
		d, err := p.Evaluate(ctx, req, pep, tid)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "the decision could not be made")
			p.log().Error("evaluation failed", "pep", pep.ID, "err", err)
			writeJSON(w, http.StatusInternalServerError, Response{Context: ResponseContext{Error: "the decision could not be made; refuse the call"}})
			return
		}
		span.SetAttributes(spanAttributes(d)...)
		writeJSON(w, http.StatusOK, Response{
			Decision: d.Outcome == v0.OutcomeAllow,
			Context: ResponseContext{
				ID: d.ID, Outcome: d.Outcome, Reasons: d.Reasons, Approval: d.Approval,
				ActionHash: d.ActionHash, Limits: d.Limits,
			},
		})
	})
	return mux
}

// authenticate finds the client whose token the request presents,
// comparing every configured token in constant time.
func authenticate(r *http.Request, clients []Client) (v0.PEP, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return v0.PEP{}, false
	}
	var found v0.PEP
	matched := 0
	for _, c := range clients {
		if subtle.ConstantTimeCompare([]byte(token), []byte(c.Token)) == 1 {
			found, matched = c.PEP, matched+1
		}
	}
	return found, matched == 1
}

// readRequest decodes an evaluation request strictly: no duplicate member,
// no unknown field, and the subject, action and resource the record needs.
func readRequest(r *http.Request) (v0.EvaluationRequest, error) {
	var req v0.EvaluationRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestSize+1))
	if err != nil {
		return req, err
	}
	if len(body) > MaxRequestSize {
		return req, fmt.Errorf("the request is larger than %d bytes", MaxRequestSize)
	}
	if err := schema.CheckDuplicateKeys(body); err != nil {
		return req, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, fmt.Errorf("not an AuthZEN evaluation request: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return req, errors.New("trailing data after the request")
	}
	switch {
	case req.Subject.Type == "" || req.Subject.ID == "":
		return req, errors.New("subject.type and subject.id are required")
	case req.Action.Name == "":
		return req, errors.New("action.name is required")
	case req.Resource.Type == "" || req.Resource.ID == "":
		return req, errors.New("resource.type and resource.id are required")
	}
	return req, nil
}

// spanAttributes describes a decision on its span. The names are doorward's
// own, not a semantic convention still in development.
func spanAttributes(d v0.Decision) []attribute.KeyValue {
	kv := []attribute.KeyValue{
		attribute.String("doorward.decision.id", d.ID),
		attribute.String("doorward.outcome", string(d.Outcome)),
		attribute.String("doorward.pep", d.PEP.ID),
		attribute.String("doorward.action", d.Request.Action.Name),
		attribute.String("doorward.resource", d.Request.Resource.ID),
	}
	if d.Principal != nil {
		kv = append(kv, attribute.String("doorward.agent", d.Principal.Agent))
	}
	if d.Grant != nil {
		kv = append(kv, attribute.String("doorward.mandate", d.Grant.Mandate))
	}
	if len(d.Reasons) > 0 {
		kv = append(kv, attribute.String("doorward.reason", string(d.Reasons[0].Code)))
	}
	if d.Approval != nil {
		kv = append(kv, attribute.String("doorward.approval", d.Approval.Request))
	}
	return kv
}

var traceparent = regexp.MustCompile(`^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$`)

// traceID takes the trace ID from a W3C traceparent header, or starts a new
// trace when there is none.
func traceID(r *http.Request) string {
	if m := traceparent.FindStringSubmatch(r.Header.Get("traceparent")); m != nil && m[1] != strings.Repeat("0", 32) {
		return m[1]
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
