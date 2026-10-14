package status

import (
	"context"
	"encoding/json"
	"net/http"
)

// Create writes data under key and schema only if the key is absent: one PUT
// at ?v=0. A key already there answers created false and no error — the
// caller's key names its content, so what is there is what it would write.
// It is the timeline's write; the roster's rows, rewritten every round, are
// Put's.
func (p *Page) Create(ctx context.Context, key, schema string, data any) (created bool, err error) {
	body, err := json.Marshal(struct {
		Schema string `json:"schema"`
		Data   any    `json:"data"`
	}{schema, data})
	if err != nil {
		return false, err
	}
	status, a, err := p.do(ctx, http.MethodPut, p.url(key)+"?v=0", body)
	switch {
	case err != nil:
		return false, err
	case status == http.StatusOK:
		return true, nil
	case status == http.StatusConflict && a.Code == "version_conflict":
		return false, nil
	}
	return false, &Error{Status: status, Code: a.Code, Message: a.Error}
}
