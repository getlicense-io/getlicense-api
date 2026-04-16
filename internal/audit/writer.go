package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Writer records domain events via the DomainEventRepository. It is
// pure — it carries no internal transaction and must be called inside
// the caller's existing tx so the event is committed atomically with
// the mutation it describes.
type Writer struct {
	repo domain.DomainEventRepository
}

// NewWriter creates a Writer backed by the given repository.
func NewWriter(repo domain.DomainEventRepository) *Writer {
	return &Writer{repo: repo}
}

// Record stamps the event with a fresh DomainEventID and the current
// timestamp, coerces nil Payload to {}, and persists it via the repo.
func (w *Writer) Record(ctx context.Context, event domain.DomainEvent) error {
	event.ID = core.NewDomainEventID()
	event.CreatedAt = time.Now().UTC()
	if event.Payload == nil {
		event.Payload = json.RawMessage(`{}`)
	}
	return w.repo.Create(ctx, &event)
}
