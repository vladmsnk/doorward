package journal

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/vladmsnk/doorward/internal/x"
)

// ExportPage is how many records Export reads from the store at a time.
const ExportPage = 1000

// Export writes the records from seq on, up to the head as it stands when
// Export starts, as JSON lines.
func Export(ctx context.Context, m Manager, from uint64, w io.Writer) error {
	head, err := m.Head(ctx)
	if errors.Is(err, x.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	for seq := from; seq <= head.Chain.Seq; seq += ExportPage {
		page, err := m.Range(ctx, seq, seq+ExportPage)
		if err != nil {
			return err
		}
		for _, rec := range page {
			line, err := json.Marshal(rec)
			if err != nil {
				return err
			}
			if _, err := w.Write(append(line, '\n')); err != nil {
				return err
			}
		}
	}
	return nil
}
