package x

import (
	"bufio"
	"bytes"
	"io"
	"strings"
)

// Event is one server-sent event: a block of lines that ends with an
// empty line.
type Event struct {
	// Data is the event's data lines, joined by newlines. It is nil when
	// the event had no data line, and empty when its data lines were.
	Data []byte
	// Fields are the event's other lines as they came: event, id and retry
	// fields, and comments.
	Fields []string
}

// ReadEvents reads a text/event-stream, calling fn with each event as it
// ends, and stops at the first error fn returns. A line longer than
// maxLine bytes is an error.
func ReadEvents(r io.Reader, maxLine int, fn func(Event) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, min(64<<10, maxLine)), maxLine)
	var data [][]byte
	var fields []string
	emit := func() error {
		if data == nil && fields == nil {
			return nil
		}
		e := Event{Fields: fields}
		if data != nil {
			e.Data = append([]byte{}, bytes.Join(data, []byte("\n"))...)
		}
		data, fields = nil, nil
		return fn(e)
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if err := emit(); err != nil {
				return err
			}
		case strings.HasPrefix(line, "data:"):
			data = append(data, []byte(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")))
		default:
			fields = append(fields, line)
		}
	}
	if err := emit(); err != nil {
		return err
	}
	return sc.Err()
}
