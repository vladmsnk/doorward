package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/store"
)

type documents struct{ pool db }

const documentColumns = "kind, name, version, digest, doc, disabled, created_at, created_by"

func scanDocument(row pgx.Row) (store.Document, error) {
	var d store.Document
	var doc string
	err := row.Scan(&d.Kind, &d.Name, &d.Version, &d.Digest, &doc, &d.Disabled, &d.CreatedAt, &d.CreatedBy)
	d.Doc = []byte(doc)
	return d, mapErr(err)
}

// Put stores doc as the next version. The version number is taken under a
// row lock on the latest version, so two concurrent writers get consecutive
// numbers instead of colliding.
func (s documents) Put(ctx context.Context, kind, name string, doc []byte, by string) (store.Document, error) {
	return s.put(ctx, kind, name, doc, false, by)
}

func (s documents) put(ctx context.Context, kind, name string, doc []byte, disabled bool, by string) (store.Document, error) {
	// Store the document in canonical form (RFC 8785), so its digest is the
	// digest of exactly the bytes that come back out, whatever key order or
	// spacing it was sent with.
	canon, digest, err := v0.CanonicalDocument(doc)
	if err != nil {
		return store.Document{}, err
	}
	var out store.Document
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext($1))", kind+"/"+name); err != nil {
			return err
		}
		var next int
		if err := tx.QueryRow(ctx,
			"SELECT coalesce(max(version), 0) + 1 FROM documents WHERE kind = $1 AND name = $2", kind, name,
		).Scan(&next); err != nil {
			return err
		}
		row := tx.QueryRow(ctx, `
			INSERT INTO documents (kind, name, version, digest, doc, disabled, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING `+documentColumns,
			kind, name, next, digest, string(canon), disabled, by)
		out, err = scanDocument(row)
		return err
	})
	return out, mapErr(err)
}

func (s documents) Current(ctx context.Context, kind, name string) (store.Document, error) {
	return scanDocument(s.pool.QueryRow(ctx,
		"SELECT "+documentColumns+" FROM current_documents WHERE kind = $1 AND name = $2", kind, name))
}

func (s documents) Version(ctx context.Context, kind, name string, version int) (store.Document, error) {
	return scanDocument(s.pool.QueryRow(ctx,
		"SELECT "+documentColumns+" FROM documents WHERE kind = $1 AND name = $2 AND version = $3", kind, name, version))
}

func (s documents) ByDigest(ctx context.Context, kind, name, digest string) (store.Document, error) {
	return scanDocument(s.pool.QueryRow(ctx,
		"SELECT "+documentColumns+" FROM documents WHERE kind = $1 AND name = $2 AND digest = $3 ORDER BY version DESC LIMIT 1",
		kind, name, digest))
}

func (s documents) List(ctx context.Context, kind string) ([]store.Document, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+documentColumns+" FROM current_documents WHERE kind = $1 ORDER BY name", kind)
	if err != nil {
		return nil, err
	}
	return collectDocuments(rows)
}

func (s documents) History(ctx context.Context, kind, name string) ([]store.Document, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+documentColumns+" FROM documents WHERE kind = $1 AND name = $2 ORDER BY version", kind, name)
	if err != nil {
		return nil, err
	}
	docs, err := collectDocuments(rows)
	if err == nil && len(docs) == 0 {
		return nil, store.ErrNotFound
	}
	return docs, err
}

func (s documents) SetDisabled(ctx context.Context, kind, name string, disabled bool, by string) (store.Document, error) {
	cur, err := s.Current(ctx, kind, name)
	if err != nil {
		return store.Document{}, err
	}
	if cur.Disabled == disabled {
		return cur, nil
	}
	return s.put(ctx, kind, name, cur.Doc, disabled, by)
}

func collectDocuments(rows pgx.Rows) ([]store.Document, error) {
	defer rows.Close()
	var out []store.Document
	for rows.Next() {
		d, err := scanDocument(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	return out, nil
}
