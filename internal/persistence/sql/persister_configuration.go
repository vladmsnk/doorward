package sql

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/x"
)

type documents struct{ pool db }

const documentColumns = "kind, name, version, digest, doc, disabled, created_at, created_by"

func scanDocument(row pgx.Row) (configuration.Document, error) {
	var d configuration.Document
	var doc string
	err := row.Scan(&d.Kind, &d.Name, &d.Version, &d.Digest, &doc, &d.Disabled, &d.CreatedAt, &d.CreatedBy)
	d.Doc = []byte(doc)
	return d, mapErr(err)
}

// Put stores doc as the next version. The version number is taken under a
// row lock on the latest version, so two concurrent writers get consecutive
// numbers instead of colliding.
func (s documents) Put(ctx context.Context, kind, name string, doc []byte, by string) (configuration.Document, error) {
	return s.put(ctx, kind, name, doc, false, by)
}

func (s documents) put(ctx context.Context, kind, name string, doc []byte, disabled bool, by string) (configuration.Document, error) {
	// Persister the document in canonical form (RFC 8785), so its digest is the
	// digest of exactly the bytes that come back out, whatever key order or
	// spacing it was sent with.
	canon, digest, err := v0.CanonicalDocument(doc)
	if err != nil {
		return configuration.Document{}, err
	}
	var out configuration.Document
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
		if out, err = scanDocument(row); err != nil {
			return err
		}
		return bumpConfig(ctx, tx)
	})
	return out, mapErr(err)
}

func (s documents) Current(ctx context.Context, kind, name string) (configuration.Document, error) {
	return scanDocument(s.pool.QueryRow(ctx,
		"SELECT "+documentColumns+" FROM current_documents WHERE kind = $1 AND name = $2", kind, name))
}

func (s documents) Version(ctx context.Context, kind, name string, version int) (configuration.Document, error) {
	return scanDocument(s.pool.QueryRow(ctx,
		"SELECT "+documentColumns+" FROM documents WHERE kind = $1 AND name = $2 AND version = $3", kind, name, version))
}

func (s documents) ByDigest(ctx context.Context, kind, name, digest string) (configuration.Document, error) {
	return scanDocument(s.pool.QueryRow(ctx,
		"SELECT "+documentColumns+" FROM documents WHERE kind = $1 AND name = $2 AND digest = $3 ORDER BY version DESC LIMIT 1",
		kind, name, digest))
}

func (s documents) List(ctx context.Context, kind string) ([]configuration.Document, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+documentColumns+" FROM current_documents WHERE kind = $1 ORDER BY name", kind)
	if err != nil {
		return nil, err
	}
	return collectDocuments(rows)
}

func (s documents) History(ctx context.Context, kind, name string) ([]configuration.Document, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+documentColumns+" FROM documents WHERE kind = $1 AND name = $2 ORDER BY version", kind, name)
	if err != nil {
		return nil, err
	}
	docs, err := collectDocuments(rows)
	if err == nil && len(docs) == 0 {
		return nil, x.ErrNotFound
	}
	return docs, err
}

func (s documents) SetDisabled(ctx context.Context, kind, name string, disabled bool, by string) (configuration.Document, error) {
	cur, err := s.Current(ctx, kind, name)
	if err != nil {
		return configuration.Document{}, err
	}
	if cur.Disabled == disabled {
		return cur, nil
	}
	return s.put(ctx, kind, name, cur.Doc, disabled, by)
}

func collectDocuments(rows pgx.Rows) ([]configuration.Document, error) {
	defer rows.Close()
	var out []configuration.Document
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

type secrets struct{ pool db }

func (s secrets) Put(ctx context.Context, name string, sealed []byte, by string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO secrets (name, value_enc, updated_by) VALUES ($1, $2, $3)
			ON CONFLICT (name) DO UPDATE SET value_enc = EXCLUDED.value_enc, updated_at = now(), updated_by = EXCLUDED.updated_by`,
			name, sealed, by); err != nil {
			return err
		}
		return bumpConfig(ctx, tx)
	})
}

func (s secrets) Get(ctx context.Context, name string) ([]byte, error) {
	var sealed []byte
	err := s.pool.QueryRow(ctx, "SELECT value_enc FROM secrets WHERE name = $1", name).Scan(&sealed)
	return sealed, mapErr(err)
}

func (s secrets) List(ctx context.Context) ([]configuration.SecretInfo, error) {
	rows, err := s.pool.Query(ctx, "SELECT name, created_at, updated_at, updated_by FROM secrets ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []configuration.SecretInfo
	for rows.Next() {
		var i configuration.SecretInfo
		if err := rows.Scan(&i.Name, &i.CreatedAt, &i.UpdatedAt, &i.UpdatedBy); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (s secrets) Delete(ctx context.Context, name string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "DELETE FROM secrets WHERE name = $1", name)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return x.ErrNotFound
		}
		return bumpConfig(ctx, tx)
	})
}
