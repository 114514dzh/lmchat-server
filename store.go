package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	ErrExists    = errors.New("account exists")
	ErrNoAccount = errors.New("no such account")
)

type Prekey struct {
	KeyID int64  `json:"keyId"`
	Blob  string `json:"blob"`
}

type Bundle struct {
	IdentityKey string  `json:"identityKey"`
	Signed      *Prekey `json:"signedPrekey"`
	OneTime     *Prekey `json:"oneTimePrekey,omitempty"`
}

type Envelope struct {
	ID      int64  `json:"id"`
	Dest    string `json:"dest"`
	Payload string `json:"payload"`
	Created int64  `json:"created"`
}

type GroupInfo struct {
	ID    string `json:"gid"`
	Name  string `json:"name"`
	Owner string `json:"owner"`
}
type Profile struct {
	AccountID   string `json:"accountId"`
	DisplayName string `json:"displayName"`
	Avatar      string `json:"avatar"`
}

type Store struct{ db *sql.DB }

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // sqlite 单写者，1 连接最稳
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS accounts(
 id TEXT PRIMARY KEY, auth_hash TEXT NOT NULL, identity_key TEXT NOT NULL,
 display_name TEXT NOT NULL DEFAULT '', avatar TEXT NOT NULL DEFAULT '',
 created INTEGER NOT NULL, last_seen INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS groups(
 id TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL, created INTEGER);
CREATE TABLE IF NOT EXISTS prekeys(
 account_id TEXT NOT NULL, key_id INTEGER NOT NULL, is_signed INTEGER NOT NULL DEFAULT 0,
 blob TEXT NOT NULL, uploaded INTEGER NOT NULL,
 PRIMARY KEY(account_id,key_id));
CREATE INDEX IF NOT EXISTS idx_prekeys_signed ON prekeys(account_id,is_signed);
CREATE TABLE IF NOT EXISTS envelopes(
 id INTEGER PRIMARY KEY AUTOINCREMENT, dest TEXT NOT NULL,
 payload TEXT NOT NULL, created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_env_dest ON envelopes(dest,id);
CREATE TABLE IF NOT EXISTS blobs(
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, size INTEGER NOT NULL,
 data BLOB NOT NULL, created INTEGER NOT NULL);`)
	return err
}

func (s *Store) CreateAccount(id, authHash, identityKey, display string, signed *Prekey, oneTime []Prekey) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM accounts WHERE id=?`, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrExists
	}
	ts := now()
	if _, err := tx.Exec(`INSERT INTO accounts(id,auth_hash,identity_key,display_name,created,last_seen) VALUES(?,?,?,?,?,?)`,
		id, authHash, identityKey, display, ts, ts); err != nil {
		return err
	}
	if signed != nil {
		if _, err := tx.Exec(`INSERT INTO prekeys(account_id,key_id,is_signed,blob,uploaded) VALUES(?,?,1,?,1)`,
			id, signed.KeyID, signed.Blob); err != nil {
			return err
		}
	}
	for _, k := range oneTime {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO prekeys(account_id,key_id,is_signed,blob,uploaded) VALUES(?,?,0,?,1)`,
			id, k.KeyID, k.Blob); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DelAccount(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM prekeys WHERE account_id=?`,
		`DELETE FROM envelopes WHERE dest=?`,
		`DELETE FROM blobs WHERE owner=?`,
		// 群主注销后群会变成孤儿：hGroupDel 查不到 owner 返回 404、
		// hGroupReg 改名也过不了鉴权，等于永久垃圾数据。一并清理。
		`DELETE FROM groups WHERE owner=?`,
		`DELETE FROM accounts WHERE id=?`,
	} {
		if _, err := tx.Exec(q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) AuthHash(id string) (string, bool) {
	var h string
	if err := s.db.QueryRow(`SELECT auth_hash FROM accounts WHERE id=?`, id).Scan(&h); err != nil {
		return "", false
	}
	return h, true
}

func (s *Store) Touch(id string) {
	s.db.Exec(`UPDATE accounts SET last_seen=? WHERE id=? AND last_seen < ?`, now(), id, now()-60)
}

func (s *Store) CountAccounts() int {
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM accounts`).Scan(&n)
	return n
}

func (s *Store) SetSignedPrekey(acc string, k Prekey) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM prekeys WHERE account_id=? AND is_signed=1`, acc); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO prekeys(account_id,key_id,is_signed,blob,uploaded) VALUES(?,?,1,?,1)`, acc, k.KeyID, k.Blob); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AddOneTime(acc string, keys []Prekey) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, k := range keys {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO prekeys(account_id,key_id,is_signed,blob,uploaded) VALUES(?,?,0,?,1)`, acc, k.KeyID, k.Blob); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) PopBundle(acc string) (*Bundle, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var idk string
	err = tx.QueryRow(`SELECT identity_key FROM accounts WHERE id=?`, acc).Scan(&idk)
	if err == sql.ErrNoRows {
		return nil, ErrNoAccount
	}
	if err != nil {
		return nil, err
	}
	b := &Bundle{IdentityKey: idk}
	var kid int64
	var blob string
	if err := tx.QueryRow(`SELECT key_id,blob FROM prekeys WHERE account_id=? AND is_signed=1 ORDER BY key_id DESC LIMIT 1`, acc).Scan(&kid, &blob); err == nil {
		b.Signed = &Prekey{KeyID: kid, Blob: blob}
	}
	row := tx.QueryRow(`DELETE FROM prekeys WHERE account_id=? AND is_signed=0 AND key_id=
		(SELECT MIN(key_id) FROM prekeys WHERE account_id=? AND is_signed=0) RETURNING key_id,blob`, acc, acc)
	if err := row.Scan(&kid, &blob); err == nil {
		b.OneTime = &Prekey{KeyID: kid, Blob: blob}
	}
	return b, tx.Commit()
}

func (s *Store) Enqueue(dest, payload string) (int64, error) {
	r, err := s.db.Exec(`INSERT INTO envelopes(dest,payload,created) VALUES(?,?,?)`, dest, payload, now())
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

func (s *Store) Fetch(dest string, after int64, limit int) []Envelope {
	rows, err := s.db.Query(`SELECT id,payload,created FROM envelopes WHERE dest=? AND id>? ORDER BY id LIMIT ?`, dest, after, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Envelope
	for rows.Next() {
		var e Envelope
		e.Dest = dest
		if rows.Scan(&e.ID, &e.Payload, &e.Created) == nil {
			out = append(out, e)
		}
	}
	return out
}

func (s *Store) Ack(dest string, ids []int64) int64 {
	if len(ids) == 0 {
		return 0
	}
	q := `DELETE FROM envelopes WHERE dest=? AND id IN (`
	args := []interface{}{dest}
	for i, id := range ids {
		if i > 0 {
			q += ","
		}
		q += "?"
		args = append(args, id)
	}
	q += ")"
	r, err := s.db.Exec(q, args...)
	if err != nil {
		return 0
	}
	n, _ := r.RowsAffected()
	return n
}

func (s *Store) PutBlob(owner string, data []byte) (string, error) {
	id := randHex(16)
	_, err := s.db.Exec(`INSERT INTO blobs(id,owner,size,data,created) VALUES(?,?,?,?,?)`, id, owner, len(data), data, now())
	return id, err
}

func (s *Store) BlobBytes(owner string) int64 {
	var n int64
	s.db.QueryRow(`SELECT COALESCE(SUM(size),0) FROM blobs WHERE owner=?`, owner).Scan(&n)
	return n
}

func (s *Store) GetBlob(id string) ([]byte, error) {
	var b []byte
	err := s.db.QueryRow(`SELECT data FROM blobs WHERE id=?`, id).Scan(&b)
	return b, err
}

func (s *Store) SetProfile(id, name, avatar string) error {
	_, err := s.db.Exec(`UPDATE accounts SET
		display_name=CASE WHEN ?='' THEN display_name ELSE ? END,
		avatar=CASE WHEN ?='' THEN avatar ELSE ? END WHERE id=?`, name, name, avatar, avatar, id)
	return err
}

func (s *Store) GetProfiles(ids []string) []Profile {
	out := []Profile{}
	for _, id := range ids {
		var p Profile
		p.AccountID = id
		if err := s.db.QueryRow(`SELECT display_name,avatar FROM accounts WHERE id=?`, id).Scan(&p.DisplayName, &p.Avatar); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// EnvelopeBytes 返回该账号当前占用的待投递消息总字节数。
// 用于发送配额：envelopes 只有 TTL 回收，此前无任何容量上限。
func (s *Store) EnvelopeBytes(dest string) int64 {
	var n int64
	s.db.QueryRow(`SELECT COALESCE(SUM(LENGTH(payload)),0) FROM envelopes WHERE dest=?`, dest).Scan(&n)
	return n
}

// EnvelopeCount 返回该账号当前待投递的消息条数。
func (s *Store) EnvelopeCount(dest string) int64 {
	var n int64
	s.db.QueryRow(`SELECT COUNT(*) FROM envelopes WHERE dest=?`, dest).Scan(&n)
	return n
}

func (s *Store) Cleanup(msgTTL, blobTTL int64) {
	s.db.Exec(`DELETE FROM envelopes WHERE created < ?`, now()-msgTTL)
	s.db.Exec(`DELETE FROM blobs WHERE created < ?`, now()-blobTTL)
}

func (s *Store) GroupReg(id, name, owner string) error {
	now := now()
	_, err := s.db.Exec(`INSERT INTO groups(id,name,owner,created) VALUES(?,?,?,?)
	 ON CONFLICT(id) DO UPDATE SET name=excluded.name`, id, name, owner, now)
	return err
}
func (s *Store) GroupSearch(q string, n int) ([]GroupInfo, error) {
	if q == "" {
		return []GroupInfo{}, nil
	}
	rows, err := s.db.Query(`SELECT id,name,owner FROM groups WHERE name LIKE ? ORDER BY created DESC LIMIT ?`, "%"+q+"%", n)
	if err != nil {
		return nil, err
	}
	out := []GroupInfo{}
	for rows.Next() {
		var g GroupInfo
		if err := rows.Scan(&g.ID, &g.Name, &g.Owner); err != nil {
			return out, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
func (s *Store) GroupOwner(id string) (string, error) {
	var o string
	err := s.db.QueryRow(`SELECT owner FROM groups WHERE id=?`, id).Scan(&o)
	return o, err
}

// OrphanGroups 返回群主已不存在的群（历史遗留：DelAccount 曾不清理 groups）。
func (s *Store) OrphanGroups() ([]GroupInfo, error) {
	rows, err := s.db.Query(`SELECT g.id,g.name,g.owner FROM groups g
		WHERE NOT EXISTS(SELECT 1 FROM accounts a WHERE a.id=g.owner)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GroupInfo{}
	for rows.Next() {
		var g GroupInfo
		if err := rows.Scan(&g.ID, &g.Name, &g.Owner); err != nil {
			return out, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// DelOrphanGroups 删除所有群主已不存在的群，返回删除条数。
func (s *Store) DelOrphanGroups() (int64, error) {
	r, err := s.db.Exec(`DELETE FROM groups WHERE NOT EXISTS(SELECT 1 FROM accounts a WHERE a.id=groups.owner)`)
	if err != nil {
		return 0, err
	}
	n, _ := r.RowsAffected()
	return n, nil
}

func (s *Store) GroupDel(id string) error {
	_, err := s.db.Exec(`DELETE FROM groups WHERE id=?`, id)
	return err
}
func now() int64 { return time.Now().Unix() }

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Store) dbWalkAccounts() {
	rows, err := s.db.Query(`SELECT id, display_name, created, last_seen FROM accounts ORDER BY created`)
	if err != nil {
		fmt.Println("db:", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		var cr, ls int64
		rows.Scan(&id, &name, &cr, &ls)
		fmt.Printf("%s  %-24s created=%s last_seen=%s\n", id, name,
			time.Unix(cr, 0).Format("2006-01-02"), time.Unix(ls, 0).Format("2006-01-02 15:04"))
	}
}
