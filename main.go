package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

// ---------------- config ----------------

type Config struct {
	Listen      string `json:"listen"`
	DB          string `json:"db"`
	Invite      string `json:"invite"`
	MsgTTLDays  int64  `json:"msg_ttl_days"`
	BlobTTLDays int64  `json:"blob_ttl_days"`
	BlobQuotaMB int64  `json:"blob_quota_mb"`
	// 待投递消息配额（按收件账号计）。0 表示用下面的默认值。
	// envelopes 此前只有 TTL 回收、无任何容量上限，单账号可无限灌入。
	MsgQuotaMB    int64 `json:"msg_quota_mb"`
	MsgQuotaCount int64 `json:"msg_quota_count"`
}

const (
	defMsgQuotaMB    = 200   // 单账号待投递消息总字节上限
	defMsgQuotaCount = 20000 // 单账号待投递消息条数上限
)

var (
	cfg      *Config
	store    *Store
	hub      *Hub
	cfgPath  = flag.String("config", "/opt/imserver/config.json", "config file")
	maxPay   = 350000 // envelope payload 上限(base64 字符)
	blobMax  = int64(21 << 20)
	upgrader = websocket.Upgrader{ReadBufferSize: 4096, WriteBufferSize: 4096}
)

func loadConfig(p string) (*Config, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	if c.Listen == "" || c.DB == "" {
		return nil, errors.New("config missing listen/db")
	}
	// Invite 允许为空：表示开放注册（不校验邀请码）
	if c.MsgQuotaMB <= 0 {
		c.MsgQuotaMB = defMsgQuotaMB
	}
	if c.MsgQuotaCount <= 0 {
		c.MsgQuotaCount = defMsgQuotaCount
	}
	return c, nil
}

// ---------------- ws hub ----------------

type Client struct {
	acc  string
	send chan []byte
}

type Hub struct {
	mu sync.Mutex
	m  map[string]*Client
}

func (h *Hub) register(c *Client) {
	h.mu.Lock()
	h.m[c.acc] = c
	h.mu.Unlock()
}

func (h *Hub) unregister(c *Client) {
	h.mu.Lock()
	if h.m[c.acc] == c {
		delete(h.m, c.acc)
	}
	h.mu.Unlock()
}

// 消息已先入库，WS 推送只是加速器，失败无害
func (h *Hub) push(dest string, msg []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c, ok := h.m[dest]; ok {
		select {
		case c.send <- msg:
		default:
		}
	}
}

// ---------------- auth ----------------

func validID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func validToken(s string) bool {
	if len(s) < 32 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func checkAuth(r *http.Request) (string, bool) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		tok = r.URL.Query().Get("auth")
	}
	acc, pass, ok := strings.Cut(tok, ":")
	if !ok || !validID(acc) || !validToken(pass) {
		return "", false
	}
	h, exists := store.AuthHash(acc)
	if !exists {
		return "", false
	}
	sum := sha256.Sum256([]byte(pass))
	if hex.EncodeToString(sum[:]) != h {
		return "", false
	}
	store.Touch(acc)
	return acc, true
}

type authedHandler func(acc string, w http.ResponseWriter, r *http.Request)

func authWrap(h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		acc, ok := checkAuth(r)
		if !ok {
			httpError(w, 401, "unauthorized")
			return
		}
		h(acc, w, r)
	}
}

func dlogf(f string, a ...interface{}) {
	if os.Getenv("IM_DEBUG") == "1" {
		log.Printf("[debug] "+f, a...)
	}
}
func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ---------------- rate limit (register) ----------------

var rlMu sync.Mutex
var rlMap = map[string][]int64{}

func allowRegister(ip string) bool {
	rlMu.Lock()
	defer rlMu.Unlock()
	nowTs := now()
	old := rlMap[ip][:0]
	for _, t := range rlMap[ip] {
		if nowTs-t < 3600 {
			old = append(old, t)
		}
	}
	if len(old) >= 10 {
		rlMap[ip] = old
		return false
	}
	rlMap[ip] = append(old, nowTs)
	return true
}

// ---------------- handlers ----------------

type regReq struct {
	Invite       string   `json:"invite"`
	AccountID    string   `json:"accountId"`
	Token        string   `json:"token"`
	DisplayName  string   `json:"displayName"`
	IdentityKey  string   `json:"identityKey"`
	SignedPrekey *Prekey  `json:"signedPrekey"`
	OneTime      []Prekey `json:"oneTimePrekeys"`
}

func hRegister(w http.ResponseWriter, r *http.Request) {
	ip := r.RemoteAddr
	if fwd := r.Header.Get("X-Real-IP"); fwd != "" {
		ip = fwd
	}
	if !allowRegister(ip) {
		httpError(w, 429, "try later")
		return
	}
	var q regReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&q); err != nil {
		httpError(w, 400, "bad json")
		return
	}
	// 邀请码可选：config.json 的 invite 为空串时跳过校验（开放注册）。
	// 客户端已移除邀请码输入框，配套把服务端校验改为可关闭。
	if cfg.Invite != "" && q.Invite != cfg.Invite {
		httpError(w, 403, "bad invite")
		return
	}
	if !validID(q.AccountID) || !validToken(q.Token) {
		httpError(w, 400, "bad account/token format")
		return
	}
	if utf8.RuneCountInString(q.DisplayName) > 32 || len(q.IdentityKey) > 200 || len(q.IdentityKey) == 0 {
		httpError(w, 400, "bad profile/identity")
		return
	}
	if q.SignedPrekey == nil || len(q.SignedPrekey.Blob) == 0 || len(q.SignedPrekey.Blob) > 4096 {
		httpError(w, 400, "bad signed prekey")
		return
	}
	if len(q.OneTime) > 200 {
		httpError(w, 400, "too many one-time prekeys")
		return
	}
	for _, k := range q.OneTime {
		if len(k.Blob) == 0 || len(k.Blob) > 4096 || k.KeyID < 0 || k.KeyID > 1<<31 {
			httpError(w, 400, "bad one-time prekey")
			return
		}
	}
	sum := sha256.Sum256([]byte(q.Token))
	if err := store.CreateAccount(q.AccountID, hex.EncodeToString(sum[:]), q.IdentityKey, q.DisplayName, q.SignedPrekey, q.OneTime); err != nil {
		if err == ErrExists {
			httpError(w, 409, "account exists")
			return
		}
		httpError(w, 500, "db error")
		return
	}
	log.Printf("register %s (%s) from %s", q.AccountID, q.DisplayName, ip)
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func hPrekeys(acc string, w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		httpError(w, 400, "bad id")
		return
	}
	b, err := store.PopBundle(id)
	if err == ErrNoAccount {
		httpError(w, 404, "no such account")
		return
	}
	if err != nil {
		httpError(w, 500, "db error")
		return
	}
	writeJSON(w, 200, b)
}

type addPrekeysReq struct {
	Signed  *Prekey  `json:"signedPrekey"`
	OneTime []Prekey `json:"oneTimePrekeys"`
}

func hAddPrekeys(acc string, w http.ResponseWriter, r *http.Request) {
	var q addPrekeysReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&q); err != nil {
		httpError(w, 400, "bad json")
		return
	}
	if q.Signed != nil {
		if len(q.Signed.Blob) == 0 || len(q.Signed.Blob) > 4096 {
			httpError(w, 400, "bad signed prekey")
			return
		}
		store.SetSignedPrekey(acc, *q.Signed)
	}
	if len(q.OneTime) > 200 {
		httpError(w, 400, "too many keys")
		return
	}
	for _, k := range q.OneTime {
		if len(k.Blob) == 0 || len(k.Blob) > 4096 || k.KeyID < 0 || k.KeyID > 1<<31 {
			httpError(w, 400, "bad key")
			return
		}
	}
	if len(q.OneTime) > 0 {
		store.AddOneTime(acc, q.OneTime)
	}
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

type sendReq struct {
	Dests []struct {
		AccountID string `json:"accountId"`
		Payload   string `json:"payload"`
	} `json:"dests"`
}

func hSend(acc string, w http.ResponseWriter, r *http.Request) {
	var q sendReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, int64(maxPay)+64<<10)).Decode(&q); err != nil {
		httpError(w, 400, "bad json")
		return
	}
	if len(q.Dests) == 0 || len(q.Dests) > 50 {
		httpError(w, 400, "dests 1..50")
		return
	}
	for _, d := range q.Dests {
		if !validID(d.AccountID) || len(d.Payload) == 0 || len(d.Payload) > maxPay {
			httpError(w, 400, "bad dest/payload")
			return
		}
	}
	// 配额预检：按收件账号汇总本次发送量，逐条检查会放大 N 倍开销。
	// 注意这里是 check-then-act，并发下可能略微超额；相比此前完全无上限
	// 已是数量级改善，且超出的部分仍受 TTL 回收，故不引入额外锁。
	addBytes := map[string]int64{}
	addCount := map[string]int64{}
	for _, d := range q.Dests {
		addBytes[d.AccountID] += int64(len(d.Payload))
		addCount[d.AccountID]++
	}
	for dest, add := range addBytes {
		if store.EnvelopeBytes(dest)+add > cfg.MsgQuotaMB<<20 {
			dlogf("quota bytes exceeded dest=%s have=%d add=%d", dest, store.EnvelopeBytes(dest), add)
			httpError(w, 507, "recipient quota exceeded")
			return
		}
		if store.EnvelopeCount(dest)+addCount[dest] > cfg.MsgQuotaCount {
			dlogf("quota count exceeded dest=%s have=%d add=%d", dest, store.EnvelopeCount(dest), addCount[dest])
			httpError(w, 507, "recipient quota exceeded")
			return
		}
	}
	for _, d := range q.Dests {
		id, err := store.Enqueue(d.AccountID, d.Payload)
		dlogf("enq id=%d dest=%s len=%d", id, d.AccountID, len(d.Payload))
		if err != nil {
			httpError(w, 500, "db error")
			return
		}
		hub.push(d.AccountID, mustJSON(map[string]interface{}{"type": "env", "id": id, "dest": d.AccountID, "payload": d.Payload}))
	}
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func hFetch(acc string, w http.ResponseWriter, r *http.Request) {
	after := queryInt(r, "after")
	limit := int(queryInt(r, "limit"))
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	writeJSON(w, 200, map[string]interface{}{"envs": store.Fetch(acc, after, limit)})
}

type ackReq struct {
	IDs []int64 `json:"ids"`
}

func hAck(acc string, w http.ResponseWriter, r *http.Request) {
	var q ackReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&q); err != nil || len(q.IDs) > 1000 {
		httpError(w, 400, "bad json")
		return
	}
	writeJSON(w, 200, map[string]interface{}{"deleted": store.Ack(acc, q.IDs)})
}

func hBlobPut(acc string, w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, blobMax))
	if err != nil {
		httpError(w, 413, "blob too large")
		return
	}
	if len(data) == 0 {
		httpError(w, 400, "empty blob")
		return
	}
	if store.BlobBytes(acc)+int64(len(data)) > cfg.BlobQuotaMB<<20 {
		httpError(w, 507, "quota exceeded")
		return
	}
	id, err := store.PutBlob(acc, data)
	if err != nil {
		httpError(w, 500, "db error")
		return
	}
	writeJSON(w, 200, map[string]string{"blobId": id})
}

func hBlobGet(acc string, w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if len(id) != 32 {
		httpError(w, 400, "bad id")
		return
	}
	b, err := store.GetBlob(id)
	if err != nil {
		httpError(w, 404, "no blob")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(b)
}

func hProfile(acc string, w http.ResponseWriter, r *http.Request) {
	var q struct {
		DisplayName string `json:"displayName"`
		Avatar      string `json:"avatar"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&q); err != nil {
		httpError(w, 400, "bad json")
		return
	}
	if utf8.RuneCountInString(q.DisplayName) > 32 || len(q.Avatar) > 64 {
		httpError(w, 400, "bad profile")
		return
	}
	store.SetProfile(acc, q.DisplayName, q.Avatar)
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func hDirectory(acc string, w http.ResponseWriter, r *http.Request) {
	ids := strings.Split(r.URL.Query().Get("ids"), ",")
	if len(ids) > 50 {
		ids = ids[:50]
	}
	clean := []string{}
	for _, id := range ids {
		if validID(strings.TrimSpace(id)) {
			clean = append(clean, strings.TrimSpace(id))
		}
	}
	writeJSON(w, 200, map[string]interface{}{"profiles": store.GetProfiles(clean)})
}

func hGroupReg(acc string, w http.ResponseWriter, r *http.Request) {
	var q struct {
		GID  string `json:"gid"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&q); err != nil ||
		len(q.GID) > 64 || len(q.GID) == 0 || utf8.RuneCountInString(q.Name) == 0 || utf8.RuneCountInString(q.Name) > 40 {
		httpError(w, 400, "bad params")
		return
	}
	// 目录改名仅允许群主(不能由非群主改)
	if own, err := store.GroupOwner(q.GID); err == nil {
		if own != acc {
			httpError(w, 403, "not owner")
			return
		}
	} else if err.Error() != "sql: no rows in result set" {
		httpError(w, 500, "db error")
		return
	}
	if err := store.GroupReg(q.GID, q.Name, acc); err != nil {
		httpError(w, 500, "db error")
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "1"})
}
func hGroupSearch(acc string, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if len(q) > 40 {
		q = q[:40]
	}
	gs, err := store.GroupSearch(q, 50)
	if err != nil {
		httpError(w, 500, "db error")
		return
	}
	writeJSON(w, 200, map[string]interface{}{"groups": gs})
}
func hGroupDel(acc string, w http.ResponseWriter, r *http.Request) {
	var q struct {
		GID string `json:"gid"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&q); err != nil || len(q.GID) > 64 {
		httpError(w, 400, "bad params")
		return
	}
	owner, err := store.GroupOwner(q.GID)
	if err != nil {
		httpError(w, 404, "no such group")
		return
	}
	if owner != acc {
		httpError(w, 403, "not owner")
		return
	}
	if err := store.GroupDel(q.GID); err != nil {
		httpError(w, 500, "db error")
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "1"})
}
func hHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]interface{}{"ok": true, "accounts": store.CountAccounts()})
}

// ---------------- websocket ----------------

func hWS(w http.ResponseWriter, r *http.Request) {
	acc, ok := checkAuth(r)
	if !ok {
		httpError(w, 401, "unauthorized")
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	c := &Client{acc: acc, send: make(chan []byte, 64)}
	hub.register(c)

	// 上线先补投最多 50 条，其余靠 HTTP 分页拉
	for _, e := range store.Fetch(acc, 0, 50) {
		c.send <- mustJSON(map[string]interface{}{"type": "env", "id": e.ID, "dest": e.Dest, "payload": e.Payload})
	}

	done := make(chan struct{})
	go func() { // writer
		defer func() { conn.Close() }()
		tick := time.NewTicker(25 * time.Second)
		defer tick.Stop()
		for {
			select {
			case msg, ok := <-c.send:
				if !ok {
					return
				}
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
					return
				}
			case <-tick.C:
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			case <-done:
				return
			}
		}
	}()

	conn.SetReadLimit(64 << 10)
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		var m struct {
			Type string  `json:"type"`
			IDs  []int64 `json:"ids"`
		}
		json.Unmarshal(data, &m)
		if m.Type == "ack" && len(m.IDs) > 0 && len(m.IDs) <= 1000 {
			store.Ack(acc, m.IDs)
		}
	}
	close(done)
	hub.unregister(c)
	close(c.send) // 唤醒 writer 退出
}

// ---------------- admin ----------------

func adminMain(args []string) {
	confPath := "/opt/imserver/config.json"
	// 解析后必须把 -config <path> 从 args 中剔除：此前它留在 args 里，
	// 会把子命令挤到 args[1]，switch args[0] 永远匹配不上（表现为静默无输出），
	// 使用者容易误以为"没生效"而改成不带 -config 重试，那反而会操作到默认的生产库。
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "-config" && i+1 < len(args) {
			confPath = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	args = rest
	c, err := loadConfig(confPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	st, err := OpenStore(c.DB)
	if err != nil {
		fmt.Fprintln(os.Stderr, "db:", err)
		os.Exit(1)
	}
	if len(args) == 0 {
		fmt.Println("usage: imserver -admin [list|del <id>|invite <code>|cleanup|orphan-groups [--del]]")
		return
	}
	switch args[0] {
	case "list":
		st.dbWalkAccounts()
	case "del":
		if len(args) < 2 {
			fmt.Println("del <id>")
			return
		}
		// 必须检查返回值：此前忽略错误，删除失败（如权限不足、库只读）
		// 也会打印 "deleted"，与博客那处"静默失败"是同一类问题。
		if err := st.DelAccount(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "del failed:", err)
			os.Exit(1)
		}
		fmt.Println("deleted", args[1])
	case "cleanup":
		st.Cleanup(c.MsgTTLDays*86400, c.BlobTTLDays*86400)
		fmt.Println("cleanup done")
	case "orphan-groups":
		// 默认只列出，加 --del 才真正删除
		if len(args) > 1 && args[1] == "--del" {
			n, err := st.DelOrphanGroups()
			if err != nil {
				fmt.Fprintln(os.Stderr, "db:", err)
				os.Exit(1)
			}
			fmt.Printf("deleted %d orphan group(s)\n", n)
			return
		}
		gs, err := st.OrphanGroups()
		if err != nil {
			fmt.Fprintln(os.Stderr, "db:", err)
			os.Exit(1)
		}
		if len(gs) == 0 {
			fmt.Println("no orphan groups")
			return
		}
		for _, g := range gs {
			fmt.Printf("%s  %-20s owner=%s (已注销)\n", g.ID, g.Name, g.Owner)
		}
		fmt.Printf("共 %d 个；加 --del 删除\n", len(gs))
	case "invite":
		if len(args) < 2 {
			fmt.Println("invite <new-code>")
			return
		}
		c.Invite = args[1]
		b, _ := json.MarshalIndent(c, "", "  ")
		// 写配置同样要检查：失败时提示语会误导成"已更新"
		if err := os.WriteFile(confPath, b, 0640); err != nil {
			fmt.Fprintln(os.Stderr, "write config failed:", err)
			os.Exit(1)
		}
		fmt.Println("invite updated")
	}
}

// ---------------- main ----------------

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-admin" {
		adminMain(os.Args[2:])
		return
	}
	flag.Parse()
	c, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatal("config: ", err)
	}
	cfg = c
	store, err = OpenStore(c.DB)
	if err != nil {
		log.Fatal("db: ", err)
	}
	hub = &Hub{m: map[string]*Client{}}

	go func() { // TTL 清理
		for {
			store.Cleanup(c.MsgTTLDays*86400, c.BlobTTLDays*86400)
			time.Sleep(6 * time.Hour)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/register", hRegister)
	mux.HandleFunc("GET /v1/prekeys/{id}", authWrap(hPrekeys))
	mux.HandleFunc("POST /v1/prekeys", authWrap(hAddPrekeys))
	mux.HandleFunc("POST /v1/messages", authWrap(hSend))
	mux.HandleFunc("GET /v1/messages", authWrap(hFetch))
	mux.HandleFunc("POST /v1/ack", authWrap(hAck))
	mux.HandleFunc("POST /v1/blob", authWrap(hBlobPut))
	mux.HandleFunc("GET /v1/blob/{id}", authWrap(hBlobGet))
	mux.HandleFunc("POST /v1/profile", authWrap(hProfile))
	mux.HandleFunc("GET /v1/directory", authWrap(hDirectory))
	mux.HandleFunc("GET /v1/ws", hWS)
	mux.HandleFunc("POST /v1/groups/reg", authWrap(hGroupReg))
	mux.HandleFunc("GET /v1/groups/search", authWrap(hGroupSearch))
	mux.HandleFunc("POST /v1/groups/del", authWrap(hGroupDel))
	mux.HandleFunc("GET /health", hHealth)

	log.Printf("imserver listening on %s", c.Listen)
	srv := &http.Server{
		Addr:              c.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		// 配合 MaxOpenConns(1)：缺写超时/空闲超时时，慢连接会串行阻塞所有 DB 访问。
		// WS 走 hijack 不受这些限制影响。
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
