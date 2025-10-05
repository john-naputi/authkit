package internaltest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/john-naputi/authkit"
	"github.com/john-naputi/authkit/httpapi"
)

/**************
 * FAKES
 **************/

// fakeClock lets tests advance time deterministically.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }

// memStore is a simple in-memory Store impl with a few test hooks.
type memStore struct {
	mu sync.Mutex

	usersByEmail map[string]authkit.User
	usersByID    map[string]authkit.User

	loginByHash map[string]*loginLink
	sessByHash  map[string]*session

	touchCountByID map[string]int
}

type loginLink struct {
	ID           string
	UserID       string
	Hash         string
	RedirectPath *string
	ExpiresAt    time.Time
	ConsumedAt   *time.Time
}

type session struct {
	ID         string
	UserID     string
	Hash       string
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
}

func toAuthLoginLink(l *loginLink) authkit.LoginLink {
	// We don't store CreatedAt/IP/UA in this mem store; nil/zero is fine for tests.
	return authkit.LoginLink{
		ID:           l.ID,
		UserID:       l.UserID,
		RedirectPath: l.RedirectPath,
		ExpiresAt:    l.ExpiresAt,
		ConsumedAt:   l.ConsumedAt,
		CreatedIP:    nil,
		CreatedUA:    nil,
		CreatedAt:    time.Time{},
	}
}

func toAuthSession(s *session) authkit.Session {
	return authkit.Session{
		ID:         s.ID,
		UserID:     s.UserID,
		ExpiresAt:  s.ExpiresAt,
		RevokedAt:  s.RevokedAt,
		LastUsedAt: s.LastUsedAt,
		CreatedIP:  nil,
		CreatedUA:  nil,
		CreatedAt:  time.Time{},
	}
}

func newMemStore() *memStore {
	return &memStore{
		usersByEmail:   make(map[string]authkit.User),
		usersByID:      make(map[string]authkit.User),
		loginByHash:    make(map[string]*loginLink),
		sessByHash:     make(map[string]*session),
		touchCountByID: make(map[string]int),
	}
}

func (m *memStore) UpsertUserByEmail(_ context.Context, email string) (authkit.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.usersByEmail[email]; ok {
		return u, nil
	}
	id := randID()
	now := time.Now()
	u := authkit.User{ID: id, Email: email, CreatedAt: now, UpdatedAt: now}
	m.usersByEmail[email] = u
	m.usersByID[id] = u
	return u, nil
}

func (m *memStore) CreateLoginLink(ctx context.Context, tokenHash []byte, userID string, redirectPath *string, expiresAt time.Time, ip *string, ua *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := string(tokenHash)
	m.loginByHash[h] = &loginLink{
		ID:           randID(),
		UserID:       userID,
		Hash:         h,
		RedirectPath: redirectPath,
		ExpiresAt:    expiresAt,
	}
	return nil
}

func (m *memStore) GetLoginLinkByHash(_ context.Context, tokenHash []byte) (authkit.LoginLink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.loginByHash[string(tokenHash)]
	if l == nil {
		return authkit.LoginLink{}, errNotFound
	}
	return toAuthLoginLink(l), nil
}

func (m *memStore) ConsumeLoginLink(ctx context.Context, id string) (userID string, redirectPath *string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, l := range m.loginByHash {
		if l.ID == id {
			now := time.Now()
			l.ConsumedAt = &now
			return l.UserID, l.RedirectPath, nil
		}
	}
	return "", nil, errNotFound
}

func (m *memStore) CreateSession(ctx context.Context, userID string, tokenHash []byte, expiresAt time.Time, ip *string, ua *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := randID()
	h := string(tokenHash)
	m.sessByHash[h] = &session{ID: id, UserID: userID, Hash: h, ExpiresAt: expiresAt}
	return nil
}

func (m *memStore) GetSessionByTokenHash(_ context.Context, tokenHash []byte) (authkit.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessByHash[string(tokenHash)]
	if s == nil {
		return authkit.Session{}, errNotFound
	}
	return toAuthSession(s), nil
}

func (m *memStore) TouchSessionLastUsed(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sessByHash {
		if s.ID == sessionID {
			now := time.Now()
			s.LastUsedAt = &now
			m.touchCountByID[sessionID]++
			return nil
		}
	}
	return errNotFound
}

func (m *memStore) RevokeSessionWithTokenHash(ctx context.Context, tokenHash []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.sessByHash[string(tokenHash)]; s != nil {
		now := time.Now()
		s.RevokedAt = &now
	}
	return nil
}

func (m *memStore) GetUserByID(ctx context.Context, id string) (authkit.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.usersByID[id]
	if !ok {
		return authkit.User{}, errNotFound
	}
	return u, nil
}

var errNotFound = &nf{}

type nf struct{}

func (*nf) Error() string { return "not found" }

type fakeMailer struct {
	mu   sync.Mutex
	last string
}

func (f *fakeMailer) SendMagicLinkWithTTL(ctx context.Context, to, link string, ttl time.Duration) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last = link
	return "fake-msg-id", nil
}

func (f *fakeMailer) LastLink() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

func randID() string {
	return strings.ReplaceAll(time.Now().Format("20060102150405.000000000"), ".", "")
}

/**************
 * HELPERS
 **************/

type testRig struct {
	t          *testing.T
	srv        *httptest.Server
	mail       *fakeMailer
	store      *memStore
	clock      *fakeClock
	cfg        authkit.Config
	cookieName string
}

func newRig(t *testing.T, env string) *testRig {
	t.Helper()
	store := newMemStore()
	mail := &fakeMailer{}
	clock := &fakeClock{t: time.Date(2025, 10, 4, 12, 0, 0, 0, time.UTC)}

	cfg := authkit.Config{
		AppOrigin:       "http://example.test",
		Env:             env,
		CookieName:      "ak_session",
		DefaultRedirect: "/",
		SessionTTL:      1 * time.Hour,
		LinkTTL:         2 * time.Minute,
		CORSOverrides:   "http://example.test",
	}
	s := authkit.New(cfg, authkit.Deps{Store: store, Mail: mail, Clock: clock})
	ts := httptest.NewServer(s.Handler())

	return &testRig{
		t:          t,
		srv:        ts,
		mail:       mail,
		store:      store,
		clock:      clock,
		cfg:        cfg,
		cookieName: cfg.CookieName,
	}
}

func (r *testRig) close() { r.srv.Close() }

func (r *testRig) start(email, path string, devReturn bool) (*http.Response, string) {
	body := httpapi.StartRequest{Email: email, RedirectPath: path}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", r.srv.URL+"/auth/start", bytes.NewReader(b))
	req.Header.Set("Origin", "http://example.test")
	req.Header.Set("Content-Type", "application/json")
	if devReturn {
		req.Header.Set("X-Debug-Return-Link", "1")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatalf("start: %v", err)
	}
	return resp, r.mail.LastLink()
}

func extractTokenFromDevLink(link string) string {
	if link == "" {
		return ""
	}
	i := strings.Index(link, "token=")
	if i < 0 {
		return ""
	}
	return link[i+len("token="):]
}

func exchangeJSON(url, token string) (*http.Response, httpapi.ExchangeResponse) {
	reqBody := httpapi.ExchangeRequest{Token: token}
	b, _ := json.Marshal(reqBody)
	resp, _ := http.Post(url+"/auth/exchange", "application/json", bytes.NewReader(b))
	var ex httpapi.ExchangeResponse
	_ = json.NewDecoder(resp.Body).Decode(&ex)
	return resp, ex
}

func setCookieHeader(cookieName, token string) string {
	return cookieName + "=" + token
}

/**************
 * TESTS
 **************/

func TestHappyPath_Start_Exchange_Me(t *testing.T) {
	r := newRig(t, "dev")
	defer r.close()

	// Start (dev: returns magic_link when header present)
	resp, _ := r.start("test@example.com", "/dashboard", true)
	if resp.StatusCode != 200 {
		t.Fatalf("start status=%d", resp.StatusCode)
	}

	// Extract token from dev link
	token := extractTokenFromDevLink(r.mail.LastLink())
	if token == "" {
		t.Fatal("missing dev magic link token")
	}

	// Exchange → cookie + JSON token
	resp2, ex := exchangeJSON(r.srv.URL, token)
	if resp2.StatusCode != 200 {
		t.Fatalf("exchange status=%d", resp2.StatusCode)
	}
	if ex.AccessToken == "" {
		t.Fatal("missing access_token")
	}
	// Check security headers present
	if rp := resp2.Header.Get("Referrer-Policy"); rp != "no-referrer" {
		t.Fatalf("missing Referrer-Policy, got %q", rp)
	}
	if cc := resp2.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("missing Cache-Control no-store, got %q", cc)
	}

	// /me with Bearer
	reqMe, _ := http.NewRequest("GET", r.srv.URL+"/me", nil)
	reqMe.Header.Set("Authorization", "Bearer "+ex.AccessToken)
	meResp, _ := http.DefaultClient.Do(reqMe)
	if meResp.StatusCode != 200 {
		t.Fatalf("/me status=%d", meResp.StatusCode)
	}
}

func TestMagicLinkReuse_Gone(t *testing.T) {
	r := newRig(t, "dev")
	defer r.close()

	_, _ = r.start("reuse@example.com", "", true)
	token := extractTokenFromDevLink(r.mail.LastLink())

	// first exchange ok
	resp1, _ := exchangeJSON(r.srv.URL, token)
	if resp1.StatusCode != 200 {
		t.Fatalf("first exchange=%d", resp1.StatusCode)
	}

	// second reuse → 410
	resp2, _ := exchangeJSON(r.srv.URL, token)
	if resp2.StatusCode != http.StatusGone {
		t.Fatalf("second exchange status=%d, want 410", resp2.StatusCode)
	}
}

func TestExpiredToken_Gone(t *testing.T) {
	r := newRig(t, "dev")
	defer r.close()

	_, _ = r.start("exp@example.com", "", true)
	token := extractTokenFromDevLink(r.mail.LastLink())
	if token == "" {
		t.Fatal("no token")
	}

	// Advance fake clock past LinkTTL
	r.clock.t = r.clock.t.Add(r.cfg.LinkTTL + 1*time.Second)

	resp, _ := exchangeJSON(r.srv.URL, token)
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("exchange after expiry = %d, want 410", resp.StatusCode)
	}
}

func TestLogout_Then_Me_Unauthorized(t *testing.T) {
	r := newRig(t, "dev")
	defer r.close()

	_, _ = r.start("logout@example.com", "", true)
	token := extractTokenFromDevLink(r.mail.LastLink())
	resp, ex := exchangeJSON(r.srv.URL, token)
	if resp.StatusCode != 200 {
		t.Fatalf("exchange=%d", resp.StatusCode)
	}

	// Logout with Bearer
	reqOut, _ := http.NewRequest("POST", r.srv.URL+"/auth/logout", nil)
	reqOut.Header.Set("Authorization", "Bearer "+ex.AccessToken)
	outResp, _ := http.DefaultClient.Do(reqOut)
	if outResp.StatusCode != 200 {
		t.Fatalf("logout=%d", outResp.StatusCode)
	}

	// /me should 401
	reqMe, _ := http.NewRequest("GET", r.srv.URL+"/me", nil)
	reqMe.Header.Set("Authorization", "Bearer "+ex.AccessToken)
	meResp, _ := http.DefaultClient.Do(reqMe)
	if meResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("me after logout=%d, want 401", meResp.StatusCode)
	}
}

func TestCORS_Preflight_Allowed(t *testing.T) {
	r := newRig(t, "dev")
	defer r.close()

	req, _ := http.NewRequest("OPTIONS", r.srv.URL+"/auth/start", nil)
	req.Header.Set("Origin", "http://example.test")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight status=%d", resp.StatusCode)
	}
	if ao := resp.Header.Get("Access-Control-Allow-Origin"); ao != "http://example.test" {
		t.Fatalf("ACAO=%q", ao)
	}
}

func TestCORS_Preflight_Forbidden(t *testing.T) {
	r := newRig(t, "dev")
	defer r.close()

	req, _ := http.NewRequest("OPTIONS", r.srv.URL+"/auth/start", nil)
	req.Header.Set("Origin", "http://evil.test")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("preflight forbidden status=%d, want 403", resp.StatusCode)
	}
}

func TestRateLimit_IP_429(t *testing.T) {
	r := newRig(t, "dev")
	defer r.close()

	// Use different emails to avoid the per-email (3/10min) cap.
	for i := 0; i < 5; i++ {
		email := fmt.Sprintf("ip-%d@example.com", i)
		resp, _ := r.start(email, "", true)
		if resp.StatusCode != 200 {
			t.Fatalf("warmup #%d status=%d", i, resp.StatusCode)
		}
	}

	// 6th request, same IP, new email -> should hit per-IP (5/min) limit
	resp, _ := r.start("ip-final@example.com", "", true)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("6th /auth/start status=%d, want 429", resp.StatusCode)
	}
}

func TestRateLimit_Email_429(t *testing.T) {
	r := newRig(t, "dev")
	defer r.close()

	// email limiter (3/10min) is enforced inside /auth/start after JSON parse
	for i := 0; i < 3; i++ {
		resp, _ := r.start("rl-email@example.com", "", true)
		if resp.StatusCode != 200 {
			t.Fatalf("warmup #%d=%d", i, resp.StatusCode)
		}
	}
	resp, _ := r.start("rl-email@example.com", "", true)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("4th same-email status=%d, want 429", resp.StatusCode)
	}
}

func TestRedirectSafety_InvalidPath_400(t *testing.T) {
	r := newRig(t, "dev")
	defer r.close()

	body := httpapi.StartRequest{Email: "evil@example.com", RedirectPath: "https://evil.com"}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", r.srv.URL+"/auth/start", bytes.NewReader(b))
	req.Header.Set("Origin", "http://example.test")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Debug-Return-Link", "1")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid redirect_path status=%d, want 400", resp.StatusCode)
	}
}

func TestBearerPrecedence_OverCookie(t *testing.T) {
	r := newRig(t, "dev")
	defer r.close()

	// Create session A (cookie)
	_, _ = r.start("prio@example.com", "", true)
	tokenA := extractTokenFromDevLink(r.mail.LastLink())
	_, exA := exchangeJSON(r.srv.URL, tokenA)

	// Create session B (Bearer)
	_, _ = r.start("prio@example.com", "", true)
	tokenB := extractTokenFromDevLink(r.mail.LastLink())
	_, exB := exchangeJSON(r.srv.URL, tokenB)

	// Build /me with BOTH: cookie=A and Bearer=B. Bearer must win.
	req, _ := http.NewRequest("GET", r.srv.URL+"/me", nil)
	req.Header.Set("Authorization", "Bearer "+exB.AccessToken)
	req.Header.Set("Cookie", setCookieHeader(r.cookieName, exA.AccessToken))
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("/me with both tokens status=%d", resp.StatusCode)
	}

	// Sanity check: ensure we touched last_used for Bearer session at least once.
	// We can approximate by hashing the raw token to locate the session record.
	hashB := sha256.Sum256([]byte(exB.AccessToken))
	maybe := r.store.sessByHash[string(hashB[:])]
	if maybe == nil {
		t.Fatal("missing session B in store")
	}
	sessIDB := maybe.ID
	if r.store.touchCountByID[sessIDB] < 1 {
		t.Fatalf("expected TouchSessionLastUsed on Bearer session, got %d", r.store.touchCountByID[sessIDB])
	}
}

func TestLastUsed_Touch_Throttle(t *testing.T) {
	r := newRig(t, "dev")
	defer r.close()

	// Create session
	_, _ = r.start("touch@example.com", "", true)
	token := extractTokenFromDevLink(r.mail.LastLink())
	_, ex := exchangeJSON(r.srv.URL, token)

	// Find session ID for touch counter
	h := sha256.Sum256([]byte(ex.AccessToken))
	s := r.store.sessByHash[string(h[:])]
	if s == nil {
		t.Fatal("missing session")
	}

	// Call /me twice quickly
	req1, _ := http.NewRequest("GET", r.srv.URL+"/me", nil)
	req1.Header.Set("Authorization", "Bearer "+ex.AccessToken)
	_, _ = http.DefaultClient.Do(req1)

	req2, _ := http.NewRequest("GET", r.srv.URL+"/me", nil)
	req2.Header.Set("Authorization", "Bearer "+ex.AccessToken)
	_, _ = http.DefaultClient.Do(req2)

	// Throttle window is 60s; should have at most 1 touch.
	if got := r.store.touchCountByID[s.ID]; got > 1 {
		t.Fatalf("expected <=1 touches in throttle window, got %d", got)
	}
}

func TestStart_InvalidJSON_400(t *testing.T) {
	r := newRig(t, "dev")
	defer r.close()

	req, _ := http.NewRequest("POST", r.srv.URL+"/auth/start", bytes.NewBufferString(`{"email":`))
	req.Header.Set("Origin", "http://example.test")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

func TestExchange_InvalidTokenFormat_400(t *testing.T) {
	r := newRig(t, "dev")
	defer r.close()

	reqBody := httpapi.ExchangeRequest{Token: "####not-base64url####"}
	b, _ := json.Marshal(reqBody)
	resp, _ := http.Post(r.srv.URL+"/auth/exchange", "application/json", bytes.NewReader(b))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 invalid_token, got %d", resp.StatusCode)
	}
}

func TestCookie_SecureFlag_DevVsProd(t *testing.T) {
	// dev: Secure should be false
	r1 := newRig(t, "dev")
	defer r1.close()
	_, _ = r1.start("cookie-dev@example.com", "", true)
	token := extractTokenFromDevLink(r1.mail.LastLink())
	resp, _ := exchangeJSON(r1.srv.URL, token)
	h := resp.Header.Get("Set-Cookie")
	if strings.Contains(h, "Secure") {
		t.Fatalf("dev cookie should NOT be Secure, got %q", h)
	}

	// prod: Secure should be true
	r2 := newRig(t, "prod")
	defer r2.close()
	_, _ = r2.start("cookie-prod@example.com", "", true)
	token2 := extractTokenFromDevLink(r2.mail.LastLink())
	resp2, _ := exchangeJSON(r2.srv.URL, token2)
	h2 := resp2.Header.Get("Set-Cookie")
	if !strings.Contains(h2, "Secure") {
		t.Fatalf("prod cookie MUST be Secure, got %q", h2)
	}
}

func TestCallback_SetsCookie_AndRedirects(t *testing.T) {
	r := newRig(t, "dev")
	defer r.close()

	// issue link with redirect (dev returns magic_link)
	_, _ = r.start("cb@example.com", "/home", true)
	link := r.mail.LastLink()
	if link == "" {
		t.Fatal("no link")
	}

	// Extract token from the dev link (which points at AppOrigin=example.test)
	token := extractTokenFromDevLink(link)
	if token == "" {
		t.Fatal("no token")
	}

	// Hit the callback on the *test server*, not example.test
	cb := r.srv.URL + "/auth/callback?token=" + token

	// Do not auto-follow redirects so we can inspect Location + Set-Cookie
	req, _ := http.NewRequest("GET", cb, nil)
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc != "/home" {
		t.Fatalf("want /home redirect, got %q", loc)
	}
	if sc := resp.Header.Get("Set-Cookie"); sc == "" {
		t.Fatal("expected Set-Cookie on callback")
	}
}

func TestCallbackJSON_NotMountedInProd(t *testing.T) {
	r := newRig(t, "prod")
	defer r.close()

	req, _ := http.NewRequest("GET", r.srv.URL+"/auth/callback/json?token=abc", nil)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("prod should 404 /auth/callback/json, got %d", resp.StatusCode)
	}
}

func TestRateLimit_WindowReset(t *testing.T) {
	r := newRig(t, "dev")
	defer r.close()

	// Hit 5 times (per-IP limit)
	for i := 0; i < 5; i++ {
		email := fmt.Sprintf("win-%d@example.com", i)
		resp, _ := r.start(email, "", true)
		if resp.StatusCode != 200 {
			t.Fatalf("warmup #%d=%d", i, resp.StatusCode)
		}
	}
	// 6th → 429
	resp, _ := r.start("win-final@example.com", "", true)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", resp.StatusCode)
	}

	// Advance fake clock 61s → window rotates → allowed again
	r.clock.t = r.clock.t.Add(61 * time.Second)
	resp2, _ := r.start("win-after@example.com", "", true)
	if resp2.StatusCode != 200 {
		t.Fatalf("after window rotate want 200, got %d", resp2.StatusCode)
	}
}
