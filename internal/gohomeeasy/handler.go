package gohomeeasy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	hostnameLabelPattern         = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	ruleNameControlCharPattern   = regexp.MustCompile(`[\x00-\x1F\x7F]`)
	ipv6BracketedAuthorityRegexp = regexp.MustCompile(`^\[([^[\]]+)\]:(\d+)$`)
	hostPortRegexp               = regexp.MustCompile(`^([^:]+):(\d+)$`)
)

const (
	sessionCookieName = "ghe_session"
)

type Record struct {
	RuleName   string `json:"ruleName"`
	Type       string `json:"type"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Method     string `json:"method,omitempty"`
	Password   string `json:"password,omitempty"`
	SourceTime string `json:"sourceTime,omitempty"`
	UpdatedAt  string `json:"updatedAt"`
}

type deletePayload struct {
	RuleName string `json:"ruleName"`
}

type Storage interface {
	DeleteRecord(ruleName string) error
	GetLegacySubscription(subtype string) (string, error)
	GetRecord(ruleName string) (*Record, error)
	ListRecords() ([]Record, error)
	PutRecord(ruleName string, record Record) error
}

type Handler struct {
	config  Config
	logger  *log.Logger
	storage Storage
}

type sessionPayload struct {
	Exp  int64  `json:"exp"`
	Mode string `json:"mode"`
}

type apiAccess struct {
	Mode string
	Via  string
}

func NewHandler(cfg Config, logger *log.Logger) http.Handler {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	return &Handler{
		config:  cfg,
		logger:  logger,
		storage: NewFileStorage(cfg.StoragePath, cfg.DefaultSubscriptionFormat),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := normalizePath(r.URL.Path)

	if r.Method == http.MethodOptions {
		h.writeResponse(w, http.StatusNoContent, "", map[string]string{
			"Allow": "GET, POST, OPTIONS",
		})
		return
	}

	switch path {
	case "/healthz":
		if r.Method != http.MethodGet {
			h.writeText(w, http.StatusMethodNotAllowed, "Method Not Allowed", map[string]string{"Allow": "GET"})
			return
		}
		h.writeText(w, http.StatusOK, "ok")
	case "/", "/subscription":
		if path == "/" && r.Method == http.MethodPost {
			h.handleWebhook(w, r)
			return
		}
		if r.Method != http.MethodGet {
			allow := "GET, OPTIONS"
			if path == "/" {
				allow = "GET, POST, OPTIONS"
			}
			h.writeText(w, http.StatusMethodNotAllowed, "Method Not Allowed", map[string]string{"Allow": allow})
			return
		}
		fallbackSubtype := "ss"
		if path == "/" {
			fallbackSubtype = h.config.DefaultSubscriptionFormat
		}
		h.handleSubscription(w, r, fallbackSubtype)
	case "/webhook":
		if r.Method != http.MethodPost {
			h.writeText(w, http.StatusMethodNotAllowed, "Method Not Allowed", map[string]string{"Allow": "POST, OPTIONS"})
			return
		}
		h.handleWebhook(w, r)
	case "/dashboard":
		if r.Method != http.MethodGet {
			h.writeText(w, http.StatusMethodNotAllowed, "Method Not Allowed", map[string]string{"Allow": "GET, OPTIONS"})
			return
		}
		h.handleDashboard(w, r)
	case "/api/records":
		if r.Method != http.MethodGet {
			h.writeText(w, http.StatusMethodNotAllowed, "Method Not Allowed", map[string]string{"Allow": "GET, OPTIONS"})
			return
		}
		h.handleRecordsAPI(w, r)
	case "/api/delete":
		if r.Method != http.MethodPost {
			h.writeText(w, http.StatusMethodNotAllowed, "Method Not Allowed", map[string]string{"Allow": "POST, OPTIONS"})
			return
		}
		h.handleDelete(w, r)
	default:
		h.writeText(w, http.StatusNotFound, "Not Found")
	}
}

func (h *Handler) handleSubscription(w http.ResponseWriter, r *http.Request, fallbackSubtype string) {
	token := readBearerToken(r.Header.Get("Authorization"))
	if token == "" {
		token = strings.TrimSpace(r.URL.Query().Get("api_key"))
	}
	if token == "" {
		token = strings.TrimSpace(r.URL.Query().Get("read_token"))
	}

	if token != h.config.ReadToken {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}

	subtype, err := extractSubtype(r.URL.Query().Get("subtype"), fallbackSubtype)
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	records, err := h.storage.ListRecords()
	if err != nil {
		h.logger.Printf("list records failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal Server Error"})
		return
	}

	ssRecords := filterAndSortSSRecords(records)
	if len(ssRecords) > 0 {
		var content string
		if subtype == "ss" {
			uris := make([]string, 0, len(ssRecords))
			for _, record := range ssRecords {
				uris = append(uris, buildShadowsocksURI(record))
			}
			content = base64.StdEncoding.EncodeToString([]byte(strings.Join(uris, "\n")))
		} else {
			content = buildClashSubscription(ssRecords)
		}

		h.writeText(w, http.StatusOK, content, map[string]string{
			"X-GoHomeEasy-Format": subtype,
		})
		return
	}

	legacySubscription, err := h.storage.GetLegacySubscription(subtype)
	if err != nil {
		h.logger.Printf("read legacy subscription failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal Server Error"})
		return
	}

	if legacySubscription == "" {
		h.writeResponse(w, http.StatusNoContent, "", nil)
		return
	}

	h.writeText(w, http.StatusOK, normalizeLegacySubscriptionBody(subtype, legacySubscription), map[string]string{
		"X-GoHomeEasy-Format":          subtype,
		"X-GoHomeEasy-Legacy-Fallback": "true",
	})
}

func (h *Handler) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if readBearerToken(r.Header.Get("Authorization")) != h.config.WriteToken {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Failed to read request body."})
		return
	}

	record, err := h.parseWebhookRecord(body)
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := h.storage.PutRecord(record.RuleName, record); err != nil {
		h.logger.Printf("write record failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal Server Error"})
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{
		"message":  "Record updated successfully.",
		"ruleName": record.RuleName,
		"type":     record.Type,
	})
}

func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(h.config.SessionSecret) == "" {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "dashboard not configured"})
		return
	}

	queryToken := strings.TrimSpace(r.URL.Query().Get("api_key"))
	if queryToken != "" {
		mode := resolveDashboardMode(queryToken, h.config.ReadToken, h.config.WriteToken)
		if mode == "" {
			h.writeHTML(w, http.StatusUnauthorized, renderDashboardHTML("", true), map[string]string{
				"X-GoHomeEasy-Auth-Error": "invalid-token",
			})
			return
		}

		cookieValue, err := createSignedSessionValue(mode, time.Now().Unix()+h.config.SessionTTLSeconds, h.config.SessionSecret)
		if err != nil {
			h.logger.Printf("create session failed: %v", err)
			h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal Server Error"})
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    cookieValue,
			HttpOnly: true,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
			Secure:   isSecureRequest(r),
		})
		w.Header().Set("Location", "/dashboard")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusFound)
		return
	}

	session, ok := h.readSession(r)
	if !ok {
		h.writeHTML(w, http.StatusOK, renderDashboardHTML("", true), nil)
		return
	}

	h.writeHTML(w, http.StatusOK, renderDashboardHTML(session.Mode, false), nil)
}

func (h *Handler) handleRecordsAPI(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(h.config.SessionSecret) == "" {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "dashboard not configured"})
		return
	}

	access := h.resolveAPIAccess(r)
	if access == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}

	records, err := h.storage.ListRecords()
	if err != nil {
		h.logger.Printf("list records failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal Server Error"})
		return
	}

	sort.Slice(records, func(left, right int) bool {
		if records[left].UpdatedAt == records[right].UpdatedAt {
			return records[left].RuleName < records[right].RuleName
		}
		return records[left].UpdatedAt > records[right].UpdatedAt
	})

	hasSS := false
	for _, record := range records {
		if record.Type == "ss" {
			hasSS = true
			break
		}
	}

	legacySS, err := h.storage.GetLegacySubscription("ss")
	if err != nil {
		h.logger.Printf("read legacy ss failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal Server Error"})
		return
	}

	legacyClash, err := h.storage.GetLegacySubscription("clash")
	if err != nil {
		h.logger.Printf("read legacy clash failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal Server Error"})
		return
	}

	payload := map[string]any{
		"legacyFallbackActive": !hasSS && (legacySS != "" || legacyClash != ""),
		"mode":                 access.Mode,
		"records":              records,
		"subscriptionUrls": map[string]string{
			"ss":    buildSubscriptionURL(resolveRequestOrigin(r), h.config.ReadToken, "ss"),
			"clash": buildSubscriptionURL(resolveRequestOrigin(r), h.config.ReadToken, "clash"),
		},
	}

	h.writeJSON(w, http.StatusOK, payload)
}

func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(h.config.SessionSecret) == "" {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "dashboard not configured"})
		return
	}

	authResult := h.resolveDeleteAccess(r)
	switch authResult {
	case "unauthorized":
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	case "forbidden":
		h.writeJSON(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Failed to read request body."})
		return
	}

	var payload deletePayload
	if err := json.Unmarshal(body, &payload); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body."})
		return
	}

	ruleName, err := normalizeRuleName(payload.RuleName)
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := h.storage.DeleteRecord(ruleName); err != nil {
		h.logger.Printf("delete record failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal Server Error"})
		return
	}

	h.writeResponse(w, http.StatusNoContent, "", nil)
}

func (h *Handler) parseWebhookRecord(body []byte) (Record, error) {
	if len(strings.TrimSpace(string(body))) == 0 {
		return Record{}, errors.New("Request body must be a non-empty JSON object.")
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return Record{}, errors.New("Invalid JSON body.")
	}

	ruleName, err := normalizeRuleName(asString(raw["ruleName"]))
	if err != nil {
		return Record{}, err
	}

	host, port, err := resolveAddress(raw)
	if err != nil {
		return Record{}, err
	}

	recordType, err := normalizeRecordType(asString(raw["type"]))
	if err != nil {
		return Record{}, err
	}

	sourceTime := strings.TrimSpace(asString(raw["time"]))
	updatedAt := time.Now().UTC().Format(time.RFC3339Nano)

	record := Record{
		RuleName:   ruleName,
		Type:       recordType,
		Host:       host,
		Port:       port,
		SourceTime: sourceTime,
		UpdatedAt:  updatedAt,
	}

	method := strings.TrimSpace(asString(raw["method"]))
	password := strings.TrimSpace(asString(raw["password"]))

	if recordType == "site" {
		if method != "" || password != "" {
			return Record{}, errors.New("type=site records must not include method or password.")
		}
		return record, nil
	}

	normalizedMethod, err := normalizeCipher(method, h.config.AllowedMethods)
	if err != nil {
		return Record{}, err
	}

	normalizedPassword, err := normalizePassword(password)
	if err != nil {
		return Record{}, err
	}

	record.Method = normalizedMethod
	record.Password = normalizedPassword
	return record, nil
}

func resolveAddress(raw map[string]any) (string, int, error) {
	for _, key := range []string{"ip", "host", "server"} {
		value := strings.TrimSpace(asString(raw[key]))
		if value == "" {
			continue
		}

		host, err := normalizeHost(value, key)
		if err != nil {
			return "", 0, err
		}

		port, err := normalizePort(raw["port"])
		if err != nil {
			return "", 0, err
		}

		return host, port, nil
	}

	ipAddr := strings.TrimSpace(asString(raw["ipAddr"]))
	if ipAddr == "" {
		return "", 0, errors.New("Either ip/host/server plus port, or ipAddr, is required.")
	}

	return parseIPAddr(ipAddr)
}

func parseIPAddr(value string) (string, int, error) {
	if match := ipv6BracketedAuthorityRegexp.FindStringSubmatch(value); match != nil {
		host, err := normalizeHost(match[1], "ipAddr")
		if err != nil {
			return "", 0, err
		}
		port, err := normalizePort(match[2])
		if err != nil {
			return "", 0, err
		}
		return host, port, nil
	}

	if match := hostPortRegexp.FindStringSubmatch(value); match != nil {
		host, err := normalizeHost(match[1], "ipAddr")
		if err != nil {
			return "", 0, err
		}
		port, err := normalizePort(match[2])
		if err != nil {
			return "", 0, err
		}
		return host, port, nil
	}

	return "", 0, errors.New("ipAddr must be in host:port or [ipv6]:port format.")
}

func normalizeRuleName(value string) (string, error) {
	ruleName := strings.TrimSpace(value)
	if ruleName == "" {
		return "", errors.New("ruleName must be a non-empty string.")
	}
	if ruleNameControlCharPattern.MatchString(ruleName) {
		return "", errors.New("ruleName must not contain control characters.")
	}
	if len([]byte(ruleName)) > 128 {
		return "", errors.New("ruleName must be 128 bytes or fewer.")
	}
	return ruleName, nil
}

func normalizeRecordType(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "ss", nil
	}

	recordType := strings.ToLower(strings.TrimSpace(value))
	if recordType != "ss" && recordType != "site" {
		return "", errors.New("type must be either 'ss' or 'site'.")
	}
	return recordType, nil
}

func normalizeHost(value string, fieldName string) (string, error) {
	host := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(value), "]"), "[")
	switch {
	case isValidIPv4(host):
		return host, nil
	case isValidIPv6(host):
		return host, nil
	case isValidHostname(host):
		return host, nil
	default:
		return "", fmt.Errorf("%s must be a valid IPv4, IPv6, or DNS name.", fieldName)
	}
}

func normalizePort(value any) (int, error) {
	switch port := value.(type) {
	case float64:
		if port != float64(int(port)) {
			return 0, errors.New("Port must be an integer between 1 and 65535.")
		}
		if int(port) < 1 || int(port) > 65535 {
			return 0, errors.New("Port must be an integer between 1 and 65535.")
		}
		return int(port), nil
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(port))
		if err != nil || parsed < 1 || parsed > 65535 {
			return 0, errors.New("Port must be an integer between 1 and 65535.")
		}
		return parsed, nil
	case json.Number:
		parsed, err := port.Int64()
		if err != nil || parsed < 1 || parsed > 65535 {
			return 0, errors.New("Port must be an integer between 1 and 65535.")
		}
		return int(parsed), nil
	default:
		return 0, errors.New("Port must be an integer between 1 and 65535.")
	}
}

func normalizeCipher(value string, allowedMethods map[string]struct{}) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", errors.New("method must be a non-empty string.")
	}

	cipher := strings.ToLower(strings.TrimSpace(value))
	if _, ok := allowedMethods[cipher]; !ok {
		return "", fmt.Errorf("Unsupported Shadowsocks cipher: %s", cipher)
	}
	return cipher, nil
}

func normalizePassword(value string) (string, error) {
	password := strings.TrimSpace(value)
	if password == "" {
		return "", errors.New("password must be a non-empty string.")
	}
	if len(password) > 1024 {
		return "", errors.New("Password is too long.")
	}
	return password, nil
}

func filterAndSortSSRecords(records []Record) []Record {
	result := make([]Record, 0)
	for _, record := range records {
		if record.Type == "ss" {
			result = append(result, record)
		}
	}

	sort.Slice(result, func(left, right int) bool {
		return result[left].RuleName < result[right].RuleName
	})
	return result
}

func extractSubtype(explicit string, fallback string) (string, error) {
	if strings.TrimSpace(explicit) == "" {
		return normalizeSubtype(fallback)
	}
	return normalizeSubtype(explicit)
}

func normalizeSubtype(value string) (string, error) {
	subtype := strings.ToLower(strings.TrimSpace(value))
	if subtype != "ss" && subtype != "clash" {
		return "", errors.New("subtype must be either 'ss' or 'clash'.")
	}
	return subtype, nil
}

func buildShadowsocksURI(record Record) string {
	userInfo := fmt.Sprintf("%s:%s@%s", record.Method, record.Password, formatAuthority(record.Host, record.Port))
	return "ss://" + base64.StdEncoding.EncodeToString([]byte(userInfo)) + "#" + url.QueryEscape(record.RuleName)
}

func normalizeLegacySubscriptionBody(subtype, legacySubscription string) string {
	if subtype != "ss" {
		return legacySubscription
	}

	trimmed := strings.TrimSpace(legacySubscription)
	if !isRawShadowsocksSubscription(trimmed) {
		return legacySubscription
	}

	return base64.StdEncoding.EncodeToString([]byte(trimmed))
}

func isRawShadowsocksSubscription(value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}

	for _, line := range strings.Split(value, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(strings.TrimSpace(line), "ss://") {
			return false
		}
	}

	return true
}

func buildClashSubscription(records []Record) string {
	lines := []string{"proxies:"}
	for _, record := range records {
		lines = append(lines,
			"  - name: "+strconv.Quote(record.RuleName),
			"    type: ss",
			"    server: "+strconv.Quote(record.Host),
			"    port: "+strconv.Itoa(record.Port),
			"    cipher: "+strconv.Quote(record.Method),
			"    password: "+strconv.Quote(record.Password),
			"    udp: true",
		)
	}
	lines = append(lines, "")
	return strings.Join(lines, "\n")
}

func resolveDashboardMode(token string, readToken string, writeToken string) string {
	if token == writeToken {
		return "write"
	}
	if token == readToken {
		return "read"
	}
	return ""
}

func (h *Handler) resolveAPIAccess(r *http.Request) *apiAccess {
	bearer := readBearerToken(r.Header.Get("Authorization"))
	if bearer != "" {
		switch bearer {
		case h.config.WriteToken:
			return &apiAccess{Mode: "write", Via: "header"}
		case h.config.ReadToken:
			return &apiAccess{Mode: "read", Via: "header"}
		default:
			return nil
		}
	}

	session, ok := h.readSession(r)
	if !ok {
		return nil
	}

	return &apiAccess{Mode: session.Mode, Via: "cookie"}
}

func (h *Handler) resolveDeleteAccess(r *http.Request) string {
	bearer := readBearerToken(r.Header.Get("Authorization"))
	if bearer != "" {
		if bearer == h.config.WriteToken {
			return "allowed"
		}
		return "unauthorized"
	}

	session, ok := h.readSession(r)
	if !ok {
		return "unauthorized"
	}
	if session.Mode != "write" {
		return "forbidden"
	}

	origin := r.Header.Get("Origin")
	if origin == "" || origin != resolveRequestOrigin(r) {
		return "forbidden"
	}
	return "allowed"
}

func (h *Handler) readSession(r *http.Request) (*sessionPayload, bool) {
	if strings.TrimSpace(h.config.SessionSecret) == "" {
		return nil, false
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, false
	}

	session, err := verifySessionValue(cookie.Value, h.config.SessionSecret)
	if err != nil {
		return nil, false
	}
	return session, true
}

func createSignedSessionValue(mode string, expiresAt int64, secret string) (string, error) {
	payload := sessionPayload{Exp: expiresAt, Mode: mode}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	encodedPayload := base64.RawURLEncoding.EncodeToString(data)
	signature := signPayload(encodedPayload, secret)
	return encodedPayload + "." + signature, nil
}

func verifySessionValue(cookieValue string, secret string) (*sessionPayload, error) {
	parts := strings.Split(cookieValue, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid cookie")
	}

	expected := signPayload(parts[0], secret)
	if !hmac.Equal([]byte(parts[1]), []byte(expected)) {
		return nil, errors.New("invalid signature")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	var payload sessionPayload
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return nil, err
	}

	if payload.Mode != "read" && payload.Mode != "write" {
		return nil, errors.New("invalid mode")
	}
	if payload.Exp <= time.Now().Unix() {
		return nil, errors.New("expired")
	}
	return &payload, nil
}

func signPayload(payload string, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func buildSubscriptionURL(origin string, readToken string, subtype string) string {
	return fmt.Sprintf("%s/subscription?subtype=%s&api_key=%s", origin, url.QueryEscape(subtype), url.QueryEscape(readToken))
}

func resolveRequestOrigin(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}

	if host == "" {
		return ""
	}

	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}

	return proto + "://" + host
}

func isSecureRequest(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return r.TLS != nil
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

func formatAuthority(host string, port int) string {
	if isValidIPv6(host) {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}

func readBearerToken(header string) string {
	if header == "" {
		return ""
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func isValidIPv4(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil
}

func isValidIPv6(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil && strings.Contains(host, ":")
}

func isValidHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if !hostnameLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	default:
		return ""
	}
}

func (h *Handler) writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		h.writeResponse(w, http.StatusInternalServerError, `{"error":"Internal Server Error"}`, map[string]string{
			"Content-Type": "application/json; charset=utf-8",
		})
		return
	}

	h.writeResponse(w, statusCode, string(data), map[string]string{
		"Content-Type": "application/json; charset=utf-8",
	})
}

func (h *Handler) writeHTML(w http.ResponseWriter, statusCode int, body string, extraHeaders map[string]string) {
	headers := map[string]string{
		"Content-Type": "text/html; charset=utf-8",
	}
	for key, value := range extraHeaders {
		headers[key] = value
	}
	h.writeResponse(w, statusCode, body, headers)
}

func (h *Handler) writeText(w http.ResponseWriter, statusCode int, body string, extraHeaders ...map[string]string) {
	headers := map[string]string{
		"Content-Type": "text/plain; charset=utf-8",
	}
	for _, group := range extraHeaders {
		for key, value := range group {
			headers[key] = value
		}
	}
	h.writeResponse(w, statusCode, body, headers)
}

func (h *Handler) writeResponse(w http.ResponseWriter, statusCode int, body string, headers map[string]string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	for key, value := range headers {
		w.Header().Set(key, value)
	}

	if statusCode == http.StatusNoContent {
		w.WriteHeader(statusCode)
		return
	}

	w.WriteHeader(statusCode)
	_, _ = io.WriteString(w, body)
}
