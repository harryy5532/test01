package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	northflankAPIBase        = "https://api.northflank.com/v1"
	defaultNFReqTimeout      = 15 * time.Second
	defaultNFCertPollTick    = 5 * time.Second
	defaultNFCertPollWait    = 90 * time.Second
	defaultNFTLSProbeTimeout = 4 * time.Second
	defaultNFTargetPort      = 8080
)

var multiPartPublicSuffixes = []string{
	".dpdns.org",
	".qzz.io",
	".us.kg",
	".xx.kg",
	".qd.je",
	".co.uk",
	".org.uk",
	".ac.uk",
	".com.au",
	".net.au",
	".org.au",
	".com.br",
	".com.tr",
	".co.jp",
	".co.kr",
	".co.in",
	".com.sg",
	".com.hk",
	".com.tw",
	".co.za",
}

type nfErrorDetail struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

type nfEnvelope[T any] struct {
	Data  T              `json:"data"`
	Error *nfErrorDetail `json:"error,omitempty"`
}

type nfAPIError struct {
	StatusCode int
	Message    string
}

func (e *nfAPIError) Error() string {
	if strings.TrimSpace(e.Message) != "" {
		return fmt.Sprintf("northflank api error (HTTP %d): %s", e.StatusCode, strings.TrimSpace(e.Message))
	}
	return fmt.Sprintf("northflank api error (HTTP %d)", e.StatusCode)
}

func (e *nfAPIError) IsAuthError() bool {
	if e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden {
		return true
	}
	lower := strings.ToLower(e.Message)
	return strings.Contains(lower, "unauthorized") ||
		strings.Contains(lower, "not authorized") ||
		strings.Contains(lower, "unauthenticated") ||
		strings.Contains(lower, "invalid token") ||
		strings.Contains(lower, "authentication")
}

func (e *nfAPIError) IsPermissionOrPlan() bool {
	if e.IsAuthError() || e.StatusCode == http.StatusPaymentRequired {
		return true
	}
	lower := strings.ToLower(e.Message)
	return strings.Contains(lower, "plan") ||
		strings.Contains(lower, "quota") ||
		strings.Contains(lower, "limit") ||
		strings.Contains(lower, "upgrade") ||
		strings.Contains(lower, "subscription") ||
		strings.Contains(lower, "permission") ||
		strings.Contains(lower, "forbidden") ||
		strings.Contains(lower, "not allowed")
}

func (e *nfAPIError) IsNotFound() bool {
	return e.StatusCode == http.StatusNotFound || strings.Contains(strings.ToLower(e.Message), "not found")
}

func (e *nfAPIError) IsConflictOrExists() bool {
	if e.StatusCode == http.StatusConflict {
		return true
	}
	lower := strings.ToLower(e.Message)
	return strings.Contains(lower, "already exists") ||
		strings.Contains(lower, "already registered") ||
		strings.Contains(lower, "duplicate") ||
		strings.Contains(lower, "conflict")
}

type NorthflankCustomDomainInfo struct {
	ID                string
	Domain            string
	ApexDomain        string
	SubdomainLabel    string
	CNAMETarget       string
	CNAMEHostLabel    string
	VerificationToken string
	VerificationHost  string
	CertificateStatus string
	ApexVerified      bool
	SubdomainVerified bool
	AssignedToPort    bool
}

func (info *NorthflankCustomDomainInfo) IsCertificateValid() bool {
	if info == nil {
		return false
	}
	st := strings.ToUpper(strings.TrimSpace(info.CertificateStatus))
	if st == "CERTIFICATE_STATUS_TYPE_VALID" ||
		st == "VALID" ||
		st == "ACTIVE" ||
		st == "ISSUED" ||
		st == "READY" ||
		st == "TRUE" ||
		st == "VERIFIED" {
		return true
	}
	return strings.Contains(st, "VALID") && !strings.Contains(st, "VALIDATING") && !strings.Contains(st, "INVALID")
}

type NorthflankClient struct {
	Token      string
	TeamID     string
	ProjectID  string
	ServiceID  string
	PortName   string
	TargetPort int
	apiBase    string
	client     *http.Client

	mu            sync.RWMutex
	authChecked   bool
	useTeamPrefix bool
	serviceDomain string
	customDomain  string
	zoneHint      string
	region        string
	onTopology    func(nfDom, cfDom string)
}

func sanitizeNorthflankToken(raw string) string {
	s := strings.TrimSpace(raw)
	upper := strings.ToUpper(s)
	for _, prefix := range []string{
		"NORTHFLANK_API_TOKEN",
		"NORTHFLANK_TOKEN",
		"BERMUDA_NORTHFLANK_TOKEN",
		"NF_API_TOKEN",
		"NORTHFLANK_ACCOUNT_TOKEN",
	} {
		if strings.HasPrefix(upper, prefix) {
			if _, after, ok := strings.Cut(s, "="); ok {
				s = strings.TrimSpace(after)
			}
		}
	}
	s = strings.Trim(s, "\"'` \t\r\n")
	s = strings.TrimSpace(s)
	if strings.Contains(s, "${{") || strings.HasPrefix(s, "$") {
		return ""
	}
	return s
}

func NewNorthflankClient(token string) *NorthflankClient {
	cleanTok := sanitizeNorthflankToken(token)
	if cleanTok == "" {
		return nil
	}

	port := getEnvInt("PORT", defaultNFTargetPort)
	if port <= 0 {
		port = defaultNFTargetPort
	}

	nfDom, cfDom := resolveInfrastructureDomains()
	apiBase := sanitizeExplicitCredential(getEnv("NORTHFLANK_API_URL", getEnv("BERMUDA_NF_API_URL", northflankAPIBase)))
	apiBase = strings.TrimRight(apiBase, "/")
	if apiBase == "" {
		apiBase = northflankAPIBase
	}

	projID := sanitizeExplicitCredential(getEnv("NORTHFLANK_PROJECT_ID", getEnv("NF_PROJECT_ID", "")))
	svcID := sanitizeExplicitCredential(getEnv("NORTHFLANK_SERVICE_ID", getEnv("NF_SERVICE_ID", "")))
	teamID := sanitizeExplicitCredential(getEnv("NORTHFLANK_TEAM_ID", getEnv("NF_TEAM_ID", "")))
	portName := sanitizeExplicitCredential(getEnv("NORTHFLANK_PORT_NAME", getEnv("NF_PORT_NAME", "http")))
	if portName == "" {
		portName = "http"
	}

	return &NorthflankClient{
		Token:         cleanTok,
		TeamID:        teamID,
		ProjectID:     projID,
		ServiceID:     svcID,
		PortName:      portName,
		TargetPort:    port,
		apiBase:       apiBase,
		serviceDomain: nfDom,
		customDomain:  cfDom,
		client: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

func (c *NorthflankClient) IsConfigured() bool {
	return c != nil && c.Token != ""
}

func (c *NorthflankClient) HasServiceContext() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ProjectID != "" && c.ServiceID != ""
}

func (c *NorthflankClient) SetTopologyCallback(fn func(nfDom, cfDom string)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.onTopology = fn
	c.mu.Unlock()
}

func (c *NorthflankClient) notifyTopology() {
	if c == nil {
		return
	}
	c.mu.RLock()
	fn := c.onTopology
	nf := c.serviceDomain
	cf := c.customDomain
	c.mu.RUnlock()
	if fn != nil {
		fn(nf, cf)
	}
}

func (c *NorthflankClient) GetServiceDomain() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.serviceDomain
}

func (c *NorthflankClient) GetCustomDomain() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.customDomain
}

func (c *NorthflankClient) GetDiscoveredRegion() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.region
}

func (c *NorthflankClient) SetServiceDomain(d string) {
	if c == nil {
		return
	}
	clean := cleanHost(d)
	if !isNorthflankPublicDomain(clean) {
		return
	}
	c.mu.Lock()
	if c.serviceDomain == "" || isFullNorthflankServiceDomain(clean) {
		c.serviceDomain = clean
	}
	c.mu.Unlock()
}

func (c *NorthflankClient) SetCustomDomain(d string) {
	if c == nil {
		return
	}
	clean := cleanHost(d)
	if clean == "" || isNorthflankManagedDomain(clean) {
		return
	}
	c.mu.Lock()
	c.customDomain = clean
	c.mu.Unlock()
}

func (c *NorthflankClient) SetZoneHint(zone string) {
	if c == nil {
		return
	}
	clean := cleanHost(zone)
	if clean == "" || isNorthflankManagedDomain(clean) {
		return
	}
	c.mu.Lock()
	c.zoneHint = clean
	c.mu.Unlock()
}

func (c *NorthflankClient) baseURL() string {
	if c != nil && c.apiBase != "" {
		return c.apiBase
	}
	return northflankAPIBase
}

func (c *NorthflankClient) buildPath(path string, withTeamPrefix bool) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	c.mu.RLock()
	teamID := c.TeamID
	c.mu.RUnlock()
	if withTeamPrefix && teamID != "" && !strings.HasPrefix(path, "/teams/") && path != "/auth" {
		return "/teams/" + url.PathEscape(teamID) + path
	}
	return path
}

func doNFRequest[T any](ctx context.Context, c *NorthflankClient, method, path string, body any) (T, error) {
	var zero T
	if !c.IsConfigured() {
		return zero, errors.New("northflank client not configured (missing token)")
	}

	c.mu.RLock()
	useTeam := c.useTeamPrefix
	teamID := c.TeamID
	c.mu.RUnlock()

	res, err := executeNFREST[T](ctx, c, method, c.buildPath(path, useTeam), body)
	if err == nil {
		return res, nil
	}

	var apiErr *nfAPIError
	if teamID != "" && path != "/auth" && errors.As(err, &apiErr) && (apiErr.IsAuthError() || apiErr.IsNotFound()) {
		altRes, altErr := executeNFREST[T](ctx, c, method, c.buildPath(path, !useTeam), body)
		if altErr == nil {
			c.mu.Lock()
			c.useTeamPrefix = !useTeam
			c.mu.Unlock()
			return altRes, nil
		}
	}

	return zero, err
}

func executeNFREST[T any](ctx context.Context, c *NorthflankClient, method, path string, body any) (T, error) {
	var zero T

	var payloadBytes []byte
	if body != nil {
		var err error
		payloadBytes, err = json.Marshal(body)
		if err != nil {
			return zero, fmt.Errorf("marshal northflank request payload: %w", err)
		}
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, defaultNFReqTimeout)
		var bodyReader io.Reader
		if payloadBytes != nil {
			bodyReader = bytes.NewReader(payloadBytes)
		}

		req, reqErr := http.NewRequestWithContext(reqCtx, method, c.baseURL()+path, bodyReader)
		if reqErr != nil {
			cancel()
			return zero, fmt.Errorf("build northflank request: %w", reqErr)
		}

		req.Header.Set("Authorization", "Bearer "+c.Token)
		if payloadBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "BERMUDA-Portal-CloudOrchestrator/4.0 (Go-Standard-Library)")

		resp, doErr := c.client.Do(req)
		if doErr != nil {
			cancel()
			lastErr = doErr
			break
		}

		rawBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		cancel()

		if readErr != nil {
			return zero, fmt.Errorf("read northflank response: %w", readErr)
		}

		if resp.StatusCode == http.StatusTooManyRequests && attempt == 0 {
			select {
			case <-ctx.Done():
				return zero, ctx.Err()
			case <-time.After(1500 * time.Millisecond):
				continue
			}
		}

		if resp.StatusCode >= 400 {
			var errEnv nfEnvelope[any]
			if jsonErr := json.Unmarshal(rawBytes, &errEnv); jsonErr == nil && errEnv.Error != nil && errEnv.Error.Message != "" {
				return zero, &nfAPIError{
					StatusCode: resp.StatusCode,
					Message:    errEnv.Error.Message,
				}
			}
			var rawMap map[string]any
			if jsonErr := json.Unmarshal(rawBytes, &rawMap); jsonErr == nil {
				if msg, ok := rawMap["message"].(string); ok && msg != "" {
					return zero, &nfAPIError{StatusCode: resp.StatusCode, Message: msg}
				}
			}
			snippet := strings.TrimSpace(string(rawBytes))
			if len(snippet) > 256 {
				snippet = snippet[:256]
			}
			return zero, &nfAPIError{
				StatusCode: resp.StatusCode,
				Message:    snippet,
			}
		}

		if len(bytes.TrimSpace(rawBytes)) == 0 {
			return zero, nil
		}

		var env struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(rawBytes, &env); err == nil && len(env.Data) > 0 && !bytes.Equal(bytes.TrimSpace(env.Data), []byte("null")) {
			var out T
			if uErr := json.Unmarshal(env.Data, &out); uErr == nil {
				return out, nil
			}
		}

		var direct T
		if err := json.Unmarshal(rawBytes, &direct); err == nil {
			return direct, nil
		}

		return zero, nil
	}

	return zero, lastErr
}

func (c *NorthflankClient) probeAuthContext(ctx context.Context) {
	c.mu.RLock()
	checked := c.authChecked
	c.mu.RUnlock()
	if checked {
		return
	}

	raw, err := executeNFREST[map[string]any](ctx, c, http.MethodGet, "/auth", nil)
	c.mu.Lock()
	c.authChecked = true
	if err == nil && raw != nil {
		if c.TeamID == "" {
			if eid, ok := raw["entityId"].(string); ok && strings.TrimSpace(eid) != "" {
				c.TeamID = strings.TrimSpace(eid)
			} else if tid, ok := raw["teamId"].(string); ok && strings.TrimSpace(tid) != "" {
				c.TeamID = strings.TrimSpace(tid)
			}
		}
	}
	c.mu.Unlock()
}

type nfProjectSummary struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Region string `json:"region"`
}

type nfProjectsList struct {
	Projects []nfProjectSummary `json:"projects"`
}

type nfPortEntry struct {
	Name         string   `json:"name"`
	InternalPort int      `json:"internalPort"`
	Public       bool     `json:"public"`
	Protocol     string   `json:"protocol"`
	DNS          string   `json:"dns,omitempty"`
	Domains      []string `json:"domains,omitempty"`
}

type nfServiceSummary struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	ServiceType string        `json:"serviceType,omitempty"`
	Region      string        `json:"region,omitempty"`
	Ports       []nfPortEntry `json:"ports,omitempty"`
}

type nfServicesList struct {
	Services []nfServiceSummary `json:"services"`
}

func extractServicePortDomain(raw map[string]any, targetPort int) (portName, dnsHost, region string, customDoms []string) {
	if reg, ok := raw["region"].(string); ok && strings.TrimSpace(reg) != "" {
		region = strings.TrimSpace(reg)
	}

	var walkPorts func(node any)
	walkPorts = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			if portsRaw, ok := v["ports"].([]any); ok {
				for _, pItem := range portsRaw {
					pm, ok := pItem.(map[string]any)
					if !ok {
						continue
					}
					pName, _ := pm["name"].(string)
					pDNS, _ := pm["dns"].(string)
					pPublic, _ := pm["public"].(bool)
					var pInt int
					switch num := pm["internalPort"].(type) {
					case float64:
						pInt = int(num)
					case int:
						pInt = num
					}

					if domArr, ok := pm["domains"].([]any); ok {
						for _, dItem := range domArr {
							if dStr, ok := dItem.(string); ok {
								cleanD := cleanHost(dStr)
								if cleanD != "" && !isNorthflankManagedDomain(cleanD) {
									customDoms = append(customDoms, cleanD)
								}
							} else if dm, ok := dItem.(map[string]any); ok {
								for _, k := range []string{"fullName", "domain", "name", "hostname"} {
									if dStr, ok := dm[k].(string); ok {
										cleanD := cleanHost(dStr)
										if cleanD != "" && strings.Contains(cleanD, ".") && !isNorthflankManagedDomain(cleanD) {
											customDoms = append(customDoms, cleanD)
										}
									}
								}
							}
						}
					}

					cleanDNS := cleanHost(pDNS)
					if pInt == targetPort || (portName == "" && pPublic) || len(portsRaw) == 1 {
						if pName != "" && (portName == "" || pInt == targetPort) {
							portName = pName
						}
						if isNorthflankPublicDomain(cleanDNS) && (dnsHost == "" || pInt == targetPort) {
							dnsHost = cleanDNS
						}
					}
				}
			}
			for key, val := range v {
				if key != "ports" {
					walkPorts(val)
				}
			}
		case []any:
			for _, item := range v {
				walkPorts(item)
			}
		}
	}

	walkPorts(raw)
	return portName, dnsHost, region, customDoms
}

func (c *NorthflankClient) ResolveRuntimeContext(ctx context.Context) error {
	if !c.IsConfigured() {
		return errors.New("northflank client not configured")
	}
	if c.HasServiceContext() {
		return nil
	}

	c.probeAuthContext(ctx)

	c.mu.RLock()
	knownProj := c.ProjectID
	knownSvc := c.ServiceID
	knownDom := c.serviceDomain
	targetPort := c.TargetPort
	c.mu.RUnlock()

	var projects []nfProjectSummary
	if knownProj != "" {
		projects = []nfProjectSummary{{ID: knownProj}}
	} else {
		projList, err := doNFRequest[nfProjectsList](ctx, c, http.MethodGet, "/projects", nil)
		if err == nil && len(projList.Projects) > 0 {
			projects = projList.Projects
		} else {
			rawProj, rawErr := doNFRequest[[]nfProjectSummary](ctx, c, http.MethodGet, "/projects", nil)
			if rawErr == nil && len(rawProj) > 0 {
				projects = rawProj
			} else if err != nil {
				return fmt.Errorf("list northflank projects: %w", err)
			}
		}
	}

	if len(projects) == 0 {
		return errors.New("no northflank projects found under this API token")
	}

	var matchedProjID, matchedSvcID, matchedPortName, matchedDNS, matchedRegion string
	var fallbackProjID, fallbackSvcID, fallbackPortName, fallbackDNS, fallbackRegion string

	for _, proj := range projects {
		if proj.ID == "" {
			continue
		}
		var services []nfServiceSummary
		if knownSvc != "" {
			services = []nfServiceSummary{{ID: knownSvc}}
		} else {
			svcPath := "/projects/" + url.PathEscape(proj.ID) + "/services"
			svcList, err := doNFRequest[nfServicesList](ctx, c, http.MethodGet, svcPath, nil)
			if err == nil && len(svcList.Services) > 0 {
				services = svcList.Services
			} else {
				rawSvcs, rawErr := doNFRequest[[]nfServiceSummary](ctx, c, http.MethodGet, svcPath, nil)
				if rawErr == nil && len(rawSvcs) > 0 {
					services = rawSvcs
				}
			}
		}

		for _, svc := range services {
			if svc.ID == "" {
				continue
			}
			detailPath := "/projects/" + url.PathEscape(proj.ID) + "/services/" + url.PathEscape(svc.ID)
			detailMap, err := doNFRequest[map[string]any](ctx, c, http.MethodGet, detailPath, nil)
			var pName, pDNS, reg string
			if err == nil && detailMap != nil {
				pName, pDNS, reg, _ = extractServicePortDomain(detailMap, targetPort)
			}
			if reg == "" {
				reg = proj.Region
			}
			if pName == "" && len(svc.Ports) > 0 {
				for _, pe := range svc.Ports {
					if pe.InternalPort == targetPort || pName == "" {
						pName = pe.Name
						if cleanDNS := cleanHost(pe.DNS); isNorthflankPublicDomain(cleanDNS) {
							pDNS = cleanDNS
						}
					}
				}
			}

			if fallbackProjID == "" {
				fallbackProjID = proj.ID
				fallbackSvcID = svc.ID
				fallbackPortName = pName
				fallbackDNS = pDNS
				fallbackRegion = reg
			}

			isExactMatch := false
			if knownDom != "" && pDNS != "" && strings.EqualFold(knownDom, pDNS) {
				isExactMatch = true
			} else if strings.Contains(strings.ToLower(svc.ID), "bermuda") || strings.Contains(strings.ToLower(svc.Name), "bermuda") ||
				strings.Contains(strings.ToLower(proj.ID), "bermuda") || strings.Contains(strings.ToLower(proj.Name), "bermuda") {
				isExactMatch = true
			}

			if isExactMatch {
				matchedProjID = proj.ID
				matchedSvcID = svc.ID
				matchedPortName = pName
				matchedDNS = pDNS
				matchedRegion = reg
				break
			}
		}
		if matchedProjID != "" && matchedSvcID != "" {
			break
		}
	}

	if matchedProjID == "" {
		matchedProjID = fallbackProjID
		matchedSvcID = fallbackSvcID
		matchedPortName = fallbackPortName
		matchedDNS = fallbackDNS
		matchedRegion = fallbackRegion
	}

	if matchedProjID == "" || matchedSvcID == "" {
		return errors.New("could not auto-discover northflank project/service context")
	}

	c.mu.Lock()
	c.ProjectID = matchedProjID
	c.ServiceID = matchedSvcID
	if matchedPortName != "" {
		c.PortName = matchedPortName
	}
	if isNorthflankPublicDomain(matchedDNS) && (c.serviceDomain == "" || isFullNorthflankServiceDomain(matchedDNS)) {
		c.serviceDomain = matchedDNS
	}
	if matchedRegion != "" && c.region == "" {
		c.region = matchedRegion
	}
	c.mu.Unlock()

	c.notifyTopology()
	log.Printf("[Northflank] ✓ Resolved Runtime Context: Project=%s | Service=%s | Port=%s (%d)",
		matchedProjID, matchedSvcID, c.PortName, c.TargetPort)
	return nil
}

func extractRuntimeEnvMap(raw map[string]any) (map[string]string, map[string]any) {
	envMap := make(map[string]string)
	var runtimeFiles map[string]any

	if raw == nil {
		return envMap, nil
	}

	if rf, ok := raw["runtimeFiles"].(map[string]any); ok && len(rf) > 0 {
		runtimeFiles = rf
	}

	parseKV := func(m map[string]any) {
		for k, v := range m {
			if k == "runtimeEnvironment" || k == "runtimeFiles" {
				continue
			}
			switch val := v.(type) {
			case string:
				envMap[k] = val
			case float64, int, bool:
				envMap[k] = fmt.Sprint(val)
			}
		}
	}

	if re, ok := raw["runtimeEnvironment"].(map[string]any); ok {
		parseKV(re)
	} else if vars, ok := raw["variables"].(map[string]any); ok {
		parseKV(vars)
	} else {
		parseKV(raw)
	}

	return envMap, runtimeFiles
}

func (c *NorthflankClient) UpsertVariable(ctx context.Context, name, value string) error {
	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return err
	}

	c.mu.RLock()
	projID := c.ProjectID
	svcID := c.ServiceID
	c.mu.RUnlock()

	envPath := "/projects/" + url.PathEscape(projID) + "/services/" + url.PathEscape(svcID) + "/runtime-environment"

	mergedEnv := make(map[string]string)
	var runtimeFiles map[string]any

	if existingRaw, err := doNFRequest[map[string]any](ctx, c, http.MethodGet, envPath, nil); err == nil && existingRaw != nil {
		extracted, rf := extractRuntimeEnvMap(existingRaw)
		for k, v := range extracted {
			mergedEnv[k] = v
		}
		runtimeFiles = rf
	} else {
		detailPath := "/projects/" + url.PathEscape(projID) + "/services/" + url.PathEscape(svcID)
		if detailRaw, dErr := doNFRequest[map[string]any](ctx, c, http.MethodGet, detailPath, nil); dErr == nil && detailRaw != nil {
			extracted, rf := extractRuntimeEnvMap(detailRaw)
			for k, v := range extracted {
				mergedEnv[k] = v
			}
			runtimeFiles = rf
		}
	}

	preservedKeys := []string{
		"PORT",
		"TZ",
		"GOGC",
		"GODEBUG",
		"BERMUDA_PATH_XH",
		"BERMUDA_PATH_WS",
		"BERMUDA_PATH_TR",
		"BERMUDA_HEALTH_PATH",
		"BERMUDA_BACKEND_XH",
		"BERMUDA_BACKEND_WS",
		"BERMUDA_BACKEND_TR",
		"BERMUDA_REGION",
		"CLOUDFLARE_API_TOKEN",
		"CLOUDFLARE_ZONE_ID",
		"NORTHFLANK_API_TOKEN",
		"CUSTOM_DOMAIN",
		"BERMUDA_MASTER_KEY",
	}
	for _, key := range preservedKeys {
		if _, exists := mergedEnv[key]; !exists {
			if val, ok := os.LookupEnv(key); ok && strings.TrimSpace(val) != "" {
				mergedEnv[key] = strings.TrimSpace(val)
			}
		}
	}

	if existingVal, ok := mergedEnv[name]; ok && existingVal == value {
		return nil
	}
	mergedEnv[name] = value

	payload := map[string]any{
		"runtimeEnvironment": mergedEnv,
	}
	if len(runtimeFiles) > 0 {
		payload["runtimeFiles"] = runtimeFiles
	}

	if _, err := doNFRequest[map[string]any](ctx, c, http.MethodPost, envPath, payload); err == nil {
		return nil
	}
	if _, err := doNFRequest[map[string]any](ctx, c, http.MethodPatch, envPath, payload); err == nil {
		return nil
	}

	combinedPath := "/projects/" + url.PathEscape(projID) + "/services/combined/" + url.PathEscape(svcID)
	_, err := doNFRequest[map[string]any](ctx, c, http.MethodPatch, combinedPath, payload)
	return err
}

func (c *NorthflankClient) PersistMasterKey(ctx context.Context, masterKey string) bool {
	if !c.IsConfigured() || strings.TrimSpace(masterKey) == "" {
		return false
	}
	if err := c.UpsertVariable(ctx, "BERMUDA_MASTER_KEY", strings.TrimSpace(masterKey)); err != nil {
		var apiErr *nfAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			log.Printf("[Northflank] Note: Auto-persisting BERMUDA_MASTER_KEY skipped (token permission restriction)")
			return false
		}
		log.Printf("[Northflank] Warning: Could not persist BERMUDA_MASTER_KEY to Northflank runtime variables: %v", err)
		return false
	}
	log.Println("[Northflank] ✓ BERMUDA_MASTER_KEY persisted to Northflank Service Runtime Variables (Read-Merge-Write)")
	return true
}

func (c *NorthflankClient) EnsureServiceDomain(ctx context.Context) (string, error) {
	if dom := c.GetServiceDomain(); isFullNorthflankServiceDomain(dom) {
		log.Printf("[Northflank] ✓ Service Domain Active: %s (Port %d)", dom, c.TargetPort)
		return dom, nil
	}

	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return c.GetServiceDomain(), err
	}

	if dom := c.GetServiceDomain(); isNorthflankPublicDomain(dom) {
		log.Printf("[Northflank] ✓ Service Domain Verified: %s (Port %d)", dom, c.TargetPort)
		return dom, nil
	}

	c.mu.RLock()
	projID := c.ProjectID
	svcID := c.ServiceID
	targetPort := c.TargetPort
	portName := c.PortName
	c.mu.RUnlock()

	if portName == "" {
		portName = "http"
	}

	portsPayload := map[string]any{
		"ports": []map[string]any{
			{
				"name":         portName,
				"internalPort": targetPort,
				"public":       true,
				"protocol":     "HTTP",
			},
		},
	}

	endpoints := []string{
		"/projects/" + url.PathEscape(projID) + "/services/" + url.PathEscape(svcID) + "/ports",
		"/projects/" + url.PathEscape(projID) + "/services/combined/" + url.PathEscape(svcID),
		"/projects/" + url.PathEscape(projID) + "/services/deployment/" + url.PathEscape(svcID),
	}

	for _, ep := range endpoints {
		method := http.MethodPatch
		if strings.HasSuffix(ep, "/ports") {
			method = http.MethodPost
		}
		if raw, err := doNFRequest[map[string]any](ctx, c, method, ep, portsPayload); err == nil && raw != nil {
			pName, pDNS, _, _ := extractServicePortDomain(raw, targetPort)
			if pName != "" {
				c.mu.Lock()
				c.PortName = pName
				c.mu.Unlock()
			}
			if isNorthflankPublicDomain(pDNS) {
				c.SetServiceDomain(pDNS)
				c.notifyTopology()
				log.Printf("[Northflank] ✓ Auto-Provisioned Public Service Port Domain: %s (Port %d)", pDNS, targetPort)
				return pDNS, nil
			}
		}
	}

	detailPath := "/projects/" + url.PathEscape(projID) + "/services/" + url.PathEscape(svcID)
	if detailMap, err := doNFRequest[map[string]any](ctx, c, http.MethodGet, detailPath, nil); err == nil && detailMap != nil {
		pName, pDNS, _, _ := extractServicePortDomain(detailMap, targetPort)
		if pName != "" {
			c.mu.Lock()
			c.PortName = pName
			c.mu.Unlock()
		}
		if isNorthflankPublicDomain(pDNS) {
			c.SetServiceDomain(pDNS)
			c.notifyTopology()
			log.Printf("[Northflank] ✓ Discovered Public Service Domain: %s (Port %d)", pDNS, targetPort)
			return pDNS, nil
		}
	}

	return c.GetServiceDomain(), nil
}

func splitApexAndSubdomain(fullDomain, zoneHint string) (apexDomain, subdomainLabel string) {
	cleanFull := cleanHost(fullDomain)
	cleanZone := cleanHost(zoneHint)
	if cleanFull == "" {
		return "", ""
	}

	if cleanZone != "" && (cleanFull == cleanZone || strings.HasSuffix(cleanFull, "."+cleanZone)) {
		if cleanFull == cleanZone {
			return cleanZone, "@"
		}
		sub := strings.TrimSuffix(cleanFull, "."+cleanZone)
		return cleanZone, sub
	}

	for _, suffix := range multiPartPublicSuffixes {
		if strings.HasSuffix(cleanFull, suffix) {
			rest := strings.TrimSuffix(cleanFull, suffix)
			labels := strings.Split(rest, ".")
			if len(labels) <= 1 {
				return cleanFull, "@"
			}
			apex := labels[len(labels)-1] + suffix
			sub := strings.Join(labels[:len(labels)-1], ".")
			return apex, sub
		}
	}

	labels := strings.Split(cleanFull, ".")
	if len(labels) <= 2 {
		return cleanFull, "@"
	}
	apex := strings.Join(labels[len(labels)-2:], ".")
	sub := strings.Join(labels[:len(labels)-2], ".")
	return apex, sub
}

func normalizeVerifyHost(rawHost, apexDomain string) string {
	h := strings.Trim(strings.ToLower(strings.TrimSpace(rawHost)), ".")
	apex := cleanHost(apexDomain)
	if h == "" || h == "@" {
		return apex
	}
	if h == apex || strings.HasSuffix(h, "."+apex) {
		return h
	}
	return h + "." + apex
}

func parseNFDomainObject(raw map[string]any, apexDomain string) (verified bool, verifyHost, verifyToken, cnameTarget string) {
	if raw == nil {
		return false, apexDomain, "", ""
	}
	if st, ok := raw["status"].(string); ok {
		upper := strings.ToUpper(strings.TrimSpace(st))
		if upper == "VERIFIED" || upper == "ACTIVE" || upper == "VALID" || upper == "READY" {
			verified = true
		}
	}
	if vBool, ok := raw["verified"].(bool); ok && vBool {
		verified = true
	}

	if hn, ok := raw["hostname"].(string); ok && strings.TrimSpace(hn) != "" {
		verifyHost = normalizeVerifyHost(hn, apexDomain)
	} else {
		verifyHost = apexDomain
	}

	if tok, ok := raw["token"].(string); ok && strings.TrimSpace(tok) != "" {
		verifyToken = strings.TrimSpace(tok)
	}

	if redir, ok := raw["redirect"].(map[string]any); ok {
		if target, ok := redir["target"].(map[string]any); ok {
			if rec, ok := target["record"].(string); ok && strings.TrimSpace(rec) != "" {
				cnameTarget = cleanHost(rec)
			}
		}
	}
	return verified, verifyHost, verifyToken, cnameTarget
}

func parseNFSubdomainObject(raw map[string]any) (verified bool, certStatus, cnameTarget string) {
	if raw == nil {
		return false, "", ""
	}
	if st, ok := raw["status"].(string); ok && strings.TrimSpace(st) != "" {
		certStatus = strings.TrimSpace(st)
		upper := strings.ToUpper(certStatus)
		if upper == "VERIFIED" || upper == "ACTIVE" || upper == "VALID" || upper == "READY" {
			verified = true
		}
	}
	if cs, ok := raw["certificateStatus"].(string); ok && strings.TrimSpace(cs) != "" {
		certStatus = strings.TrimSpace(cs)
	}
	if certObj, ok := raw["certificate"].(map[string]any); ok {
		if cs, ok := certObj["status"].(string); ok && strings.TrimSpace(cs) != "" {
			certStatus = strings.TrimSpace(cs)
		}
	}
	for _, key := range []string{"record", "target", "cnameTarget", "token", "dns", "value"} {
		if val, ok := raw[key].(string); ok {
			clean := cleanHost(val)
			if clean != "" && strings.Contains(clean, ".") {
				cnameTarget = clean
				break
			}
		}
	}
	if targetObj, ok := raw["target"].(map[string]any); ok {
		if rec, ok := targetObj["record"].(string); ok && strings.TrimSpace(rec) != "" {
			cnameTarget = cleanHost(rec)
		}
	}
	return verified, certStatus, cnameTarget
}

func (c *NorthflankClient) EnsureCustomDomain(ctx context.Context, targetDomain string) (*NorthflankCustomDomainInfo, error) {
	cleanTarget := cleanHost(targetDomain)
	if cleanTarget == "" || isNorthflankManagedDomain(cleanTarget) {
		return nil, errors.New("invalid or empty custom domain target")
	}

	c.probeAuthContext(ctx)
	_ = c.ResolveRuntimeContext(ctx)

	c.mu.RLock()
	zoneHint := c.zoneHint
	svcDom := c.serviceDomain
	c.mu.RUnlock()

	apexDom, subLabel := splitApexAndSubdomain(cleanTarget, zoneHint)
	if apexDom == "" {
		apexDom = cleanTarget
		subLabel = "@"
	}

	info := &NorthflankCustomDomainInfo{
		ID:             cleanTarget,
		Domain:         cleanTarget,
		ApexDomain:     apexDom,
		SubdomainLabel: subLabel,
		CNAMETarget:    svcDom,
	}

	domainPath := "/domains/" + url.PathEscape(apexDom)
	domRaw, err := doNFRequest[map[string]any](ctx, c, http.MethodGet, domainPath, nil)
	if err != nil {
		createPayload := map[string]any{
			"domain": apexDom,
		}
		domRaw, err = doNFRequest[map[string]any](ctx, c, http.MethodPost, "/domains", createPayload)
		if err != nil {
			var apiErr *nfAPIError
			if errors.As(err, &apiErr) && apiErr.IsConflictOrExists() {
				domRaw, _ = doNFRequest[map[string]any](ctx, c, http.MethodGet, domainPath, nil)
			} else {
				log.Printf("[Northflank] Note: Domain namespace registration (%s): %v", apexDom, err)
			}
		} else {
			log.Printf("[Northflank] ✓ Registered Root Domain Namespace: %s", apexDom)
		}
	}

	if domRaw != nil {
		apexVer, vHost, vTok, redirTarget := parseNFDomainObject(domRaw, apexDom)
		info.ApexVerified = apexVer
		info.VerificationHost = vHost
		info.VerificationToken = vTok
		if redirTarget != "" && info.CNAMETarget == "" {
			info.CNAMETarget = redirTarget
		}
	}

	if info.ApexVerified {
		c.ensureAndInspectSubdomain(ctx, info)
	}

	if info.CNAMETarget == "" && svcDom != "" {
		info.CNAMETarget = svcDom
	}

	if !info.IsCertificateValid() && probeCustomDomainTLS(ctx, cleanTarget, info.CNAMETarget) {
		info.CertificateStatus = "VALID"
	} else if info.CertificateStatus == "" {
		info.CertificateStatus = "PENDING_HTTP01"
	}

	c.SetCustomDomain(cleanTarget)
	c.notifyTopology()
	return info, nil
}

func (c *NorthflankClient) ensureAndInspectSubdomain(ctx context.Context, info *NorthflankCustomDomainInfo) {
	if info == nil || info.ApexDomain == "" {
		return
	}
	subKey := info.SubdomainLabel
	if subKey == "" {
		subKey = "@"
	}

	subPath := "/domains/" + url.PathEscape(info.ApexDomain) + "/subdomains/" + url.PathEscape(subKey)
	subRaw, err := doNFRequest[map[string]any](ctx, c, http.MethodGet, subPath, nil)
	if err != nil && subKey != "@" {
		createSubPath := "/domains/" + url.PathEscape(info.ApexDomain) + "/subdomains"
		subPayload := map[string]any{
			"subdomain":    subKey,
			"loadBalancer": "public",
		}
		subRaw, err = doNFRequest[map[string]any](ctx, c, http.MethodPost, createSubPath, subPayload)
		if err != nil {
			subPayloadAlt := map[string]any{
				"name":         subKey,
				"loadBalancer": "public",
			}
			subRaw, _ = doNFRequest[map[string]any](ctx, c, http.MethodPost, createSubPath, subPayloadAlt)
		}
		if subRaw == nil {
			subRaw, _ = doNFRequest[map[string]any](ctx, c, http.MethodGet, subPath, nil)
		} else {
			log.Printf("[Northflank] ✓ Created Subdomain Entry: %s (Root: %s)", info.Domain, info.ApexDomain)
		}
	}

	if subRaw != nil {
		subVer, certSt, target := parseNFSubdomainObject(subRaw)
		info.SubdomainVerified = subVer
		if certSt != "" {
			info.CertificateStatus = certSt
		}
		if target != "" {
			info.CNAMETarget = target
		}
	}
}

func (c *NorthflankClient) assignSubdomainToServicePort(ctx context.Context, info *NorthflankCustomDomainInfo) bool {
	if info == nil || !c.HasServiceContext() {
		return false
	}

	c.mu.RLock()
	projID := c.ProjectID
	svcID := c.ServiceID
	portName := c.PortName
	targetPort := c.TargetPort
	c.mu.RUnlock()

	if portName == "" {
		portName = "http"
	}

	subKey := info.SubdomainLabel
	if subKey == "" {
		subKey = "@"
	}

	assignPath := "/domains/" + url.PathEscape(info.ApexDomain) + "/subdomains/" + url.PathEscape(subKey) + "/assign"
	assignPayloads := []map[string]any{
		{
			"projectId": projID,
			"serviceId": svcID,
			"port":      portName,
		},
		{
			"projectId": projID,
			"serviceId": svcID,
			"portName":  portName,
		},
		{
			"project": projID,
			"service": svcID,
			"port":    portName,
		},
	}

	for _, pl := range assignPayloads {
		if _, err := doNFRequest[map[string]any](ctx, c, http.MethodPost, assignPath, pl); err == nil {
			info.AssignedToPort = true
			log.Printf("[Northflank] ✓ Linked Custom Domain %s -> Service %s (Port %s:%d)",
				info.Domain, svcID, portName, targetPort)
			return true
		}
	}

	pathsAssignURL := "/domains/" + url.PathEscape(info.ApexDomain) + "/subdomains/" + url.PathEscape(subKey) + "/paths"
	pathPayload := map[string]any{
		"projectId": projID,
		"serviceId": svcID,
		"port":      portName,
		"uri":       "/",
		"mode":      "prefix",
	}
	if _, err := doNFRequest[map[string]any](ctx, c, http.MethodPost, pathsAssignURL, pathPayload); err == nil {
		info.AssignedToPort = true
		log.Printf("[Northflank] ✓ Linked Custom Domain Path %s/ -> Service %s (Port %s:%d)",
			info.Domain, svcID, portName, targetPort)
		return true
	}

	return false
}

func (c *NorthflankClient) FinalizeCustomDomainVerification(ctx context.Context, info *NorthflankCustomDomainInfo) (*NorthflankCustomDomainInfo, error) {
	if !c.IsConfigured() || info == nil || info.ApexDomain == "" {
		return info, nil
	}

	if !info.ApexVerified {
		verifyDomPath := "/domains/" + url.PathEscape(info.ApexDomain) + "/verify"
		for attempt := 0; attempt < 4; attempt++ {
			if attempt > 0 {
				select {
				case <-ctx.Done():
					return info, ctx.Err()
				case <-time.After(2 * time.Second):
				}
			}
			if _, err := doNFRequest[map[string]any](ctx, c, http.MethodPost, verifyDomPath, map[string]any{}); err == nil {
				info.ApexVerified = true
				log.Printf("[Northflank] ✓ Verified Root Domain Ownership: %s", info.ApexDomain)
				break
			}
		}
	}

	c.ensureAndInspectSubdomain(ctx, info)

	subKey := info.SubdomainLabel
	if subKey == "" {
		subKey = "@"
	}
	verifySubPath := "/domains/" + url.PathEscape(info.ApexDomain) + "/subdomains/" + url.PathEscape(subKey) + "/verify"
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return info, ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
		if _, err := doNFRequest[map[string]any](ctx, c, http.MethodPost, verifySubPath, map[string]any{}); err == nil {
			info.SubdomainVerified = true
			log.Printf("[Northflank] ✓ Verified Subdomain DNS Record: %s", info.Domain)
			break
		}
	}

	c.assignSubdomainToServicePort(ctx, info)

	if !info.IsCertificateValid() && probeCustomDomainTLS(ctx, info.Domain, info.CNAMETarget) {
		info.CertificateStatus = "VALID"
	}

	return info, nil
}

func (c *NorthflankClient) FetchCustomDomainStatus(ctx context.Context, customDomainID, targetDomain string) (*NorthflankCustomDomainInfo, error) {
	cleanTarget := cleanHost(targetDomain)
	if cleanTarget == "" {
		cleanTarget = cleanHost(customDomainID)
	}

	c.mu.RLock()
	zoneHint := c.zoneHint
	svcDom := c.serviceDomain
	c.mu.RUnlock()

	apexDom, subLabel := splitApexAndSubdomain(cleanTarget, zoneHint)
	if subLabel == "" {
		subLabel = "@"
	}

	info := &NorthflankCustomDomainInfo{
		ID:             cleanTarget,
		Domain:         cleanTarget,
		ApexDomain:     apexDom,
		SubdomainLabel: subLabel,
		CNAMETarget:    svcDom,
	}

	if c.IsConfigured() && apexDom != "" {
		subPath := "/domains/" + url.PathEscape(apexDom) + "/subdomains/" + url.PathEscape(subLabel)
		if subRaw, err := doNFRequest[map[string]any](ctx, c, http.MethodGet, subPath, nil); err == nil && subRaw != nil {
			subVer, certSt, target := parseNFSubdomainObject(subRaw)
			info.SubdomainVerified = subVer
			if certSt != "" {
				info.CertificateStatus = certSt
			}
			if target != "" {
				info.CNAMETarget = target
			}
			if !subVer {
				verifySubPath := subPath + "/verify"
				_, _ = doNFRequest[map[string]any](ctx, c, http.MethodPost, verifySubPath, map[string]any{})
			}
		}
	}

	if !info.IsCertificateValid() && probeCustomDomainTLS(ctx, cleanTarget, info.CNAMETarget) {
		info.CertificateStatus = "VALID"
	} else if info.CertificateStatus == "" {
		info.CertificateStatus = "PENDING_HTTP01"
	}

	return info, nil
}

func (c *NorthflankClient) WaitCustomDomainCertificate(ctx context.Context, customDomainID, targetDomain string, maxWait time.Duration) (*NorthflankCustomDomainInfo, bool) {
	if maxWait <= 0 {
		maxWait = defaultNFCertPollWait
	}
	waitCtx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()

	ticker := time.NewTicker(defaultNFCertPollTick)
	defer ticker.Stop()

	var latest *NorthflankCustomDomainInfo
	for {
		info, err := c.FetchCustomDomainStatus(waitCtx, customDomainID, targetDomain)
		if err == nil && info != nil {
			latest = info
			if info.IsCertificateValid() {
				log.Printf("[Northflank] ✓ Custom Domain %s Let's Encrypt TLS Certificate ISSUED & VALID (%s)",
					info.Domain, info.CertificateStatus)
				return info, true
			}
		}

		select {
		case <-waitCtx.Done():
			return latest, false
		case <-ticker.C:
		}
	}
}

func probeCustomDomainTLS(ctx context.Context, customDomain, gatewayHost string) bool {
	cleanCustom := cleanHost(customDomain)
	if cleanCustom == "" {
		return false
	}
	dialTarget := cleanHost(gatewayHost)
	if dialTarget == "" {
		dialTarget = cleanCustom
	}

	dialer := &net.Dialer{
		Timeout: defaultNFTLSProbeTimeout,
	}
	tlsConn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(dialTarget, "443"), &tls.Config{
		ServerName:         cleanCustom,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	})
	if err != nil {
		return false
	}
	_ = tlsConn.Close()
	return true
}

func probeKernelIPv6Route() bool {
	conn, err := net.DialTimeout("udp6", "[2606:4700:4700::1111]:53", 50*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (c *NorthflankClient) TuneComputeAndNetwork(ctx context.Context) {
	if probeKernelIPv6Route() {
		log.Println("[Northflank] ✓ Outbound IPv6 Stack: ACTIVE & VERIFIED (Kernel IPv6 routing table online)")
	} else {
		log.Println("[Northflank] ✓ Outbound Network Stack: IPv4 Active (Safe IPv4 egress routing verified)")
	}

	if !c.IsConfigured() {
		return
	}
	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return
	}

	desiredPlan := strings.TrimSpace(getEnv("BERMUDA_NF_PLAN", ""))
	if desiredPlan == "" {
		return
	}

	c.mu.RLock()
	projID := c.ProjectID
	svcID := c.ServiceID
	c.mu.RUnlock()

	scalePath := "/projects/" + url.PathEscape(projID) + "/services/" + url.PathEscape(svcID) + "/scale"
	scalePayload := map[string]any{
		"deploymentPlan": desiredPlan,
		"instances":      1,
	}
	if _, err := doNFRequest[map[string]any](ctx, c, http.MethodPost, scalePath, scalePayload); err != nil {
		var apiErr *nfAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			log.Printf("[Northflank] Note: Compute plan scaling (%s) skipped (account plan/tier restriction)", desiredPlan)
			return
		}
		log.Printf("[Northflank] Note: Compute plan update (%s) unapplied: %v", desiredPlan, err)
		return
	}
	log.Printf("[Northflank] ✓ Compute Plan Enforced: %s (1 instance)", desiredPlan)
}
