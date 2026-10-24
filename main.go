package main

import (
	"context"
	"errors"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultPort            = "8080"
	fallbackSelfMemMB      = 128
	fallbackXrayMemMB      = 550
	defaultGOMAXPROCS      = 2
	gatewayMemPercent      = 12
	xrayMemPercent         = 55
	httpDrainTimeout       = 7 * time.Second
	edgeKeepAlivePeriod    = 15 * time.Second
	drainPropagationWindow = 400 * time.Millisecond
	tcpUserTimeoutOpt      = 18
)

func cgroupMemoryLimit() (uint64, bool) {
	candidates := []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(data))
		if s == "" || s == "max" {
			continue
		}
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil || n == 0 || n >= 1<<50 {
			continue
		}
		return n, true
	}
	return 0, false
}

func deriveMemoryBudget() (gwMB, xrayMB int) {
	gwMB, xrayMB = fallbackSelfMemMB, fallbackXrayMemMB
	limit, limited := cgroupMemoryLimit()
	if limited {
		totalMB := int(limit >> 20)
		gwMB = totalMB * gatewayMemPercent / 100
		xrayMB = totalMB * xrayMemPercent / 100

		allowedMB := totalMB * 67 / 100
		if gwMB < 32 {
			gwMB = 32
		}
		if xrayMB < 64 {
			xrayMB = 64
		}
		if total := gwMB + xrayMB; total > allowedMB && allowedMB >= 96 {
			gwMB = allowedMB * gatewayMemPercent / 67
			xrayMB = allowedMB * xrayMemPercent / 67
		}
	}

	gwMB = getEnvInt("BERMUDA_SELF_MEM_MB", gwMB)
	xrayMB = getEnvInt("BERMUDA_XRAY_MEM_MB", xrayMB)
	return gwMB, xrayMB
}

func applyMemoryCeiling(selfMB int) {
	debug.SetMemoryLimit(int64(selfMB) << 20)
	debug.SetGCPercent(100)
}

func cgroupCPUQuota() (float64, bool) {
	if data, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		f := strings.Fields(string(data))
		if len(f) == 2 && f[0] != "max" {
			q, e1 := strconv.ParseFloat(f[0], 64)
			p, e2 := strconv.ParseFloat(f[1], 64)
			if e1 == nil && e2 == nil && q > 0 && p > 0 {
				return q / p, true
			}
		}
		return 0, false
	}
	qb, e1 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	pb, e2 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if e1 == nil && e2 == nil {
		q, e3 := strconv.ParseFloat(strings.TrimSpace(string(qb)), 64)
		p, e4 := strconv.ParseFloat(strings.TrimSpace(string(pb)), 64)
		if e3 == nil && e4 == nil && q > 0 && p > 0 {
			return q / p, true
		}
	}
	return 0, false
}

func applyGOMAXPROCS() int {
	n := getEnvInt("BERMUDA_GOMAXPROCS", 0)
	if n == 0 {
		if q, ok := cgroupCPUQuota(); ok {
			n = int(math.Ceil(q))
		}
	}
	if n <= 0 {
		n = defaultGOMAXPROCS
	}
	if cpus := runtime.NumCPU(); n > cpus {
		n = cpus
	}
	runtime.GOMAXPROCS(n)
	return n
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func cleanHost(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "${{") || strings.HasPrefix(h, "$") {
		return ""
	}
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	h = strings.TrimRight(h, "/")
	if idx := strings.Index(h, ":"); idx != -1 && !strings.Contains(h, "]") {
		h = h[:idx]
	}
	return strings.ToLower(strings.TrimSpace(h))
}

func isNorthflankManagedDomain(h string) bool {
	if h == "" {
		return false
	}
	return strings.Contains(h, "code.run") ||
		strings.Contains(h, "northflank.app") ||
		strings.Contains(h, "northflank.com") ||
		strings.HasSuffix(h, ".cluster.local") ||
		strings.HasSuffix(h, ".svc") ||
		strings.HasSuffix(h, ".internal")
}

func isNorthflankPublicDomain(h string) bool {
	return h != "" &&
		(strings.Contains(h, "code.run") || strings.Contains(h, "northflank.app")) &&
		!strings.HasSuffix(h, ".internal") &&
		!strings.HasSuffix(h, ".cluster.local") &&
		!strings.HasSuffix(h, ".svc")
}

func normalizeRegion(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(s, "zurich") || strings.Contains(s, "ch-") || strings.Contains(s, "swiss") || strings.Contains(s, "switzerland") || strings.Contains(s, "zrh"):
		return "ch-central"
	case strings.Contains(s, "netherlands") || strings.Contains(s, "europe-west4") || strings.Contains(s, "amsterdam") || strings.Contains(s, "drams") || strings.Contains(s, "ams") || strings.Contains(s, "nl"):
		return "europe-west4"
	case strings.Contains(s, "frankfurt") || strings.Contains(s, "eu-central") || strings.Contains(s, "de-") || strings.Contains(s, "germany") || strings.Contains(s, "fra"):
		return "eu-central"
	case s == "europe-west" || strings.Contains(s, "london") || strings.Contains(s, "uk") || strings.Contains(s, "lhr") || strings.Contains(s, "gb"):
		return "eu-west-london"
	case strings.Contains(s, "us-central") || strings.Contains(s, "iowa") || strings.Contains(s, "ord") || strings.Contains(s, "dfw"):
		return "us-central"
	case strings.Contains(s, "us-east") || strings.Contains(s, "virginia") || strings.Contains(s, "ohio") || strings.Contains(s, "eqdc") || strings.Contains(s, "iad"):
		return "us-east4"
	case strings.Contains(s, "us-west") || strings.Contains(s, "california") || strings.Contains(s, "oregon") || strings.Contains(s, "sjc") || strings.Contains(s, "pdx"):
		return "us-west"
	case strings.Contains(s, "asia-northeast") || strings.Contains(s, "asia-east") || strings.Contains(s, "tokyo") || strings.Contains(s, "taiwan") || strings.Contains(s, "nrt"):
		return "asia-northeast"
	case strings.Contains(s, "asia") || strings.Contains(s, "singapore") || strings.Contains(s, "eqsg") || strings.Contains(s, "sin") || strings.Contains(s, "ap-"):
		return "asia-southeast1"
	case strings.Contains(s, "africa") || strings.Contains(s, "af-south") || strings.Contains(s, "johannesburg") || strings.Contains(s, "jnb"):
		return "af-south"
	case strings.Contains(s, "southamerica") || strings.Contains(s, "sa-east") || strings.Contains(s, "brazil") || strings.Contains(s, "sao-paulo") || strings.Contains(s, "gru"):
		return "sa-east"
	default:
		return "eu-central"
	}
}

func resolveInfrastructureDomains() (nfDomain, customDomain string) {
	staticURL := cleanHost(getEnv("NORTHFLANK_SERVICE_URL", getEnv("NORTHFLANK_STATIC_URL", "")))
	publicDomain := cleanHost(getEnv("NORTHFLANK_PUBLIC_DOMAIN", getEnv("NORTHFLANK_DOMAIN", getEnv("NF_PUBLIC_DOMAIN", ""))))
	explicitNF := cleanHost(getEnv("NORTHFLANK_DEFAULT_DOMAIN", getEnv("BERMUDA_NORTHFLANK_DOMAIN", "")))
	customEnv := cleanHost(getEnv("CUSTOM_DOMAIN", getEnv("BERMUDA_CUSTOM_DOMAIN", "")))

	for _, candidate := range []string{explicitNF, publicDomain, staticURL} {
		if isNorthflankPublicDomain(candidate) {
			nfDomain = candidate
			break
		}
	}

	for _, candidate := range []string{customEnv, publicDomain, staticURL, explicitNF} {
		if candidate != "" && !isNorthflankManagedDomain(candidate) {
			customDomain = candidate
			break
		}
	}

	return nfDomain, customDomain
}

func orchestrateCloudInfrastructure(
	ctx context.Context,
	sup *Supervisor,
	gw *Gateway,
	nf *NorthflankClient,
	cf *CloudflareClient,
	initialNF string,
	initialCF string,
	initialRegion string,
) {
	nfDomain := cleanHost(initialNF)
	customDomain := cleanHost(initialCF)
	region := initialRegion
	topologyUpdated := false

	syncDomains := func(newNF, newCF string) {
		cleanNF := cleanHost(newNF)
		cleanCF := cleanHost(newCF)
		if isNorthflankPublicDomain(cleanNF) {
			if nfDomain == "" || (!isFullNorthflankServiceDomain(nfDomain) && isFullNorthflankServiceDomain(cleanNF)) {
				if nfDomain != cleanNF {
					nfDomain = cleanNF
					topologyUpdated = true
				}
			}
		}
		if cleanCF != "" && !isNorthflankManagedDomain(cleanCF) {
			if customDomain == "" || strings.HasSuffix(cleanCF, "."+customDomain) {
				if customDomain != cleanCF {
					customDomain = cleanCF
					topologyUpdated = true
				}
			}
		}
		sup.SetInfrastructureDomains(nfDomain, customDomain, region)
		gw.SetInfrastructureDomains(nfDomain, customDomain, region)
		if cf != nil {
			if nfDomain != "" {
				cf.SetNorthflankOrigin(nfDomain)
			}
			if customDomain != "" {
				cf.SetPreferredDomain(customDomain)
			}
		}
		if nf != nil {
			if nfDomain != "" {
				nf.SetServiceDomain(nfDomain)
			}
			if customDomain != "" {
				nf.SetCustomDomain(customDomain)
			}
		}
	}

	if nf != nil && nf.IsConfigured() {
		if sup.IsMasterKeyAutoGenerated() || sanitizeMasterKey(getEnv("BERMUDA_MASTER_KEY", getEnv("MASTER_KEY", ""))) == "" {
			nf.PersistMasterKey(ctx, sup.MasterKey())
		}

		if srvDom, err := nf.EnsureServiceDomain(ctx); err == nil && srvDom != "" {
			if discReg := nf.GetDiscoveredRegion(); discReg != "" && getEnv("BERMUDA_REGION", "") == "" {
				region = normalizeRegion(discReg)
			}
			syncDomains(srvDom, "")
		} else if err != nil {
			log.Printf("[Northflank] Notice: Service domain check: %v", err)
		}
	}

	if cf != nil && cf.Token != "" {
		probeCtx, probeCancel := context.WithTimeout(ctx, 12*time.Second)
		if cfDom, err := cf.FetchZoneDomain(probeCtx); err == nil && cfDom != "" {
			if nf != nil && cf.ZoneRootDomain() != "" {
				nf.SetZoneHint(cf.ZoneRootDomain())
			}
			syncDomains(cf.GetNorthflankOrigin(), cfDom)
		} else if err != nil {
			log.Printf("[Cloudflare] Notice: Zone domain discovery: %v", err)
		}
		probeCancel()
	}

	var customDomInfo *NorthflankCustomDomainInfo
	var cnameRecordID string

	if customDomain != "" && (nf != nil || nfDomain != "") {
		if nf != nil && nf.IsConfigured() {
			info, err := nf.EnsureCustomDomain(ctx, customDomain)
			if err != nil {
				log.Printf("[Northflank] Notice: Custom domain registration (%s): %v", customDomain, err)
			} else if info != nil {
				customDomInfo = info
				syncDomains(nf.GetServiceDomain(), info.Domain)
			}
		}
		if customDomInfo == nil && nfDomain != "" {
			certState := "PENDING_HTTP01"
			if probeCustomDomainTLS(ctx, customDomain, nfDomain) {
				certState = "VALID"
			}
			customDomInfo = &NorthflankCustomDomainInfo{
				ID:                customDomain,
				Domain:            customDomain,
				CNAMETarget:       nfDomain,
				CertificateStatus: certState,
			}
		}
		if customDomInfo != nil && cf != nil && cf.Token != "" {
			recID, dnsErr := cf.ProvisionNorthflankDNS(ctx, customDomInfo)
			if dnsErr != nil {
				log.Printf("[Cloudflare] Warning: Automated Northflank DNS provisioning: %v", dnsErr)
			} else {
				cnameRecordID = recID
			}
		}
		if customDomInfo != nil && nf != nil && nf.IsConfigured() {
			prevTarget := customDomInfo.CNAMETarget
			if updatedInfo, verErr := nf.FinalizeCustomDomainVerification(ctx, customDomInfo); verErr == nil && updatedInfo != nil {
				customDomInfo = updatedInfo
				if cf != nil && cf.Token != "" && updatedInfo.CNAMETarget != "" && updatedInfo.CNAMETarget != prevTarget {
					if recID, dnsErr := cf.ProvisionNorthflankDNS(ctx, updatedInfo); dnsErr == nil && recID != "" {
						cnameRecordID = recID
					}
				}
			}
		}
	}

	if cf != nil && cf.Token != "" && ctx.Err() == nil {
		cf.Tune(ctx)
		syncDomains(cf.GetNorthflankOrigin(), cf.CachedZoneDomain())
	}

	if cf != nil && customDomInfo != nil && !customDomInfo.IsCertificateValid() && ctx.Err() == nil {
		log.Printf("[Northflank] Waiting for Let's Encrypt HTTP-01 TLS validation on %s before enabling Cloudflare Orange Cloud...", customDomInfo.Domain)
		if nf != nil && nf.IsConfigured() {
			updatedInfo, valid := nf.WaitCustomDomainCertificate(ctx, customDomInfo.ID, customDomInfo.Domain, defaultNFCertPollWait)
			if valid && updatedInfo != nil {
				cf.PromoteCustomDomainToOrangeCloud(ctx, updatedInfo.Domain, updatedInfo.CNAMETarget, cnameRecordID)
			} else if ctx.Err() == nil {
				go watchAndPromoteCustomDomain(ctx, nf, cf, customDomInfo, cnameRecordID)
			}
		} else {
			go watchAndPromoteCustomDomain(ctx, nil, cf, customDomInfo, cnameRecordID)
		}
	}

	if nf != nil && nf.IsConfigured() && ctx.Err() == nil {
		nf.TuneComputeAndNetwork(ctx)
	}

	if ctx.Err() == nil && (topologyUpdated || nf != nil || cf != nil) {
		log.Printf("[Runtime] Synchronized Cloud Topology: NorthflankDomain=%q | CloudflareDomain=%q | Region=%q",
			nfDomain, customDomain, region)
		sup.LogProvisioningLink("")
	}
}

func watchAndPromoteCustomDomain(
	parent context.Context,
	nf *NorthflankClient,
	cf *CloudflareClient,
	info *NorthflankCustomDomainInfo,
	cnameRecordID string,
) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
	defer cancel()

	ticker := time.NewTicker(12 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if nf != nil && nf.IsConfigured() {
				latest, err := nf.FetchCustomDomainStatus(ctx, info.ID, info.Domain)
				if err == nil && latest != nil && latest.IsCertificateValid() {
					log.Printf("[Northflank] ✓ Deferred HTTP-01 TLS validation completed for %s (%s)",
						latest.Domain, latest.CertificateStatus)
					cf.PromoteCustomDomainToOrangeCloud(ctx, latest.Domain, latest.CNAMETarget, cnameRecordID)
					return
				}
			} else if probeCustomDomainTLS(ctx, info.Domain, info.CNAMETarget) {
				log.Printf("[Northflank] ✓ Direct TLS Handshake verified for %s on %s", info.Domain, info.CNAMETarget)
				cf.PromoteCustomDomainToOrangeCloud(ctx, info.Domain, info.CNAMETarget, cnameRecordID)
				return
			}
		}
	}
}

func teardown(
	srv *http.Server,
	gw *Gateway,
	sup *Supervisor,
	supCancel context.CancelFunc,
	cloudCancel context.CancelFunc,
	graceful bool,
) {
	hardDeadline := time.Now().Add(18 * time.Second)

	if cloudCancel != nil {
		cloudCancel()
	}

	gw.SetDraining()
	if graceful {
		log.Println("[Gateway] Stage 1/5: Health status flipped to 503 (traffic shedding)...")
		time.Sleep(drainPropagationWindow)
	}

	if graceful {
		log.Println("[Gateway] Stage 2/5: Draining HTTP server listeners and active XHTTP streams...")
		httpDeadline := minTime(hardDeadline.Add(-6*time.Second), time.Now().Add(10*time.Second))
		httpCtx, cancelHTTP := context.WithDeadline(context.Background(), httpDeadline)
		if err := srv.Shutdown(httpCtx); err != nil {
			log.Printf("[Gateway] HTTP server drain timeout (%v); forcing listener closure", err)
			_ = srv.Close()
		} else {
			log.Println("[Gateway] HTTP server listener drained successfully")
		}
		cancelHTTP()

		log.Println("[Gateway] Stage 3/5: Waiting for active WebSocket/hijacked tunnels to conclude...")
		tunnelDeadline := minTime(hardDeadline.Add(-5*time.Second), time.Now().Add(httpDrainTimeout))
		if tunnelDeadline.After(time.Now()) {
			tunnelCtx, cancelTunnel := context.WithDeadline(context.Background(), tunnelDeadline)
			gw.WaitTunnels(tunnelCtx)
			cancelTunnel()
		}
	} else {
		_ = srv.Close()
	}

	log.Println("[Gateway] Stage 4/5: Force-closing remaining hijacked sockets and backend pools...")
	gw.CloseTunnels()
	gw.CloseIdleBackendConns()

	log.Println("[Gateway] Stage 5/5: Tearing down engine worker process group...")
	supCancel()
	remainingSupTime := time.Until(hardDeadline)
	if remainingSupTime <= 0 {
		remainingSupTime = 2 * time.Second
	}
	sup.Stop(remainingSupTime)
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.Println("[Gateway] Initializing BERMUDA PORTAL Gateway (Northflank + Cloudflare Edition)...")

	gwMB, xrayMB := deriveMemoryBudget()
	applyMemoryCeiling(gwMB)
	procs := applyGOMAXPROCS()

	_ = syscall.Setenv("BERMUDA_XRAY_MEM_MB", strconv.Itoa(xrayMB))
	_ = syscall.Setenv("BERMUDA_XRAY_GOMAXPROCS", strconv.Itoa(procs))
	log.Printf("[Runtime] Dynamic memory ceiling: Gateway=%dMiB, Engine=%dMiB (GOGC=100) | GOMAXPROCS=%d",
		gwMB, xrayMB, procs)

	sigCtx, stopSig := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stopSig()

	port := getEnv("PORT", defaultPort)
	nfDomain, customDomain := resolveInfrastructureDomains()

	rawRegion := getEnv("BERMUDA_REGION", getEnv("NORTHFLANK_REGION", getEnv("NF_REGION", getEnv("REGION", ""))))
	region := normalizeRegion(rawRegion)

	sup := NewSupervisor()
	if err := sup.PreflightContext(sigCtx); err != nil {
		log.Printf("[Gateway] Warning: Supervisor preflight issue: %v. Continuing to start...", err)
	}

	cfToken := sanitizeCloudflareToken(getEnv("CLOUDFLARE_API_TOKEN", getEnv("BERMUDA_CF_API_TOKEN", "")))
	cfZoneID := sanitizeExplicitCredential(getEnv("CLOUDFLARE_ZONE_ID", getEnv("BERMUDA_CF_ZONE_ID", "")))
	var cf *CloudflareClient
	if cfToken != "" {
		cf = NewCloudflareClient(cfToken, cfZoneID)
		if nfDomain != "" {
			cf.SetNorthflankOrigin(nfDomain)
		}
		if customDomain != "" {
			cf.SetPreferredDomain(customDomain)
		}
	} else {
		log.Println("[Cloudflare] Notice: CLOUDFLARE_API_TOKEN unset. Edge auto-tuning bypassed.")
	}

	nfToken := sanitizeNorthflankToken(getEnv("NORTHFLANK_API_TOKEN", getEnv("NORTHFLANK_TOKEN", getEnv("BERMUDA_NORTHFLANK_TOKEN", getEnv("NF_API_TOKEN", "")))))
	var nf *NorthflankClient
	if nfToken != "" {
		nf = NewNorthflankClient(nfToken)
		if nfDomain != "" {
			nf.SetServiceDomain(nfDomain)
		}
		if customDomain != "" {
			nf.SetCustomDomain(customDomain)
		}
	} else {
		log.Println("[Northflank] Notice: NORTHFLANK_API_TOKEN unset. Northflank self-provisioning bypassed.")
	}

	sup.SetInfrastructureDomains(nfDomain, customDomain, region)
	primaryLogDomain := customDomain
	if primaryLogDomain == "" {
		primaryLogDomain = nfDomain
	}
	if primaryLogDomain != "" {
		sup.SetPublicDomain(primaryLogDomain)
	}

	log.Printf("[Runtime] Initial Infrastructure Topology: NorthflankDomain=%q | CloudflareDomain=%q | Region=%q",
		nfDomain, customDomain, region)

	gw := NewGateway(sup, cf, nfDomain, customDomain, region)
	gw.SetNorthflankClient(nf)

	topologyUpdater := func(nfDom, cfDom string) {
		sup.SetInfrastructureDomains(nfDom, cfDom, region)
		gw.SetInfrastructureDomains(nfDom, cfDom, region)
	}
	if cf != nil {
		cf.SetTopologyCallback(topologyUpdater)
	}
	if nf != nil {
		nf.SetTopologyCallback(topologyUpdater)
	}

	supCtx, supCancel := context.WithCancel(context.Background())
	supErrCh := make(chan error, 1)
	go func() {
		supErrCh <- sup.Run(supCtx)
	}()

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       16 * time.Minute,
		MaxHeaderBytes:    32 << 10,
		ConnState:         gw.TrackConnState,
	}

	listenCfg := net.ListenConfig{
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     edgeKeepAlivePeriod,
			Interval: edgeKeepAlivePeriod,
			Count:    4,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {
				if e := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeoutOpt, 90000); e != nil {
					controlErr = e
				}
			})
			if err != nil {
				return err
			}
			return controlErr
		},
	}

	ln, err := listenCfg.Listen(context.Background(), "tcp", srv.Addr)
	if err != nil {
		log.Fatalf("[Gateway] Fatal: Cannot bind listener on %s: %v", srv.Addr, err)
	}

	serverErrCh := make(chan error, 1)
	go func() {
		log.Printf("[Gateway] Edge listener active on :%s (PID %d, GOMAXPROCS=%d)", port, os.Getpid(), procs)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- err
		}
	}()

	cloudCtx, cloudCancel := context.WithCancel(sigCtx)
	defer cloudCancel()
	if nf != nil || cf != nil {
		go orchestrateCloudInfrastructure(cloudCtx, sup, gw, nf, cf, nfDomain, customDomain, region)
	}

	select {
	case err := <-serverErrCh:
		log.Printf("[Gateway] Fatal: HTTP server failure: %v", err)
		teardown(srv, gw, sup, supCancel, cloudCancel, false)
		os.Exit(1)
	case err := <-supErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("[Gateway] Fatal: Supervisor halted unexpectedly: %v", err)
		}
		teardown(srv, gw, sup, supCancel, cloudCancel, false)
		os.Exit(1)
	case <-sigCtx.Done():
		log.Println("[Gateway] Termination signal intercepted. Commencing graceful teardown...")
	}

	teardown(srv, gw, sup, supCancel, cloudCancel, true)
	log.Println("[Gateway] BERMUDA PORTAL Gateway shutdown complete. Ports released cleanly. Exit 0.")
}
