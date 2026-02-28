package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/jilanisayyad/tcputils/internal/tracer"
)

type Diagnostics struct {
	Target string    `json:"target"`
	Port   int       `json:"port"`
	DNS    DNSDiag   `json:"dns"`
	TCP    TCPDiag   `json:"tcp"`
	TLS    *TLSDiag  `json:"tls,omitempty"`
	HTTP   *HTTPDiag `json:"http,omitempty"`
	RunAt  time.Time `json:"run_at"`
	Notes  []string  `json:"notes,omitempty"`
}

type DNSDiag struct {
	LookupDuration time.Duration `json:"lookup_duration"`
	IPv4           []string      `json:"ipv4"`
	IPv6           []string      `json:"ipv6"`
	Error          string        `json:"error,omitempty"`
}

type TCPDiag struct {
	Attempts int           `json:"attempts"`
	Timeout  time.Duration `json:"timeout"`
	Samples  []TCPAttempt  `json:"samples"`
	MinRTT   time.Duration `json:"min_rtt"`
	AvgRTT   time.Duration `json:"avg_rtt"`
	MaxRTT   time.Duration `json:"max_rtt"`
	Failures int           `json:"failures"`
	P95RTT   time.Duration `json:"p95_rtt"`
	Jitter   time.Duration `json:"jitter"`
}

type TCPAttempt struct {
	Attempt int           `json:"attempt"`
	RTT     time.Duration `json:"rtt"`
	Success bool          `json:"success"`
	Error   string        `json:"error,omitempty"`
}

type TLSDiag struct {
	Attempted    bool          `json:"attempted"`
	Success      bool          `json:"success"`
	ServerName   string        `json:"server_name,omitempty"`
	HandshakeRTT time.Duration `json:"handshake_rtt"`
	Version      string        `json:"version,omitempty"`
	CipherSuite  string        `json:"cipher_suite,omitempty"`
	ALPN         string        `json:"alpn,omitempty"`
	CertSubject  string        `json:"cert_subject,omitempty"`
	CertIssuer   string        `json:"cert_issuer,omitempty"`
	CertNotAfter time.Time     `json:"cert_not_after,omitempty"`
	Error        string        `json:"error,omitempty"`
}

type HTTPDiag struct {
	URL          string            `json:"url"`
	Method       string            `json:"method"`
	StatusCode   int               `json:"status_code"`
	RemoteAddr   string            `json:"remote_addr,omitempty"`
	Total        time.Duration     `json:"total"`
	DNS          time.Duration     `json:"dns"`
	Connect      time.Duration     `json:"connect"`
	TLSHandshake time.Duration     `json:"tls_handshake"`
	TTFB         time.Duration     `json:"ttfb"`
	Headers      map[string]string `json:"headers,omitempty"`
	Error        string            `json:"error,omitempty"`
}

type CLIOutput struct {
	Diagnostics *Diagnostics        `json:"diagnostics,omitempty"`
	TCPPing     *TCPPingResult      `json:"tcpping,omitempty"`
	Trace       *tracer.TraceResult `json:"trace,omitempty"`
}

type TCPPingResult struct {
	Target     string          `json:"target"`
	Port       int             `json:"port"`
	Count      int             `json:"count"`
	Interval   time.Duration   `json:"interval"`
	Timeout    time.Duration   `json:"timeout"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at"`
	Samples    []TCPPingSample `json:"samples"`
	PacketLoss float64         `json:"packet_loss"`
	MinRTT     time.Duration   `json:"min_rtt"`
	AvgRTT     time.Duration   `json:"avg_rtt"`
	MaxRTT     time.Duration   `json:"max_rtt"`
	Jitter     time.Duration   `json:"jitter"`
	P95RTT     time.Duration   `json:"p95_rtt"`
}

type TCPPingSample struct {
	Seq     int           `json:"seq"`
	RTT     time.Duration `json:"rtt"`
	Success bool          `json:"success"`
	Error   string        `json:"error,omitempty"`
}

func main() {
	var (
		port            = flag.Int("p", 80, "destination TCP port")
		maxHops         = flag.Int("m", 30, "max hops")
		firstHop        = flag.Int("f", 1, "first hop (TTL)")
		probes          = flag.Int("q", 3, "probes per hop")
		timeout         = flag.Duration("w", 2*time.Second, "timeout per probe")
		connectTries    = flag.Int("connect-attempts", 3, "TCP connect attempts in --diag mode")
		connectTO       = flag.Duration("connect-timeout", 2*time.Second, "TCP connect timeout in --diag mode")
		tcpLatency      = flag.Bool("tcp-latency", false, "alias for --tcpping")
		tcpPingMode     = flag.Bool("tcpping", false, "run TCP ping latency probes")
		tcpPingOnly     = flag.Bool("tcpping-only", false, "run TCP ping probes and skip diagnostics/traceroute")
		tcpPingCount    = flag.Int("tcpping-count", 5, "number of probes for --tcpping")
		tcpPingIntv     = flag.Duration("tcpping-interval", 1*time.Second, "interval between --tcpping probes")
		tcpPingTO       = flag.Duration("tcpping-timeout", 2*time.Second, "timeout per --tcpping probe")
		tcpPingForever  = flag.Bool("tcpping-forever", false, "run TCP ping continuously until Ctrl+C")
		tcpPingDeadline = flag.Duration("tcpping-deadline", 0, "maximum total runtime for --tcpping (e.g. 30s, 5m)")
		diagMode        = flag.Bool("diag", false, "run diagnostic checks (DNS/TCP/TLS/HTTP)")
		diagOnly        = flag.Bool("diag-only", false, "run diagnostics and skip traceroute")
		tlsCheck        = flag.Bool("tls", false, "run TLS handshake check in --diag mode (auto-enabled for port 443)")
		sni             = flag.String("sni", "", "override TLS SNI/ServerName in --diag mode")
		insecureTLS     = flag.Bool("k", false, "skip TLS certificate verification for --diag TLS/HTTP checks")
		httpProbe       = flag.Bool("http", false, "run HTTP probe in --diag mode")
		httpURL         = flag.String("http-url", "", "HTTP URL to probe in --diag mode")
		httpMethod      = flag.String("http-method", "GET", "HTTP method for --http-url in --diag mode")
		httpTimeout     = flag.Duration("http-timeout", 8*time.Second, "HTTP request timeout in --diag mode")
		noRDNS          = flag.Bool("no-rdns", false, "disable reverse DNS lookups for hops")
		jsonOut         = flag.Bool("json", false, "print results as JSON")
		showHelp        = flag.Bool("h", false, "show help")
		showHelpLong    = flag.Bool("help", false, "show help")
	)

	flag.Parse()
	if *showHelp || *showHelpLong || flag.NArg() != 1 {
		printUsage()
		if flag.NArg() != 1 {
			os.Exit(2)
		}
		return
	}

	target := flag.Arg(0)
	if *tcpLatency {
		*tcpPingMode = true
	}
	if *tcpPingOnly {
		*tcpPingMode = true
	}
	if *diagOnly {
		*diagMode = true
	}

	var tcpPing *TCPPingResult
	if *tcpPingMode {
		opt := tcpPingOptions{
			count:    *tcpPingCount,
			timeout:  *tcpPingTO,
			interval: *tcpPingIntv,
			forever:  *tcpPingForever,
			deadline: *tcpPingDeadline,
		}
		if !*jsonOut {
			printTCPPingHeader(target, *port, opt)
			opt.onSample = printTCPPingSample
		}
		tcpPing = runTCPPing(target, *port, opt)
		if !*jsonOut {
			printTCPPingSummary(tcpPing)
		}
	}

	if *tcpPingOnly {
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(CLIOutput{TCPPing: tcpPing})
		}
		return
	}

	var diag *Diagnostics
	if *diagMode {
		diag = runDiagnostics(diagInput{
			target:          target,
			port:            *port,
			connectAttempts: *connectTries,
			connectTimeout:  *connectTO,
			tlsCheck:        *tlsCheck || *port == 443,
			sni:             *sni,
			insecureTLS:     *insecureTLS,
			httpProbe:       *httpProbe || *httpURL != "",
			httpURL:         *httpURL,
			httpMethod:      strings.ToUpper(strings.TrimSpace(*httpMethod)),
			httpTimeout:     *httpTimeout,
		})

		if !*jsonOut {
			printDiagnostics(diag)
		}
	}

	if *diagOnly {
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(CLIOutput{Diagnostics: diag, TCPPing: tcpPing})
		}
		return
	}

	cfg := tracer.Config{
		Target:          target,
		Port:            *port,
		MaxHops:         *maxHops,
		FirstHop:        *firstHop,
		ProbesPerHop:    *probes,
		Timeout:         *timeout,
		ResolveHopNames: !*noRDNS,
	}

	if !*jsonOut {
		targetIP := firstIPv4(target)
		if targetIP != "" {
			fmt.Printf("traceroute to %s (%s), %d hops max, TCP SYN to port %d\n", target, targetIP, *maxHops, *port)
		} else {
			fmt.Printf("traceroute to %s, %d hops max, TCP SYN to port %d\n", target, *maxHops, *port)
		}
		printer := &livePrinter{}
		cfg.OnHopStart = printer.startHop
		cfg.OnProbe = printer.printProbe
		cfg.OnHop = printer.finishHop
	}

	res, err := tracer.Trace(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if diag != nil {
			_ = enc.Encode(CLIOutput{Diagnostics: diag, TCPPing: tcpPing, Trace: res})
		} else if tcpPing != nil {
			_ = enc.Encode(CLIOutput{TCPPing: tcpPing, Trace: res})
		} else {
			_ = enc.Encode(res)
		}
		return
	}

	printCompletion(res)
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: tcputils [flags] <host>\n\n")
	fmt.Fprintf(os.Stderr, "A TCP SYN traceroute with DNS/TCP/TLS/HTTP diagnostics for troubleshooting.\n\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  tcputils -p 443 -m 20 github.com\n")
	fmt.Fprintf(os.Stderr, "  tcputils --tcpping --tcpping-count 10 -p 443 github.com\n")
	fmt.Fprintf(os.Stderr, "  tcputils --tcpping --tcpping-forever -p 443 github.com\n")
	fmt.Fprintf(os.Stderr, "  tcputils --diag -p 443 --http github.com\n")
	fmt.Fprintf(os.Stderr, "  tcputils --diag-only -p 443 --http-url https://github.com github.com\n")
}

type tcpPingOptions struct {
	count    int
	timeout  time.Duration
	interval time.Duration
	forever  bool
	deadline time.Duration
	onSample func(TCPPingSample)
}

func runTCPPing(target string, port int, opt tcpPingOptions) *TCPPingResult {
	count := opt.count
	timeout := opt.timeout
	interval := opt.interval
	if count < 1 {
		count = 5
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if interval < 0 {
		interval = 0
	}

	out := &TCPPingResult{
		Target:    target,
		Port:      port,
		Count:     count,
		Interval:  interval,
		Timeout:   timeout,
		StartedAt: time.Now(),
		Samples:   make([]TCPPingSample, 0, maxInt(1, count)),
	}

	successRTTs := make([]time.Duration, 0, count)
	if opt.forever {
		out.Count = 0
	}

	var (
		stop <-chan os.Signal
		sigC chan os.Signal
	)
	if opt.forever {
		sigC = make(chan os.Signal, 1)
		signal.Notify(sigC, os.Interrupt, syscall.SIGTERM)
		stop = sigC
		defer signal.Stop(sigC)
	}

	var deadlineTime time.Time
	if opt.deadline > 0 {
		deadlineTime = out.StartedAt.Add(opt.deadline)
	}

	for i := 1; ; i++ {
		if !opt.forever && i > count {
			break
		}
		if !deadlineTime.IsZero() && time.Now().After(deadlineTime) {
			break
		}
		select {
		case <-stop:
			out.FinishedAt = time.Now()
			finalizeTCPPing(out, successRTTs)
			return out
		default:
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		start := time.Now()
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(target, fmt.Sprint(port)))
		rtt := time.Since(start)
		cancel()

		sample := TCPPingSample{Seq: i, RTT: rtt, Success: err == nil}
		if err != nil {
			sample.Error = err.Error()
		} else {
			_ = conn.Close()
			successRTTs = append(successRTTs, rtt)
		}
		out.Samples = append(out.Samples, sample)
		out.Count++
		if opt.onSample != nil {
			opt.onSample(sample)
		}

		if interval > 0 {
			if !deadlineTime.IsZero() {
				remaining := time.Until(deadlineTime)
				if remaining <= 0 {
					break
				}
				if interval > remaining {
					time.Sleep(remaining)
					break
				}
			}
			time.Sleep(interval)
		}
	}

	out.FinishedAt = time.Now()
	finalizeTCPPing(out, successRTTs)
	return out
}

func finalizeTCPPing(out *TCPPingResult, successRTTs []time.Duration) {
	if out.Count == 0 {
		return
	}
	out.PacketLoss = float64(out.Count-len(successRTTs)) / float64(out.Count) * 100
	if len(successRTTs) == 0 {
		return
	}
	stats := latencyStats(successRTTs)
	out.MinRTT = stats.MinRTT
	out.AvgRTT = stats.AvgRTT
	out.MaxRTT = stats.MaxRTT
	out.Jitter = stats.Jitter
	out.P95RTT = stats.P95RTT
}

type latencySummary struct {
	MinRTT time.Duration
	AvgRTT time.Duration
	MaxRTT time.Duration
	Jitter time.Duration
	P95RTT time.Duration
}

func latencyStats(samples []time.Duration) latencySummary {
	if len(samples) == 0 {
		return latencySummary{}
	}
	out := latencySummary{MinRTT: samples[0], MaxRTT: samples[0]}
	var sum time.Duration
	for _, s := range samples {
		if s < out.MinRTT {
			out.MinRTT = s
		}
		if s > out.MaxRTT {
			out.MaxRTT = s
		}
		sum += s
	}
	out.AvgRTT = sum / time.Duration(len(samples))

	if len(samples) > 1 {
		var jitterSum time.Duration
		for i := 1; i < len(samples); i++ {
			delta := samples[i] - samples[i-1]
			if delta < 0 {
				delta = -delta
			}
			jitterSum += delta
		}
		out.Jitter = jitterSum / time.Duration(len(samples)-1)
	}

	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(math.Ceil(0.95*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	out.P95RTT = sorted[idx]
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func printTCPPingHeader(target string, port int, opt tcpPingOptions) {
	countText := fmt.Sprintf("count=%d", opt.count)
	if opt.forever {
		countText = "count=forever"
	}
	fmt.Printf("\nTCP ping %s:%d, %s timeout=%s interval=%s\n", target, port, countText, opt.timeout.Round(time.Millisecond), opt.interval.Round(time.Millisecond))
}

func printTCPPingSample(s TCPPingSample) {
	if s.Success {
		fmt.Printf("seq=%d connected rtt=%s\n", s.Seq, s.RTT.Round(time.Millisecond))
		return
	}
	fmt.Printf("seq=%d timeout/error (%s)\n", s.Seq, s.Error)
}

func printTCPPingSummary(r *TCPPingResult) {
	if r.AvgRTT > 0 {
		fmt.Printf("summary: loss=%.0f%% min/avg/max=%s/%s/%s p95=%s jitter=%s\n",
			r.PacketLoss,
			r.MinRTT.Round(time.Millisecond),
			r.AvgRTT.Round(time.Millisecond),
			r.MaxRTT.Round(time.Millisecond),
			r.P95RTT.Round(time.Millisecond),
			r.Jitter.Round(time.Millisecond),
		)
	} else {
		fmt.Printf("summary: loss=%.0f%% (no successful connections)\n", r.PacketLoss)
	}
}

type diagInput struct {
	target          string
	port            int
	connectAttempts int
	connectTimeout  time.Duration
	tlsCheck        bool
	sni             string
	insecureTLS     bool
	httpProbe       bool
	httpURL         string
	httpMethod      string
	httpTimeout     time.Duration
}

func runDiagnostics(in diagInput) *Diagnostics {
	if in.connectAttempts < 1 {
		in.connectAttempts = 3
	}
	if in.connectTimeout <= 0 {
		in.connectTimeout = 2 * time.Second
	}
	if in.httpMethod == "" {
		in.httpMethod = http.MethodGet
	}

	result := &Diagnostics{
		Target: in.target,
		Port:   in.port,
		RunAt:  time.Now(),
	}

	result.DNS = diagnoseDNS(in.target)
	result.TCP = diagnoseTCP(in.target, in.port, in.connectAttempts, in.connectTimeout)

	if in.tlsCheck {
		tlsRes := diagnoseTLS(in.target, in.port, in.sni, in.insecureTLS, in.connectTimeout)
		result.TLS = &tlsRes
	}

	if in.httpProbe {
		httpRes := diagnoseHTTP(in.target, in.port, in.httpURL, in.httpMethod, in.httpTimeout, in.insecureTLS, in.sni)
		result.HTTP = &httpRes
	}

	if result.TCP.Failures == result.TCP.Attempts {
		result.Notes = append(result.Notes, "All TCP connect attempts failed. Validate firewall/security groups/NACLs and destination service health.")
	}
	if result.TLS != nil && !result.TLS.Success {
		result.Notes = append(result.Notes, "TLS handshake failed. Check SNI/certificate chain/TLS policy.")
	}
	if result.HTTP != nil && result.HTTP.Error != "" {
		result.Notes = append(result.Notes, "HTTP probe failed. Verify URL/path, proxy requirements, and app availability.")
	}

	return result
}

func diagnoseDNS(target string) DNSDiag {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, target)
	out := DNSDiag{LookupDuration: time.Since(start)}
	if err != nil {
		out.Error = err.Error()
		return out
	}

	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil {
			out.IPv4 = append(out.IPv4, v4.String())
			continue
		}
		if a.IP.To16() != nil {
			out.IPv6 = append(out.IPv6, a.IP.String())
		}
	}
	return out
}

func diagnoseTCP(target string, port, attempts int, timeout time.Duration) TCPDiag {
	out := TCPDiag{
		Attempts: attempts,
		Timeout:  timeout,
		Samples:  make([]TCPAttempt, 0, attempts),
	}

	successRTTs := make([]time.Duration, 0, attempts)
	for i := 1; i <= attempts; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		start := time.Now()
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(target, fmt.Sprint(port)))
		rtt := time.Since(start)
		cancel()

		sample := TCPAttempt{Attempt: i, RTT: rtt, Success: err == nil}
		if err != nil {
			sample.Error = err.Error()
			out.Failures++
		} else {
			_ = conn.Close()
			successRTTs = append(successRTTs, rtt)
		}
		out.Samples = append(out.Samples, sample)
	}

	if len(successRTTs) > 0 {
		stats := latencyStats(successRTTs)
		out.MinRTT = stats.MinRTT
		out.AvgRTT = stats.AvgRTT
		out.MaxRTT = stats.MaxRTT
		out.P95RTT = stats.P95RTT
		out.Jitter = stats.Jitter
	}

	return out
}

func diagnoseTLS(target string, port int, sni string, insecure bool, timeout time.Duration) TLSDiag {
	serverName := sni
	if serverName == "" {
		serverName = target
	}
	out := TLSDiag{Attempted: true, ServerName: serverName}

	dialer := &net.Dialer{Timeout: timeout}
	conf := &tls.Config{ServerName: serverName, InsecureSkipVerify: insecure}
	start := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(target, fmt.Sprint(port)), conf)
	out.HandshakeRTT = time.Since(start)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	defer conn.Close()

	state := conn.ConnectionState()
	out.Success = true
	out.Version = tlsVersionName(state.Version)
	out.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	out.ALPN = state.NegotiatedProtocol
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		out.CertSubject = leaf.Subject.String()
		out.CertIssuer = leaf.Issuer.String()
		out.CertNotAfter = leaf.NotAfter
	}
	return out
}

func diagnoseHTTP(target string, port int, rawURL, method string, timeout time.Duration, insecure bool, sni string) HTTPDiag {
	resolvedURL := rawURL
	if strings.TrimSpace(resolvedURL) == "" {
		scheme := "http"
		if port == 443 {
			scheme = "https"
		}
		hostPort := target
		if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
			hostPort = net.JoinHostPort(target, fmt.Sprint(port))
		}
		resolvedURL = fmt.Sprintf("%s://%s", scheme, hostPort)
	}

	out := HTTPDiag{URL: resolvedURL, Method: method}

	if _, err := url.ParseRequestURI(resolvedURL); err != nil {
		out.Error = fmt.Sprintf("invalid URL: %v", err)
		return out
	}

	var (
		start         time.Time
		dnsStart      time.Time
		connStart     time.Time
		tlsStart      time.Time
		firstByteTime time.Time
	)

	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone: func(httptrace.DNSDoneInfo) {
			if !dnsStart.IsZero() {
				out.DNS = time.Since(dnsStart)
			}
		},
		ConnectStart: func(_, _ string) { connStart = time.Now() },
		ConnectDone: func(_, _ string, _ error) {
			if !connStart.IsZero() {
				out.Connect = time.Since(connStart)
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			if !tlsStart.IsZero() {
				out.TLSHandshake = time.Since(tlsStart)
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				out.RemoteAddr = info.Conn.RemoteAddr().String()
			}
		},
		GotFirstResponseByte: func() { firstByteTime = time.Now() },
	}

	req, err := http.NewRequest(method, resolvedURL, nil)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	req.Header.Set("User-Agent", "tcputils/1.0")

	ctx, cancel := context.WithTimeout(httptrace.WithClientTrace(req.Context(), trace), timeout)
	defer cancel()
	req = req.WithContext(ctx)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
			ServerName:         sni,
		},
	}
	client := &http.Client{Transport: transport, Timeout: timeout}

	start = time.Now()
	resp, err := client.Do(req)
	out.Total = time.Since(start)
	if !firstByteTime.IsZero() {
		out.TTFB = firstByteTime.Sub(start)
	}
	if err != nil {
		out.Error = err.Error()
		return out
	}
	defer resp.Body.Close()

	out.StatusCode = resp.StatusCode
	out.Headers = map[string]string{}
	for _, key := range []string{"Server", "Content-Type", "Location"} {
		if value := resp.Header.Get(key); value != "" {
			out.Headers[key] = value
		}
	}

	_, _ = io.CopyN(io.Discard, resp.Body, 4096)
	return out
}

func printDiagnostics(d *Diagnostics) {
	fmt.Printf("\nDiagnostics for %s:%d\n", d.Target, d.Port)
	fmt.Printf("DNS: %s", d.DNS.LookupDuration.Round(time.Millisecond))
	if d.DNS.Error != "" {
		fmt.Printf(" (error: %s)\n", d.DNS.Error)
	} else {
		fmt.Printf(" (IPv4=%d IPv6=%d)\n", len(d.DNS.IPv4), len(d.DNS.IPv6))
	}

	fmt.Printf("TCP connect: attempts=%d failures=%d", d.TCP.Attempts, d.TCP.Failures)
	if d.TCP.AvgRTT > 0 {
		fmt.Printf(" min/avg/max=%s/%s/%s p95=%s jitter=%s",
			d.TCP.MinRTT.Round(time.Millisecond),
			d.TCP.AvgRTT.Round(time.Millisecond),
			d.TCP.MaxRTT.Round(time.Millisecond),
			d.TCP.P95RTT.Round(time.Millisecond),
			d.TCP.Jitter.Round(time.Millisecond),
		)
	}
	fmt.Println()

	if d.TLS != nil {
		if d.TLS.Success {
			fmt.Printf("TLS: ok version=%s cipher=%s handshake=%s", d.TLS.Version, d.TLS.CipherSuite, d.TLS.HandshakeRTT.Round(time.Millisecond))
			if !d.TLS.CertNotAfter.IsZero() {
				fmt.Printf(" cert_expires=%s", d.TLS.CertNotAfter.Format("2006-01-02"))
			}
			fmt.Println()
		} else {
			fmt.Printf("TLS: failed (%s)\n", d.TLS.Error)
		}
	}

	if d.HTTP != nil {
		if d.HTTP.Error == "" {
			fmt.Printf("HTTP: %s %s -> %d total=%s ttfb=%s\n", d.HTTP.Method, d.HTTP.URL, d.HTTP.StatusCode, d.HTTP.Total.Round(time.Millisecond), d.HTTP.TTFB.Round(time.Millisecond))
		} else {
			fmt.Printf("HTTP: failed %s %s (%s)\n", d.HTTP.Method, d.HTTP.URL, d.HTTP.Error)
		}
	}

	for _, note := range d.Notes {
		fmt.Printf("Note: %s\n", note)
	}
	fmt.Println()
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}

func printCompletion(res *tracer.TraceResult) {
	duration := res.FinishedAt.Sub(res.StartedAt)
	fmt.Printf("\nCompleted in %s\n", duration.Round(time.Millisecond))
}

type livePrinter struct {
	lineOpen     bool
	labelPrinted bool
}

func (p *livePrinter) startHop(ttl int) {
	if p.lineOpen {
		fmt.Println()
	}
	fmt.Printf("%2d  ", ttl)
	p.lineOpen = true
	p.labelPrinted = false
}

func (p *livePrinter) printProbe(h tracer.HopResult, pr tracer.ProbeResult) {
	if !p.labelPrinted {
		fmt.Printf("%-45s  ", hopLabel(h, pr))
		p.labelPrinted = true
	}

	if pr.Timeout {
		fmt.Printf("*  ")
		return
	}
	fmt.Printf("%.2f ms  ", float64(pr.RTT.Microseconds())/1000.0)
}

func (p *livePrinter) finishHop(h tracer.HopResult) {
	if !p.labelPrinted {
		fmt.Printf("%-45s  ", hopLabel(h, tracer.ProbeResult{}))
		p.labelPrinted = true
	}

	if h.MinRTT > 0 {
		fmt.Printf("[min/avg/max %.2f/%.2f/%.2f ms, loss %.0f%%]",
			float64(h.MinRTT.Microseconds())/1000.0,
			float64(h.AvgRTT.Microseconds())/1000.0,
			float64(h.MaxRTT.Microseconds())/1000.0,
			h.PacketLoss,
		)
	} else {
		fmt.Printf("[loss %.0f%%]", h.PacketLoss)
	}
	fmt.Println()
	p.lineOpen = false
}

func hopLabel(h tracer.HopResult, pr tracer.ProbeResult) string {
	if h.HostIP != "" && h.HostIP != "*" {
		if h.HostName != "" {
			return fmt.Sprintf("%s (%s)", h.HostName, h.HostIP)
		}
		return h.HostIP
	}
	if pr.FromIP != "" && pr.FromIP != "*" {
		if pr.FromName != "" {
			return fmt.Sprintf("%s (%s)", pr.FromName, pr.FromIP)
		}
		return pr.FromIP
	}
	return "*"
}

func firstIPv4(host string) string {
	addrs, err := net.LookupIP(host)
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if v4 := addr.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}
