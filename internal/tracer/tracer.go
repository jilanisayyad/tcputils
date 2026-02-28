package tracer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type Config struct {
	Target          string
	Port            int
	MaxHops         int
	FirstHop        int
	ProbesPerHop    int
	Timeout         time.Duration
	ResolveHopNames bool
	OnHopStart      func(ttl int)
	OnProbe         func(HopResult, ProbeResult)
	OnHop           func(HopResult)
}

type ProbeResult struct {
	ProbeIndex int           `json:"probe_index"`
	FromIP     string        `json:"from_ip,omitempty"`
	FromName   string        `json:"from_name,omitempty"`
	RTT        time.Duration `json:"rtt"`
	Reached    bool          `json:"reached"`
	Timeout    bool          `json:"timeout"`
	Err        string        `json:"err,omitempty"`
}

type HopResult struct {
	TTL         int           `json:"ttl"`
	HostIP      string        `json:"host_ip"`
	HostName    string        `json:"host_name,omitempty"`
	Probes      []ProbeResult `json:"probes"`
	PacketLoss  float64       `json:"packet_loss"`
	MinRTT      time.Duration `json:"min_rtt"`
	AvgRTT      time.Duration `json:"avg_rtt"`
	MaxRTT      time.Duration `json:"max_rtt"`
	Destination bool          `json:"destination"`
}

type TraceResult struct {
	Target     string      `json:"target"`
	TargetIP   string      `json:"target_ip"`
	Port       int         `json:"port"`
	StartedAt  time.Time   `json:"started_at"`
	FinishedAt time.Time   `json:"finished_at"`
	Hops       []HopResult `json:"hops"`
}

type dnsCache struct {
	mu   sync.Mutex
	data map[string]string
}

const reverseDNSTimeout = 500 * time.Millisecond

func (d *dnsCache) lookup(ip string, enabled bool) string {
	if !enabled || ip == "" || ip == "*" {
		return ""
	}
	d.mu.Lock()
	if d.data == nil {
		d.data = make(map[string]string)
	}
	if name, ok := d.data[ip]; ok {
		d.mu.Unlock()
		return name
	}
	d.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), reverseDNSTimeout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	name := strings.TrimSuffix(names[0], ".")
	d.mu.Lock()
	d.data[ip] = name
	d.mu.Unlock()
	return name
}

func Trace(cfg Config) (*TraceResult, error) {
	if cfg.Target == "" {
		return nil, errors.New("target is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", cfg.Port)
	}
	if cfg.MaxHops < 1 {
		cfg.MaxHops = 30
	}
	if cfg.FirstHop < 1 {
		cfg.FirstHop = 1
	}
	if cfg.ProbesPerHop < 1 {
		cfg.ProbesPerHop = 3
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}

	dstIP, err := resolveIPv4(cfg.Target)
	if err != nil {
		return nil, err
	}
	localIP, err := outboundIPv4(dstIP, cfg.Port)
	if err != nil {
		return nil, err
	}

	sendConn, err := net.ListenPacket("ip4:tcp", localIP.String())
	if err != nil {
		return nil, fmt.Errorf("open raw TCP send socket failed: %w (try sudo/root)", err)
	}
	defer sendConn.Close()
	sendPC := ipv4.NewPacketConn(sendConn)

	icmpConn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("open ICMP socket failed: %w (try sudo/root)", err)
	}
	defer icmpConn.Close()

	recvTCPConn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("open raw TCP recv socket failed: %w (try sudo/root)", err)
	}
	defer recvTCPConn.Close()

	result := &TraceResult{
		Target:    cfg.Target,
		TargetIP:  dstIP.String(),
		Port:      cfg.Port,
		StartedAt: time.Now(),
	}
	cache := &dnsCache{}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	basePort := 33434 + rng.Intn(10000)

	destinationReached := false
	for ttl := cfg.FirstHop; ttl <= cfg.MaxHops; ttl++ {
		hop := HopResult{TTL: ttl, Probes: make([]ProbeResult, 0, cfg.ProbesPerHop)}
		if cfg.OnHopStart != nil {
			cfg.OnHopStart(ttl)
		}

		for probe := 0; probe < cfg.ProbesPerHop; probe++ {
			srcPort := nextSrcPort(basePort, ttl, probe)
			seq := rng.Uint32()
			start := time.Now()
			pr := ProbeResult{ProbeIndex: probe + 1, Timeout: true}

			if err := sendPC.SetTTL(ttl); err != nil {
				pr.Err = err.Error()
			} else {
				tcpPacket, err := buildTCPSYN(localIP, dstIP, srcPort, cfg.Port, seq)
				if err != nil {
					pr.Err = err.Error()
				} else if _, err := sendConn.WriteTo(tcpPacket, &net.IPAddr{IP: dstIP}); err != nil {
					pr.Err = err.Error()
				} else {
					pr = waitForReply(waitInput{
						icmpConn:    icmpConn,
						recvTCPConn: recvTCPConn,
						start:       start,
						timeout:     cfg.Timeout,
						targetIP:    dstIP,
						targetPort:  cfg.Port,
						srcPort:     srcPort,
						probeIndex:  probe + 1,
					})
				}
			}

			pr.FromName = cache.lookup(pr.FromIP, cfg.ResolveHopNames)
			hop.Probes = append(hop.Probes, pr)

			if pr.FromIP != "" && hop.HostIP == "" {
				hop.HostIP = pr.FromIP
				hop.HostName = pr.FromName
			}
			if pr.Reached {
				hop.Destination = true
				destinationReached = true
			}
			if cfg.OnProbe != nil {
				cfg.OnProbe(hop, pr)
			}
		}

		computeHopStats(&hop)
		if hop.HostIP == "" {
			hop.HostIP = "*"
		}
		result.Hops = append(result.Hops, hop)
		if cfg.OnHop != nil {
			cfg.OnHop(hop)
		}
		if destinationReached {
			break
		}
	}

	result.FinishedAt = time.Now()
	return result, nil
}

type waitInput struct {
	icmpConn    net.PacketConn
	recvTCPConn net.PacketConn
	start       time.Time
	timeout     time.Duration
	targetIP    net.IP
	targetPort  int
	srcPort     int
	probeIndex  int
}

func waitForReply(in waitInput) ProbeResult {
	deadline := in.start.Add(in.timeout)
	probe := ProbeResult{ProbeIndex: in.probeIndex, Timeout: true}
	icmpBuf := make([]byte, 1500)
	tcpBuf := make([]byte, 1500)

	for time.Now().Before(deadline) {
		now := time.Now()
		readUntil := now.Add(20 * time.Millisecond)
		if readUntil.After(deadline) {
			readUntil = deadline
		}

		if err := in.icmpConn.SetReadDeadline(readUntil); err == nil {
			n, peer, err := in.icmpConn.ReadFrom(icmpBuf)
			if err == nil {
				if fromIP, ok := parseICMPForProbe(icmpBuf[:n], peer, in.targetIP, in.targetPort, in.srcPort); ok {
					probe.Timeout = false
					probe.FromIP = fromIP
					probe.RTT = time.Since(in.start)
					return probe
				}
			}
		}

		if err := in.recvTCPConn.SetReadDeadline(readUntil); err == nil {
			n, peer, err := in.recvTCPConn.ReadFrom(tcpBuf)
			if err == nil {
				if fromIP, reached, ok := parseTCPReplyForProbe(tcpBuf[:n], peer, in.targetIP, in.targetPort, in.srcPort); ok {
					probe.Timeout = false
					probe.FromIP = fromIP
					probe.Reached = reached
					probe.RTT = time.Since(in.start)
					return probe
				}
			}
		}
	}

	return probe
}

func parseICMPForProbe(payload []byte, peer net.Addr, targetIP net.IP, targetPort, srcPort int) (string, bool) {
	msg, err := icmp.ParseMessage(1, payload)
	if err != nil {
		return "", false
	}

	var data []byte
	switch body := msg.Body.(type) {
	case *icmp.TimeExceeded:
		data = body.Data
	case *icmp.DstUnreach:
		data = body.Data
	default:
		return "", false
	}

	if len(data) < ipv4.HeaderLen {
		return "", false
	}
	innerIP, err := ipv4.ParseHeader(data)
	if err != nil {
		return "", false
	}
	if !innerIP.Dst.Equal(targetIP.To4()) {
		return "", false
	}
	if len(data) < innerIP.Len+8 {
		return "", false
	}
	tcpStart := innerIP.Len
	innerSrc := int(binary.BigEndian.Uint16(data[tcpStart : tcpStart+2]))
	innerDst := int(binary.BigEndian.Uint16(data[tcpStart+2 : tcpStart+4]))
	if innerSrc != srcPort || innerDst != targetPort {
		return "", false
	}
	if ip, ok := peer.(*net.IPAddr); ok {
		return ip.IP.String(), true
	}
	return innerIP.Src.String(), true
}

func parseTCPReplyForProbe(payload []byte, peer net.Addr, targetIP net.IP, targetPort, srcPort int) (string, bool, bool) {
	if len(payload) < 20 {
		return "", false, false
	}
	remotePort := int(binary.BigEndian.Uint16(payload[0:2]))
	localPort := int(binary.BigEndian.Uint16(payload[2:4]))
	if remotePort != targetPort || localPort != srcPort {
		return "", false, false
	}
	flags := payload[13]
	reached := (flags&0x12) == 0x12 || (flags&0x04) == 0x04

	from := ""
	if ip, ok := peer.(*net.IPAddr); ok {
		from = ip.IP.String()
	}
	if from == "" {
		from = targetIP.String()
	}
	return from, reached, true
}

func computeHopStats(h *HopResult) {
	if len(h.Probes) == 0 {
		return
	}
	rtts := make([]time.Duration, 0, len(h.Probes))
	timeouts := 0
	for _, p := range h.Probes {
		if p.Timeout {
			timeouts++
			continue
		}
		rtts = append(rtts, p.RTT)
	}
	h.PacketLoss = float64(timeouts) / float64(len(h.Probes)) * 100
	if len(rtts) == 0 {
		return
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	h.MinRTT = rtts[0]
	h.MaxRTT = rtts[len(rtts)-1]
	var sum time.Duration
	for _, r := range rtts {
		sum += r
	}
	h.AvgRTT = sum / time.Duration(len(rtts))
}

func resolveIPv4(target string) (net.IP, error) {
	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, fmt.Errorf("resolve target failed: %w", err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address found for %q", target)
}

func outboundIPv4(dstIP net.IP, port int) (net.IP, error) {
	conn, err := net.Dial("udp4", net.JoinHostPort(dstIP.String(), fmt.Sprint(port)))
	if err != nil {
		return nil, fmt.Errorf("detect local interface failed: %w", err)
	}
	defer conn.Close()
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || localAddr.IP == nil {
		return nil, errors.New("cannot determine local IPv4 address")
	}
	return localAddr.IP.To4(), nil
}

func nextSrcPort(base, ttl, probe int) int {
	v := base + ttl*64 + probe
	for v > 65535 {
		v -= 30000
	}
	if v < 1024 {
		v += 1024
	}
	return v
}

func buildTCPSYN(srcIP, dstIP net.IP, srcPort, dstPort int, seq uint32) ([]byte, error) {
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcpHeader[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(tcpHeader[4:8], seq)
	binary.BigEndian.PutUint32(tcpHeader[8:12], 0)
	tcpHeader[12] = 5 << 4
	tcpHeader[13] = 0x02
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535)
	binary.BigEndian.PutUint16(tcpHeader[16:18], 0)
	binary.BigEndian.PutUint16(tcpHeader[18:20], 0)

	chk, err := tcpChecksum(srcIP, dstIP, tcpHeader)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(tcpHeader[16:18], chk)
	return tcpHeader, nil
}

func tcpChecksum(srcIP, dstIP net.IP, segment []byte) (uint16, error) {
	src := srcIP.To4()
	dst := dstIP.To4()
	if src == nil || dst == nil {
		return 0, errors.New("checksum requires IPv4 addresses")
	}
	pseudo := make([]byte, 12+len(segment))
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[8] = 0
	pseudo[9] = syscall.IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(segment)))
	copy(pseudo[12:], segment)

	var sum uint32
	for i := 0; i+1 < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	if len(pseudo)%2 == 1 {
		sum += uint32(pseudo[len(pseudo)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum), nil
}
