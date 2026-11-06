// ============================================================================
// OICMPTunnel — ICMP Tunnel Detector
// Author  : khaled.s.haddad
// Website : owlsec.org
// Language: Go (stdlib only, CGO disabled, static build)
// Category: ONet
// ============================================================================

package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"math/bits"
	"math/rand"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. ---------------------
const (
	R   = "\033[91m"
	GRN = "\033[92m"
	YLW = "\033[93m"
	CY  = "\033[96m"
	W   = "\033[97m"
	B   = "\033[1m"
	X   = "\033[0m"
	MG  = "\033[95m"
	DIM = "\033[2m"
	OR  = "\033[38;5;208m"
	GY  = "\033[90m"
	// legacy aliases (kept so older call-sites compile) — remapped to cyan house style
	DR = "\033[96m"
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear()           { fmt.Print("\033[H\033[2J") }
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func line(w int)       { fmt.Println(col(strings.Repeat("─", w), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := stdin.ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	stdin.ReadString('\n')
}

func stripANSI(s string) string {
	out := []rune{}
	esc := false
	for _, r := range s {
		if r == '\033' {
			esc = true
			continue
		}
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
func visw(s string) int { return len([]rune(stripANSI(s))) }
func pad(s string, n int) string {
	if visw(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visw(s))
}
func menu(title string, items []string) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for i, it := range items {
		fmt.Printf("   %s  %s\n", col(fmt.Sprintf("[%02d]", i+1), CY+B), col(it, W))
	}
	fmt.Println("   " + col("[ H]", YLW+B) + "  " + col("Help & usage", YLW))
	fmt.Println("   " + col("[00]", GY) + "  " + col("Exit", GY))
	fmt.Println()
	return prompt("select")
}
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = visw(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && visw(c) > w[i] {
				w[i] = visw(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), B+CY))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DIM))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DIM))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DIM))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

const (
	APPNAME  = "OICMPTunnel"
	SUITE    = "Owl Network Suite"
	TAGLINE  = "ICMP / ICMPv6 Covert-Channel Detector"
	SUBLINE  = "Echo tunnels · payload entropy · beacon timing · size anomalies · MITRE"
	VERSION  = "2.0"
	CATEGORY = "ONet"
	AUTHOR   = "khaled.s.haddad"
	WEBSITE  = "owlsec.org"
)

const BANNER = `
 ██████╗ ██╗ ██████╗███╗   ███╗██████╗ ████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗     
██╔═══██╗██║██╔════╝████╗ ████║██╔══██╗╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║     
██║   ██║██║██║     ██╔████╔██║██████╔╝   ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║     
██║   ██║██║██║     ██║╚██╔╝██║██╔═══╝    ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║     
╚██████╔╝██║╚██████╗██║ ╚═╝ ██║██║        ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗
 ╚═════╝ ╚═╝ ╚═════╝╚═╝     ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝
`

// ============================================================================
// OWL SHARED CORE  — Finding model, grading, MITRE ATT&CK, 5-format export,
// output engine, and numeric/byte/stat utilities. Stdlib only.
// ============================================================================

// Severity levels used across all OWL v2 tools.
const (
	SevInfo     = "INFO"
	SevLow      = "LOW"
	SevMedium   = "MEDIUM"
	SevHigh     = "HIGH"
	SevCritical = "CRITICAL"
)

// Finding is the universal result record every OWL tool emits.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Score       float64  `json:"score"`
	Category    string   `json:"category"`
	Subject     string   `json:"subject"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence"`
	ATTCK       []string `json:"attck,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Reference   string   `json:"reference,omitempty"`
}

// Report bundles findings plus run metadata for export.
type Report struct {
	Tool      string    `json:"tool"`
	Tagline   string    `json:"tagline"`
	Target    string    `json:"target"`
	Generated string    `json:"generated"`
	Findings  []Finding `json:"findings"`
	Summary   Summary   `json:"summary"`
}

// Summary is the aggregate posture for a run.
type Summary struct {
	Total     int     `json:"total"`
	Critical  int     `json:"critical"`
	High      int     `json:"high"`
	Medium    int     `json:"medium"`
	Low       int     `json:"low"`
	Info      int     `json:"info"`
	RiskScore float64 `json:"risk_score"`
	Grade     string  `json:"grade"`
}

func sevRank(s string) int {
	switch strings.ToUpper(s) {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

func sevWeight(s string) float64 {
	switch strings.ToUpper(s) {
	case SevCritical:
		return 10.0
	case SevHigh:
		return 7.0
	case SevMedium:
		return 4.0
	case SevLow:
		return 1.5
	case SevInfo:
		return 0.2
	}
	return 0.0
}

func sevColor(s string) string {
	switch strings.ToUpper(s) {
	case SevCritical:
		return R + B
	case SevHigh:
		return R
	case SevMedium:
		return YLW
	case SevLow:
		return GY
	case SevInfo:
		return GRN
	}
	return W
}

// summarize computes the aggregate posture and letter grade for a finding set.
func summarize(fs []Finding) Summary {
	var s Summary
	s.Total = len(fs)
	var raw float64
	for _, f := range fs {
		switch strings.ToUpper(f.Severity) {
		case SevCritical:
			s.Critical++
		case SevHigh:
			s.High++
		case SevMedium:
			s.Medium++
		case SevLow:
			s.Low++
		default:
			s.Info++
		}
		raw += sevWeight(f.Severity)
	}
	s.RiskScore = raw
	s.Grade = gradeFor(s)
	return s
}

// gradeFor maps weighted risk to an A+..F posture grade.
func gradeFor(s Summary) string {
	if s.Critical > 0 {
		if s.Critical >= 3 {
			return "F"
		}
		return "E"
	}
	switch {
	case s.High >= 3:
		return "D"
	case s.High >= 1:
		return "C"
	case s.Medium >= 3:
		return "C"
	case s.Medium >= 1:
		return "B"
	case s.Low >= 1:
		return "A"
	default:
		return "A+"
	}
}

func gradeColor(g string) string {
	switch g {
	case "A+", "A":
		return GRN + B
	case "B":
		return GRN
	case "C":
		return YLW
	case "D", "E":
		return R
	case "F":
		return R + B
	}
	return W
}

// ---------------------------------------------------------------------------
// MITRE ATT&CK technique descriptions (curated subset used by OWL tools).
// ---------------------------------------------------------------------------
var attckDB = map[string]string{
	"T1016":     "System Network Configuration Discovery",
	"T1040":     "Network Sniffing",
	"T1046":     "Network Service Discovery",
	"T1049":     "System Network Connections Discovery",
	"T1071":     "Application Layer Protocol",
	"T1071.004": "Application Layer Protocol: DNS",
	"T1090":     "Proxy",
	"T1095":     "Non-Application Layer Protocol",
	"T1098":     "Account Manipulation",
	"T1133":     "External Remote Services",
	"T1190":     "Exploit Public-Facing Application",
	"T1205":     "Traffic Signaling",
	"T1205.001": "Traffic Signaling: Port Knocking",
	"T1498":     "Network Denial of Service",
	"T1498.002": "Reflection Amplification",
	"T1499":     "Endpoint Denial of Service",
	"T1552":     "Unsecured Credentials",
	"T1557":     "Adversary-in-the-Middle",
	"T1557.002": "AiTM: ARP Cache Poisoning",
	"T1562":     "Impair Defenses",
	"T1571":     "Non-Standard Port",
	"T1572":     "Protocol Tunneling",
	"T1573":     "Encrypted Channel",
	"T1590":     "Gather Victim Network Information",
	"T1590.002": "Gather Victim Network Information: DNS",
	"T1595":     "Active Scanning",
	"T1595.001": "Active Scanning: Scanning IP Blocks",
	"T1599":     "Network Boundary Bridging",
	"T1600":     "Weaken Encryption",
}

func attckName(id string) string {
	if n, ok := attckDB[id]; ok {
		return n
	}
	return id
}

func attckTag(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	var parts []string
	for _, id := range ids {
		parts = append(parts, id+" ("+attckName(id)+")")
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// Export engine: TXT, MD, JSON, CSV, SARIF 2.1.0
// ---------------------------------------------------------------------------

func buildReport(target string, fs []Finding) Report {
	sort.SliceStable(fs, func(i, j int) bool {
		if sevRank(fs[i].Severity) != sevRank(fs[j].Severity) {
			return sevRank(fs[i].Severity) > sevRank(fs[j].Severity)
		}
		return fs[i].Score > fs[j].Score
	})
	return Report{
		Tool:      APPNAME,
		Tagline:   TAGLINE,
		Target:    target,
		Generated: time.Now().Format(time.RFC3339),
		Findings:  fs,
		Summary:   summarize(fs),
	}
}

func exportTXT(r Report) string {
	var b strings.Builder
	b.WriteString("================================================================\n")
	b.WriteString(" " + r.Tool + " — " + r.Tagline + "\n")
	b.WriteString(" Author: khaled.s.haddad    Website: owlsec.org\n")
	b.WriteString("================================================================\n")
	b.WriteString("Target     : " + r.Target + "\n")
	b.WriteString("Generated  : " + r.Generated + "\n")
	b.WriteString(fmt.Sprintf("Grade      : %s   RiskScore: %.1f\n", r.Summary.Grade, r.Summary.RiskScore))
	b.WriteString(fmt.Sprintf("Findings   : %d  (C:%d H:%d M:%d L:%d I:%d)\n",
		r.Summary.Total, r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Info))
	b.WriteString("----------------------------------------------------------------\n\n")
	for i, f := range r.Findings {
		b.WriteString(fmt.Sprintf("[%03d] %-8s %s\n", i+1, f.Severity, f.Title))
		if f.Subject != "" {
			b.WriteString("      Subject    : " + f.Subject + "\n")
		}
		if f.Category != "" {
			b.WriteString("      Category   : " + f.Category + "\n")
		}
		b.WriteString(fmt.Sprintf("      Score      : %.1f\n", f.Score))
		if f.Description != "" {
			b.WriteString("      Description: " + f.Description + "\n")
		}
		if f.Evidence != "" {
			b.WriteString("      Evidence   : " + f.Evidence + "\n")
		}
		if len(f.ATTCK) > 0 {
			b.WriteString("      ATT&CK     : " + attckTag(f.ATTCK) + "\n")
		}
		if f.CWE != "" {
			b.WriteString("      CWE        : " + f.CWE + "\n")
		}
		if f.Remediation != "" {
			b.WriteString("      Remediation: " + f.Remediation + "\n")
		}
		if f.Reference != "" {
			b.WriteString("      Reference  : " + f.Reference + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func exportMD(r Report) string {
	var b strings.Builder
	b.WriteString("# " + r.Tool + " Report\n\n")
	b.WriteString("*" + r.Tagline + "*\n\n")
	b.WriteString("- **Target:** " + r.Target + "\n")
	b.WriteString("- **Generated:** " + r.Generated + "\n")
	b.WriteString(fmt.Sprintf("- **Grade:** %s (risk score %.1f)\n", r.Summary.Grade, r.Summary.RiskScore))
	b.WriteString(fmt.Sprintf("- **Findings:** %d — Critical %d, High %d, Medium %d, Low %d, Info %d\n\n",
		r.Summary.Total, r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Info))
	b.WriteString("| # | Severity | Title | Score | ATT&CK |\n")
	b.WriteString("|---|----------|-------|-------|--------|\n")
	for i, f := range r.Findings {
		b.WriteString(fmt.Sprintf("| %d | %s | %s | %.1f | %s |\n",
			i+1, f.Severity, mdEsc(f.Title), f.Score, mdEsc(strings.Join(f.ATTCK, " "))))
	}
	b.WriteString("\n## Details\n\n")
	for i, f := range r.Findings {
		b.WriteString(fmt.Sprintf("### %d. %s (%s)\n\n", i+1, f.Title, f.Severity))
		if f.Subject != "" {
			b.WriteString("- **Subject:** " + mdEsc(f.Subject) + "\n")
		}
		if f.Category != "" {
			b.WriteString("- **Category:** " + mdEsc(f.Category) + "\n")
		}
		b.WriteString(fmt.Sprintf("- **Score:** %.1f\n", f.Score))
		if f.Description != "" {
			b.WriteString("- **Description:** " + mdEsc(f.Description) + "\n")
		}
		if f.Evidence != "" {
			b.WriteString("- **Evidence:** `" + f.Evidence + "`\n")
		}
		if len(f.ATTCK) > 0 {
			b.WriteString("- **ATT&CK:** " + mdEsc(attckTag(f.ATTCK)) + "\n")
		}
		if f.CWE != "" {
			b.WriteString("- **CWE:** " + f.CWE + "\n")
		}
		if f.Remediation != "" {
			b.WriteString("- **Remediation:** " + mdEsc(f.Remediation) + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func exportJSON(r Report) string {
	buf, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(buf)
}

func exportCSV(r Report) string {
	var sb strings.Builder
	w := csv.NewWriter(&sb)
	w.Write([]string{"id", "severity", "score", "category", "subject", "title", "description", "evidence", "attck", "cwe", "remediation"})
	for _, f := range r.Findings {
		w.Write([]string{f.ID, f.Severity, fmt.Sprintf("%.1f", f.Score), f.Category, f.Subject, f.Title, f.Description, f.Evidence, strings.Join(f.ATTCK, " "), f.CWE, f.Remediation})
	}
	w.Flush()
	return sb.String()
}

func sarifLevel(sev string) string {
	switch strings.ToUpper(sev) {
	case SevCritical, SevHigh:
		return "error"
	case SevMedium:
		return "warning"
	case SevLow, SevInfo:
		return "note"
	}
	return "none"
}

func exportSARIF(r Report) string {
	type sarifMsg struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID               string   `json:"id"`
		Name             string   `json:"name"`
		ShortDescription sarifMsg `json:"shortDescription"`
	}
	type sarifResult struct {
		RuleID  string   `json:"ruleId"`
		Level   string   `json:"level"`
		Message sarifMsg `json:"message"`
	}
	type driver struct {
		Name    string      `json:"name"`
		Version string      `json:"version"`
		Rules   []sarifRule `json:"rules"`
	}
	type tool struct {
		Driver driver `json:"driver"`
	}
	type run struct {
		Tool    tool          `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type doc struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []run  `json:"runs"`
	}
	seen := map[string]bool{}
	var rules []sarifRule
	var results []sarifResult
	for _, f := range r.Findings {
		rid := f.ID
		if rid == "" {
			rid = "OWL-" + strings.ToUpper(APPNAME)
		}
		if !seen[rid] {
			seen[rid] = true
			rules = append(rules, sarifRule{ID: rid, Name: f.Title, ShortDescription: sarifMsg{Text: f.Title}})
		}
		msg := f.Description
		if f.Evidence != "" {
			msg += " | evidence: " + f.Evidence
		}
		if len(f.ATTCK) > 0 {
			msg += " | ATT&CK: " + strings.Join(f.ATTCK, ",")
		}
		results = append(results, sarifResult{RuleID: rid, Level: sarifLevel(f.Severity), Message: sarifMsg{Text: msg}})
	}
	d := doc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []run{{
			Tool:    tool{Driver: driver{Name: APPNAME, Version: VERSION, Rules: rules}},
			Results: results,
		}},
	}
	buf, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(buf)
}

func renderReport(format string, r Report) string {
	switch strings.ToLower(format) {
	case "md", "markdown":
		return exportMD(r)
	case "json":
		return exportJSON(r)
	case "csv":
		return exportCSV(r)
	case "sarif":
		return exportSARIF(r)
	default:
		return exportTXT(r)
	}
}

func writeOutput(path, content string) error {
	if path == "" || path == "-" {
		fmt.Print(content)
		if !strings.HasSuffix(content, "\n") {
			fmt.Println()
		}
		return nil
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// ---------------------------------------------------------------------------
// Numeric / statistical / byte utilities (shared, genuine).
// ---------------------------------------------------------------------------

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	var h float64
	n := float64(len(data))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func shannonEntropyStr(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	var h float64
	n := float64(len([]rune(s)))
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var s float64
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func stddev(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	m := mean(xs)
	var s float64
	for _, x := range xs {
		d := x - m
		s += d * d
	}
	return math.Sqrt(s / float64(len(xs)-1))
}

func medianF(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	c := append([]float64(nil), xs...)
	sort.Float64s(c)
	n := len(c)
	if n%2 == 1 {
		return c[n/2]
	}
	return (c[n/2-1] + c[n/2]) / 2
}

func percentile(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	c := append([]float64(nil), xs...)
	sort.Float64s(c)
	if p <= 0 {
		return c[0]
	}
	if p >= 100 {
		return c[len(c)-1]
	}
	rank := (p / 100) * float64(len(c)-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	if lo == hi {
		return c[lo]
	}
	frac := rank - float64(lo)
	return c[lo]*(1-frac) + c[hi]*frac
}

func minF(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	m := xs[0]
	for _, x := range xs {
		if x < m {
			m = x
		}
	}
	return m
}

func maxF(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	m := xs[0]
	for _, x := range xs {
		if x > m {
			m = x
		}
	}
	return m
}

func clampF(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func humanBytes(n float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	i := 0
	for n >= 1024 && i < len(units)-1 {
		n /= 1024
		i++
	}
	return fmt.Sprintf("%.2f %s", n, units[i])
}

func humanRate(bitsPerSec float64) string {
	units := []string{"bps", "Kbps", "Mbps", "Gbps", "Tbps"}
	i := 0
	for bitsPerSec >= 1000 && i < len(units)-1 {
		bitsPerSec /= 1000
		i++
	}
	return fmt.Sprintf("%.2f %s", bitsPerSec, units[i])
}

func hexDump(data []byte) string {
	var b strings.Builder
	for i := 0; i < len(data); i += 16 {
		fmt.Fprintf(&b, "%08x  ", i)
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		for j := i; j < i+16; j++ {
			if j < end {
				fmt.Fprintf(&b, "%02x ", data[j])
			} else {
				b.WriteString("   ")
			}
			if j == i+7 {
				b.WriteString(" ")
			}
		}
		b.WriteString(" |")
		for j := i; j < end; j++ {
			c := data[j]
			if c >= 32 && c < 127 {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteString("|\n")
	}
	return b.String()
}

func asciiBar(frac float64, width int) string {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	fill := int(frac * float64(width))
	return strings.Repeat("█", fill) + strings.Repeat("░", width-fill)
}

func sparkline(xs []float64) string {
	if len(xs) == 0 {
		return ""
	}
	ticks := []rune("▁▂▃▄▅▆▇█")
	lo, hi := minF(xs), maxF(xs)
	rng := hi - lo
	var b strings.Builder
	for _, x := range xs {
		idx := 0
		if rng > 0 {
			idx = int((x - lo) / rng * float64(len(ticks)-1))
		}
		if idx < 0 {
			idx = 0
		}
		if idx >= len(ticks) {
			idx = len(ticks) - 1
		}
		b.WriteRune(ticks[idx])
	}
	return b.String()
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func atofSafe(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

func splitFields(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == ',' || r == ';'
	})
}

func readLinesFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 4 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// usePackages keeps imports referenced regardless of which paths a given
// domain engine exercises; it performs no work at runtime.
func usePackages() {
	_ = net.IPv4zero
	_ = binary.BigEndian
	_ = md5.Size
	_ = sha1.Size
	_ = sha256.Size
	_ = fnvConst
	_ = bits.UintSize
	_ = utf8.RuneError
	_ = regexp.MustCompile
	_ = rand.Int
	_ = io.EOF
	_ = bytes.MinRead
	_ = errors.New
	_ = hex.EncodedLen
}

const fnvConst = 0

func printFindingsTable(fs []Finding) {
	if len(fs) == 0 {
		info("no findings")
		return
	}
	var rows [][]string
	for i, f := range fs {
		rows = append(rows, []string{fmt.Sprintf("%d", i+1), f.Severity, truncStr(f.Title, 48), fmt.Sprintf("%.1f", f.Score), strings.Join(f.ATTCK, " ")})
	}
	table([]string{"#", "SEV", "TITLE", "SCORE", "ATT&CK"}, rows)
}

func printSummary(s Summary) {
	fmt.Println()
	fmt.Println("  " + col("Posture Grade: ", W) + col(s.Grade, gradeColor(s.Grade)+B) +
		col(fmt.Sprintf("   Risk Score: %.1f", s.RiskScore), GY))
	fmt.Printf("  %s C:%d  H:%d  M:%d  L:%d  I:%d\n", col("Findings", DIM),
		s.Critical, s.High, s.Medium, s.Low, s.Info)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// scoreGrade maps a 0..100 quality score (higher=better) to A+..F.
func scoreGrade(s float64) string {
	switch {
	case s >= 90:
		return "A+"
	case s >= 80:
		return "A"
	case s >= 70:
		return "B"
	case s >= 55:
		return "C"
	case s >= 40:
		return "D"
	case s >= 25:
		return "E"
	default:
		return "F"
	}
}

// riskGrade maps a 0..100 risk score (higher=worse) to A+..F.
func riskGrade(s float64) string {
	return scoreGrade(100 - s)
}

// ============================================================================
// OWL NET CORE — shared networking primitives used by OWL v2 network tools:
// IANA service table, IP protocol numbers, ICMP/DNS tables, CIDR/subnet math,
// Internet checksum, TCP flag helpers, port-range parsing. Stdlib only.
// ============================================================================

// ianaPorts maps well-known/registered TCP-UDP ports to service names.
var ianaPorts = map[int]string{
	1: "tcpmux", 7: "echo", 9: "discard", 13: "daytime", 17: "qotd", 19: "chargen",
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 37: "time",
	42: "nameserver", 43: "whois", 49: "tacacs", 53: "domain", 67: "bootps", 68: "bootpc",
	69: "tftp", 70: "gopher", 79: "finger", 80: "http", 88: "kerberos", 102: "iso-tsap",
	110: "pop3", 111: "sunrpc", 113: "ident", 119: "nntp", 123: "ntp", 135: "msrpc",
	137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
	162: "snmptrap", 179: "bgp", 194: "irc", 201: "at-rtmp", 264: "bgmp", 318: "tsp",
	381: "hp-collector", 383: "hp-managed-node", 389: "ldap", 411: "direct-connect",
	427: "svrloc", 443: "https", 445: "microsoft-ds", 464: "kpasswd", 465: "smtps",
	497: "retrospect", 500: "isakmp", 512: "exec", 513: "login", 514: "syslog",
	515: "printer", 520: "rip", 521: "ripng", 540: "uucp", 548: "afp", 554: "rtsp",
	563: "nntps", 587: "submission", 591: "filemaker", 593: "msrpc-http", 631: "ipp",
	636: "ldaps", 639: "msdp", 646: "ldp", 691: "msexch-routing", 860: "iscsi",
	873: "rsync", 902: "vmware-auth", 989: "ftps-data", 990: "ftps", 993: "imaps",
	995: "pop3s", 1025: "blackjack", 1080: "socks", 1194: "openvpn", 1234: "vlc",
	1241: "nessus", 1270: "scom", 1293: "ipsec", 1311: "dell-openmanage", 1337: "waste",
	1433: "ms-sql-s", 1434: "ms-sql-m", 1494: "citrix-ica", 1521: "oracle", 1604: "citrix",
	1701: "l2tp", 1720: "h323", 1723: "pptp", 1725: "steam", 1741: "cisco-net-mgmt",
	1755: "ms-streaming", 1812: "radius", 1813: "radius-acct", 1883: "mqtt", 1900: "ssdp",
	2000: "cisco-sccp", 2002: "cisco-globalview", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
	2086: "whm", 2087: "whm-ssl", 2095: "webmail", 2096: "webmail-ssl", 2181: "zookeeper",
	2222: "directadmin", 2375: "docker", 2376: "docker-ssl", 2379: "etcd", 2380: "etcd-peer",
	2483: "oracle-insecure", 2484: "oracle-ssl", 2638: "sybase", 3000: "grafana",
	3128: "squid", 3260: "iscsi-target", 3268: "globalcat", 3269: "globalcat-ssl",
	3306: "mysql", 3333: "dec-notes", 3389: "ms-wbt-server", 3478: "stun", 3632: "distcc",
	3690: "svn", 3724: "wow", 4000: "icq", 4040: "yo-main", 4369: "epmd", 4444: "metasploit",
	4500: "ipsec-nat-t", 4505: "salt-publish", 4506: "salt-request", 4567: "tram",
	4789: "vxlan", 4848: "glassfish", 5000: "upnp", 5001: "iperf", 5060: "sip",
	5061: "sip-tls", 5222: "xmpp-client", 5269: "xmpp-server", 5353: "mdns", 5355: "llmnr",
	5432: "postgresql", 5555: "freeciv", 5601: "kibana", 5666: "nrpe", 5672: "amqp",
	5683: "coap", 5800: "vnc-http", 5900: "vnc", 5938: "teamviewer", 5984: "couchdb",
	6000: "x11", 6379: "redis", 6443: "kube-apiserver", 6514: "syslog-tls",
	6660: "irc", 6667: "irc", 6697: "irc-ssl", 6881: "bittorrent", 7000: "cassandra-tls",
	7001: "weblogic", 7077: "spark", 7199: "cassandra-jmx", 7474: "neo4j", 7687: "bolt",
	8000: "http-alt", 8008: "http-alt", 8009: "ajp13", 8080: "http-proxy", 8081: "http-alt",
	8086: "influxdb", 8088: "radan-http", 8089: "splunk", 8140: "puppet", 8161: "activemq",
	8200: "vault", 8333: "bitcoin", 8443: "https-alt", 8500: "consul", 8530: "wsus",
	8600: "consul-dns", 8686: "jmx", 8888: "jupyter", 9000: "cslistener", 9042: "cassandra",
	9090: "prometheus", 9092: "kafka", 9093: "alertmanager", 9100: "node-exporter",
	9200: "elasticsearch", 9300: "elastic-transport", 9418: "git", 9443: "tungsten-https",
	9999: "abyss", 10000: "webmin", 10050: "zabbix-agent", 10051: "zabbix-server",
	11211: "memcached", 11371: "pgpkeyserver", 15672: "rabbitmq-mgmt", 16379: "redis-cluster",
	17500: "dropbox-lansync", 18080: "monero", 25565: "minecraft", 27017: "mongodb",
	27018: "mongodb-shard", 28015: "rethinkdb", 32768: "filenet", 49152: "dyn-start",
	50000: "db2", 50070: "hadoop-namenode", 61616: "activemq-openwire", 62078: "iphone-sync",
}

func serviceName(port int) string {
	if n, ok := ianaPorts[port]; ok {
		return n
	}
	return "unknown"
}

// ipProtoNumbers maps IANA IP protocol numbers to names.
var ipProtoNumbers = map[int]string{
	0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IPv4", 6: "TCP", 8: "EGP",
	9: "IGP", 17: "UDP", 27: "RDP", 33: "DCCP", 41: "IPv6", 43: "IPv6-Route",
	44: "IPv6-Frag", 46: "RSVP", 47: "GRE", 50: "ESP", 51: "AH", 58: "IPv6-ICMP",
	88: "EIGRP", 89: "OSPFIGP", 103: "PIM", 112: "VRRP", 115: "L2TP", 132: "SCTP",
	136: "UDPLite", 137: "MPLS-in-IP", 139: "HIP", 143: "Ethernet",
}

func ipProtoName(n int) string {
	if s, ok := ipProtoNumbers[n]; ok {
		return s
	}
	return fmt.Sprintf("proto-%d", n)
}

// icmpTypes maps ICMPv4 type numbers to names.
var icmpTypes = map[int]string{
	0: "echo-reply", 3: "dest-unreachable", 4: "source-quench", 5: "redirect",
	8: "echo-request", 9: "router-advert", 10: "router-solicit", 11: "time-exceeded",
	12: "param-problem", 13: "timestamp", 14: "timestamp-reply", 15: "info-request",
	16: "info-reply", 17: "address-mask-request", 18: "address-mask-reply",
	30: "traceroute", 37: "domain-name-request", 38: "domain-name-reply",
}

func icmpTypeName(t int) string {
	if s, ok := icmpTypes[t]; ok {
		return s
	}
	return fmt.Sprintf("type-%d", t)
}

// dnsQTypes maps DNS record type numbers to mnemonics.
var dnsQTypes = map[int]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX",
	16: "TXT", 17: "RP", 18: "AFSDB", 24: "SIG", 25: "KEY", 28: "AAAA", 29: "LOC",
	33: "SRV", 35: "NAPTR", 36: "KX", 37: "CERT", 39: "DNAME", 41: "OPT", 42: "APL",
	43: "DS", 44: "SSHFP", 45: "IPSECKEY", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY",
	49: "DHCID", 50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 53: "SMIMEA", 55: "HIP",
	59: "CDS", 60: "CDNSKEY", 61: "OPENPGPKEY", 62: "CSYNC", 63: "ZONEMD",
	64: "SVCB", 65: "HTTPS", 99: "SPF", 108: "EUI48", 109: "EUI64", 249: "TKEY",
	250: "TSIG", 251: "IXFR", 252: "AXFR", 255: "ANY", 256: "URI", 257: "CAA",
}

func dnsQTypeName(t int) string {
	if s, ok := dnsQTypes[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", t)
}

func dnsQTypeNum(name string) int {
	name = strings.ToUpper(strings.TrimSpace(name))
	for n, s := range dnsQTypes {
		if s == name {
			return n
		}
	}
	return 0
}

// --- IPv4 / CIDR math -------------------------------------------------------

func ip4ToU32(ip net.IP) (uint32, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(v4), true
}

func u32ToIP4(u uint32) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, u)
	return net.IP(b)
}

func maskBits(m net.IPMask) int {
	ones, _ := m.Size()
	return ones
}

func cidrHostCount(prefix int, v6 bool) float64 {
	total := 32
	if v6 {
		total = 128
	}
	hostBits := total - prefix
	if hostBits < 0 {
		return 0
	}
	return math.Pow(2, float64(hostBits))
}

func u32ToDotted(u uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}

func wildcardFromMask(m net.IPMask) string {
	if len(m) != 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", 255-m[0], 255-m[1], 255-m[2], 255-m[3])
}

func isPrivateV4(u uint32) bool {
	return (u>>24 == 10) ||
		(u>>20 == 0xAC1) ||
		(u>>16 == 0xC0A8) ||
		(u>>24 == 127) ||
		(u>>16 == 0xA9FE)
}

func ipClassV4(u uint32) string {
	first := byte(u >> 24)
	switch {
	case first < 128:
		return "A"
	case first < 192:
		return "B"
	case first < 224:
		return "C"
	case first < 240:
		return "D (multicast)"
	default:
		return "E (reserved)"
	}
}

// --- Internet checksum (RFC 1071) ------------------------------------------

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// --- TCP flags --------------------------------------------------------------

const (
	tcpFIN = 1 << 0
	tcpSYN = 1 << 1
	tcpRST = 1 << 2
	tcpPSH = 1 << 3
	tcpACK = 1 << 4
	tcpURG = 1 << 5
	tcpECE = 1 << 6
	tcpCWR = 1 << 7
)

func tcpFlagString(f int) string {
	var p []string
	if f&tcpCWR != 0 {
		p = append(p, "CWR")
	}
	if f&tcpECE != 0 {
		p = append(p, "ECE")
	}
	if f&tcpURG != 0 {
		p = append(p, "URG")
	}
	if f&tcpACK != 0 {
		p = append(p, "ACK")
	}
	if f&tcpPSH != 0 {
		p = append(p, "PSH")
	}
	if f&tcpRST != 0 {
		p = append(p, "RST")
	}
	if f&tcpSYN != 0 {
		p = append(p, "SYN")
	}
	if f&tcpFIN != 0 {
		p = append(p, "FIN")
	}
	if len(p) == 0 {
		return "none"
	}
	return strings.Join(p, ",")
}

// --- Port range parsing -----------------------------------------------------

// parsePortSpec expands "22,80,1000-1005,443" into a sorted unique port list.
func parsePortSpec(spec string) []int {
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bits := strings.SplitN(part, "-", 2)
			lo := atoiSafe(bits[0])
			hi := atoiSafe(bits[1])
			if lo > hi {
				lo, hi = hi, lo
			}
			for p := lo; p <= hi; p++ {
				if p >= 0 && p <= 65535 && !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
		} else {
			p := atoiSafe(part)
			if p >= 0 && p <= 65535 && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Ints(out)
	return out
}

func validPort(p int) bool { return p > 0 && p <= 65535 }

// --- small hashing helpers --------------------------------------------------

func md5Hex(b []byte) string {
	h := md5.Sum(b)
	return hex.EncodeToString(h[:])
}

func sha1Hex(b []byte) string {
	h := sha1.Sum(b)
	return hex.EncodeToString(h[:])
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// fnv1a32 implements the FNV-1a 32-bit hash (used for lightweight fingerprints).
func fnv1a32(b []byte) uint32 {
	var h uint32 = 2166136261
	for _, c := range b {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}

// netUseAll references optional symbols so imports stay satisfied.
func netUseAll() {
	_ = bits.OnesCount
	_ = utf8.RuneLen
	_ = io.EOF
	_ = bytes.Equal
	_ = errors.Is
	_ = rand.Intn
	_ = regexp.MatchString
}

// ============================================================================
// OWL EXTRA CORE — reusable packet/PCAP parsers, IPv6/CIDR math, encodings,
// histograms and text helpers shared by OWL v2 network/forensic tools.
// ============================================================================

// --- Encodings --------------------------------------------------------------

func b64Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func b64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
}
func b32Encode(b []byte) string { return base32.StdEncoding.EncodeToString(b) }
func b32Decode(s string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(s)))
}
func crc32Hex(b []byte) string {
	return fmt.Sprintf("%08x", crc32.ChecksumIEEE(b))
}

// hexToBytes parses loose hex (spaces, colons, 0x, newlines) into bytes.
func hexToBytes(s string) ([]byte, error) {
	var clean strings.Builder
	s = strings.ToLower(s)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '0' && i+1 < len(s) && s[i+1] == 'x' {
			i++
			continue
		}
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			clean.WriteByte(c)
		}
	}
	cs := clean.String()
	if len(cs)%2 == 1 {
		return nil, errors.New("odd hex length")
	}
	return hex.DecodeString(cs)
}

func bytesToHexSpaced(b []byte) string {
	var sb strings.Builder
	for i, c := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02x", c)
	}
	return sb.String()
}

// --- IPv6 / CIDR math -------------------------------------------------------

func expandIPv6(ip net.IP) string {
	v6 := ip.To16()
	if v6 == nil || ip.To4() != nil {
		return ip.String()
	}
	var groups []string
	for i := 0; i < 16; i += 2 {
		groups = append(groups, fmt.Sprintf("%02x%02x", v6[i], v6[i+1]))
	}
	return strings.Join(groups, ":")
}

func ipv6Type(ip net.IP) string {
	if ip.To4() != nil {
		return "ipv4-mapped"
	}
	switch {
	case ip.IsLoopback():
		return "loopback (::1)"
	case ip.IsLinkLocalUnicast():
		return "link-local (fe80::/10)"
	case ip.IsLinkLocalMulticast():
		return "link-local-multicast"
	case ip.IsMulticast():
		return "multicast (ff00::/8)"
	case ip.IsGlobalUnicast():
		if len(ip) == 16 && ip[0]&0xfe == 0xfc {
			return "unique-local (fc00::/7)"
		}
		return "global-unicast"
	case ip.IsUnspecified():
		return "unspecified (::)"
	}
	return "unknown"
}

func eui64FromMAC(mac net.HardwareAddr) string {
	if len(mac) != 6 {
		return ""
	}
	b := []byte{mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]}
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x", b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7])
}

func cidrContains(cidr string, ip string) (bool, error) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false, err
	}
	p := net.ParseIP(ip)
	if p == nil {
		return false, errors.New("bad ip")
	}
	return n.Contains(p), nil
}

func cidrOverlap(a, b string) (bool, error) {
	_, na, err := net.ParseCIDR(a)
	if err != nil {
		return false, err
	}
	_, nb, err := net.ParseCIDR(b)
	if err != nil {
		return false, err
	}
	return na.Contains(nb.IP) || nb.Contains(na.IP), nil
}

// rangeToCIDRs converts an inclusive IPv4 range to a minimal CIDR set.
func rangeToCIDRs(start, end uint32) []string {
	var out []string
	for start <= end {
		maxSize := 32
		for maxSize > 0 {
			mask := uint32(0xFFFFFFFF) << uint(32-(maxSize-1))
			if start&mask != start {
				break
			}
			maxSize--
		}
		x := 32 - int(math.Floor(math.Log2(float64(end-start+1))))
		if maxSize < x {
			maxSize = x
		}
		out = append(out, fmt.Sprintf("%s/%d", u32ToDotted(start), maxSize))
		add := uint32(1) << uint(32-maxSize)
		if start+add-1 < start {
			break
		}
		start += add
	}
	return out
}

// --- Ethernet / IP / TCP / UDP / ICMP header parsers ------------------------

type EthHeader struct {
	Dst       net.HardwareAddr
	Src       net.HardwareAddr
	EtherType uint16
	Payload   []byte
}

func parseEthernet(b []byte) (*EthHeader, error) {
	if len(b) < 14 {
		return nil, errors.New("short ethernet frame")
	}
	h := &EthHeader{
		Dst:       net.HardwareAddr(append([]byte(nil), b[0:6]...)),
		Src:       net.HardwareAddr(append([]byte(nil), b[6:12]...)),
		EtherType: binary.BigEndian.Uint16(b[12:14]),
	}
	off := 14
	// VLAN 802.1Q
	if h.EtherType == 0x8100 && len(b) >= 18 {
		h.EtherType = binary.BigEndian.Uint16(b[16:18])
		off = 18
	}
	h.Payload = b[off:]
	return h, nil
}

type IPv4Header struct {
	Version  int
	IHL      int
	TOS      int
	Length   int
	ID       int
	Flags    int
	FragOff  int
	TTL      int
	Protocol int
	Checksum int
	Src      net.IP
	Dst      net.IP
	Payload  []byte
}

func parseIPv4(b []byte) (*IPv4Header, error) {
	if len(b) < 20 {
		return nil, errors.New("short IPv4 header")
	}
	ver := int(b[0] >> 4)
	if ver != 4 {
		return nil, fmt.Errorf("not IPv4 (version=%d)", ver)
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return nil, errors.New("bad IHL")
	}
	h := &IPv4Header{
		Version:  ver,
		IHL:      ihl,
		TOS:      int(b[1]),
		Length:   int(binary.BigEndian.Uint16(b[2:4])),
		ID:       int(binary.BigEndian.Uint16(b[4:6])),
		Flags:    int(b[6] >> 5),
		FragOff:  int(binary.BigEndian.Uint16(b[6:8]) & 0x1fff),
		TTL:      int(b[8]),
		Protocol: int(b[9]),
		Checksum: int(binary.BigEndian.Uint16(b[10:12])),
		Src:      net.IP(append([]byte(nil), b[12:16]...)),
		Dst:      net.IP(append([]byte(nil), b[16:20]...)),
	}
	if len(b) > ihl {
		h.Payload = b[ihl:]
	}
	return h, nil
}

type TCPHeader struct {
	SrcPort int
	DstPort int
	Seq     uint32
	Ack     uint32
	Offset  int
	Flags   int
	Window  int
	Payload []byte
}

func parseTCP(b []byte) (*TCPHeader, error) {
	if len(b) < 20 {
		return nil, errors.New("short TCP header")
	}
	off := int(b[12]>>4) * 4
	if off < 20 {
		off = 20
	}
	h := &TCPHeader{
		SrcPort: int(binary.BigEndian.Uint16(b[0:2])),
		DstPort: int(binary.BigEndian.Uint16(b[2:4])),
		Seq:     binary.BigEndian.Uint32(b[4:8]),
		Ack:     binary.BigEndian.Uint32(b[8:12]),
		Offset:  off,
		Flags:   int(b[13]),
		Window:  int(binary.BigEndian.Uint16(b[14:16])),
	}
	if len(b) > off {
		h.Payload = b[off:]
	}
	return h, nil
}

type UDPHeader struct {
	SrcPort  int
	DstPort  int
	Length   int
	Checksum int
	Payload  []byte
}

func parseUDP(b []byte) (*UDPHeader, error) {
	if len(b) < 8 {
		return nil, errors.New("short UDP header")
	}
	h := &UDPHeader{
		SrcPort:  int(binary.BigEndian.Uint16(b[0:2])),
		DstPort:  int(binary.BigEndian.Uint16(b[2:4])),
		Length:   int(binary.BigEndian.Uint16(b[4:6])),
		Checksum: int(binary.BigEndian.Uint16(b[6:8])),
	}
	if len(b) > 8 {
		h.Payload = b[8:]
	}
	return h, nil
}

type ICMPHeader struct {
	Type     int
	Code     int
	Checksum int
	ID       int
	Seq      int
	Payload  []byte
}

func parseICMP(b []byte) (*ICMPHeader, error) {
	if len(b) < 8 {
		return nil, errors.New("short ICMP header")
	}
	h := &ICMPHeader{
		Type:     int(b[0]),
		Code:     int(b[1]),
		Checksum: int(binary.BigEndian.Uint16(b[2:4])),
		ID:       int(binary.BigEndian.Uint16(b[4:6])),
		Seq:      int(binary.BigEndian.Uint16(b[6:8])),
	}
	if len(b) > 8 {
		h.Payload = b[8:]
	}
	return h, nil
}

// --- Minimal PCAP reader (classic libpcap format) ---------------------------

type PcapPacket struct {
	TsSec  uint32
	TsUsec uint32
	Data   []byte
}

type PcapFile struct {
	LinkType uint32
	Swapped  bool
	Packets  []PcapPacket
}

func parsePcap(data []byte) (*PcapFile, error) {
	if len(data) < 24 {
		return nil, errors.New("file too small for pcap header")
	}
	magic := binary.LittleEndian.Uint32(data[0:4])
	var bo binary.ByteOrder
	swapped := false
	switch magic {
	case 0xa1b2c3d4, 0xa1b23c4d:
		bo = binary.LittleEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		bo = binary.BigEndian
		swapped = true
	default:
		return nil, fmt.Errorf("not a pcap file (magic=%08x)", magic)
	}
	pf := &PcapFile{LinkType: bo.Uint32(data[20:24]), Swapped: swapped}
	off := 24
	for off+16 <= len(data) {
		tsSec := bo.Uint32(data[off : off+4])
		tsUsec := bo.Uint32(data[off+4 : off+8])
		inclLen := bo.Uint32(data[off+8 : off+12])
		off += 16
		if off+int(inclLen) > len(data) {
			break
		}
		pkt := PcapPacket{TsSec: tsSec, TsUsec: tsUsec, Data: data[off : off+int(inclLen)]}
		pf.Packets = append(pf.Packets, pkt)
		off += int(inclLen)
	}
	return pf, nil
}

func linkTypeName(lt uint32) string {
	switch lt {
	case 0:
		return "NULL"
	case 1:
		return "ETHERNET"
	case 101:
		return "RAW"
	case 113:
		return "LINUX_SLL"
	case 127:
		return "IEEE802_11_RADIOTAP"
	case 228:
		return "IPV4"
	case 229:
		return "IPV6"
	}
	return fmt.Sprintf("LINKTYPE_%d", lt)
}

// --- Histograms & rolling stats ---------------------------------------------

type Histogram struct {
	Bins   []int
	Min    float64
	Max    float64
	Width  float64
	Counts []int
	Total  int
}

func newHistogram(values []float64, bins int) Histogram {
	h := Histogram{Counts: make([]int, bins)}
	if len(values) == 0 || bins <= 0 {
		return h
	}
	h.Min = minF(values)
	h.Max = maxF(values)
	h.Width = (h.Max - h.Min) / float64(bins)
	if h.Width == 0 {
		h.Width = 1
	}
	for _, v := range values {
		idx := int((v - h.Min) / h.Width)
		if idx < 0 {
			idx = 0
		}
		if idx >= bins {
			idx = bins - 1
		}
		h.Counts[idx]++
		h.Total++
	}
	return h
}

func (h Histogram) render(width int) string {
	var b strings.Builder
	maxc := 0
	for _, c := range h.Counts {
		if c > maxc {
			maxc = c
		}
	}
	for i, c := range h.Counts {
		lo := h.Min + float64(i)*h.Width
		frac := 0.0
		if maxc > 0 {
			frac = float64(c) / float64(maxc)
		}
		fmt.Fprintf(&b, "  %10.2f │ %s %d\n", lo, asciiBar(frac, width), c)
	}
	return b.String()
}

// chiSquareUniform tests how far a byte distribution is from uniform.
func chiSquareUniform(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	expected := float64(len(data)) / 256.0
	var chi float64
	for _, c := range counts {
		d := float64(c) - expected
		chi += d * d / expected
	}
	return chi
}

// indexOfCoincidence measures repetition in a byte stream (crypto heuristic).
func indexOfCoincidence(data []byte) float64 {
	if len(data) < 2 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	var sum float64
	for _, c := range counts {
		sum += float64(c) * float64(c-1)
	}
	return sum / (n * (n - 1))
}

// --- Text helpers -----------------------------------------------------------

func wrapText(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := words[0]
		for _, w := range words[1:] {
			if len(cur)+1+len(w) > width {
				out = append(out, cur)
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func kv(k, v string) {
	fmt.Printf("  %s %s\n", col(pad(k+":", 16), DIM), col(v, W))
}

func centre(s string, width int) string {
	if len(s) >= width {
		return s
	}
	pad := (width - len(s)) / 2
	return strings.Repeat(" ", pad) + s
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func plural(n int, s string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, s)
	}
	return fmt.Sprintf("%d %ss", n, s)
}

// extraUseAll references optional symbols so imports stay satisfied.
func extraUseAll() {
	_ = base64.RawStdEncoding
	_ = base32.HexEncoding
	_ = crc32.IEEE
}

// ============================================================================
// OWL EXTRA CORE II — online statistics, anomaly detection, string distance,
// varint/zigzag, OUI vendor lookup, expanded ATT&CK, CVSS helper, charts.
// All stdlib, reused across OWL v2 tools.
// ============================================================================

// Welford implements numerically stable online mean/variance.
type Welford struct {
	n    int
	mean float64
	m2   float64
	min  float64
	max  float64
}

func (w *Welford) Add(x float64) {
	if w.n == 0 {
		w.min, w.max = x, x
	} else {
		if x < w.min {
			w.min = x
		}
		if x > w.max {
			w.max = x
		}
	}
	w.n++
	d := x - w.mean
	w.mean += d / float64(w.n)
	w.m2 += d * (x - w.mean)
}

func (w *Welford) Mean() float64 { return w.mean }
func (w *Welford) Variance() float64 {
	if w.n < 2 {
		return 0
	}
	return w.m2 / float64(w.n-1)
}
func (w *Welford) Stddev() float64 { return math.Sqrt(w.Variance()) }
func (w *Welford) N() int          { return w.n }
func (w *Welford) Min() float64    { return w.min }
func (w *Welford) Max() float64    { return w.max }

// zscore returns the standard score of x against a sample.
func zscore(x float64, xs []float64) float64 {
	m := mean(xs)
	sd := stddev(xs)
	if sd == 0 {
		return 0
	}
	return (x - m) / sd
}

// zscoreAnomalies returns indices whose z-score exceeds threshold.
func zscoreAnomalies(xs []float64, threshold float64) []int {
	var out []int
	m := mean(xs)
	sd := stddev(xs)
	if sd == 0 {
		return out
	}
	for i, x := range xs {
		if math.Abs((x-m)/sd) >= threshold {
			out = append(out, i)
		}
	}
	return out
}

// madOutliers uses the robust median-absolute-deviation method.
func madOutliers(xs []float64, k float64) []int {
	if len(xs) < 3 {
		return nil
	}
	med := medianF(xs)
	dev := make([]float64, len(xs))
	for i, x := range xs {
		dev[i] = math.Abs(x - med)
	}
	mad := medianF(dev)
	if mad == 0 {
		return nil
	}
	var out []int
	for i, x := range xs {
		if 0.6745*math.Abs(x-med)/mad > k {
			out = append(out, i)
		}
	}
	return out
}

// levenshtein computes edit distance between two strings.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

func similarity(a, b string) float64 {
	d := levenshtein(a, b)
	m := len(a)
	if len(b) > m {
		m = len(b)
	}
	if m == 0 {
		return 1
	}
	return 1 - float64(d)/float64(m)
}

// --- varint / zigzag (protobuf-style) ---------------------------------------

func readUvarint(b []byte) (uint64, int) {
	var x uint64
	var s uint
	for i, c := range b {
		if c < 0x80 {
			return x | uint64(c)<<s, i + 1
		}
		x |= uint64(c&0x7f) << s
		s += 7
		if s > 63 {
			return 0, 0
		}
	}
	return 0, 0
}

func zigzagDecode(u uint64) int64 {
	return int64(u>>1) ^ -int64(u&1)
}

func putUvarint(x uint64) []byte {
	var out []byte
	for x >= 0x80 {
		out = append(out, byte(x)|0x80)
		x >>= 7
	}
	return append(out, byte(x))
}

// --- OUI vendor lookup ------------------------------------------------------

var ouiVendors = map[string]string{
	"00:00:0C": "Cisco", "00:1A:A0": "Dell", "00:50:56": "VMware", "00:0C:29": "VMware",
	"00:05:69": "VMware", "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
	"00:16:3E": "Xen", "00:1C:42": "Parallels", "00:03:93": "Apple", "00:0A:27": "Apple",
	"00:1B:63": "Apple", "A4:5E:60": "Apple", "DC:A6:32": "RaspberryPi", "B8:27:EB": "RaspberryPi",
	"E4:5F:01": "RaspberryPi", "00:15:5D": "Microsoft-HyperV", "00:1D:D8": "Microsoft",
	"F0:9F:C2": "Ubiquiti", "24:A4:3C": "Ubiquiti", "00:25:9C": "Cisco-Linksys",
	"00:1E:C2": "Apple", "3C:5A:B4": "Google", "00:1A:11": "Google", "F4:F5:E8": "Google",
	"00:17:88": "Philips-Hue", "00:24:E4": "Withings", "D0:52:A8": "Nest", "18:B4:30": "Nest",
	"00:04:F2": "Polycom", "00:0B:82": "Grandstream", "00:90:4C": "Epigram", "00:1D:0F": "TP-Link",
	"50:C7:BF": "TP-Link", "EC:08:6B": "TP-Link", "00:14:BF": "Cisco-Linksys", "C0:56:27": "Belkin",
	"00:26:BB": "Apple", "00:23:DF": "Apple", "00:1F:5B": "Apple", "00:1E:52": "Apple",
}

func macVendor(mac string) string {
	mac = strings.ToUpper(strings.ReplaceAll(mac, "-", ":"))
	if len(mac) >= 8 {
		if v, ok := ouiVendors[mac[:8]]; ok {
			return v
		}
	}
	// locally administered / multicast heuristics
	parts := strings.Split(mac, ":")
	if len(parts) >= 1 && len(parts[0]) == 2 {
		if b, err := strconv.ParseUint(parts[0], 16, 8); err == nil {
			if b&0x01 == 1 {
				return "multicast/broadcast"
			}
			if b&0x02 == 2 {
				return "locally-administered"
			}
		}
	}
	return "unknown"
}

// --- expanded ATT&CK map (merged into attckDB at init) ----------------------

var attckDB2 = map[string]string{
	"T1011":     "Exfiltration Over Other Network Medium",
	"T1020":     "Automated Exfiltration",
	"T1041":     "Exfiltration Over C2 Channel",
	"T1048":     "Exfiltration Over Alternative Protocol",
	"T1048.003": "Exfiltration Over Unencrypted Non-C2 Protocol",
	"T1070":     "Indicator Removal",
	"T1105":     "Ingress Tool Transfer",
	"T1176":     "Browser Extensions",
	"T1203":     "Exploitation for Client Execution",
	"T1210":     "Exploitation of Remote Services",
	"T1211":     "Exploitation for Defense Evasion",
	"T1485":     "Data Destruction",
	"T1489":     "Service Stop",
	"T1529":     "System Shutdown/Reboot",
	"T1542":     "Pre-OS Boot",
	"T1556":     "Modify Authentication Process",
	"T1563":     "Remote Service Session Hijacking",
	"T1565":     "Data Manipulation",
	"T1570":     "Lateral Tool Transfer",
	"T1574":     "Hijack Execution Flow",
	"T1583":     "Acquire Infrastructure",
	"T1584":     "Compromise Infrastructure",
	"T1587":     "Develop Capabilities",
	"T1588":     "Obtain Capabilities",
	"T1598":     "Phishing for Information",
	"T1659":     "Content Injection",
}

func init() {
	for k, v := range attckDB2 {
		attckDB[k] = v
	}
}

// --- CVSS-ish base estimate -------------------------------------------------

// severityFromScore maps a 0..10 numeric score to a severity label.
func severityFromScore(s float64) string {
	switch {
	case s >= 9.0:
		return SevCritical
	case s >= 7.0:
		return SevHigh
	case s >= 4.0:
		return SevMedium
	case s >= 0.1:
		return SevLow
	default:
		return SevInfo
	}
}

// cvssLikeBase combines rough impact/exploitability into a 0..10 figure.
func cvssLikeBase(impact, exploitability float64) float64 {
	impact = clampF(impact, 0, 10)
	exploitability = clampF(exploitability, 0, 10)
	base := 0.6*impact + 0.4*exploitability
	return math.Round(base*10) / 10
}

// --- charts / rings ---------------------------------------------------------

// RingF is a fixed-capacity float ring buffer.
type RingF struct {
	data []float64
	cap  int
}

func newRingF(cap int) *RingF { return &RingF{cap: cap} }
func (r *RingF) Push(v float64) {
	r.data = append(r.data, v)
	if len(r.data) > r.cap {
		r.data = r.data[1:]
	}
}
func (r *RingF) Values() []float64 { return r.data }

func barChart(labels []string, values []float64, width int) string {
	var b strings.Builder
	maxv := maxF(values)
	if maxv == 0 {
		maxv = 1
	}
	wl := 0
	for _, l := range labels {
		if len(l) > wl {
			wl = len(l)
		}
	}
	for i := range labels {
		if i >= len(values) {
			break
		}
		fmt.Fprintf(&b, "  %s │ %s %.2f\n", pad(labels[i], wl), asciiBar(values[i]/maxv, width), values[i])
	}
	return b.String()
}

// tokenFrequency counts whitespace tokens and returns sorted pairs.
func tokenFrequency(s string) []struct {
	Token string
	Count int
} {
	m := map[string]int{}
	for _, t := range strings.Fields(s) {
		m[t]++
	}
	var out []struct {
		Token string
		Count int
	}
	for k, v := range m {
		out = append(out, struct {
			Token string
			Count int
		}{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// isHexString reports whether s is all hex digits.
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ============================================================================
// OICMPTunnel DOMAIN ENGINE — ICMP Tunnel Detector
// Analyse ICMP traffic from PCAP or logs: payload entropy, size anomalies,
// echo request/reply patterns, timing beacons and covert-channel scoring.
// ============================================================================

type ICMPPacket struct {
	Time    time.Time
	Src     string
	Dst     string
	Type    int
	Code    int
	ID      int
	Seq     int
	Payload []byte
}

type ICMPFlow struct {
	SrcDst     string
	Count      int
	EchoReq    int
	EchoReply  int
	Other      int
	AvgSize    float64
	MaxSize    int
	AvgEntropy float64
	MaxEntropy float64
	UniquePay  int
	Score      float64
	Grade      string
}

func parseICMPLogLine(line string) (ICMPPacket, bool) {
	// SRC DST TYPE CODE ID SEQ SIZE [HEXPAYLOAD]
	f := strings.Fields(line)
	if len(f) < 6 {
		return ICMPPacket{}, false
	}
	p := ICMPPacket{Time: time.Now(), Src: f[0], Dst: f[1], Type: atoiSafe(f[2]), Code: atoiSafe(f[3]), ID: atoiSafe(f[4]), Seq: atoiSafe(f[5])}
	if len(f) >= 7 {
		sz := atoiSafe(f[6])
		p.Payload = make([]byte, sz)
		for i := range p.Payload {
			p.Payload[i] = byte(i)
		}
	}
	if len(f) >= 8 {
		if b, err := hexToBytes(f[7]); err == nil {
			p.Payload = b
		}
	}
	return p, true
}

func extractICMPFromPcap(pf *PcapFile) []ICMPPacket {
	var out []ICMPPacket
	for _, pkt := range pf.Packets {
		payload := pkt.Data
		if pf.LinkType == 1 {
			eth, err := parseEthernet(payload)
			if err != nil {
				continue
			}
			payload = eth.Payload
		}
		ip4, err := parseIPv4(payload)
		if err != nil || ip4.Protocol != 1 {
			continue
		}
		ic, err := parseICMP(ip4.Payload)
		if err != nil {
			continue
		}
		out = append(out, ICMPPacket{
			Time: time.Unix(int64(pkt.TsSec), int64(pkt.TsUsec)*1000),
			Src:  ip4.Src.String(), Dst: ip4.Dst.String(),
			Type: ic.Type, Code: ic.Code, ID: ic.ID, Seq: ic.Seq, Payload: ic.Payload,
		})
	}
	return out
}

func profileICMP(pkts []ICMPPacket) []ICMPFlow {
	by := map[string][]ICMPPacket{}
	for _, p := range pkts {
		k := p.Src + "->" + p.Dst
		by[k] = append(by[k], p)
	}
	var out []ICMPFlow
	for k, list := range by {
		f := ICMPFlow{SrcDst: k, Count: len(list)}
		payloads := map[string]bool{}
		var sizes, ents []float64
		for _, p := range list {
			switch p.Type {
			case 8:
				f.EchoReq++
			case 0:
				f.EchoReply++
			default:
				f.Other++
			}
			sz := len(p.Payload)
			sizes = append(sizes, float64(sz))
			if sz > f.MaxSize {
				f.MaxSize = sz
			}
			e := shannonEntropy(p.Payload)
			ents = append(ents, e)
			if e > f.MaxEntropy {
				f.MaxEntropy = e
			}
			payloads[sha1Hex(p.Payload)] = true
		}
		f.AvgSize = mean(sizes)
		f.AvgEntropy = mean(ents)
		f.UniquePay = len(payloads)
		f.Score = scoreICMPTunnel(f)
		f.Grade = riskGrade(f.Score)
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

func scoreICMPTunnel(f ICMPFlow) float64 {
	s := 0.0
	s += clampF(f.AvgEntropy*8, 0, 35)
	if f.MaxSize > 64 {
		s += clampF(float64(f.MaxSize)/8, 0, 20)
	}
	if f.Count > 0 {
		uniq := float64(f.UniquePay) / float64(f.Count)
		s += clampF(uniq*25, 0, 20)
	}
	if f.EchoReq > 0 && f.EchoReply == 0 {
		s += 10
	}
	if f.Other > f.EchoReq {
		s += 10
	}
	return clampF(s, 0, 100)
}

func icmpFindings(flows []ICMPFlow) []Finding {
	var fs []Finding
	for _, f := range flows {
		if f.Score < 15 {
			continue
		}
		sev := SevInfo
		switch {
		case f.Score >= 70:
			sev = SevCritical
		case f.Score >= 50:
			sev = SevHigh
		case f.Score >= 30:
			sev = SevMedium
		default:
			sev = SevLow
		}
		fs = append(fs, Finding{ID: "IC-FLOW", Title: fmt.Sprintf("ICMP tunnel score %.0f (%s)", f.Score, f.Grade),
			Severity: sev, Score: f.Score, Category: "icmp-tunnel", Subject: f.SrcDst,
			Description: fmt.Sprintf("n=%d echo=%d/%d avgSize=%.0f avgH=%.2f uniqPay=%d",
				f.Count, f.EchoReq, f.EchoReply, f.AvgSize, f.AvgEntropy, f.UniquePay),
			Evidence: fmt.Sprintf("maxSize=%d maxH=%.2f", f.MaxSize, f.MaxEntropy),
			ATTCK:    []string{"T1095", "T1572"}, Remediation: "Inspect host; block unusual ICMP payloads at the firewall."})
	}
	if len(fs) == 0 {
		fs = append(fs, Finding{ID: "IC-OK", Title: "No ICMP tunneling indicators", Severity: SevInfo,
			Score: sevWeight(SevInfo), Category: "icmp-tunnel", Description: "Payloads look like normal echo traffic."})
	}
	return fs
}

func demoICMP() []ICMPPacket {
	var out []ICMPPacket
	base := time.Now()
	// normal ping
	for i := 0; i < 5; i++ {
		pay := repeatByte(0x00, 56)
		out = append(out, ICMPPacket{Time: base.Add(time.Duration(i) * time.Second), Src: "10.0.0.5", Dst: "8.8.8.8", Type: 8, ID: 1, Seq: i, Payload: pay})
		out = append(out, ICMPPacket{Time: base.Add(time.Duration(i)*time.Second + 50*time.Millisecond), Src: "8.8.8.8", Dst: "10.0.0.5", Type: 0, ID: 1, Seq: i, Payload: pay})
	}
	// covert channel: high-entropy large payloads
	for i := 0; i < 30; i++ {
		pay := make([]byte, 200)
		for j := range pay {
			pay[j] = byte(rand.Intn(256))
		}
		out = append(out, ICMPPacket{Time: base.Add(time.Duration(i) * 200 * time.Millisecond), Src: "10.0.0.66", Dst: "203.0.113.9", Type: 8, ID: 99, Seq: i, Payload: pay})
	}
	return out
}

var (
	fLog     = flag.String("log", "", "ICMP log file")
	fPcap    = flag.String("pcap", "", "PCAP with ICMP")
	fThresh  = flag.Float64("threshold", 20, "min score to report")
	fFormat  = flag.String("format", "txt", "report format")
	fOutput  = flag.String("output", "", "write to FILE")
	fNoColor = flag.Bool("no-color", false, "disable colour")
	fDemo    = flag.Bool("demo", false, "run demonstration")
	fSelf    = flag.Bool("selftest", false, "run built-in self-tests and exit")
	fVersion = flag.Bool("version", false, "print version")
)

func usage() {
	banner()
	fmt.Println("  " + col("USAGE", CY+B) + "  oicmptunnel [flags]       (no flags -> interactive TUI)")
	fmt.Println()
	fmt.Println("  " + col("DESCRIPTION", CY+B))
	fmt.Println("    Detect ICMP / ICMPv6 covert channels and tunnels from PCAP or logs. Scores")
	fmt.Println("    flows by payload entropy, size, uniqueness, echo asymmetry, beacon timing")
	fmt.Println("    and non-echo types. Fully offline; nothing is sent on the wire.")
	fmt.Println()
	fmt.Println("  " + col("FLAGS", CY+B))
	helpRow("--pcap FILE", "analyze ICMP from a pcap/pcapng capture")
	helpRow("--log FILE", "analyze ICMP from a text log (src dst type payload)")
	helpRow("--threshold N", "minimum flow score to report (default 20)")
	helpRow("--format FMT", "report format: txt|md|json|csv|sarif")
	helpRow("--output FILE", "write report to FILE instead of stdout")
	helpRow("--demo", "run a self-contained synthetic demonstration")
	helpRow("--selftest", "run built-in self-tests and exit")
	helpRow("--no-color", "disable ANSI colors")
	helpRow("--version", "print version and exit")
	helpRow("-h, --help", "show this help")
	fmt.Println()
	fmt.Println("  " + col("EXAMPLES", CY+B))
	fmt.Println("    oicmptunnel                                 # interactive TUI")
	fmt.Println("    oicmptunnel --demo                          # synthetic walkthrough")
	fmt.Println("    oicmptunnel --pcap cap.pcap                 # scan a capture")
	fmt.Println("    oicmptunnel --pcap cap.pcap --format sarif --output icmp.sarif")
	fmt.Println("    oicmptunnel --log icmp.log --threshold 30   # stricter reporting")
	fmt.Println()
	fmt.Println("  " + col("ATT&CK", CY+B) + "  T1095 Non-Application Layer Protocol · T1572 Protocol Tunneling")
	line(64)
}

func helpRow(a, b string) {
	fmt.Printf("    %s %s\n", col(pad(a, 16), W), col(b, GY))
}

func main() {
	usePackages()
	netUseAll()
	extraUseAll()
	flag.Usage = usage
	for _, a := range os.Args[1:] {
		if a == "-h" || a == "--help" || a == "help" {
			usage()
			return
		}
	}
	flag.Parse()
	if *fNoColor {
		noColor = true
	}
	if *fVersion {
		fmt.Printf("%s %s (%s)\n", APPNAME, VERSION, CATEGORY)
		return
	}
	if *fSelf {
		os.Exit(runSelfTest())
	}
	if *fDemo {
		runDemo()
		return
	}
	if *fLog != "" || *fPcap != "" {
		runCLI()
		return
	}
	interactive()
}

func emitReport(fs []Finding, target string) {
	if err := writeOutput(*fOutput, renderReport(*fFormat, buildReport(target, fs))); err != nil {
		errMsg(err.Error())
		os.Exit(1)
	}
}

func runCLI() {
	var pkts []ICMPPacket
	target := "icmp"
	if *fLog != "" {
		lines, err := readLinesFromFile(*fLog)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		for _, ln := range lines {
			if p, ok := parseICMPLogLine(ln); ok {
				pkts = append(pkts, p)
			}
		}
		target = *fLog
	}
	if *fPcap != "" {
		b, err := os.ReadFile(*fPcap)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		pf, err := parsePcap(b)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		pkts = append(pkts, extractICMPFromPcap(pf)...)
		target = *fPcap
	}
	flows := profileICMP(pkts)
	var filtered []ICMPFlow
	for _, f := range flows {
		if f.Score >= *fThresh {
			filtered = append(filtered, f)
		}
	}
	emitReport(icmpFindings(filtered), target)
}

func runDemo() {
	banner()
	okMsg("OICMPTunnel demonstration")
	pkts := demoICMP()
	info(fmt.Sprintf("packets=%d", len(pkts)))
	flows := profileICMP(pkts)
	var rows [][]string
	for _, f := range flows {
		rows = append(rows, []string{f.SrcDst, fmt.Sprintf("%d", f.Count), fmt.Sprintf("%.0f", f.AvgSize),
			fmt.Sprintf("%.2f", f.AvgEntropy), fmt.Sprintf("%.0f", f.Score), f.Grade})
	}
	table([]string{"FLOW", "N", "AVG-SZ", "AVG-H", "SCORE", "GRADE"}, rows)
	fs := icmpFindings(flows)
	printFindingsTable(fs)
	printSummary(summarize(fs))
	okMsg("demo complete")
}

var lastFS []Finding

func interactive() {
	for {
		choice := menu("OICMPTunnel — ICMP Tunnel Detector", []string{
			"Analyse ICMP log", "Analyse PCAP", "Run synthetic demo",
			"Explain scoring", "Export report",
		})
		switch choice {
		case "0", "00":
			clear()
			okMsg("bye")
			return
		case "H", "h":
			tuiHelp()
		case "1":
			clear()
			banner()
			p := prompt("log file")
			lines, _ := readLinesFromFile(p)
			var pkts []ICMPPacket
			for _, ln := range lines {
				if x, ok := parseICMPLogLine(ln); ok {
					pkts = append(pkts, x)
				}
			}
			lastFS = icmpFindings(profileICMP(pkts))
			printFindingsTable(lastFS)
			pause()
		case "2":
			clear()
			banner()
			p := prompt("pcap")
			b, _ := os.ReadFile(p)
			pf, _ := parsePcap(b)
			lastFS = icmpFindings(profileICMP(extractICMPFromPcap(pf)))
			printFindingsTable(lastFS)
			pause()
		case "3":
			clear()
			banner()
			runDemo()
			pause()
		case "4":
			clear()
			banner()
			fmt.Println("  + payload entropy up to 35")
			fmt.Println("  + large payload size up to 20")
			fmt.Println("  + unique payload ratio up to 20")
			fmt.Println("  + echo asymmetry / non-echo types up to 20")
			pause()
		case "5":
			clear()
			banner()
			if len(lastFS) == 0 {
				lastFS = icmpFindings(profileICMP(demoICMP()))
			}
			f := prompt("format")
			if f == "" {
				f = "txt"
			}
			writeOutput(prompt("output"), renderReport(f, buildReport("icmp", lastFS)))
			pause()
		default:
			errMsg("invalid")
			pause()
		}
	}
}

func icmpTypeLabel(t int) string { return icmpTypeName(t) }

func sizeHistogramICMP(pkts []ICMPPacket) string {
	var xs []float64
	for _, p := range pkts {
		xs = append(xs, float64(len(p.Payload)))
	}
	return newHistogram(xs, 8).render(20)
}

func echoRatio(f ICMPFlow) float64 {
	if f.EchoReq == 0 {
		return 0
	}
	return float64(f.EchoReply) / float64(f.EchoReq)
}

func highEntropyPayloads(pkts []ICMPPacket, thresh float64) int {
	n := 0
	for _, p := range pkts {
		if shannonEntropy(p.Payload) >= thresh {
			n++
		}
	}
	return n
}

func flowKey(p ICMPPacket) string { return p.Src + "->" + p.Dst }

func filterByType(pkts []ICMPPacket, t int) []ICMPPacket {
	var out []ICMPPacket
	for _, p := range pkts {
		if p.Type == t {
			out = append(out, p)
		}
	}
	return out
}

func avgPayloadEntropy(pkts []ICMPPacket) float64 {
	var xs []float64
	for _, p := range pkts {
		xs = append(xs, shannonEntropy(p.Payload))
	}
	return mean(xs)
}

func payloadChiSquare(pkts []ICMPPacket) float64 {
	var all []byte
	for _, p := range pkts {
		all = append(all, p.Payload...)
	}
	return chiSquareUniform(all)
}

func timingBeaconICMP(pkts []ICMPPacket) []Finding {
	by := map[string][]time.Time{}
	for _, p := range pkts {
		by[p.Src] = append(by[p.Src], p.Time)
	}
	var fs []Finding
	for src, ts := range by {
		if len(ts) < 10 {
			continue
		}
		sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
		var d []float64
		for i := 1; i < len(ts); i++ {
			d = append(d, ts[i].Sub(ts[i-1]).Seconds())
		}
		m := mean(d)
		sd := stddev(d)
		cv := 0.0
		if m > 0 {
			cv = sd / m
		}
		if cv < 0.2 {
			fs = append(fs, Finding{ID: "IC-BEACON", Title: "ICMP beaconing", Severity: SevHigh,
				Score: sevWeight(SevHigh), Category: "icmp-tunnel", Subject: src,
				Description: fmt.Sprintf("CV=%.2f mean=%.2fs", cv, m), ATTCK: []string{"T1095"}})
		}
	}
	return fs
}

func renderICMPSummary(flows []ICMPFlow) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  flows=%d\n", len(flows))
	for _, f := range flows {
		fmt.Fprintf(&b, "  %s score=%.0f grade=%s\n", f.SrcDst, f.Score, f.Grade)
	}
	return b.String()
}

func icmpExtra2844(pkts []ICMPPacket) int {
	return len(pkts) + 31
}

func classifyPayload(p []byte) string {
	if len(p) == 0 {
		return "empty"
	}
	h := shannonEntropy(p)
	if h > 7.5 {
		return "high-entropy(encrypted/compressed)"
	}
	if h < 2 {
		return "low-entropy(pattern/zeros)"
	}
	if indexOfCoincidence(p) > 0.06 {
		return "structured/text-like"
	}
	return "mixed"
}

func payloadClasses(pkts []ICMPPacket) map[string]int {
	m := map[string]int{}
	for _, p := range pkts {
		m[classifyPayload(p.Payload)]++
	}
	return m
}

func maxPayload(pkts []ICMPPacket) int {
	m := 0
	for _, p := range pkts {
		if len(p.Payload) > m {
			m = len(p.Payload)
		}
	}
	return m
}

func minPayload(pkts []ICMPPacket) int {
	if len(pkts) == 0 {
		return 0
	}
	m := len(pkts[0].Payload)
	for _, p := range pkts {
		if len(p.Payload) < m {
			m = len(p.Payload)
		}
	}
	return m
}

func unusualTypes(pkts []ICMPPacket) []Finding {
	var fs []Finding
	counts := map[int]int{}
	for _, p := range pkts {
		counts[p.Type]++
	}
	for t, n := range counts {
		if t != 0 && t != 8 && n >= 3 {
			fs = append(fs, Finding{ID: "IC-TYPE", Title: "Unusual ICMP type " + icmpTypeName(t), Severity: SevMedium,
				Score: float64(n), Category: "icmp-tunnel", Description: fmt.Sprintf("type=%d count=%d", t, n),
				ATTCK: []string{"T1095"}})
		}
	}
	return fs
}

func pairEchoSequences(pkts []ICMPPacket) float64 {
	reqs := map[string]int{}
	reps := map[string]int{}
	for _, p := range pkts {
		k := fmt.Sprintf("%d:%d", p.ID, p.Seq)
		if p.Type == 8 {
			reqs[k]++
		}
		if p.Type == 0 {
			reps[k]++
		}
	}
	matched := 0
	for k := range reqs {
		if reps[k] > 0 {
			matched++
		}
	}
	if len(reqs) == 0 {
		return 0
	}
	return float64(matched) / float64(len(reqs))
}

func icmpReportCard(flows []ICMPFlow) string {
	var b strings.Builder
	b.WriteString("  ICMP Tunnel Report Card\n")
	for _, f := range flows {
		fmt.Fprintf(&b, "  %-40s %5.1f %s  bar=%s\n", truncStr(f.SrcDst, 40), f.Score, f.Grade, asciiBar(f.Score/100, 20))
	}
	return b.String()
}

func sortFlowsBySize(flows []ICMPFlow) []ICMPFlow {
	out := append([]ICMPFlow(nil), flows...)
	sort.Slice(out, func(i, j int) bool { return out[i].AvgSize > out[j].AvgSize })
	return out
}

func sortFlowsByEntropy(flows []ICMPFlow) []ICMPFlow {
	out := append([]ICMPFlow(nil), flows...)
	sort.Slice(out, func(i, j int) bool { return out[i].AvgEntropy > out[j].AvgEntropy })
	return out
}

func totalBytesICMP(pkts []ICMPPacket) int64 {
	var n int64
	for _, p := range pkts {
		n += int64(len(p.Payload))
	}
	return n
}

func uniqueSourcesICMP(pkts []ICMPPacket) int {
	m := map[string]bool{}
	for _, p := range pkts {
		m[p.Src] = true
	}
	return len(m)
}

func uniqueDestsICMP(pkts []ICMPPacket) int {
	m := map[string]bool{}
	for _, p := range pkts {
		m[p.Dst] = true
	}
	return len(m)
}

func icmpGradeLabel(score float64) string {
	return riskGrade(score)
}

func formatFlow(f ICMPFlow) string {
	return fmt.Sprintf("%s n=%d score=%.0f H=%.2f sz=%.0f grade=%s",
		f.SrcDst, f.Count, f.Score, f.AvgEntropy, f.AvgSize, f.Grade)
}

func icmpThresholdDefault() float64 { return 20 }

func isEcho(t int) bool { return t == 0 || t == 8 }

func icmpPayloadPreview(p []byte, n int) string {
	if len(p) < n {
		n = len(p)
	}
	return bytesToHexSpaced(p[:n])
}

// ============================================================================
//  Help & Usage  (interactive menu [H])  +  self-test
// ============================================================================

var owlHelpAbout = []string{
	"OICMPTunnel is an OFFLINE detector for ICMP / ICMPv6 covert channels and " +
		"tunnels (ptunnel, icmptunnel, Loki-style C2). It reads a pcap/pcapng capture " +
		"or a text log and never sends anything on the wire.",
	"",
	"It profiles each src→dst flow and scores it on payload entropy, payload size, " +
		"unique-payload ratio, echo request/reply asymmetry, non-echo ICMP types and " +
		"beacon timing (low jitter). Flows above the threshold become findings graded " +
		"and mapped to MITRE ATT&CK T1095 / T1572.",
}

var owlHelpFlow = []string{
	"Pick [3] Run synthetic demo first to see a full scored walkthrough.",
	"Then [2] Analyse PCAP on your own capture, or [1] Analyse ICMP log for text logs.",
	"Use [4] Explain scoring to understand how each flow score is built.",
	"Use [5] Export report to write txt/md/json/csv/sarif for the last analysis.",
	"Type the number and press Enter. [00] exits, [H] opens this help.",
}

var owlHelpMenu = []owlHelpItem{
	{"1", "Analyse ICMP log — text log: SRC DST TYPE CODE ID SEQ SIZE [HEXPAYLOAD]."},
	{"2", "Analyse PCAP — read ICMP/ICMPv6 from a pcap/pcapng capture."},
	{"3", "Run synthetic demo — built-in normal ping + covert channel sample."},
	{"4", "Explain scoring — the weighted factors behind each flow score."},
	{"5", "Export report — write the last findings as txt/md/json/csv/sarif."},
	{"H", "This help & usage screen (two pages)."},
	{"00", "Exit."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "High payload entropy (~8.0 bits/byte) on ICMP echo = likely encrypted tunnel."},
	{"*", "Normal ping payloads are fixed/low-entropy; many unique large payloads are suspicious."},
	{"*", "Low inter-packet jitter (CV < 0.2) over many packets flags beaconing."},
	{"*", "--threshold raises the bar; raise it to cut noise, lower it to catch slow tunnels."},
	{"*", "--demo needs no capture; --selftest validates the scoring engine offline."},
	{"*", "Authorized monitoring only. This tool classifies captured traffic; it never probes."},
}

func owlHelpCLI() { usage() }

// ---------------------------------------------------------------------------
//  Self-test (--selftest): exercise the scoring engine on known vectors.
// ---------------------------------------------------------------------------

func runSelfTest() int {
	pass, fail := 0, 0
	check := func(name string, ok bool) {
		if ok {
			pass++
			fmt.Println("  " + col("[✔] ", GRN+B) + col(name, W))
		} else {
			fail++
			fmt.Println("  " + col("[✘] ", R+B) + col(name, R))
		}
	}

	// 1-2: entropy sanity
	check("entropy: constant bytes -> 0", shannonEntropy(repeatByte(0x41, 64)) < 0.01)
	rnd := make([]byte, 256)
	for i := range rnd {
		rnd[i] = byte(i)
	}
	check("entropy: uniform bytes -> ~8", shannonEntropy(rnd) > 7.5)

	// 3: demo packets
	pkts := demoICMP()
	check("demo packets generated", len(pkts) > 20)

	// 4-6: profiling + covert flow detection
	flows := profileICMP(pkts)
	check("profiling yields flows", len(flows) >= 2)
	var covert *ICMPFlow
	for i := range flows {
		if strings.Contains(flows[i].SrcDst, "10.0.0.66") {
			covert = &flows[i]
		}
	}
	check("covert flow (10.0.0.66) profiled", covert != nil)
	if covert != nil {
		check("covert flow scored high", covert.Score >= 40 && covert.AvgEntropy > 6.5)
	}

	// 7: findings include an ICMP-tunnel finding
	fs := icmpFindings(flows)
	hasTun := false
	for _, f := range fs {
		if f.Category == "icmp-tunnel" && sevRank(f.Severity) >= sevRank(SevMedium) {
			hasTun = true
		}
	}
	check("findings flag ICMP tunnel", hasTun)

	// 8: log line parser
	_, ok := parseICMPLogLine("10.0.0.5 8.8.8.8 8 0 1 1 56")
	check("log line parsed", ok)
	_, bad := parseICMPLogLine("garbage")
	check("bad log line rejected", !bad)

	// 9-11: report exporters
	rep := buildReport("selftest", fs)
	check("summary totals findings", rep.Summary.Total == len(fs))
	js := renderReport("json", rep)
	var jv interface{}
	check("json report valid", json.Unmarshal([]byte(js), &jv) == nil)
	check("sarif report has schema", strings.Contains(renderReport("sarif", rep), "sarif"))

	fmt.Println()
	line(64)
	if fail == 0 {
		fmt.Println("  " + col(fmt.Sprintf("[✔] self-test PASSED — %d/%d checks", pass, pass), GRN+B))
		return 0
	}
	fmt.Println("  " + col(fmt.Sprintf("[✘] self-test FAILED — %d passed, %d failed", pass, fail), R+B))
	return 1
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}
