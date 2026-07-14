package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Record struct {
	Name     string
	Type     string
	Priority int
	Expected string
}

type answer struct {
	kind  string
	value string
	pref  uint16
}

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Usage: go run main.go <csv_file> <first_dns> <second_dns>")
		os.Exit(1)
	}

	records, err := loadRecords(os.Args[1])
	if err != nil {
		fmt.Printf("CSV error: %v\n", err)
		os.Exit(1)
	}

	var errors []string
	servers := []string{os.Args[2], os.Args[3]}

	for _, srv := range servers {
		ns := normalizeServer(srv)

		for _, rec := range records {
			qtype, ok := typeToQtype(rec.Type)
			if !ok {
				errors = append(errors, fmt.Sprintf("[Server %s] Name: %s (%s) | Unsupported record type",
					srv, rec.Name, rec.Type))
				continue
			}

			answers, err := queryAll(ns, rec.Name, qtype)
			if err != nil {
				errors = append(errors, fmt.Sprintf("[Server %s] Name: %s (expected %s) | Expected: %s | Got: <error: %v>",
					srv, rec.Name, rec.Type, rec.Expected, err))
				continue
			}

			if _, ok := findMatch(rec, answers); !ok {
				got := describeMismatch(rec, answers)
				errors = append(errors, fmt.Sprintf("[Server %s] Name: %s (expected %s) | Expected: %s | Got: %s",
					srv, rec.Name, rec.Type, rec.Expected, got))
			}
		}
	}

	if len(errors) > 0 {
		fmt.Printf("Warning: %d DNS Validation issues from a total %d records\n\n", len(errors), len(records))
		for _, e := range errors {
			fmt.Println(e)
		}
		os.Exit(1)
	}

	fmt.Printf("Successfully tested %d records and all passed\n", len(records))
}

func loadRecords(path string) ([]Record, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("file error: %w", err)
	}
	defer func() { _ = file.Close() }()

	lines, err := readCSV(file)
	if err != nil {
		return nil, err
	}

	var records []Record
	for _, line := range lines {
		if len(line) < 4 {
			continue
		}
		priority, _ := strconv.Atoi(strings.TrimSpace(line[2]))
		records = append(records, Record{
			Name:     strings.TrimSpace(line[0]),
			Type:     strings.ToUpper(strings.TrimSpace(line[1])),
			Priority: priority,
			Expected: strings.TrimSpace(line[3]),
		})
	}
	return records, nil
}

func readCSV(f *os.File) ([][]string, error) {
	r := csv.NewReader(f)
	return r.ReadAll()
}

func normalizeServer(s string) string {
	if !strings.Contains(s, ":") {
		return s + ":53"
	}
	return s
}

func typeToQtype(t string) (uint16, bool) {
	switch t {
	case "A":
		return dns.TypeA, true
	case "CNAME":
		return dns.TypeCNAME, true
	case "TXT":
		return dns.TypeTXT, true
	case "MX":
		return dns.TypeMX, true
	}
	return 0, false
}

func queryAll(server, name string, qtype uint16) ([]*answer, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true

	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, server)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns response code %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		return nil, fmt.Errorf("no answer records")
	}

	var answers []*answer
	for _, rr := range resp.Answer {
		a, err := parseRR(rr)
		if err != nil {
			continue
		}
		answers = append(answers, a)
	}
	return answers, nil
}

func parseRR(rr dns.RR) (*answer, error) {
	switch r := rr.(type) {
	case *dns.A:
		return &answer{kind: "A", value: r.A.String()}, nil
	case *dns.CNAME:
		return &answer{kind: "CNAME", value: trimDot(strings.ToLower(r.Target))}, nil
	case *dns.TXT:
		if len(r.Txt) > 0 {
			return &answer{kind: "TXT", value: r.Txt[0]}, nil
		}
		return &answer{kind: "TXT", value: ""}, nil
	case *dns.MX:
		return &answer{kind: "MX", value: trimDot(r.Mx), pref: r.Preference}, nil
	default:
		return &answer{kind: dns.TypeToString[r.Header().Rrtype], value: rr.String()}, nil
	}
}

func findMatch(rec Record, answers []*answer) (*answer, bool) {
	for _, ans := range answers {
		if ans.kind != rec.Type {
			continue
		}
		switch rec.Type {
		case "A":
			if ans.value == rec.Expected {
				return ans, true
			}
		case "CNAME":
			if ans.value == trimDot(strings.ToLower(rec.Expected)) {
				return ans, true
			}
		case "TXT":
			if ans.value == rec.Expected {
				return ans, true
			}
		case "MX":
			if ans.value == trimDot(rec.Expected) && int(ans.pref) == rec.Priority {
				return ans, true
			}
		}
	}
	return nil, false
}

func describeMismatch(rec Record, answers []*answer) string {
	// If a different record type was returned (e.g. CNAME where A was expected),
	// report that as the difference. Otherwise report the first answer of the
	// expected type, or fall back to the first answer.
	for _, ans := range answers {
		if ans.kind != rec.Type {
			return fmt.Sprintf("%s -> %s", ans.kind, ans.value)
		}
	}
	for _, ans := range answers {
		if ans.kind == rec.Type {
			return fmt.Sprintf("%s -> %s", ans.kind, ans.value)
		}
	}
	if len(answers) > 0 {
		return fmt.Sprintf("%s -> %s", answers[0].kind, answers[0].value)
	}
	return "<no answers>"
}

func trimDot(s string) string {
	return strings.TrimSuffix(s, ".")
}
