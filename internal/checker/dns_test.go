package checker

import (
	"encoding/binary"
	"testing"
)

func TestParseCAARData(t *testing.T) {
	record, ok := parseCAARData([]byte{0, 5, 'i', 's', 's', 'u', 'e', 'l', 'e', 't', 's', 'e', 'n', 'c', 'r', 'y', 'p', 't', '.', 'o', 'r', 'g'})
	if !ok {
		t.Fatalf("expected CAA record to parse")
	}
	if record.Flag != 0 || record.Tag != "issue" || record.Value != "letsencrypt.org" {
		t.Fatalf("unexpected CAA record: %+v", record)
	}
}

func TestParseCAAResponse(t *testing.T) {
	queryID := uint16(0x1234)
	query, err := buildCAAQuery(queryID, "example.com")
	if err != nil {
		t.Fatalf("buildCAAQuery returned error: %v", err)
	}

	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response, 0xc0, 0x0c)
	response = binary.BigEndian.AppendUint16(response, 257)
	response = binary.BigEndian.AppendUint16(response, 1)
	response = binary.BigEndian.AppendUint32(response, 300)
	rdata := []byte{0, 5, 'i', 's', 's', 'u', 'e', 'd', 'i', 'g', 'i', 'c', 'e', 'r', 't', '.', 'c', 'o', 'm'}
	response = binary.BigEndian.AppendUint16(response, uint16(len(rdata)))
	response = append(response, rdata...)

	records, err := parseCAAResponse(response, queryID)
	if err != nil {
		t.Fatalf("parseCAAResponse returned error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 CAA record, got %d", len(records))
	}
	if records[0].Tag != "issue" || records[0].Value != "digicert.com" {
		t.Fatalf("unexpected CAA record: %+v", records[0])
	}
}
