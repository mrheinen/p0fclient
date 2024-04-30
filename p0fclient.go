// This is a client of the p0f passive fingerprinter.
package p0fclient

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
)

// ErrSocketCommunication can be returned by queries. This error is worth
// catching and to try and re-establish the connection with the socket.
var ErrSocketCommunication = fmt.Errorf("could not communicate with p0f socket")

// The fields below are all well documented in the p0f README section 4.

const (
	P0F_STATUS_BADQUERY = 0x00
	P0F_STATUS_OK       = 0x10
	P0F_STATUS_NOMATCH  = 0x20
	P0F_ADDR_IPV4       = 0x04
	P0F_ADDR_IPV6       = 0x06
	P0F_MATCH_FUZZY     = 0x01
	P0F_MATCH_GENERIC   = 0x02
	P0F_REQUEST_MAGIC   = 0x50304601
	P0F_RESPONSE_MAGIC  = 0x50304602
)

type Query struct {
	Magic       uint32
	AddressType uint8
	Address     [16]uint8
}

type Response struct {
	Magic         uint32
	Status        uint32
	FirstSeen     uint32
	LastSeen      uint32
	TotalCount    uint32
	UptimeMinutes uint32
	UpModDays     uint32
	LastNat       uint32
	LastChg       uint32
	Distance      int16
	BadSw         uint8
	OsMatchQ      uint8
	OsName        [32]uint8
	OsFlavor      [32]uint8
	HttpName      [32]uint8
	HttpFlavor    [32]uint8
	LinkType      [32]uint8
	Language      [32]uint8
}

func (r *Response) String() string {
	ret := fmt.Sprintf("%s %s", r.OsName, r.OsFlavor)
	if r.OsMatchQ == P0F_MATCH_FUZZY {
		ret += " (fuzzy)"
	} else {
		ret += " (generic)"
	}

	return ret
}

type P0fClient struct {
	socketFile string
	connection net.Conn
	mu         sync.Mutex
}

// NewP0fClient returns a new instance of P0fClient.
// Remember to call Connect() before doing any queries.
//
// Typical usage looks like:
//
//		pc := NewP0fClient("/path/to/socket")
//	 if err := pc.Connect(); err != nil {
//	   // handle error
//	 }
//
//	 parsedIP, _ := net.ParseIP("1.2.3.4")
//	 res := pc.QueryIP(parsedIP)
//	 fmt.Printf("OS: %s\n", res.OsName)
func NewP0fClient(socketFile string) *P0fClient {
	return &P0fClient{
		socketFile: socketFile,
	}
}

// Set the socket
func (p *P0fClient) SetSocket(socket string) {
	p.socketFile = socket
}

// Connect opens a connection to the p0f socket.
func (p *P0fClient) Connect() error {
	if _, err := os.Stat(p.socketFile); err != nil {
		return fmt.Errorf("could not stat file: %w", err)
	}

	conn, err := net.Dial("unix", p.socketFile)
	if err != nil {
		return fmt.Errorf("could not open socket: %w", err)
	}

	p.connection = conn
	return nil
}

func createQueryForIP(ip net.IP) (Query, error) {
	query := Query{Magic: P0F_REQUEST_MAGIC}

	ipBytes := ip.To4()
	if ipBytes == nil {
		ipBytes = ip.To16()
		query.AddressType = P0F_ADDR_IPV6
	} else {
		query.AddressType = P0F_ADDR_IPV4
	}

	if ipBytes == nil {
		// This probably will never happen. Famous last words..
		return query, fmt.Errorf("could not convert IP to bytes")
	}

	idx := 0
	for _, b := range ipBytes {
		query.Address[idx] = b
		idx += 1
	}

	return query, nil
}

// QueryIP queries the P0f server for the given IP address.
// The IP address can be IPv4 or IPv6 and QueryIP will sort out how to
// do the p0f query. If the query is successful then a response struct is
// returned. Note that this does not mean whether the query indicated a
// match in the fingerprint database; it just indicates that communication
// with the p0f socket went successfully. It is up to the called to still
// check resp.Status to check if their was a fingerprint match.
func (p *P0fClient) QueryIP(ip net.IP) (*Response, error) {
	resp := &Response{}

	query, err := createQueryForIP(ip)
	if err != nil {
		return nil, fmt.Errorf("could not create query: %w", err)
	}

	var querybuf bytes.Buffer
	if err = binary.Write(&querybuf, binary.LittleEndian, query); err != nil {
		return nil, fmt.Errorf("could not write query to binary: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	_, err = p.connection.Write(querybuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("writing to socket: %w", ErrSocketCommunication)
	}

	var n int
	readbuf := make([]byte, binary.Size(resp))
	n, err = p.connection.Read(readbuf[:])
	if err != nil {
		return nil, fmt.Errorf("reading from socket: %w", ErrSocketCommunication)
	}

	buf := bytes.NewReader(readbuf[0:n])
	err = binary.Read(buf, binary.LittleEndian, resp)
	if err != nil {
		return nil, fmt.Errorf("could not convert response: %w", err)
	}

	// First check if the magic actually makes sense.
	if resp.Magic != P0F_RESPONSE_MAGIC {
		return nil, fmt.Errorf("got bad magic: %x", resp.Magic)
	}

	switch resp.Status {
	case P0F_STATUS_OK:
		return resp, nil
	case P0F_STATUS_NOMATCH:
		return resp, nil
	case P0F_STATUS_BADQUERY:
		return nil, fmt.Errorf("performed a bad query!: %w", err)
	default:
		return nil, fmt.Errorf("got unknown response status: %x", resp.Status)
	}
}

func (p *P0fClient) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.connection.Close()
}
