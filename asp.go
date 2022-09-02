package xua

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

var (
	state      = down
	eventStack = make(chan message, 1024)
	// msgStack   = make(map[uint16]chan message)

	ta    = time.Second * 2
	tr    = time.Second * 2
	tack  = time.Second * 2
	tair  = time.Minute * 15
	tbeat = time.Second * 30

	requestStack   message = nil
	RoutingContext []uint32
)

const (
	down     byte = iota
	inactive byte = iota
	active   byte = iota
)

const (
	Override  uint32 = 1
	Loadshare uint32 = 2
	Broadcast uint32 = 3
)

/*
TF: MTP3 Transfer Messages
Message class = 0x01
// 0x01 Payload Data (DATA)

QPTM: Q.921/Q.931 Boundary Primitives Transport Messages
Message class = 0x05
// 0x01 Data Request Message
// 0x02 Data Indication Message
// 0x03 Unit Data Request Message
// 0x04 Unit Data Indication Message
// 0x05 Establish Request
// 0x06 Establish Confirm
// 0x07 Establish Indication
// 0x08 Release Request
// 0x09 Release Confirm
// 0x0a Release Indication

MAUP: MTP2 User Adaptation Messages
Message class = 0x06
// 0x01 Data
// 0x02 Establish Request
// 0x03 Establish Confirm
// 0x04 Release Request
// 0x05 Release Confirm
// 0x06 Release Indication
// 0x07 State Request
// 0x08 State Confirm
// 0x09 State Indication
// 0x0a Data Retrieval Request
// 0x0b Data Retrieval Confirm
// 0x0c Data Retrieval Indication
// 0x0d Data Retrieval Complete Indication
// 0x0e Congestion Indication
// 0x0f Data Acknowledge

CO: SCCP Connection-Oriented Messages
Message class = 0x08
// 0x01 Connection Request (CORE)
// 0x02 Connection Acknowledge (COAK)
// 0x03 Connection Refused (COREF)
// 0x04 Release Request (RELRE)
// 0x05 Release Complete (RELCO)
// 0x06 Reset Confirm (RESCO)
// 0x07 Reset Request (RESRE)
// 0x08 Connection Oriented Data Transfer (CODT)
// 0x09 Connection Oriented Data Acknowledge (CODA)
// 0x0a Connection Oriented Error (COERR)
// 0x0b Inactivity Test (COIT)

RKM: Routing Key Management Messages
Message class = 0x09
// 0x01 Registration Request (REG REQ)
// 0x02 Registration Response (REG RSP)
// 0x03 Deregistration Request (DEREG REQ)
// 0x04 Deregistration Response (DEREG RSP)

IIM: Interface Identifier Management Messages
Message class = 0x0a
// 0x01 Registration Request (REG REQ)
// 0x02 Registration Response (REG RSP)
// 0x03 Deregistration Request (DEREG REQ)
// 0x04 Deregistration Response (DEREG RSP)
*/

/*
Message of xUA

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|    Version    |   Reserved    | Message Class | Message Type  |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                        Message Length                         |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                         Message Data                          |
*/
type message interface {
	// handleMessage handles this message
	handleMessage(net.Conn)

	// handleResult handles result of this message
	handleResult(message)

	// marshal returns Message Class, Message Type and binary Message Data
	marshal() (uint8, uint8, []byte)

	// unmarshal decodes specified Tag/length TLV value from reader
	unmarshal(uint16, uint16, io.ReadSeeker) error
}

func writeHandler(c net.Conn, m message) (e error) {
	if requestStack != nil {
		e = errors.New("any other request is waiting answer")
	} else {
		cls, typ, b := m.marshal()
		buf := bufio.NewWriter(c)

		// version
		buf.WriteByte(1)
		// reserved
		buf.WriteByte(0)
		// Message Class
		buf.WriteByte(cls)
		// Message Type
		buf.WriteByte(typ)
		// Message Length
		binary.Write(buf, binary.BigEndian, uint32(len(b)+8))
		// Message Data
		buf.Write(b)

		e = buf.Flush()
	}

	if e == nil {
		requestStack = m
		time.AfterFunc(tack, func() {
			if requestStack == m {
				// Protocol Error
				eventStack <- &ERR{code: 0x07}
			}
		})
	}
	return
}

func readHandler(c, t uint8, d []byte) (m message) {
	switch c {
	case 0x00:
		switch t {
		case 0x00:
			m = new(ERR)
		case 0x01:
			m = new(NTFY)
		}
	case 0x02:
		switch t {
		case 0x01:
			m = new(DUNA)
		case 0x02:
			m = new(DAVA)
		case 0x04:
			m = new(SCON)
		case 0x05:
			m = new(DUPU)
		case 0x06:
			m = new(DRST)
		}
	case 0x03:
		switch t {
		case 0x04:
			m = new(ASPUPAck)
		case 0x05:
			m = new(ASPDNAck)
		case 0x06:
			m = new(BEATAck)
		}
	case 0x04:
		switch t {
		case 0x03:
			m = new(ASPACAck)
		case 0x04:
			m = new(ASPIAAck)
		}
	case 0x07:
		switch t {
		case 0x01:
			m = &CLDT{tx: false}
		case 0x02:
			m = &CLDR{tx: false}
		}
	}

	if m != nil {
		r := bytes.NewReader(d)
		for r.Len() > 0 {
			var t, l uint16
			if e := binary.Read(r, binary.BigEndian, &t); e != nil {
				break
			}
			if e := binary.Read(r, binary.BigEndian, &l); e != nil {
				break
			}
			l -= 4

			if e := m.unmarshal(t, l, r); e != nil {
				break
			}
		}
	}
	return
}

// Dial connects and active ASP
func DialASP(c net.Conn) (e error) {
	go func() {
		// event handler
		for e, ok := <-eventStack; ok; e, ok = <-eventStack {
			e.handleMessage(c)
		}
	}()
	go func() {
		// rx message handler
		buf := make([]byte, 4)
		for n, e := c.Read(buf); e != nil && n == 4; n, e = c.Read(buf) {
			if buf[0] != 1 {
				// invalid version
				continue
			}

			var l uint32
			if e = binary.Read(c, binary.BigEndian, &l); e != nil {
				break
			}

			data := make([]byte, l)
			offset := 0
			for offset < 1 {
				n, e = c.Read(data[offset:])
				offset += n
				if e != nil {
					break
				}
			}

			m := readHandler(buf[2], buf[3], data)
			if m != nil {
				eventStack <- m
			}
		}
		close(eventStack)
	}()

	r := make(chan error, 1)
	eventStack <- &ASPUP{result: r}
	e = <-r

	if e == nil {
		eventStack <- &ASPAC{
			mode:   Loadshare,
			ctx:    RoutingContext,
			result: r}
		e = <-r
	}

	return
}

// Close disconnect ASP
func Close() (e error) {
	r := make(chan error, 1)
	eventStack <- &ASPDN{result: r}
	e = <-r

	return
}

// Activate ASPAC
/*
func (a ASP) Activate(mode trafficMode, rc []uint32, tid, drn *Label) (e error) {
	body := new(bytes.Buffer)
	// Traffic Mode Type (Optional)
	if mode != 0 {
		writeParam(body, 0x000b, 8)
		binary.Write(body, binary.BigEndian, mode)
	}
	// Routing Context (Optional)
	if len(rc) != 0 {
		writeParam(body, 0x0006, 4+len(rc)*4)
		for _, r := range rc {
			binary.Write(body, binary.BigEndian, r)
		}
	}
	// TID Label
	if tid != nil {
		writeParam(body, 0x0110, 8)
		body.WriteByte(byte(tid.start))
		body.WriteByte(byte(tid.end))
		binary.Write(body, binary.BigEndian, tid.value)
	}
	// DRN Label
	if drn != nil {
		writeParam(body, 0x010f, 8)
		body.WriteByte(byte(drn.start))
		body.WriteByte(byte(drn.end))
		binary.Write(body, binary.BigEndian, drn.value)
	}

	// INFO String (Optioal)

	// ASP Active (ASPAC)
	mc := ASPTM
	mt := byte(0x01)
	if e = write(a.con, mc, mt, body); e != nil {
	} else if mc, mt, body, e = read(a.con); e != nil {
	} else if mc != ASPTM {
		e = errors.New("invalid message class response")
	} else if mt != 0x0008 {
		e = errors.New("invalid message type response")
	}
	for body != nil {
		if body.Len() < 4 {
			break
		}

		var tag, l uint16
		binary.Read(body, binary.BigEndian, &tag)
		binary.Read(body, binary.BigEndian, &l)
		if l > uint16(body.Len()) {
			break
		}
		switch tag {
		case 0x000b:
			binary.Read(body, binary.BigEndian, &mode)
		case 0x0006:
			rc = make([]uint32, int(l-4)/4)
			for i := range rc {
				binary.Read(body, binary.BigEndian, &rc[i])
			}
		default:
			body.Read(make([]byte, l))
		}
	}

	return
}

// Deactivate ASPIA
func (a ASP) Deactivate(rc []uint32) (e error) {
	body := new(bytes.Buffer)
	// Routing Context (Optional)
	if len(rc) != 0 {
		writeParam(body, 0x0006, 4+len(rc)*4)
		for _, r := range rc {
			binary.Write(body, binary.BigEndian, r)
		}
	}
	// INFO String (Optioal)

	// ASP Inactive (ASPIA)
	mc := ASPTM
	mt := byte(0x02)
	if e = write(a.con, mc, mt, body); e != nil {
	} else if mc, mt, body, e = read(a.con); e != nil {
	} else if mc != ASPTM {
		e = errors.New("invalid message class response")
	} else if mt != 0x0004 {
		e = errors.New("invalid message type response")
	}
	for body != nil {
		if body.Len() < 4 {
			break
		}

		var tag, l uint16
		binary.Read(body, binary.BigEndian, &tag)
		binary.Read(body, binary.BigEndian, &l)
		if l > uint16(body.Len()) {
			break
		}
		switch tag {
		case 0x0006:
			rc = make([]uint32, int(l-4)/4)
			for i := range rc {
				binary.Read(body, binary.BigEndian, &rc[i])
			}
		default:
			body.Read(make([]byte, l))
		}
	}
	return nil
}

func write(c net.Conn, mclass msgClass, mtype byte, body *bytes.Buffer) error {
	buf := bufio.NewWriter(c)
	buf.WriteByte(1)
	buf.WriteByte(0)
	buf.WriteByte(byte(mclass))
	buf.WriteByte(mtype)

	if body != nil {
		// Message Length
		binary.Write(buf, binary.BigEndian, uint32(body.Len()+8))
		// Message Data
		body.WriteTo(buf)
	} else {
		// Message Length
		binary.Write(buf, binary.BigEndian, uint32(8))
	}

	return buf.Flush()
}

func read(c net.Conn) (mclass msgClass, mtype byte, body *bytes.Buffer, e error) {
	buf := make([]byte, 4)
	if _, e = c.Read(buf); e != nil {
		return
	}
	if buf[0] != 1 {
		e = errors.New("invalid version")
		return
	}
	mclass = msgClass(buf[2])
	mtype = buf[3]

	var l uint32
	if e = binary.Read(c, binary.BigEndian, &l); e != nil {
		return
	}

	if l != 0 {
		b := make([]byte, l)
		offset := 0
		n := 0
		for offset < 1 {
			n, e = c.Read(b[offset:])
			offset += n
			if e != nil {
				break
			}
		}
		body = bytes.NewBuffer(b)
	}
	return
}
*/
