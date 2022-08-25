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

	requestStack message = nil
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
const (
	MGMT  byte = 0x00 //UA Management (MGMT) Message
	TF    byte = 0x01 //MTP3 Transfer (TF) Messages
	SSNM  byte = 0x02 //SS7 Signalling Network Management (SSNM) Messages
	ASPSM byte = 0x03 //ASP State Maintenance (ASPSM) Messages
	ASPTM byte = 0x04 //ASP Traffic Maintenance (ASPTM) Messages
	QPTM  byte = 0x05 //Q.921/Q.931 Boundary Primitives Transport (QPTM) Messages
	MAUP  byte = 0x06 //MTP2 User Adaptation (MAUP) Messages
	CL    byte = 0x07 //SCCP Connectionless (CL) Messages
	CO    byte = 0x08 //SCCP Connection-Oriented (CO) Messages
	RKM   byte = 0x09 //Routing Key Management (RKM) Messages
	IIM   byte = 0x0a //Interface Identifier Management (IIM) Messages

	ERR  byte = 0x00
	NTFY byte = 0x01

	DUNA byte = 0x01
	DAVA byte = 0x02
	DAUD byte = 0x03
	SCON byte = 0x04
	DUPU byte = 0x05
	DRST byte = 0x06

	ASPUP    byte = 0x01
	ASPDN    byte = 0x02
	BEAT     byte = 0x03
	ASPUPack byte = 0x04
	ASPDNack byte = 0x05
	BEATack  byte = 0x06

	ASPAC    byte = 0x01
	ASPIA    byte = 0x02
	ASPACack byte = 0x03
	ASPIAack byte = 0x04

	CLDT byte = 0x01
	CLDR byte = 0x02
)
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
				eventStack <- &ERR{
					code: 0x07, // Protocol Error
				}
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

// DialASP connects and active ASP
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
		eventStack <- &ASPAC{result: r}
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

func writeParam(buf *bytes.Buffer, tag, length int) {
	binary.Write(buf, binary.BigEndian, uint16(tag))
	binary.Write(buf, binary.BigEndian, uint16(length))
}

func (a ASP) msgHandler() {
	for {

	}
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
// MGMT

// 0x02 TEI Status Request
// 0x03 TEI Status Confirm
// 0x04 TEI Status Indication

// TF
// 0x01 Payload Data (DATA)

// SSNM
// 0x01 Destination Unavailable (DUNA)
// 0x02 Destination Available (DAVA)
/*
  0x03 Destination State Audit (DAUD)
  ASP -> SG
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tag = 0x0006          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                       Routing Context                         /
\                                                               \
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tag = 0x0012          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                        Affected Point Code                    /
\                                                               \
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tag = 0x8003          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              SSN                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tag = 0x010C          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           User/Cause                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tag = 0x0004          |             Length            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                          Info String                          /
\                                                               \
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
// 0x04 Signalling Congestion (SCON)
// 0x05 Destination User Part Unavailable (DUPU)
// 0x06 Destination Restricted (DRST)

// ASPSM
// 0x03 Heartbeat (BEAT)
// 0x06 Heartbeat Ack (BEAT ACK)

// QPTM
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

// MAUP
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

// CL

// CO
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

// RKM
// 0x01 Registration Request (REG REQ)
// 0x02 Registration Response (REG RSP)
// 0x03 Deregistration Request (DEREG REQ)
// 0x04 Deregistration Response (DEREG RSP)

// IIM
// 0x01 Registration Request (REG REQ)
// 0x02 Registration Response (REG RSP)
// 0x03 Deregistration Request (DEREG REQ)
// 0x04 Deregistration Response (DEREG RSP)
