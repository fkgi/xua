package xua

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/fkgi/xua/sctp"
)

var (
	eventStack = make(chan message, 1024)

	ta    = time.Second * 2
	tr    = time.Second * 2
	tack  = time.Second * 2
	tair  = time.Minute * 15
	tbeat = time.Second * 30

	requestStack   message = nil
	RoutingContext []uint32
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
	handleMessage()

	// handleResult handles result of this message
	handleResult(message)

	// marshal returns Message Class, Message Type and binary Message Data
	marshal() (uint8, uint8, []byte)

	// unmarshal decodes specified Tag/length TLV value from reader
	unmarshal(uint16, uint16, io.ReadSeeker) error
}

func writeHandler(m message) (e error) {
	if requestStack != nil {
		e = errors.New("any other request is waiting answer")
	} else {
		cls, typ, b := m.marshal()
		buf := new(bytes.Buffer)

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

		e = sctp.Write(buf.Bytes())
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

func readHandler(buf []byte) {
	// rx message handler
	if buf[0] != 1 || len(buf) < 8 {
		// invalid version
		return
	}

	r := bytes.NewReader(buf[4:])
	var l uint32
	if e := binary.Read(r, binary.BigEndian, &l); e != nil {
		return
	}

	var m message = nil
	switch buf[2] {
	case 0x00:
		switch buf[3] {
		case 0x00:
			m = new(ERR)
		case 0x01:
			m = new(NTFY)
		}
	case 0x02:
		switch buf[3] {
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
		switch buf[3] {
		case 0x03:
			m = &BEAT{tx: false}
		case 0x04:
			m = new(ASPUPAck)
		case 0x05:
			m = new(ASPDNAck)
		case 0x06:
			m = &BEATAck{tx: false}
		}
	case 0x04:
		switch buf[3] {
		case 0x03:
			m = new(ASPACAck)
		case 0x04:
			m = new(ASPIAAck)
		}
	case 0x07:
		switch buf[3] {
		case 0x01:
			m = &CLDT{tx: false}
		case 0x02:
			m = &CLDR{tx: false}
		}
	}

	if m == nil {
		return
	}

	r = bytes.NewReader(buf[8:l])
	for r.Len() > 8 {
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

		if l%4 != 0 {
			r.Seek(int64(4-l%4), io.SeekCurrent)
		}
	}
	eventStack <- m
}

// Serve connects and active ASP
func Serve(handleData func([]byte), handleUp, handleDown func()) error {
	return sctp.Serve(
		readHandler,
		func() {
			go func() {
				// event handler
				for e, ok := <-eventStack; ok; e, ok = <-eventStack {
					e.handleMessage()
				}
			}()

			r := make(chan error, 1)
			eventStack <- &ASPUP{result: r}
			if e := <-r; e != nil {
				sctp.Abort("invalid ASP message")
				return
			}
			eventStack <- &ASPAC{
				mode:   Loadshare,
				ctx:    RoutingContext,
				result: r}
			if e := <-r; e != nil {
				sctp.Abort("invalid ASP message")
			}

			go handleUp()
		},
		func() {
			close(eventStack)
			go handleDown()
		})
}

// Close disconnect ASP
func Close() error {
	r := make(chan error, 1)
	eventStack <- &ASPDN{result: r}
	<-r

	return sctp.Close()
}
