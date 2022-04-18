package xua

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"net"
)

type msgClass uint8

const (
	MGMT  msgClass = 0x00 //UA Management (MGMT) Message
	TF    msgClass = 0x01 //MTP3 Transfer (TF) Messages
	SSNM  msgClass = 0x02 //SS7 Signalling Network Management (SSNM) Messages
	ASPSM msgClass = 0x03 //ASP State Maintenance (ASPSM) Messages
	ASPTM msgClass = 0x04 //ASP Traffic Maintenance (ASPTM) Messages
	QPTM  msgClass = 0x05 //Q.921/Q.931 Boundary Primitives Transport (QPTM) Messages
	MAUP  msgClass = 0x06 //MTP2 User Adaptation (MAUP) Messages
	CL    msgClass = 0x07 //SCCP Connectionless (CL) Messages
	CO    msgClass = 0x08 //SCCP Connection-Oriented (CO) Messages
	RKM   msgClass = 0x09 //Routing Key Management (RKM) Messages
	IIM   msgClass = 0x0a //Interface Identifier Management (IIM) Messages
)

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Version    |   Reserved    | Message Class | Message Type  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Message Length                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Message Data                          |
*/
type Message struct {
	// version = 1
	msgClass
	msgType uint8 // individual id for each class
	// length = total (include header) byte length
	body bytes.Buffer
}

type AS struct {
	proc []ASP
}

type ASP struct {
	con net.Conn
	act bool
}

// DialASP ASPUP
/*
   0x01 ASP Up (ASPUP)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Tag = 0x0011          |           Length = 8          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         ASP Identifier                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Tag = 0x0004          |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                          INFO String                          /
   \                                                               \
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   0x04 ASP Up Ack (ASPUP ACK)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Tag =0x0004           |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                          INFO String                          /
   \                                                               \
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
func DialASP(c net.Conn, id *uint32) (a ASP, e error) {
	a.con = c
	a.act = false

	body := new(bytes.Buffer)
	// AS Identifier (Optional)
	if id != nil {
		binary.Write(body, binary.BigEndian, uint16(0x0011))
		binary.Write(body, binary.BigEndian, uint16(8))
		binary.Write(body, binary.BigEndian, *id)
	}
	// INFO String (Optioal)

	// ASP Up (ASPUP)
	mc := ASPSM
	mt := byte(0x01)
	if e = write(c, mc, mt, body); e != nil {
	} else if mc, mt, _, e = read(c); e != nil {
	} else if mc != ASPSM {
		e = errors.New("invalid message class response")
	} else if mt != 0x04 {
		e = errors.New("invalid message type response")
	}

	return
}

// Close ASPDN
/*
   0x02 ASP Down (ASPDN)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Tag =0x0004           |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                         INFO String                           /
   \                                                               \
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   0x05 ASP Down Ack (ASPDN ACK)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Tag = 0x0004          |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                         INFO String                           /
   \                                                               \
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
func (a ASP) Close() (e error) {
	// INFO String (Optioal)

	// ASP Down (ASPDN)
	mc := ASPSM
	mt := byte(0x02)
	if e = write(a.con, mc, mt, nil); e != nil {
	} else if mc, mt, _, e = read(a.con); e != nil {
	} else if mc != ASPSM {
		e = errors.New("invalid message class response")
	} else if mt != 0x05 {
		e = errors.New("invalid message type response")
	}
	return
}

// Activate ASPAC
/*
  0x01 ASP Active (ASPAC)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Tag = 0x000B        |            Length = 8         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Traffic Mode Type                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Tag = 0x0006        |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                       Routing Context                         /
   \                                                               \
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Tag = 0x0110         |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           TID Label                           |
   +-------------------------------+-------------------------------+
   |          Tag = 0x010F         |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           DRN Label                           |
   +-------------------------------+-------------------------------+
   |           Tag = 0x0004        |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                          Info String                          /
   \                                                               \
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  0x03 ASP Active Ack (ASPAC ACK)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Tag = 0x000B        |            Length = 8         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Traffic Mode Type                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Tag = 0x0006        |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                       Routing Context                         /
   \                                                               \
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Tag = 0x0004         |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                          Info String                          /
   \                                                               \
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
func (a ASP) Activate(mode *uint32) error {
	mc := ASPTM
	return nil
}

// Deactivate ASPIA
// 0x02 ASP Inactive (ASPIA)
// 0x04 ASP Inactive Ack (ASPIA ACK)
func (a ASP) Deactivate() error {
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

// MGMT
// 0x00 Error (ERR)
// 0x01 Notify (NTFY)
// 0x02 TEI Status Request
// 0x03 TEI Status Confirm
// 0x04 TEI Status Indication

// TF
// 0x01 Payload Data (DATA)

// SSNM
// 0x01 Destination Unavailable (DUNA)
// 0x02 Destination Available (DAVA)
// 0x03 Destination State Audit (DAUD)
// 0x04 Signalling Congestion (SCON)
// 0x05 Destination User Part Unavailable (DUPU)
// 0x06 Destination Restricted (DRST)

// ASPSM
// 0x03 Heartbeat (BEAT)
// 0x06 Heartbeat Ack (BEAT ACK)

// ASPTM
// 0x01 ASP Active (ASPAC)
// 0x02 ASP Inactive (ASPIA)
// 0x03 ASP Active Ack (ASPAC ACK)
// 0x04 ASP Inactive Ack (ASPIA ACK)

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
// 0x01 Connectionless Data Transfer (CLDT)
// 0x02 Connectionless Data Response (CLDR)

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
