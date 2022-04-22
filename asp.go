package xua

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

var (
	active    = false
	waitStack map[byte]chan Message
)

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
)

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
type Message struct {
	msgClass byte
	msgType  byte // individual id for each class
	body     []byte
}

func (m Message) WriteTo(w io.Writer) (e error) {
	buf := bufio.NewWriter(w)

	// version
	buf.WriteByte(1)
	// reserved
	buf.WriteByte(0)
	buf.WriteByte(m.msgClass)
	buf.WriteByte(m.msgType)

	// Message Length
	binary.Write(buf, binary.BigEndian, uint32(len(m.body)+8))

	if len(m.body) != 0 {
		// Message Data
		buf.Write(m.body)
	}

	return buf.Flush()
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
func DialASP(c net.Conn) (e error) {
	/*
		body := new(bytes.Buffer)
		// ASP Identifier (Optional)
		if id != nil {
			binary.Write(buf, binary.BigEndian, uint16(0x0011))
			binary.Write(buf, binary.BigEndian, uint16(8))
			binary.Write(body, binary.BigEndian, *id)
		}
		// INFO String (Optioal)
		if len(info) != 0 {
			writeINFO(buf, info)
		}
	*/
	e = Message{
		msgClass: ASPSM,
		msgType:  0x01, // ASPUP
	}.WriteTo(c)
	if e != nil {
		return
	}

	go func() {
		for {
		}
	}()
	a.con = c
	a.act = false

	if e = write(c, mc, mt, body); e != nil {
	} else if mc, mt, _, e = read(c); e != nil {
	} else if mc == MGMT && mt == 0x00 {
		e = errors.New("error response")
	} else if mc != ASPSM {
		e = errors.New("invalid message class response")
	} else if mt != 0x04 {
		e = errors.New("invalid message type response")
	} else {
		go func() {
			for a.state != closed {
				mc, mt, body, e = read(c)
				if e != nil {
					a.state = closed
					break
				}
			}
		}()
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

type trafficMode uint32

const (
	Override  trafficMode = 1
	Loadshare trafficMode = 2
	Broadcast trafficMode = 3
)

var (
	Mode trafficMode = Loadshare
)

type Label struct {
	start uint8
	end   uint8
	value uint16
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
   |          Tag = 0x0110         |            Length = 8         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           TID Label                           |
   +-------------------------------+-------------------------------+
   |          Tag = 0x010F         |            Length = 8         |
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
/*
  0x02 ASP Inactive (ASPIA)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Tag = 0x0006        |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                       Routing Context                         /
   \                                                               \
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Tag = 0x0004        |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                          INFO String                          /
   \                                                               \
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   0x04 ASP Inactive Ack (ASPIA ACK)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Tag = 0x0006         |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                       Routing Context                         /
   \                                                               \
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Tag = 0x0004         |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                          INFO String                          /
   \                                                               \
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
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

// MGMT
/*
  0x00 Error (ERR)
  SG <-> ASP
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Tag = 0x000C         |             Length            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Error Code                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tag = 0x0006          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                       Routing Context                         /
\                                                               \
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tag = 0x0012          |             Length            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Mask     |                 Affected PC 1                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                              ...                              /
\                                                               \
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Mask     |                 Affected PC n                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tag = 0x010D          |         Length = 8            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Network Appearance                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Tag = 0x0007         |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                        Diagnostic Info                        /
\                                                               \
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/*
  0x01 Notify (NTFY)
  SG -> ASP
0                     1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Tag = 0x000D         |             Length            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Status                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Tag = 0x0011       |             Length            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        ASP Identifier                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|          Tag = 0x0006         |             Length            |
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
/*
  0x01 Connectionless Data Transfer (CLDT)
  ASP <-> SG
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Tag = 0x0006         |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                     * Routing Context                         /
\                                                               \
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tag = 0x0115          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       * Protocol Class                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tag = 0x0102          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                      * Source Address                         /
\                                                               \
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tag = 0x0103          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                   * Destination Address                       /
\                                                               \
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tag = 0x0116         |             Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      * Sequence Control                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tag = 0x0101          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         SS7 Hop Count                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tag = 0x0113          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Importance                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tag = 0x0114          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Message Priority                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tag = 0x0013          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Correlation ID                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tag = 0x0117          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Segmentation                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Tag = 0x010B          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                           * Data                              /
\                                                               \
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  0x02 Connectionless Data Response (CLDR)
  SG <-> AS
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Tag = 0x0006         |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                     * Routing Context                         /
   \                                                               \
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Tag = 0x0106          |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         * SCCP Cause                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Tag = 0x0102          |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                      * Source Address                         /
   \                                                               \
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Tag = 0x0103          |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                   * Destination Address                       /
   \                                                               \
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Tag = 0x0101          |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         SS7 Hop Count                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Tag = 0x0113          |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Importance                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Tag = 0x0114          |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Message Priority                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Tag = 0x0013          |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Correlation ID                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Tag = 0x0117          |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Segmentation                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Tag = 0x010b          |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
   /                             Data                              /
   \                                                               \
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

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
