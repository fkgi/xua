package xua

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strconv"

	"github.com/fkgi/xua/sctp"
)

/*
CL: SCCP Connectionless (CL) Messages
Message class = 0x07
*/

/*
CLDT is Connectionless Data Transfer message. (Message type = 0x01)

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|          Tag = 0x0006         |            Length             |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	/                     * Routing Context                         /
	\                                                               \
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Tag = 0x0115          |             Length = 8        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|              Reserved                         | *Protocol Cl. |
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
	|         Tag = 0x0116          |             Length = 8        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                      * Sequence  Control                      |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Tag = 0x0101          |             Length = 8        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|              Reserved                         | SS7 Hop Count |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Tag = 0x0113          |             Length = 8        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                Reserved                       |   Importance  |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Tag = 0x0114          |             Length = 8        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|              Reserved                         |  Msg Priority |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Tag = 0x0013          |            Length = 8         |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                         Correlation ID                        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Tag = 0x0117          |            Length = 32        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	| first/remain  |             Segmentation Reference            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Tag = 0x010B          |            Length             |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	/                           * Data                              /
	\                                                               \
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type CLDT struct {
	tx bool

	ctx           []uint32
	returnOnError bool
	protocolClass uint8
	cgpa          SCCPAddress
	cdpa          SCCPAddress
	sequenceCtrl  uint32

	// hopCount   uint8
	// importance *uint8
	// priority   *uint8
	// correlation *uint32

	// first      bool
	// remain     uint8
	// segmentRef *uint32

	data []byte
}

func (m *CLDT) handleMessage() {
	if m.tx {
		m.handleMessageTx()
	} else {
		m.handleMessageRx()
	}
}

func (m *CLDT) handleMessageTx() {
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

	sctp.Write(buf.Bytes())
}

func (m *CLDT) handleMessageRx()         {}
func (m *CLDT) handleResult(msg message) {}

func (m *CLDT) marshal() (uint8, uint8, []byte) {
	buf := new(bytes.Buffer)

	// Routing Context
	writeRoutingContext(buf, m.ctx)

	// Protocol Class
	if m.returnOnError {
		writeUint8(buf, 0x0115, m.protocolClass|0x80)
	} else {
		writeUint8(buf, 0x0115, m.protocolClass)
	}

	// Source Address
	m.cgpa.marshal(buf, 0x0102)

	// Destination Address
	m.cdpa.marshal(buf, 0x0103)

	// Sequence Control
	writeUint32(buf, 0x0116, m.sequenceCtrl)

	// SS7 Hop Count (Optional)
	// if m.hopCount != 0 {
	// 	writeUint8(buf, 0x0101, m.hopCount)
	// }

	// Importance (Optional)
	// if m.importance != nil {
	// 	writeUint8(buf, 0x0113, *m.importance)
	// }

	// Message Priority (Optional)
	// if m.priority != nil {
	//	writeUint8(buf, 0x0114, *m.priority)
	// }

	// Correlation ID (Optional)
	// if m.correlation != nil {
	//	writeUint32(buf, 0x0013, *m.correlation)
	// }

	// Segmentation (Optional)
	// if m.segmentRef != nil {
	//	var v uint32
	//	if m.first {
	//		v |= 0x80000000
	//	}
	//	v |= uint32(m.remain) << 32
	//	v |= *m.segmentRef
	//	writeUint32(buf, 0x0117, v)
	// }

	// Data
	writeData(buf, m.data)

	return 0x07, 0x01, buf.Bytes()
}

func (m *CLDT) unmarshal(t, l uint16, r io.ReadSeeker) (e error) {
	switch t {
	case 0x0006:
		// Routing Context
		m.ctx, e = readRoutingContext(r, l)
	case 0x0115:
		// Protocol Class
		m.protocolClass, e = readUint8(r, l)
		m.returnOnError = m.protocolClass&0x80 == 0x80
		m.protocolClass = m.protocolClass & 0x7F
	case 0x0102:
		// Source Address
		m.cgpa, e = readAddress(r, l)
	case 0x0103:
		// Destination Address
		m.cdpa, e = readAddress(r, l)
	case 0x0116:
		// Sequence Control
		m.sequenceCtrl, e = readUint32(r, l)
	// case 0x0101:
	//	// SS7 Hop Count (Optional)
	//	m.hopCount, e = readUint8(r, l)
	// case 0x0113:
	//	// Importance (Optional)
	//	var tmp uint8
	//	if tmp, e = readUint8(r, l); e == nil {
	//		m.importance = &tmp
	//	}
	// case 0x0114:
	//	// Message Priority (Optional)
	//	var tmp uint8
	//	if tmp, e = readUint8(r, l); e == nil {
	//		m.priority = &tmp
	//	}
	case 0x010B:
		m.data, e = readData(r, l)
	default:
		_, e = r.Seek(int64(l), io.SeekCurrent)
	}
	return
}

/*
TxCLDR is Connectionless Data Response message. (Message type = 0x02)

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
	|              Reserved                         | SS7 Hop Count |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Tag = 0x0113          |             Length            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                Reserved                       |   Importance  |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Tag = 0x0114          |             Length            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|              Reserved                         |  Msg Priority |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Tag = 0x0013          |             Length            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                         Correlation ID                        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Tag = 0x0117          |            Length             |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	| first/remain  |             Segmentation Reference            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Tag = 0x010b          |             Length            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	/                             Data                              /
	\                                                               \
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type CLDR struct {
	tx bool

	ctx   []uint32
	cause uint32
	cgpa  SCCPAddress
	cdpa  SCCPAddress

	// hopCount   uint8
	// importance *uint8
	// priority   *uint8
	// correlation *uint32

	// first      bool
	// remain     uint8
	// segmentRef *uint32

	data []byte
}

func (m *CLDR) handleMessage() {
	if m.tx {
		m.handleMessageTx()
	} else {
		m.handleMessageRx()
	}
}

func (m *CLDR) handleMessageTx() {
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

	sctp.Write(buf.Bytes())
}

func (m *CLDR) handleMessageRx()         {}
func (m *CLDR) handleResult(msg message) {}
func (m *CLDR) marshal() (uint8, uint8, []byte) {
	buf := new(bytes.Buffer)

	// Routing Context
	writeRoutingContext(buf, m.ctx)

	// SCCP Cause
	writeUint32(buf, 0x0106, m.cause)

	// Source Address
	m.cgpa.marshal(buf, 0x0102)

	// Destination Address
	m.cdpa.marshal(buf, 0x0103)

	// SS7 Hop Count (Optional)
	// if m.hopCount != 0 {
	// 	writeUint8(buf, 0x0101, m.hopCount)
	// }

	// Importance (Optional)
	// if m.importance != nil {
	// 	writeUint8(buf, 0x0113, *m.importance)
	// }

	// Message Priority (Optional)
	// if m.priority != nil {
	//	writeUint8(buf, 0x0114, *m.priority)
	// }

	// Correlation ID (Optional)
	// if m.correlation != nil {
	//	writeUint32(buf, 0x0013, *m.correlation)
	// }

	// Segmentation (Optional)
	// if m.segmentRef != nil {
	//	var v uint32
	//	if m.first {
	//		v |= 0x80000000
	//	}
	//	v |= uint32(m.remain) << 32
	//	v |= *m.segmentRef
	//	writeUint32(buf, 0x0117, v)
	// }

	// Data
	if len(m.data) != 0 {
		writeData(buf, m.data)
	}
	return 0x07, 0x02, buf.Bytes()
}

func (m *CLDR) unmarshal(t, l uint16, r io.ReadSeeker) (e error) {
	switch t {
	case 0x0006:
		// Routing Context
		m.ctx, e = readRoutingContext(r, l)
	case 0x0106:
		// Sequence Control
		m.cause, e = readUint32(r, l)
	case 0x0102:
		// Source Address
		m.cgpa, e = readAddress(r, l)
	case 0x0103:
		// Destination Address
		m.cdpa, e = readAddress(r, l)
		// case 0x0101:
		//	// SS7 Hop Count (Optional)
		//	m.hopCount, e = readUint8(r, l)
		// case 0x0113:
		//	// Importance (Optional)
		//	var tmp uint8
		//	if tmp, e = readUint8(r, l); e == nil {
		//		m.importance = &tmp
		//	}
		// case 0x0114:
		//	// Message Priority (Optional)
		//	var tmp uint8
		//	if tmp, e = readUint8(r, l); e == nil {
		//		m.priority = &tmp
		//	}
	case 0x010B:
		m.data, e = readData(r, l)
	default:
		_, e = r.Seek(int64(l), io.SeekCurrent)
	}
	return
}

/*
SCCPAddress is address of SCCP

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|      Routing Indicator        |       Address Indicator       |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	/                       Address parameter(s)                    /
	\                                                               \
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Global Title

	0                 1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Tag = 0x8001          |            Length             |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                Reserved                       |      GTI      |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|   No. Digits  | Trans. type   |    Num. Plan  | Nature of Add |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|2 addr.|1 addr.|4 addr.|3 addr.|6 addr.|5 addr.|8 addr.|7 addr.|
	|  sig. | sig.  |  sig. | sig.  |  sig. | sig.  |  sig. | sig.  |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|        .............          |filler |N addr.|   filler      |
	|                               |if req | sig.  |               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Point Code

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Tag = 0x8002          |            Length = 8         |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                            Point Code                         |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Subsystem Number

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Tag = 0x8003          |            Length = 8         |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                 Reserved                      |   SSN value   |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type SCCPAddress struct {
	// RoutingIndicator
	// ai uint16

	// GlobalTitleIndicator
	TranslationType uint8
	NumberingPlan
	NatureOfAddress
	GlobalTitle string

	PointCode       uint32
	SubsystemNumber uint8
}

type NumberingPlan uint8

const (
	NPI_Unknown NumberingPlan = 0
	NPI_E164    NumberingPlan = 1
	NPI_Generic NumberingPlan = 2
	NPI_X121    NumberingPlan = 3
	NPI_F69     NumberingPlan = 4
	NPI_E211    NumberingPlan = 5
	NPI_E212    NumberingPlan = 6
	NPI_E214    NumberingPlan = 7
	NPI_Private NumberingPlan = 14
)

type NatureOfAddress uint8

const (
	NAI_Unknown             NatureOfAddress = 0
	NAI_Subscriber          NatureOfAddress = 1
	NAI_NationalUse         NatureOfAddress = 2
	NAI_NationalSignificant NatureOfAddress = 3
	NAI_International       NatureOfAddress = 4
)

func (a *SCCPAddress) marshal(w io.Writer, id uint16) {
	buf := new(bytes.Buffer)

	var ai uint16
	if len(a.GlobalTitle) != 0 {
		l := len(a.GlobalTitle)
		l = (l + (l % 2)) / 2
		if l%4 != 0 {
			l += 4 - l%4
		}
		l += 12

		var gti uint32
		if a.TranslationType == 0 &&
			a.NumberingPlan == NPI_Unknown {
			gti = 1 // NAI only
		} else if a.NatureOfAddress == NAI_Unknown &&
			a.NumberingPlan == NPI_Unknown {
			gti = 2 // TT only
		} else if a.NatureOfAddress == NAI_Unknown {
			gti = 3 // TT and NPI
		} else {
			gti = 4 // TT, NPI and NAI
		}

		binary.Write(buf, binary.BigEndian, uint16(0x8001))
		binary.Write(buf, binary.BigEndian, uint16(l))
		binary.Write(buf, binary.BigEndian, gti)
		buf.WriteByte(uint8(len(a.GlobalTitle)))
		buf.WriteByte(a.TranslationType)
		buf.WriteByte(byte(a.NumberingPlan))
		buf.WriteByte(byte(a.NatureOfAddress))

		l = len(a.GlobalTitle)
		for i := 0; i < l; i++ {
			var b byte
			d, e := strconv.Atoi(string(a.GlobalTitle[i]))
			if e != nil {
				d = 0
			}
			b = byte(d)
			i++
			if i < l {
				d, e = strconv.Atoi(string(a.GlobalTitle[i]))
				if e != nil {
					d = 0
				}
				b |= byte(d << 4)
			}
			buf.WriteByte(b)
		}
		if l%8 != 0 {
			l = 8 - l%8
			l = (l - (l % 2)) / 2
			buf.Write(make([]byte, l))
		}
		ai |= 0x04
	}
	if a.PointCode != 0 {
		writeUint32(buf, 0x8002, a.PointCode)
		ai |= 0x02
	}
	if a.SubsystemNumber != 0 {
		writeUint8(buf, 0x8003, a.SubsystemNumber)
		ai |= 0x01
	}

	var ri uint16 = 1 // Rout on GT
	if a.PointCode != 0 && a.SubsystemNumber != 0 {
		ri = 2 // Route on PC+SSN
	}

	binary.Write(w, binary.BigEndian, id)
	binary.Write(w, binary.BigEndian, uint16(8+buf.Len()))
	binary.Write(w, binary.BigEndian, ri)
	binary.Write(w, binary.BigEndian, ai)
	buf.WriteTo(w)
}

func readAddress(r io.ReadSeeker, l uint16) (a SCCPAddress, e error) {
	if l%4 != 0 {
		e = errors.New("invalid lenght of parameter")
		return
	}
	var ri, ai uint16
	if e = binary.Read(r, binary.BigEndian, &ri); e != nil {
		return
	}
	if e = binary.Read(r, binary.BigEndian, &ai); e != nil {
		return
	}

	buf := make([]byte, l-4)
	if _, e = r.Read(buf); e != nil {
		return
	}
	rr := bytes.NewReader(buf)
	for rr.Len() > 4 {
		var t, l uint16
		if e = binary.Read(rr, binary.BigEndian, &t); e != nil {
			break
		}
		if e = binary.Read(rr, binary.BigEndian, &l); e != nil {
			break
		}
		l -= 4

		switch t {
		case 0x8001:
			// GT
			if l < 8 {
				e = errors.New("invalid lenght of parameter")
				break
			}
			gthdr := make([]byte, 8)
			if _, e = rr.Read(gthdr); e != nil {
				break
			}
			// gti = gthdr[3]
			a.TranslationType = gthdr[5]
			a.NumberingPlan = NumberingPlan(gthdr[6])
			a.NatureOfAddress = NatureOfAddress(gthdr[7])

			buf = make([]byte, l-8)
			if _, e = rr.Read(buf); e != nil {
				break
			}
			for i := 0; i < int(gthdr[4]); i++ {
				g := buf[(i-(i%2))/2]
				if i%2 == 0 {
					a.GlobalTitle += strconv.Itoa(int(g & 0x0F))
				} else {
					a.GlobalTitle += strconv.Itoa(int(g & 0xF0 >> 4))
				}
			}
		case 0x8002:
			// PC
			a.PointCode, e = readUint32(rr, l)
		case 0x8003:
			// SSN
			a.SubsystemNumber, e = readUint8(rr, l)
		default:
			_, e = r.Seek(int64(l), io.SeekCurrent)
		}
		if e != nil {
			break
		}
	}

	return
}
