package xua

import (
	"bytes"
	"encoding/binary"
	"io"
	"strconv"
)

/*
CL: SCCP Connectionless (CL) Messages
Message class = 0x07
*/

/*
address of SCCP

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
	/                         Global Title Digits                   /
	\                                                               \
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type address struct {
	ri uint16
	ai uint16

	gti uint8
	tt  uint8
	npi uint8
	nai uint8
	gt  string

	pc  uint32
	ssn uint8
}

func (a *address) marshal(w io.Writer, id uint16) {
	buf := new(bytes.Buffer)

	if len(a.gt) != 0 {
		l := len(a.gt)
		if l%8 != 0 {
			l += 8 - l%8
		}
		l += 12
		binary.Write(buf, binary.BigEndian, uint16(0x8001))
		binary.Write(buf, binary.BigEndian, uint16(l))
		binary.Write(buf, binary.BigEndian, uint32(a.gti))
		buf.WriteByte(uint8(len(a.gt)))
		buf.WriteByte(a.tt)
		buf.WriteByte(a.npi)
		buf.WriteByte(a.nai)

		l = len(a.gt)
		for i := 0; i < l; i++ {
			var b byte
			d, e := strconv.Atoi(string(a.gt[i]))
			if e != nil {
				d = 0
			}
			b = byte(d)
			i++
			if i < l {
				d, e = strconv.Atoi(string(a.gt[i]))
				if e != nil {
					d = 0
				}
				b |= byte(d << 4)
			}
			buf.WriteByte(b)
		}
		if l%8 != 0 {
			buf.Write(make([]byte, 8-l%8))
		}
	}
	if a.pc != 0 {
		writeUint32(buf, 0x8002, a.pc)
	}
	if a.ssn != 0 {
		writeUint8(buf, 0x8003, a.ssn)
	}

	binary.Write(w, binary.BigEndian, id)
	binary.Write(w, binary.BigEndian, uint16(8+buf.Len()))
	binary.Write(w, binary.BigEndian, a.ri)
	binary.Write(w, binary.BigEndian, a.ai)
	buf.WriteTo(w)
}

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
	cgpa          address
	cdpa          address
	sequenceCtrl  uint32

	hopCount   uint8
	importance *uint8
	priority   *uint8
	// correlation *uint32

	// first      bool
	// remain     uint8
	// segmentRef *uint32

	data []byte
}

func (m *CLDT) handleMessage() {
}

func (m *CLDT) handleResult(msg message) {
}

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
	m.cgpa.marshal(buf, 0x0103)

	// Sequence Control
	if m.sequenceCtrl != 0 {
		writeUint32(buf, 0x0116, m.sequenceCtrl)
	}

	// SS7 Hop Count (Optional)
	if m.hopCount != 0 {
		writeUint8(buf, 0x0101, m.hopCount)
	}

	// Importance (Optional)
	if m.importance != nil {
		writeUint8(buf, 0x0113, *m.importance)
	}

	// Message Priority (Optional)
	if m.priority != nil {
		writeUint8(buf, 0x0114, *m.priority)
	}

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

	return 0x07, 0x01, buf.Bytes()
}

func (m *CLDT) unmarshal(t, l uint16, r io.ReadSeeker) (e error) {
	switch t {
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
type CLDR struct {
	tx bool

	ctx   []uint32
	cause uint32
	cgpa  address
	cdpa  address

	hopCount   uint8
	importance *uint8
	priority   *uint8
	// correlation *uint32

	// first      bool
	// remain     uint8
	// segmentRef *uint32

	data []byte
}

func (m *CLDR) handleMessage() {
}
func (m *CLDR) handleResult(msg message) {
}
func (m *CLDR) marshal() (uint8, uint8, []byte) {
	buf := new(bytes.Buffer)
	return 0x07, 0x02, buf.Bytes()
}

func (m *CLDR) unmarshal(t, l uint16, r io.ReadSeeker) (e error) {
	switch t {
	default:
		_, e = r.Seek(int64(l), io.SeekCurrent)
	}
	return
}
