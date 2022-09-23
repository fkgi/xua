package xua

import (
	"bytes"
	"io"
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
	cgpa          address
	cdpa          address
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

func (m *CLDT) handleMessage() {}

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
	cgpa  address
	cdpa  address

	// hopCount   uint8
	// importance *uint8
	// priority   *uint8
	// correlation *uint32

	// first      bool
	// remain     uint8
	// segmentRef *uint32

	data []byte
}

func (m *CLDR) handleMessage()           {}
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
	writeData(buf, m.data)

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
