package xua

import (
	"io"
	"net"
)

/*
MGMT: Management Messages
Message class = 0x00
*/

/*
ERR is Error message. (Message type = 0x00)
Direction is SGP -> ASP.

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|          Tag = 0x000C         |           Length = 8          |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                        * Error Code                           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Tag = 0x0006          |            Length             |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	/                       Routing Context                         /
	\                                                               \
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Tag = 0x0012          |            Length             |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|    Mask       |                 Affected PC 1                 |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	/                        Affected Point Code                    /
	\                                                               \
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Tag = 0x010D          |          Length = 8           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                     Network Appearance                        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|          Tag = 0x0007         |            Length             |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	/                        Diagnostic Info                        /
	\                                                               \
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type ERR struct {
	code uint32
	ctx  []uint32
	apc  []PointCode
	na   *uint32
	// info []byte
}

func (m *ERR) handleMessage(c net.Conn) {
	if requestStack != nil {
		requestStack.handleResult(m)
		requestStack = nil
	}
}
func (m *ERR) handleResult(msg message) {}

func (m *ERR) marshal() (uint8, uint8, []byte) {
	return 0x00, 0x00, nil
}

func (m *ERR) unmarshal(t, l uint16, r io.ReadSeeker) (e error) {
	switch t {
	case 0x000C:
		// Error Code
		m.code, e = readUint32(r, l)
	case 0x0006:
		// Routing Context (Optional)
		m.ctx, e = readRoutingContext(r, l)
	case 0x0012:
		// Affected Point Code (Optional)
		m.apc, e = readAPC(r, l)
	case 0x010D:
		// Network Appearance (Optional)
		*m.na, e = readUint32(r, l)
	// case 0x0007:
	// Diagnostic Info (Optional)
	//	m.info = make([]byte, l)
	//	_, e = r.Read(m.info)
	//	if e == nil && l%4 != 0 {
	//		_, e = r.Seek(int64(4-l%4), io.SeekCurrent)
	//	}
	default:
		_, e = r.Seek(int64(l), io.SeekCurrent)
	}
	return
}

/*
NTFY is Notify message. (Message type = 0x01)

	 0                     1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|          Tag = 0x000D         |            Length = 8         |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                         * Status                              |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|            Tag = 0x0011       |            Length = 8         |
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
type NTFY struct {
	status uint32
	// id     *uint32
	ctx []uint32
	// info    string
}

func (m *NTFY) handleMessage(c net.Conn) {}
func (m *NTFY) handleResult(msg message) {}

func (m *NTFY) marshal() (uint8, uint8, []byte) {
	return 0x00, 0x01, nil
}

func (m *NTFY) unmarshal(t, l uint16, r io.ReadSeeker) (e error) {
	//	b []byte) (e error) {
	switch t {
	case 0x000D:
		// Status
		m.status, e = readUint32(r, l)
	// case 0x0011:
	//	// ASP Identifier (Optional)
	//	*(m.id), e = readUint32(r, l)
	case 0x0006:
		// Routing Context (Optional)
		m.ctx, e = readRoutingContext(r, l)
	// case 0x0004:
	// Info String (Optional)
	// 	m.info, e = readInfo(r, l)
	default:
		_, e = r.Seek(int64(l), io.SeekCurrent)
	}
	return
}
