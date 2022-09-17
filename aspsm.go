package xua

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

/*
ASPSM: ASP State Maintenance Messages
Message class = 0x03
*/

/*
ASPUP is ASP Up message. (Message type = 0x01)

	 0                     1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|            Tag = 0x0011       |             Length            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                        ASP Identifier                         |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|            Tag = 0x0004       |             Length            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	/                          Info String                          /
	\                                                               \
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type ASPUP struct {
	// id *uint32
	// info   string
	result chan error
}

func (m *ASPUP) handleMessage() {
	fmt.Println("handle ASPUP")
	if e := writeHandler(m); e != nil {
		m.result <- e
	}
}

func (m *ASPUP) handleResult(msg message) {
	switch res := msg.(type) {
	case *ERR:
		m.result <- fmt.Errorf("error with code %d", res.code)
	case *ASPUPAck:
		m.result <- nil
	default:
		m.result <- fmt.Errorf("unexpected result")
	}
}

func (m *ASPUP) marshal() (uint8, uint8, []byte) {
	buf := new(bytes.Buffer)

	// ASP Identifier (Optional)
	// if m.id != nil {
	//	writeUint32(buf, 0x0011, *m.id)
	// }

	// Info String (Optioal)
	// if len(m.info) != 0 {
	// 	writeInfo(buf, m.info)
	// }
	return 0x03, 0x01, buf.Bytes()
}

func (m *ASPUP) unmarshal(t, l uint16, r io.ReadSeeker) (e error) {
	return
}

/*
ASPDN is ASP Down message. (Message type = 0x02)

	 0                     1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|           Tag = 0x0004        |             Length            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	/                          Info String                          /
	\                                                               \
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type ASPDN struct {
	// info   string
	result chan error
}

func (m *ASPDN) handleMessage() {
	if e := writeHandler(m); e != nil {
		m.result <- e
	}
}

func (m *ASPDN) handleResult(msg message) {
	switch res := msg.(type) {
	case *ERR:
		m.result <- fmt.Errorf("error with code %d", res.code)
	case *ASPDNAck:
		m.result <- nil
	default:
		m.result <- fmt.Errorf("unexpected result")
	}
}

func (m *ASPDN) marshal() (uint8, uint8, []byte) {
	// Info String (Optioal)
	// if len(m.info) != 0 {
	// 	writeInfo(buf, m.info)
	// }
	return 0x03, 0x02, []byte{}
}
func (m *ASPDN) unmarshal(t, l uint16, r io.ReadSeeker) (e error) {
	return
}

/*
BEAT is Heartbeat message. (Message type = 0x03)

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|           Tag = 0x0009        |             Length            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	/                       Heartbeat Data                          /
	\                                                               \
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type BEAT struct {
	tx   bool
	data []byte
}

func (m *BEAT) handleMessage()           {}
func (m *BEAT) handleResult(msg message) {}

func (m *BEAT) marshal() (uint8, uint8, []byte) {
	buf := new(bytes.Buffer)

	// Heartbeat Data (Optional)
	binary.Write(buf, binary.BigEndian, uint16(0x0009))
	binary.Write(buf, binary.BigEndian, uint16(4+len(m.data)))
	buf.Write(m.data)
	if len(m.data)%4 != 0 {
		buf.Write(make([]byte, 4-len(m.data)%4))
	}
	return 0x03, 0x03, buf.Bytes()
}

func (m *BEAT) unmarshal(t, l uint16, r io.ReadSeeker) (e error) {
	switch t {
	case 0x0009:
		// Heartbeat Data (Optional)
		m.data = make([]byte, l)
		_, e = r.Read(m.data)
		if e == nil && l%4 != 0 {
			_, e = r.Seek(int64(4-l%4), io.SeekCurrent)
		}
	default:
		_, e = r.Seek(int64(l), io.SeekCurrent)
	}
	return
}

/*
ASPUPAck is ASP Up Ack message. (Message type = 0x04)

	 0                     1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|            Tag = 0x0004       |             Length            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	/                          Info String                          /
	\                                                               \
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type ASPUPAck struct {
	// info   string
}

func (m *ASPUPAck) handleMessage() {
	if requestStack != nil {
		requestStack.handleResult(m)
		requestStack = nil
	}
}
func (m *ASPUPAck) handleResult(msg message) {}

func (m *ASPUPAck) marshal() (uint8, uint8, []byte) {
	return 0x03, 0x04, nil
}

func (m *ASPUPAck) unmarshal(t, l uint16, r io.ReadSeeker) (e error) {
	// switch t {
	// case 0x0004:
	// Info String (Optional)
	// 	m.info, e = readInfo(r, l)
	// default:
	_, e = r.Seek(int64(l), io.SeekCurrent)
	// }
	return
}

/*
ASPDNAck is ASP Down Ack message. (Message type = 0x05)

	 0                     1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|           Tag = 0x0004        |             Length            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	/                          Info String                          /
	\                                                               \
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type ASPDNAck struct {
	// info   string
}

func (m *ASPDNAck) handleMessage() {
	if requestStack != nil {
		requestStack.handleResult(m)
		requestStack = nil
	}
}

func (m *ASPDNAck) handleResult(msg message) {}

func (m *ASPDNAck) marshal() (uint8, uint8, []byte) {
	return 0x03, 0x05, nil
}

func (m *ASPDNAck) unmarshal(t, l uint16, r io.ReadSeeker) (e error) {
	// switch t {
	// case 0x0004:
	// Info String (Optional)
	// 	m.info, e = readInfo(r, l)
	// default:
	_, e = r.Seek(int64(l), io.SeekCurrent)
	// }
	return
}

/*
BEATAck is Heartbeat Ack message. (Message type = 0x06)

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|           Tag = 0x0009        |             Length            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	/                       Heartbeat Data                          /
	\                                                               \
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type BEATAck struct {
	tx   bool
	data []byte
}

func (m *BEATAck) handleMessage()           {}
func (m *BEATAck) handleResult(msg message) {}

func (m *BEATAck) marshal() (uint8, uint8, []byte) {
	buf := new(bytes.Buffer)

	// Heartbeat Data (Optional)
	binary.Write(buf, binary.BigEndian, uint16(0x0009))
	binary.Write(buf, binary.BigEndian, uint16(4+len(m.data)))
	buf.Write(m.data)
	if len(m.data)%4 != 0 {
		buf.Write(make([]byte, 4-len(m.data)%4))
	}
	return 0x03, 0x06, buf.Bytes()
}

func (m *BEATAck) unmarshal(t, l uint16, r io.ReadSeeker) (e error) {
	switch t {
	case 0x0009:
		// Heartbeat Data (Optional)
		m.data = make([]byte, l)
		_, e = r.Read(m.data)
		if e == nil && l%4 != 0 {
			_, e = r.Seek(int64(4-l%4), io.SeekCurrent)
		}
	default:
		_, e = r.Seek(int64(l), io.SeekCurrent)
	}
	return
}
