package xua

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
)

/*
func writeInfo(w io.Writer, info string) {
	d := []byte(info)
	if len(d) > 248 {
		d = d[:248]
	}
	binary.Write(w, binary.BigEndian, uint16(0x0004))
	binary.Write(w, binary.BigEndian, uint16(4+len(d)))
	w.Write(d)
	if len(d)%4 != 0 {
		w.Write(make([]byte, 4-len(d)%4))
	}
}

func readInfo(r io.ReadSeeker, l uint16) (v string, e error) {
	d := make([]byte, l)
	_, e = r.Read(d)
	if e == nil && l%4 != 0 {
		_, e = r.Seek(int64(4-l%4), io.SeekCurrent)
	}
	v = string(d)
	return
}
*/

func writeRoutingContext(w io.Writer, cx []uint32) {
	binary.Write(w, binary.BigEndian, uint16(0x0006))
	binary.Write(w, binary.BigEndian, uint16(4+len(cx)*4))
	for _, c := range cx {
		binary.Write(w, binary.BigEndian, c)
	}
}

func readRoutingContext(r io.ReadSeeker, l uint16) (v []uint32, e error) {
	if l%4 != 0 {
		e = errors.New("invalid lenght of parameter")
	} else {
		v = make([]uint32, l/4)
		for i := range v {
			if e = binary.Read(r, binary.BigEndian, &(v[i])); e != nil {
				return
			}
		}
	}
	return
}

type PointCode struct {
	mask byte
	pc   uint32
}

func writeAPC(w io.Writer, v []PointCode) {
	binary.Write(w, binary.BigEndian, uint16(0x0012))
	binary.Write(w, binary.BigEndian, uint16(4+4*len(v)))
	for _, a := range v {
		w.Write([]byte{a.mask, byte(a.pc >> 16), byte(a.pc >> 8), byte(a.pc)})
	}
}

func readAPC(r io.ReadSeeker, l uint16) (v []PointCode, e error) {
	if l%4 != 0 {
		e = errors.New("invalid lenght of parameter")
	} else {
		v = make([]PointCode, l/4)
		for i := range v {
			if e = binary.Read(r, binary.BigEndian, &(v[i].pc)); e != nil {
				break
			}
			v[i].mask = byte(v[i].pc >> 24)
			v[i].pc = v[i].pc & 0x0fff
		}
	}
	return
}

func writeUint32(w io.Writer, t uint16, v uint32) {
	binary.Write(w, binary.BigEndian, t)
	binary.Write(w, binary.BigEndian, uint16(8))
	binary.Write(w, binary.BigEndian, v)
}

func readUint32(r io.ReadSeeker, l uint16) (v uint32, e error) {
	if l != 4 {
		e = errors.New("invalid lenght of parameter")
	} else {
		e = binary.Read(r, binary.BigEndian, &v)
	}
	return
}

func writeUint8(w io.Writer, t uint16, v uint8) {
	binary.Write(w, binary.BigEndian, t)
	binary.Write(w, binary.BigEndian, uint16(8))
	binary.Write(w, binary.BigEndian, uint32(v))
}

func readUint8(r io.ReadSeeker, l uint16) (v uint8, e error) {
	if l != 4 {
		e = errors.New("invalid lenght of parameter")
	} else if _, e = r.Seek(3, io.SeekCurrent); e != nil {
		e = binary.Read(r, binary.BigEndian, &v)
	}
	return
}

func writeData(w io.Writer, d []byte) {
	binary.Write(w, binary.BigEndian, uint16(0x010B))
	binary.Write(w, binary.BigEndian, uint16(4+len(d)))
	w.Write(d)
	if len(d)%4 != 0 {
		w.Write(make([]byte, 4-len(d)%4))
	}
}

func readData(r io.ReadSeeker, l uint16) (d []byte, e error) {
	d = make([]byte, l)
	_, e = r.Read(d)
	return
}

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

func readAddress(r io.ReadSeeker, l uint16) (a address, e error) {
	if l%4 != 0 {
		e = errors.New("invalid lenght of parameter")
		return
	}
	if e = binary.Read(r, binary.BigEndian, &a.ri); e != nil {
		return
	}
	if e = binary.Read(r, binary.BigEndian, &a.ai); e != nil {
		return
	}

	buf := make([]byte, l-4)
	if _, e = r.Read(buf); e != nil {
		return
	}
	rr := bytes.NewReader(buf)
	for rr.Len() > 8 {
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
			a.gti = gthdr[3]
			a.tt = gthdr[5]
			a.npi = gthdr[6]
			a.nai = gthdr[7]

			buf = make([]byte, l-8)
			for i := 0; i < int(gthdr[4]); i++ {
				g := buf[(i-(i%2))/2]
				if i%2 == 0 {
					a.gt = a.gt + strconv.Itoa(int(g&0x0F))
				} else {
					a.gt = a.gt + strconv.Itoa(int(g&0xF0>>4))
				}
			}
		case 0x8002:
			// PC
			a.pc, e = readUint32(rr, l)
		case 0x8003:
			// SSN
			a.ssn, e = readUint8(rr, l)
		default:
			_, e = r.Seek(int64(l), io.SeekCurrent)
		}
		if e != nil {
			break
		}
	}

	return
}
