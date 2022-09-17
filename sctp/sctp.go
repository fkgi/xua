package sctp

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"syscall"
)

var (
	// LocalAddr is SCTP local address
	LocalAddr *SCTPAddr
	// PeerAddr is SCTP peer address
	PeerAddr *SCTPAddr

	// ProtocolID of data layer
	ProtocolID uint32 = 67108864

	sock    int
	assocID assocT

	TTL uint32 = 0
)

type sndrcvInfo struct {
	stream     uint16
	ssn        uint16
	flags      uint16
	ppid       uint32
	context    uint32
	timetolive uint32
	tsn        uint32
	cumtsn     uint32
	assocID    assocT
}

func Serve(handleData func([]byte), handleUp, handleDown func()) (e error) {
	// create SCTP connection socket
	if LocalAddr.IP[0].To4() != nil && PeerAddr.IP[0].To4() != nil {
		sock, e = sockOpenV4()
	} else if LocalAddr.IP[0].To16() != nil && PeerAddr.IP[0].To16() != nil {
		sock, e = sockOpenV6()
	} else {
		e = &net.AddrError{
			Err:  "unknown address format",
			Addr: LocalAddr.String()}
	}
	if e != nil {
		e = &net.OpError{
			Op: "makesock", Net: "sctp",
			Addr: LocalAddr, Err: e}
		return
	}

	// set notifycation enabled
	e = setNotify(sock)
	if e != nil {
		sockClose(sock)
		e = &net.OpError{
			Op: "setsockopt", Net: "sctp",
			Addr: LocalAddr, Err: e}
		return
	}

	// bind SCTP connection to LocalAddr
	ptr, n := LocalAddr.rawAddr()
	if e = sctpBindx(sock, ptr, n); e != nil {
		sockClose(sock)
		e = &net.OpError{
			Op: "bind", Net: "sctp",
			Addr: LocalAddr, Err: e}
		return
	}

	// connect SCTP connection to PeerAddr
	ptr, n = PeerAddr.rawAddr()
	if assocID, e = sctpConnectx(sock, ptr, n); e != nil {
		sockClose(sock)
		e = &net.OpError{
			Op: "connect", Net: "sctp",
			Source: LocalAddr, Addr: PeerAddr, Err: e}
		return
	}

	// receive message
	buf := make([]byte, 1500)
	info := sndrcvInfo{}
	flag := 0

	for {
		n, e = sctpRecvmsg(sock, buf, &info, &flag)
		if e != nil {
			if eno, ok := e.(*syscall.Errno); ok && eno.Temporary() {
				continue
			} else {
				break
			}
		}

		if flag&msgNotification != msgNotification {
			handleData(buf[:n])
			continue
		}

		r := bytes.NewReader(buf[:n])
		var chtype uint16
		if e = binary.Read(r, binary.LittleEndian, &chtype); e != nil {
			continue
		}
		if chtype != sctpAssocChange {
			continue
		}

		if _, e = r.Seek(int64(6), io.SeekCurrent); e != nil {
			continue
		}
		/*
			var flags uint16
			if e := binary.Read(r, binary.LittleEndian, &flags); e != nil {
				continue
			}
			var length uint32
			if e := binary.Read(r, binary.LittleEndian, &length); e != nil {
				continue
			}
			/*
				ToDo: length check
		*/
		var state uint16
		if e = binary.Read(r, binary.LittleEndian, &state); e != nil {
			continue
		}
		if _, e = r.Seek(int64(6), io.SeekCurrent); e != nil {
			continue
		}
		/*
			var sacError uint16
			if e := binary.Read(r, binary.LittleEndian, &sacError); e != nil {
				return
			}
			var outboundStreams uint16
			if e := binary.Read(r, binary.LittleEndian, &outboundStreams); e != nil {
				return
			}
			var inboundStreams uint16
			if e := binary.Read(r, binary.LittleEndian, &inboundStreams); e != nil {
				return
			}
		*/
		var id assocT
		if e = binary.Read(r, binary.LittleEndian, &id); e != nil {
			continue
		}
		if id != assocID {
			continue
		}

		switch state {
		case sctpCommUp:
			go handleUp()
		case sctpCommLost, sctpShutdownComp:
			go handleDown()
			// case sctpRestart:
			// case sctpCantStrAssoc:
		}
	}

	sockClose(sock)
	return
}

func Write(b []byte) (e error) {
	buf := make([]byte, len(b))
	copy(buf, b)

	info := sndrcvInfo{
		timetolive: TTL,
		stream:     0,
		flags:      0,
		assocID:    assocID,
		ppid:       ProtocolID}
	if _, e = sctpSend(sock, buf, &info, 0); e != nil {
		e = &net.OpError{
			Op: "write", Net: "sctp",
			Source: LocalAddr, Addr: PeerAddr, Err: e}
	}
	return
}

// Close closes the connection.
func Close() (e error) {
	info := sndrcvInfo{
		timetolive: TTL,
		stream:     0,
		flags:      sctpEoF,
		assocID:    assocID,
		ppid:       0}
	if _, e = sctpSend(sock, []byte{}, &info, 0); e != nil {
		e = &net.OpError{
			Op: "close", Net: "sctp",
			Source: LocalAddr, Addr: PeerAddr, Err: e}
	}
	return e
}

// Abort closes the connection with abort message.
func Abort(reason string) (e error) {
	buf := make([]byte, len([]byte(reason)))
	copy(buf, []byte(reason))
	info := sndrcvInfo{
		timetolive: TTL,
		stream:     0,
		flags:      sctpAbort,
		assocID:    assocID,
		ppid:       0}
	if _, e = sctpSend(sock, buf, &info, 0); e != nil {
		e = &net.OpError{
			Op: "abort", Net: "sctp",
			Source: LocalAddr, Addr: PeerAddr, Err: e}
	}
	return
}
