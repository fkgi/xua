package sctp

/*
#cgo CFLAGS: -Wall
#cgo LDFLAGS: -lsctp

#include <netinet/sctp.h>
*/
import "C"

import (
	"syscall"
	"unsafe"
)

const (
	sctpEoF       = C.SCTP_EOF
	sctpAbort     = C.SCTP_ABORT
	sctpUnordered = C.SCTP_UNORDERED
	sctpAddrOver  = C.SCTP_ADDR_OVER

	// SCTP_SENDALL = C.SCTP_SENDALL
	// SCTP_EOR = C.SCTP_EOR

	//SCTP_SACK_IMMEDIATELY = C.SCTP_SACK_IMMEDIATELY

	// SOL_SCTP    = C.SOL_SCTP
	// SCTP_EVENTS = C.SCTP_EVENTS

	msgNotification              = C.MSG_NOTIFICATION
	sctpDataIO                   = C.SCTP_DATA_IO_EVENT
	sctpAssocChange              = C.SCTP_ASSOC_CHANGE
	sctpPeerAddrChange           = C.SCTP_PEER_ADDR_CHANGE
	sctpSendFailed               = C.SCTP_SEND_FAILED
	sctpRemoteError              = C.SCTP_REMOTE_ERROR
	sctpShutdownEvent            = C.SCTP_SHUTDOWN_EVENT
	sctpPartialDeliveryEvent     = C.SCTP_PARTIAL_DELIVERY_EVENT
	sctpAdaptationIndication     = C.SCTP_ADAPTATION_INDICATION
	sctpAuthenticationIndication = C.SCTP_AUTHENTICATION_INDICATION
	sctpSenderDryEvent           = C.SCTP_SENDER_DRY_EVENT
	sctpStreamResetEvent         = C.SCTP_STREAM_RESET_EVENT
	sctpAssocResetEvent          = C.SCTP_ASSOC_RESET_EVENT
	sctpStreamChangeEvent        = C.SCTP_STREAM_CHANGE_EVENT

	sctpCommUp       = C.SCTP_COMM_UP
	sctpCommLost     = C.SCTP_COMM_LOST
	sctpRestart      = C.SCTP_RESTART
	sctpShutdownComp = C.SCTP_SHUTDOWN_COMP
	sctpCantStrAssoc = C.SCTP_CANT_STR_ASSOC
)

type assocT C.sctp_assoc_t

func setNotify(fd int) error {
	type opt struct {
		dataIo          uint8
		association     uint8
		address         uint8
		sendFailed      uint8
		peerError       uint8
		shutdown        uint8
		partialDelivery uint8
		adaptationLayer uint8
		authentication  uint8
		senderDry       uint8
	}

	event := opt{
		dataIo:          1,
		association:     1,
		address:         0,
		sendFailed:      0,
		peerError:       0,
		shutdown:        0,
		partialDelivery: 0,
		adaptationLayer: 0,
		authentication:  0,
		senderDry:       0}
	l := unsafe.Sizeof(event)
	p := unsafe.Pointer(&event)

	return setSockOpt(fd, C.SCTP_EVENTS, p, l)
}

func setSockOpt(fd, opt int, p unsafe.Pointer, l uintptr) error {
	n, e := C.setsockopt(
		C.int(fd),
		C.SOL_SCTP,
		C.int(opt),
		p,
		C.socklen_t(l))
	if int(n) < 0 {
		return e
	}
	return nil
}

func sockOpenV4() (int, error) {
	return syscall.Socket(
		syscall.AF_INET,
		syscall.SOCK_SEQPACKET,
		syscall.IPPROTO_SCTP)
}

func sockOpenV6() (int, error) {
	return syscall.Socket(
		syscall.AF_INET6,
		syscall.SOCK_SEQPACKET,
		syscall.IPPROTO_SCTP)
}

func sockClose(fd int) error {
	return syscall.Close(fd)
}

func sctpBindx(fd int, ptr unsafe.Pointer, l int) error {
	n, e := C.sctp_bindx(
		C.int(fd),
		(*C.struct_sockaddr)(ptr),
		C.int(l),
		C.SCTP_BINDX_ADD_ADDR)
	if int(n) < 0 {
		return e
	}
	return nil
}

func sctpConnectx(fd int, ptr unsafe.Pointer, l int) (assocT, error) {
	t := assocT(0)
	n, e := C.sctp_connectx(
		C.int(fd),
		(*C.struct_sockaddr)(ptr),
		C.int(l),
		(*C.sctp_assoc_t)(unsafe.Pointer(&t)))
	if int(n) < 0 {
		return t, e
	}
	return t, nil
}

func sctpSend(fd int, b []byte, info *sndrcvInfo, flag int) (int, error) {
	buf := unsafe.Pointer(nil)
	if len(b) > 0 {
		buf = unsafe.Pointer(&b[0])
	}
	n, e := C.sctp_send(
		C.int(fd),
		buf,
		C.size_t(len(b)),
		(*C.struct_sctp_sndrcvinfo)(unsafe.Pointer(info)),
		C.int(flag))
	if int(n) < 0 {
		return -1, e
	}
	return int(n), nil
}
func sctpRecvmsg(fd int, b []byte, info *sndrcvInfo, flag *int) (int, error) {
	n, e := C.sctp_recvmsg(
		C.int(fd),
		unsafe.Pointer(&b[0]),
		C.size_t(len(b)),
		nil,
		nil,
		(*C.struct_sctp_sndrcvinfo)(unsafe.Pointer(info)),
		(*C.int)(unsafe.Pointer(flag)))
	if int(n) < 0 {
		return -1, e
	}
	return int(n), nil
}
