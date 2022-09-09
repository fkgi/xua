package sctp

import (
	"log"
	"syscall"
	"unsafe"
)

const (
	ipprotoSctp      = 0x84
	sctpBindxAddAddr = 0x00008001
	// sctpBindxRemAddr = 0x00008002

	sctpEoF       = 0x0100
	sctpAbort     = 0x0200
	sctpUnordered = 0x0400
	// SCTP_ADDR_OVER = 0x0800
	// SCTP_SENDALL = 0x1000
	// SCTP_EOR = 0x2000
	// SCTP_SACK_IMMEDIATELY = 0x4000

	msgNotification          = 0x1000
	sctpAssocChange          = 0x0001
	sctpPeerAddrChange       = 0x0002
	sctpRemoteError          = 0x0003
	sctpSendFailed           = 0x0004
	sctpShutdownEvent        = 0x0005
	sctpAdaptationIndication = 0x0006
	sctpPartialDeliveryEvent = 0x0007
	sctpSenderDryEvent       = 0x000a

	sctpCommUp       = 0x0001
	sctpCommLost     = 0x0002
	sctpRestart      = 0x0003
	sctpShutdownComp = 0x0004
	sctpCantStrAssoc = 0x0005
)

type assocT uint32

var (
	fsctpBindx    *syscall.Proc
	fsctpConnectx *syscall.Proc
	fsctpSend     *syscall.Proc
	fsctpRecvmsg  *syscall.Proc
	dll           *syscall.DLL
)

func init() {
	var d syscall.WSAData
	e := syscall.WSAStartup(uint32(0x202), &d)
	if e != nil {
		log.Fatal(e)
	}

	dll, e = syscall.LoadDLL("sctpsp.dll")
	if e != nil {
		log.Fatal(e)
	}
	// dll.Release()

	fsctpBindx, e = dll.FindProc("internal_sctp_bindx")
	if e != nil {
		log.Fatal(e)
	}
	fsctpConnectx, e = dll.FindProc("internal_sctp_connectx")
	if e != nil {
		log.Fatal(e)
	}
	fsctpSend, e = dll.FindProc("internal_sctp_send")
	if e != nil {
		log.Fatal(e)
	}
	fsctpRecvmsg, e = dll.FindProc("internal_sctp_recvmsg")
	if e != nil {
		log.Fatal(e)
	}
}

func sockOpenV4() (int, error) {
	sock, e := syscall.Socket(
		syscall.AF_INET,
		syscall.SOCK_SEQPACKET,
		ipprotoSctp)
	return int(sock), e
}

func sockOpenV6() (int, error) {
	sock, e := syscall.Socket(
		syscall.AF_INET6,
		syscall.SOCK_SEQPACKET,
		ipprotoSctp)
	return int(sock), e
}

func sockClose(fd int) error {
	e1 := syscall.Shutdown(syscall.Handle(fd), syscall.SHUT_RD)
	e2 := syscall.Closesocket(syscall.Handle(fd))
	if e1 != nil {
		return e1
	}
	return e2
}

func sctpBindx(fd int, ptr unsafe.Pointer, l int) error {
	n, _, e := fsctpBindx.Call(
		uintptr(fd),
		uintptr(ptr),
		uintptr(l),
		sctpBindxAddAddr)
	if int(n) < 0 {
		return e
	}
	return nil
}

func sctpConnectx(fd int, ptr unsafe.Pointer, l int) (assocT, error) {
	t := assocT(0)
	n, _, e := fsctpConnectx.Call(
		uintptr(fd),
		uintptr(ptr),
		uintptr(l),
		uintptr(unsafe.Pointer(&t)))
	if int(n) < 0 {
		return t, e
	}
	return t, nil
}

func sctpSend(fd int, b []byte, info *sndrcvInfo, flag int) (int, error) {
	buf := uintptr(0)
	if len(b) != 0 {
		buf = uintptr(unsafe.Pointer(&b[0]))
	}
	n, _, e := fsctpSend.Call(
		uintptr(fd),
		buf,
		uintptr(len(b)),
		uintptr(unsafe.Pointer(info)),
		uintptr(flag))
	if int(n) < 0 {
		return -1, e
	}
	return int(n), nil
}

func sctpRecvmsg(fd int, b []byte, info *sndrcvInfo, flag *int) (int, error) {
	n, _, e := fsctpRecvmsg.Call(
		uintptr(fd),
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		0,
		0,
		uintptr(unsafe.Pointer(info)),
		uintptr(unsafe.Pointer(flag)))
	if int(n) <= 0 {
		return -1, e
	}
	return int(n), nil
}
