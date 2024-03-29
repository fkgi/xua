package main

import (
	"flag"
	"log"
	"time"

	"github.com/fkgi/xua"
	"github.com/fkgi/xua/sctp"
)

type IPList string

func (l *IPList) String() string {
	return string(*l)
}

func (l *IPList) Set(s string) error {
	*l = IPList(string(*l) + "/" + s)
	return nil
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("starting simple echo client")

	// get option flag
	var li, ri IPList
	flag.Var(&li, "la", "local IP address")
	flag.Var(&ri, "ra", "remote IP address")
	lp := flag.String("lp", "14001", "local port number")
	rp := flag.String("rp", "14001", "remote port number")
	flag.Parse()

	if len(li) == 0 || len(ri) == 0 {
		log.Fatal("no IP address")
	}

	var e error
	log.Print("creating address...")
	sctp.LocalAddr, e = sctp.ResolveSCTPAddr("sctp", string(li)[1:]+":"+*lp)
	if e != nil {
		log.Fatal(e)
	}
	log.Print("success as ", sctp.LocalAddr, "(local)")

	sctp.PeerAddr, e = sctp.ResolveSCTPAddr("sctp", string(ri)[1:]+":"+*rp)
	if e != nil {
		log.Fatal(e)
	}
	log.Print("success as ", sctp.PeerAddr, "(remote)")

	xua.RoutingContext = []uint32{101}
	log.Print("dialing...")
	e = xua.Serve(
		func(b []byte) {
			log.Print("Rx: \"", string(b), "\"")
		},
		func() {
			time.Sleep(time.Second)
			xua.Write(
				xua.SCCPAddress{
					NatureOfAddress: xua.NAI_International,
					NumberingPlan:   xua.NPI_E164,
					GlobalTitle:     "12345",
					SubsystemNumber: 0x06},
				xua.SCCPAddress{
					NatureOfAddress: xua.NAI_International,
					NumberingPlan:   xua.NPI_E164,
					GlobalTitle:     "67890",
					SubsystemNumber: 0x07}, make([]byte, 10))
			time.Sleep(time.Second)
			xua.Close()
		},
		func() {})
	if e != nil {
		log.Fatal(e)
	}
}
