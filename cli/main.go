package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/mrheinen/p0fclient"
)

var (
	socketFile = flag.String("s", "", "p0f socket file")
	ipAddress  = flag.String("ip", "", "IP address to query (IPv4 or IPv6)")
)

func main() {

	flag.Parse()
	if *socketFile == "" || *ipAddress == "" {
		fmt.Printf("Usage: %s -socket <socket> -ip <ip>\n", os.Args[0])
		return
	}

	cli := p0fclient.NewP0fClient(*socketFile)
	if err := cli.Connect(); err != nil {
		fmt.Printf("Can't connect to socket: %s\n", err)
		return
	}

	ip := net.ParseIP(*ipAddress)
	if ip == nil {
		fmt.Printf("Error: invalid IP address: %s\n", *ipAddress)
		return
	}

	res, err := cli.QueryIP(ip)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	if res.Status == p0fclient.P0F_STATUS_NOMATCH {
		fmt.Println("No match found")
	} else {
		fmt.Printf("Response: %s\n", res)
	}
}
