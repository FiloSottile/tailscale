// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package portmapper is a UDP port mapping client. It currently only does
// NAT-PMP, but will likely do UPnP and perhaps PCP later.
package portmapper

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"inet.af/netaddr"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/netns"
	"tailscale.com/types/logger"
)

//lint:file-ignore U1000 Ignore unused WIP code

// References:
//
// NAT-PMP: https://tools.ietf.org/html/rfc6886
//

const pmpPort = 5351

const portMapCreateTimeout = 250 * time.Millisecond

type Client struct {
	logf logger.Logf

	mu        sync.Mutex
	localPort int
}

func NewClient(logf logger.Logf, localPort int) *Client {
	return &Client{
		logf:      logf,
		localPort: localPort,
	}
}

func (c *Client) SetLocalPort(localPort int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.localPort = localPort
}

func (c *Client) Refresh(ctx context.Context) (external netaddr.IPPort, validFor time.Duration, ok bool) {
	gw, _, ok := interfaces.LikelyHomeRouterIP()
	if !ok {
		return netaddr.IPPort{}, 0, false
	}
	c.mu.Lock()
	localPort := c.localPort
	c.mu.Unlock()

	uc, err := netns.Listener().ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		c.logf("ListenPacket: %v", err)
		return netaddr.IPPort{}, 0, false
	}
	defer uc.Close()

	uc.SetReadDeadline(time.Now().Add(portMapCreateTimeout))
	// TODO: spin up goroutine to await ctx cancel and close uc?

	pmpAddr := netaddr.IPPort{IP: gw, Port: pmpPort}.UDPAddr()

	prevPort := 0 // or 0 if unknown; TODO
	pmpReqMapping := buildPMPRequestMappingPacket(localPort, prevPort)
	c.logf("Writing: % 02x", pmpReqMapping)
	if _, err := uc.WriteTo(pmpReqMapping, pmpAddr); err != nil {
		c.logf("WriteTo.PMP: %v", err)
		return netaddr.IPPort{}, 0, false
	}

	res := make([]byte, 1500)
	for {
		n, addr, err := uc.ReadFrom(res)
		if err != nil {
			return netaddr.IPPort{}, 0, false
		}
		switch addr.(*net.UDPAddr).Port {
		case 5351:
			pmpRes, ok := parsePMPResponse(res[:n])
			if !ok {
				c.logf("unexpected PMP response: % 02x", res[:n])
				break
			}
			c.logf("From %v: %+v (% 02x)", addr, pmpRes, res[:n])
			return netaddr.IPPort{}, 0, true
		}
	}
}

type pmpResultCode uint16

// NAT-PMP constants.
const (
	pmpOpMapUDP = 1

	pmpCodeOK                 pmpResultCode = 0
	pmpCodeUnsupportedVersion pmpResultCode = 1
	pmpCodeNotAuthorized      pmpResultCode = 2 // "e.g., box supports mapping, but user has turned feature off"
	pmpCodeNetworkFailure     pmpResultCode = 3 // "e.g., NAT box itself has not obtained a DHCP lease"
	pmpCodeOutOfResources     pmpResultCode = 4
	pmpCodeUnsupportedOpcode  pmpResultCode = 5
)

func buildPMPRequestMappingPacket(localPort, prevPort int) (pkt []byte) {
	pkt = make([]byte, 12)

	pkt[1] = pmpOpMapUDP
	binary.BigEndian.PutUint16(pkt[4:], uint16(localPort))
	binary.BigEndian.PutUint16(pkt[6:], uint16(prevPort))
	binary.BigEndian.PutUint32(pkt[8:], 600) // RFC recommended seconds (2 hours)

	return pkt
}

type pmpResponse struct {
	ResCode             pmpResultCode
	SecondsSinceEpoch   uint32
	InternalPort        uint16
	ExternalPort        uint16
	MappingValidSeconds uint32
}

func parsePMPResponse(pkt []byte) (res pmpResponse, ok bool) {
	if len(pkt) != 16 {
		return
	}
	op := pkt[1]
	if op != 0x80+pmpOpMapUDP {
		return
	}
	res.ResCode = pmpResultCode(binary.BigEndian.Uint16(pkt[2:]))
	res.SecondsSinceEpoch = binary.BigEndian.Uint32(pkt[4:])
	res.InternalPort = binary.BigEndian.Uint16(pkt[8:])
	res.ExternalPort = binary.BigEndian.Uint16(pkt[10:])
	res.MappingValidSeconds = binary.BigEndian.Uint32(pkt[12:])
	return res, true
}
