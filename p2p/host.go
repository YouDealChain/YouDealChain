// Copyright (c) 2018 YouDealChain Authors.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package p2p

import (
	"crypto/rand"
	"fmt"
	"net"

	"github.com/YouDealChain/YouDealChain/log"
	"github.com/jbenet/goprocess"
	goprocessctx "github.com/jbenet/goprocess/context"
	libp2p "github.com/libp2p/go-libp2p"
	crypto "github.com/libp2p/go-libp2p-crypto"
	host "github.com/libp2p/go-libp2p-host"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	peer "github.com/libp2p/go-libp2p-peer"
	pstore "github.com/libp2p/go-libp2p-peerstore"
	ma "github.com/multiformats/go-multiaddr"
)

// Host is host.Host wrapper
type Host struct {
	host.Host
	cmgr    *ConnManager
	routing *dht.IpfsDHT // TODO change it to YouDealChain impl
	proc    goprocess.Process
}

var logger log.Logger // logger

// init function
func init() {
	ma.SwapToP2pMultiaddrs() // change ma.P_P2P from 'ipfs' to 'p2p'
	logger = log.NewLogger("p2p")
}

// NewDefaultHost creates a wrapper of host.Host
func NewDefaultHost(parent goprocess.Process, listenAddress net.IP, listenPort uint) (*Host, error) {
	return NewHost(parent, listenAddress, listenPort, pstore.NewPeerstore())
}

// NewHost creates a wrapper of host.Host, with given peerstore & notifiee, and listening on given port/address
func NewHost(parent goprocess.Process, listenAddress net.IP, listenPort uint, ps pstore.Peerstore) (*Host, error) {
	if listenAddress == nil {
		listenAddress = net.IPv4zero
	}

	var r = rand.Reader

	// Generate a key pair for this host. We will use it at least
	// to obtain a valid host ID.
	priv, _, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, r)
	if err != nil {
		return nil, err
	}

	proc := goprocess.WithParent(parent) // p2p proc
	hostContext := goprocessctx.OnClosingContext(proc)

	var addr string // TODO find a better way to converto IP to ip4/ip6 ma
	if p4 := listenAddress.To4(); len(p4) == net.IPv4len {
		addr = fmt.Sprintf("/ip4/%s/tcp/%d", listenAddress, listenPort)
	} else {
		addr = fmt.Sprintf("/ip6/%s/tcp/%d", listenAddress, listenPort)
	}

	cmgr := NewConnManager()
	opts := []libp2p.Option{
		libp2p.ListenAddrStrings(addr),
		libp2p.Identity(priv),
		libp2p.ConnectionManager(cmgr),
		libp2p.Peerstore(ps), // TODO NAT/Relay/...
	}

	localhost, err := libp2p.New(hostContext, opts...)
	if err != nil {
		return nil, err
	}

	// Build host multiaddress
	hostAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/%s/%s", ma.ProtocolWithCode(ma.P_P2P).Name, localhost.ID().Pretty()))

	// Now we can build a full multiaddress to reach this host
	fullAddr := localhost.Addrs()[0].Encapsulate(hostAddr)
	logger.Infof("Now listening on %s", fullAddr)

	// create dht routing table
	routing, err := dht.New(hostContext, localhost)
	if err != nil {
		return nil, err
	}

	h := &Host{Host: localhost, cmgr: cmgr, routing: routing, proc: proc}

	// start connmanager
	h.cmgr.Start(proc)
	//  bootstrap dht routing table
	h.routing.Bootstrap(hostContext)

	return h, nil
}

// ConnectPeer establishs p2p connection with specified multiaddr
func (h *Host) ConnectPeer(parent goprocess.Process, multiaddr ma.Multiaddr) error {
	pid, err := multiaddr.ValueForProtocol(ma.P_P2P)
	if err != nil {
		return err
	}

	peerID, err := peer.IDB58Decode(pid)
	if err != nil {
		return err
	}

	peerAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/%s/%s", ma.ProtocolWithCode(ma.P_P2P).Name, pid))
	targetAddr := multiaddr.Decapsulate(peerAddr)

	// add target peer id to peer store
	h.Peerstore().AddAddr(peerID, targetAddr, pstore.AddressTTL)

	peerInfo := pstore.PeerInfo{ID: peerID}
	return h.Connect(goprocessctx.OnClosingContext(parent), peerInfo)
}

// Process returns the running process of the Host object
func (h *Host) Process() goprocess.Process {
	return h.proc
}
