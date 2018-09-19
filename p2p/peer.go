// Copyright (c) 2018 YouDealChain Authors.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package p2p

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"sync"

	"github.com/jbenet/goprocess"
	goprocessctx "github.com/jbenet/goprocess/context"
	libp2p "github.com/libp2p/go-libp2p"
	crypto "github.com/libp2p/go-libp2p-crypto"
	host "github.com/libp2p/go-libp2p-host"
	libp2pnet "github.com/libp2p/go-libp2p-net"
	peer "github.com/libp2p/go-libp2p-peer"
	peerstore "github.com/libp2p/go-libp2p-peerstore"
	multiaddr "github.com/multiformats/go-multiaddr"
)

// YdcPeer represents a connected remote node.
type YdcPeer struct {
	conns           map[peer.ID]interface{}
	config          *Config
	host            host.Host
	proc            goprocess.Process
	id              peer.ID
	table           *Table
	networkIdentity crypto.PrivKey
	notifier        *Notifier
	mu              sync.Mutex
}

// NewYdcPeer create a YdcPeer
func NewYdcPeer(config *Config, parent goprocess.Process) (*YdcPeer, error) {
	// ctx := context.Background()
	proc := goprocess.WithParent(parent) // p2p proc
	ctx := goprocessctx.OnClosingContext(proc)
	ydcPeer := &YdcPeer{conns: make(map[peer.ID]interface{}), config: config, notifier: NewNotifier(), proc: proc}
	networkIdentity, err := loadNetworkIdentity(config.KeyPath)
	if err != nil {
		return nil, err
	}
	ydcPeer.networkIdentity = networkIdentity
	ydcPeer.id, err = peer.IDFromPublicKey(networkIdentity.GetPublic())
	if err != nil {
		return nil, err
	}

	opts := []libp2p.Option{
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/%s/tcp/%d", config.Address, config.Port)),
		libp2p.Identity(networkIdentity),
		libp2p.DefaultTransports,
		libp2p.DefaultMuxers,
		libp2p.DefaultSecurity,
		libp2p.NATPortMap(),
	}

	ydcPeer.host, err = libp2p.New(ctx, opts...)
	ydcPeer.host.SetStreamHandler(ProtocolID, ydcPeer.handleStream)
	ydcPeer.table = NewTable(ydcPeer)
	logger.Infof("YdcPeer starting...ID: %s listen: %s", ydcPeer.id.Pretty(), fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", config.Port))
	return ydcPeer, nil
}

// Bootstrap schedules lookup and discover new peer
func (p *YdcPeer) Bootstrap() {
	if len(p.config.Seeds) > 0 {
		p.connectSeeds()
		p.table.Loop(p.proc)
	}
	p.notifier.Loop(p.proc)
}

func loadNetworkIdentity(path string) (crypto.PrivKey, error) {
	var key crypto.PrivKey
	if path == "" {
		key, _, err := crypto.GenerateEd25519Key(rand.Reader)
		return key, err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) { // file does not exist.
		key, _, err := crypto.GenerateEd25519Key(rand.Reader)
		return key, err
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decodeData, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	key, err = crypto.UnmarshalPrivateKey(decodeData)

	return key, err
}

func (p *YdcPeer) handleStream(s libp2pnet.Stream) {
	conn := NewConn(s, p, s.Conn().RemotePeer())
	go conn.loop()
}

func (p *YdcPeer) connectSeeds() {
	host := p.host
	for _, v := range p.config.Seeds {
		if err := p.addAddrToPeerstore(host, v); err != nil {
			logger.Warn("Failed to add seed to peerstore.", err)
		}
		// conn := NewConn(nil, p, peerID)
		// go conn.loop()
	}
}

func (p *YdcPeer) addAddrToPeerstore(h host.Host, addr string) error {
	ipfsaddr, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		return err
	}
	pid, err := ipfsaddr.ValueForProtocol(multiaddr.P_IPFS)
	if err != nil {
		return err
	}

	peerid, err := peer.IDB58Decode(pid)
	if err != nil {
		return err
	}
	targetPeerAddr, _ := multiaddr.NewMultiaddr(
		fmt.Sprintf("/ipfs/%s", peer.IDB58Encode(peerid)))
	targetAddr := ipfsaddr.Decapsulate(targetPeerAddr)

	h.Peerstore().AddAddr(peerid, targetAddr, peerstore.PermanentAddrTTL)
	p.table.routeTable.Update(peerid)
	return nil
}

// Broadcast business message.
func (p *YdcPeer) Broadcast(code uint32, message Serializable) {

}

// SendMessageToPeer send message to a peer.
func (p *YdcPeer) SendMessageToPeer(code uint32, message Serializable, pid peer.ID) {

}

// Subscribe a message notification.
func (p *YdcPeer) Subscribe(notifiee *Notifiee) {
	p.notifier.Subscribe(notifiee)
}

// UnSubscribe cancel subcribe.
func (p *YdcPeer) UnSubscribe(notifiee *Notifiee) {
	p.notifier.UnSubscribe(notifiee)
}
