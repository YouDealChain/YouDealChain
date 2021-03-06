// Copyright (c) 2018 YouDealChain Authors.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package core

import (
	"github.com/YouDealChain/YouDealChain/core/types"
	"github.com/YouDealChain/YouDealChain/crypto"
	"github.com/YouDealChain/YouDealChain/log"
	"github.com/YouDealChain/YouDealChain/p2p"
	"github.com/jbenet/goprocess"
)

// const defines constants
const (
	BlockMsgChBufferSize = 1024
)

var logger log.Logger // logger

func init() {
	logger = log.NewLogger("core")
}

// BlockChain define chain struct
type BlockChain struct {
	notifiee      p2p.Net
	newblockMsgCh chan p2p.Message
	txpool        *TransactionPool
	proc          goprocess.Process

	// Actually a tree-shaped structure where any node can have
	// multiple children.  However, there can only be one active branch (longest) which does
	// indeed form a chain from the tip all the way back to the genesis block.
	hashToBlock map[crypto.HashType]*types.Block

	// longest chain
	longestChainHeight int
	longestChainTip    *types.Block

	// orphan block pool
	hashToOrphanBlockmap map[crypto.HashType]*types.Block
	// orphan block's parents; one parent can have multiple orphan children
	parentToOrphanBlock map[crypto.HashType]*types.Block
}

// NewBlockChain return a blockchain.
func NewBlockChain(parent goprocess.Process, notifiee p2p.Net) *BlockChain {

	return &BlockChain{
		notifiee:      notifiee,
		newblockMsgCh: make(chan p2p.Message, BlockMsgChBufferSize),
		proc:          goprocess.WithParent(parent),
		txpool:        NewTransactionPool(parent, notifiee),
	}
}

// Run launch blockchain.
func (chain *BlockChain) Run() {

	chain.subscribeMessageNotifiee(chain.notifiee)
	go chain.loop()
	chain.txpool.Run()
}

func (chain *BlockChain) subscribeMessageNotifiee(notifiee p2p.Net) {
	notifiee.Subscribe(p2p.NewNotifiee(p2p.NewBlockMsg, chain.newblockMsgCh))
}

func (chain *BlockChain) loop() {
	for {
		select {
		case msg := <-chain.newblockMsgCh:
			chain.processBlock(msg)
		case <-chain.proc.Closing():
			logger.Info("Quit blockchain loop.")
			return
		}
	}
}

func (chain *BlockChain) processBlock(msg p2p.Message) {

}
