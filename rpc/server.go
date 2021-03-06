// Copyright (c) 2018 YouDealChain Authors.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package rpc

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"google.golang.org/grpc"
)

func serve(port string) {
	if !strings.HasPrefix(port, ":") {
		port = ":" + port
	}

	lis, err := net.Listen("tcp4", port)
	if err != nil {
		fmt.Printf("failed to listen: %v", err)
		os.Exit(1)
	}

	s := grpc.NewServer()

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
