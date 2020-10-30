/*
Copyright (c) 2020, ETH and Andrea Tulimiero

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package main

import (
	"flag"
	"fmt"
	"github.com/andreatulimiero/seg/gateway"
	ipAdapter "github.com/andreatulimiero/seg/gateway/adapters/ip"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

	"github.com/scionproto/scion/go/lib/log"
)

var (
	confPath   = flag.String("conf", "./conf.yaml", "Path to the config file")
	dbPath     = flag.String("db", "", "path to a database of SCION paths")
	logConsole string
)

func init() {
	flag.StringVar(&logConsole, "log.console", "info",
		"Console logging level: trace|debug|info|warn|error|crit")
}

func main() {
	flag.Parse()

	logCfg := log.Config{Console: log.ConsoleConfig{Level: logConsole}}
	if err := log.Setup(logCfg); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s", err)
	}
	setupSignalHandler()

	gatewayConfBuf, err := ioutil.ReadFile(*confPath)
	if err != nil {
		gateway.LogFatal("Error loading conf file")
	}
	g, err := gateway.NewGateway(gatewayConfBuf, *dbPath)
	if err != nil {
		gateway.LogFatal("Cannot create Gateway", "err", err)
	}

	adapterConfBuf, err := ioutil.ReadFile(g.GetAdapterConfPath())
	if err != nil {
		gateway.LogFatal("Error loading conf file", "err", err)
	}
	a, err := ipAdapter.NewIPAdapter(adapterConfBuf)
	if err != nil {
		gateway.LogFatal("Cannot create IP adapter", "err", err)
	}

	g.SetAdapter(a)
	g.Start()
	select {}
}

func setupSignalHandler() {
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		log.Info("Received terminate signal ...")
		os.Exit(0)
	}()
}
