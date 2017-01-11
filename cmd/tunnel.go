package cmd

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/armon/go-socks5"
	"golang.org/x/net/context"

	boshssh "github.com/cloudfoundry/bosh-cli/ssh"
	boshui "github.com/cloudfoundry/bosh-cli/ui"
)

type TunnelCmd struct {
	ui               boshui.UI
	sshClientFactory boshssh.ClientFactory

	pidEnv string
}

func NewTunnelCmd(ui boshui.UI, sshClientFactory boshssh.ClientFactory) TunnelCmd {
	return TunnelCmd{ui: ui, sshClientFactory: sshClientFactory, pidEnv: "BOSH_TUNNEL_PID"}
}

func (c TunnelCmd) Run(opts TunnelOpts) error {
	if opts.Kill {
		return c.kill()
	} else {
		c.kill()
	}

	clientOpts := boshssh.ClientOpts{
		Host: opts.Host,
		Port: opts.Port,

		User:       opts.Username,
		PrivateKey: string(opts.PrivateKey.Bytes),

		// Do not allow tunneling over another SOCKS proxy
		// to allow repeated tunnel cmd invocations without clearing envs
		DisableSOCKS: true,
	}

	sshClient := c.sshClientFactory.New(clientOpts)

	err := sshClient.Start()
	if err != nil {
		return err
	}

	defer sshClient.Stop()

	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return sshClient.Dial(network, addr)
		},
	}

	server, err := socks5.New(conf)
	if err != nil {
		return err
	}

	listner, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		return err
	}

	c.printEnv(listner)

	serverErrCh := make(chan error)
	lifetimeCh := time.After(opts.Lifetime)

	go func() {
		serverErrCh <- server.Serve(listner)
	}()

	select {
	case err = <-serverErrCh:
		return err
	case <-lifetimeCh:
		return nil
	}
}

func (c TunnelCmd) kill() error {
	pidStr := os.Getenv(c.pidEnv)
	if len(pidStr) == 0 {
		return nil
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return err
	}

	c.ui.ErrorLinef("Killing existing tunnel PID '%d'", pid)

	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}

	return proc.Kill()
}

func (c TunnelCmd) printEnv(listner net.Listener) {
	env := []string{
		fmt.Sprintf("export BOSH_ALL_PROXY=socks5://%s", listner.Addr()),
		fmt.Sprintf("export %s=%d", c.pidEnv, os.Getpid()),
	}

	// Print out environment variables ready to be bash eval-ed
	c.ui.PrintBlock(strings.Join(env, "\n"))
	c.ui.Flush()

	// Allow bash eval to continue
	os.Stdin.Close()
	os.Stdout.Close()
	os.Stderr.Close()
}
