package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/brennocm/escalint/internal/contract"
	"github.com/brennocm/escalint/internal/server"
)

func newServeCommand() *cobra.Command {
	var f analysisFlags
	var listen string
	var allowRemote bool
	cmd := &cobra.Command{
		Use:   "serve <snapshot|analysis.json>",
		Short: "Open the web UI on 127.0.0.1 (random port, one-time token)",
		Long: "Analyze the input and serve the UI read-only on the loopback interface. The printed URL\n" +
			"carries a random token that is exchanged for an HttpOnly cookie on first use; share it\n" +
			"with no one. --listen binds another address only together with --allow-remote, and\n" +
			"prints a warning: anyone who can reach the port and learns the token sees who can\n" +
			"become administrator in the account.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !server.IsLoopback(listen) && !allowRemote {
				return fmt.Errorf("--listen %s: %w; add --allow-remote to expose the UI beyond this machine", listen, server.ErrNotLoopback)
			}
			l, err := f.load(cmd, args[0])
			if err != nil {
				return err
			}
			if err := f.finish(l); err != nil {
				return err
			}
			data, err := contract.Marshal(l.analysis)
			if err != nil {
				return err
			}
			assets, err := server.UIAssets()
			if err != nil {
				return err
			}
			token, err := server.NewToken()
			if err != nil {
				return err
			}
			ln, err := net.Listen("tcp", listen)
			if err != nil {
				return err
			}
			if !server.IsLoopback(listen) {
				fmt.Fprintf(cmd.ErrOrStderr(), "escalint: WARNING: listening on %s, beyond loopback; protect the token and stop the server when done\n", ln.Addr())
			}
			srv := &http.Server{
				Handler:           server.New(assets, data, token, server.Hosts(ln.Addr())),
				ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout:       10 * time.Second,
				WriteTimeout:      30 * time.Second,
				IdleTimeout:       60 * time.Second,
				MaxHeaderBytes:    16 << 10,
			}
			host := ln.Addr().String()
			if tcp, ok := ln.Addr().(*net.TCPAddr); ok && tcp.IP.IsLoopback() {
				host = net.JoinHostPort("127.0.0.1", fmt.Sprint(tcp.Port))
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "escalint: open http://%s/?token=%s (Ctrl+C to stop)\n", host, token)
			ctx, stop := signal.NotifyContext(cmdContext(cmd), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			errc := make(chan error, 1)
			go func() { errc <- srv.Serve(ln) }()
			select {
			case err := <-errc:
				if errors.Is(err, http.ErrServerClosed) {
					return nil
				}
				return err
			case <-ctx.Done():
				shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				return srv.Shutdown(shutdown)
			}
		},
	}
	f.register(cmd)
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:0", "address to listen on (default: loopback, random port)")
	cmd.Flags().BoolVar(&allowRemote, "allow-remote", false, "allow a --listen address beyond loopback")
	return cmd
}

func cmdContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}
