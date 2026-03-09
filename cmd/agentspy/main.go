package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"xiu.zyx/agentspy/internal/auditor"
	"xiu.zyx/agentspy/internal/client"
	"xiu.zyx/agentspy/internal/config"
	"xiu.zyx/agentspy/internal/ebpfcmd"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to config.yaml")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config failed: %v", err)
	}

	wsURL := "ws://" + cfg.SSL.WSAddr + "/"
	baseCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(baseCtx)
	defer cancel()

	aud := auditor.NewAuditor()

	type runner struct {
		name string
		run  func(context.Context) error
	}

	var runners []runner
	if cfg.SSL.Enabled {
		agent := client.NewAgentClientWithAuditor(client.Config{
			ServerURL:     wsURL,
			Origin:        cfg.SSL.WSOrigin,
			RetryInterval: cfg.RetryDuration(),
		}, aud)
		runners = append(runners, runner{
			name: "ssl",
			run:  agent.Start,
		})
	}
	if cfg.CommandEBPF.Enabled {
		module := ebpfcmd.NewModule(ebpfcmd.Config{
			Enabled:       true,
			ClaudeBinPath: cfg.CommandEBPF.ClaudeBin,
		})
		runners = append(runners, runner{
			name: "cmd-ebpf",
			run: func(ctx context.Context) error {
				return module.Start(ctx, aud.HandleCommandEvent)
			},
		})
	}
	if len(runners) == 0 {
		log.Fatal("no module enabled in config.yaml")
	}

	errCh := make(chan error, len(runners))
	var wg sync.WaitGroup
	for _, r := range runners {
		r := r
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Printf("module %s started", r.name)
			if err := r.run(ctx); err != nil {
				errCh <- err
				cancel()
				return
			}
			log.Printf("module %s stopped", r.name)
		}()
	}

	select {
	case err = <-errCh:
		wg.Wait()
		log.Fatalf("module exited with error: %v", err)
	case <-ctx.Done():
		wg.Wait()
	}
}
