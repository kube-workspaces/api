// A separate test-only module permits use of the sibling desktop client's
// internal RFB decoder without introducing it into the API's runtime imports.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kube-workspaces/desktop-client/internal/rfb"
	"github.com/kube-workspaces/desktop-client/internal/wsio"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: native-client ws://fixture-url")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws, _, err := websocket.DefaultDialer.DialContext(ctx, os.Args[1], nil)
	if err != nil {
		return err
	}
	defer ws.Close()
	stop := context.AfterFunc(ctx, func() { _ = ws.Close() })
	defer stop()
	phase := 0
	c, err := rfb.NewConn(wsio.New(ws), rfb.Config{OnFramebufferUpdate: func(f *rfb.Framebuffer, _ []rfb.Rect) {
		if f.Width == 2 && f.Height == 1 {
			if phase == 0 && f.Pix[0] == 255 && f.Pix[1] == 0 && f.Pix[2] == 0 && f.Pix[5] == 255 {
				phase = 1
			}
			if phase == 1 && f.Pix[0] == 0 && f.Pix[1] == 0 && f.Pix[2] == 255 && f.Pix[5] == 255 {
				phase = 2
			}
		}
		if phase == 2 && f.Width == 1 && f.Height == 2 && f.Pix[0] == 255 && f.Pix[1] == 255 && f.Pix[2] == 255 && f.Pix[4] == 0 && f.Pix[5] == 0 && f.Pix[6] == 255 {
			phase = 3
			cancel()
		}
	}})
	if err != nil {
		return err
	}
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		ticker := time.NewTicker(30 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := c.RequestUpdate(false); err != nil {
					return
				}
			}
		}
	}()
	_ = c.Run(ctx)
	cancel()
	<-pumpDone
	if phase != 3 {
		return fmt.Errorf("native decode missed expected frames: phase %d", phase)
	}
	fmt.Println("native desktop RFB client: initial frame, partial update and resize decoded")
	return nil
}
