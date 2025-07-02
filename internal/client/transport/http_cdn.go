package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/musix/backhaul/internal/config"
	"github.com/musix/backhaul/internal/utils"
	"github.com/musix/backhaul/internal/web"
	"github.com/sirupsen/logrus"
)

type HttpCdnClient struct {
	config         *HttpCdnClientConfig
	parentCtx      context.Context
	ctx            context.Context
	cancel         context.CancelFunc
	logger         *logrus.Logger
	connPool       chan net.Conn
	controlChannel net.Conn
	restartMutex   sync.Mutex
	usageMonitor   *web.Usage
}

type HttpCdnClientConfig struct {
	RemoteAddr     string
	Token          string
	SnifferLog     string
	TunnelStatus   string
	EdgeIP         string
	Nodelay        bool
	Sniffer        bool
	AggressivePool bool
	KeepAlive      time.Duration
	DialTimeOut    time.Duration
	RetryInterval  time.Duration
	ConnPoolSize   int
	WebPort        int
	Mode           config.TransportType
}

func NewHttpCdnClient(parentCtx context.Context, config *HttpCdnClientConfig, logger *logrus.Logger) *HttpCdnClient {
	ctx, cancel := context.WithCancel(parentCtx)
	client := &HttpCdnClient{
		config:       config,
		parentCtx:    parentCtx,
		ctx:          ctx,
		cancel:       cancel,
		logger:       logger,
		connPool:     make(chan net.Conn, config.ConnPoolSize),
		usageMonitor: web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, &config.TunnelStatus, logger),
	}
	return client
}

func (c *HttpCdnClient) Start() {
	go c.dialControl()

	<-c.ctx.Done()
}

func (c *HttpCdnClient) Restart() {
	if !c.restartMutex.TryLock() {
		return
	}
	defer c.restartMutex.Unlock()

	c.logger.Info("restarting client...")
	if c.cancel != nil {
		c.cancel()
	}

	if c.controlChannel != nil {
		c.controlChannel.Close()
	}

	time.Sleep(c.config.RetryInterval)

	ctx, cancel := context.WithCancel(c.parentCtx)
	c.ctx = ctx
	c.cancel = cancel
	c.connPool = make(chan net.Conn, c.config.ConnPoolSize)
	c.controlChannel = nil

	go c.Start()
}

func (c *HttpCdnClient) dial() (net.Conn, error) {
	var conn net.Conn
	var err error

	dialer := &net.Dialer{
		Timeout: c.config.DialTimeOut,
	}

	if c.config.Mode == config.HTTPCDN {
		conn, err = dialer.Dial("tcp", c.config.RemoteAddr)
	} else { // https_cdn
		conn, err = tls.DialWithDialer(dialer, "tcp", c.config.RemoteAddr, &tls.Config{InsecureSkipVerify: true})
	}

	if err != nil {
		return nil, err
	}

	req, _ := http.NewRequest("POST", fmt.Sprintf("/tunnel/%s", uuid.New().String()), nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.config.Token))
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Content-Length", "0")
	req.Host = strings.Split(c.config.RemoteAddr, ":")[0]
	if c.config.EdgeIP != "" {
		req.Host = c.config.EdgeIP
	}

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}

	// Check response
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil && err != io.EOF {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("server returned non-200 status code: %d", resp.StatusCode)
	}

	return conn, nil
}

func (c *HttpCdnClient) dialControl() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			var conn net.Conn
			var err error
			dialer := &net.Dialer{
				Timeout: c.config.DialTimeOut,
			}
			if c.config.Mode == config.HTTPCDN {
				conn, err = dialer.Dial("tcp", c.config.RemoteAddr)
			} else {
				conn, err = tls.DialWithDialer(dialer, "tcp", c.config.RemoteAddr, &tls.Config{InsecureSkipVerify: true})
			}

			if err != nil {
				c.logger.Errorf("failed to dial control channel: %v", err)
				time.Sleep(c.config.RetryInterval)
				continue
			}

			req, _ := http.NewRequest("POST", fmt.Sprintf("/control/%s", uuid.New().String()), nil)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.config.Token))
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("Content-Length", "0")
			req.Host = strings.Split(c.config.RemoteAddr, ":")[0]
			if c.config.EdgeIP != "" {
				req.Host = c.config.EdgeIP
			}

			if err := req.Write(conn); err != nil {
				conn.Close()
				c.logger.Errorf("failed to write control request: %v", err)
				time.Sleep(c.config.RetryInterval)
				continue
			}

			resp, err := http.ReadResponse(bufio.NewReader(conn), req)
			if err != nil && err != io.EOF {
				conn.Close()
				c.logger.Errorf("failed to read control response: %v", err)
				time.Sleep(c.config.RetryInterval)
				continue
			}
			if resp.StatusCode != http.StatusOK {
				conn.Close()
				c.logger.Errorf("control channel returned non-200 status: %d", resp.StatusCode)
				time.Sleep(c.config.RetryInterval)
				continue
			}

			c.controlChannel = conn
			c.logger.Info("control channel established")
			go c.maintainConnectionPool()
			c.handleControlChannel()
			return
		}
	}
}

func (c *HttpCdnClient) maintainConnectionPool() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			if len(c.connPool) < c.config.ConnPoolSize {
				conn, err := c.dial()
				if err != nil {
					c.logger.Errorf("failed to dial for connection pool: %v", err)
					time.Sleep(c.config.RetryInterval)
					continue
				}
				c.connPool <- conn
			} else {
				time.Sleep(1 * time.Second)
			}
		}
	}
}

func (c *HttpCdnClient) handleControlChannel() {
	messageChan := make(chan byte, 1)
	go func() {
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
				msg, err := utils.ReceiveBinaryByte(c.controlChannel)
				if err != nil {
					c.logger.Error("failed to read from control channel", err)
					go c.Restart()
					return
				}
				messageChan <- msg
			}
		}
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		case msg := <-messageChan:
			switch msg {
			case utils.SG_Chan:
				go func() {
					conn, err := c.dial()
					if err != nil {
						c.logger.Errorf("failed to dial new connection: %v", err)
						return
					}
					c.handleConnection(conn)
				}()
			case utils.SG_HB:
				// Heartbeat received
			case utils.SG_Closed:
				c.logger.Warn("control channel closed by server")
				go c.Restart()
				return
			}
		}
	}
}

func (c *HttpCdnClient) handleConnection(conn net.Conn) {
	remoteAddr, transport, err := utils.ReceiveBinaryTransportString(conn)
	if err != nil || transport != utils.SG_TCP {
		c.logger.Errorf("failed to get remote address or invalid transport: %v", err)
		conn.Close()
		return
	}

	localConn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		c.logger.Errorf("failed to dial local service at %s: %v", remoteAddr, err)
		conn.Close()
		return
	}

	utils.TCPConnectionHandler(conn, localConn, c.logger, c.usageMonitor, 0, false)
}
