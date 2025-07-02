package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/sahmadiut/backhaul/internal/config"
	"github.com/sahmadiut/backhaul/internal/utils"
	"github.com/sahmadiut/backhaul/internal/web"
	"github.com/sirupsen/logrus"
)

type HttpCdnClient struct {
	config          *HttpCdnClientConfig
	parentCtx       context.Context
	ctx             context.Context
	cancel          context.CancelFunc
	logger          *logrus.Logger
	controlChannel  net.Conn
	restartMutex    sync.Mutex
	usageMonitor    *web.Usage
	poolConnections int32
	loadConnections int32
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
		usageMonitor: web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, &config.TunnelStatus, logger),
	}
	return client
}

func (c *HttpCdnClient) Start() {
	if c.config.WebPort > 0 {
		go c.usageMonitor.Monitor()
	}
	c.config.TunnelStatus = fmt.Sprintf("Disconnected (%s)", c.config.Mode)
	go c.maintainControlChannel()
	<-c.ctx.Done()
}

func (c *HttpCdnClient) Restart() {
	if !c.restartMutex.TryLock() {
		return
	}
	defer c.restartMutex.Unlock()

	c.logger.Info("restarting client...")
	level := c.logger.Level
	c.logger.SetLevel(logrus.FatalLevel)

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
	c.controlChannel = nil
	c.config.TunnelStatus = fmt.Sprintf("Reconnecting (%s)", c.config.Mode)
	atomic.StoreInt32(&c.poolConnections, 0)
	atomic.StoreInt32(&c.loadConnections, 0)
	c.logger.SetLevel(level)

	go c.Start()
}

func (c *HttpCdnClient) maintainControlChannel() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			c.logger.Info("attempting to establish control channel...")
			conn, err := c.dial("/control/" + uuid.NewString())
			if err != nil {
				c.logger.Errorf("failed to dial control channel: %v", err)
				c.config.TunnelStatus = fmt.Sprintf("Disconnected (%s)", c.config.Mode)
				time.Sleep(c.config.RetryInterval)
				continue
			}

			c.controlChannel = conn
			c.logger.Info("control channel established successfully")
			c.config.TunnelStatus = fmt.Sprintf("Connected (%s)", c.config.Mode)

			go c.maintainConnectionPool()
			c.handleControlChannel() // This blocks until the connection fails

			c.logger.Warn("control channel lost, will attempt to reconnect...")
			c.config.TunnelStatus = fmt.Sprintf("Reconnecting (%s)", c.config.Mode)
		}
	}
}

func (c *HttpCdnClient) maintainConnectionPool() {
	for i := 0; i < c.config.ConnPoolSize; i++ {
		go c.createAndHandleTunnel()
	}
}

func (c *HttpCdnClient) createAndHandleTunnel() {
	conn, err := c.dial("/tunnel/" + uuid.NewString())
	if err != nil {
		c.logger.Debugf("failed to dial for connection pool: %v", err)
		return
	}

	atomic.AddInt32(&c.poolConnections, 1)
	defer atomic.AddInt32(&c.poolConnections, -1)

	c.logger.Debugf("tunnel connection established and waiting for job. current pool size: %d", atomic.LoadInt32(&c.poolConnections))
	c.handleTunnelJob(conn)
}

func (c *HttpCdnClient) handleTunnelJob(tunnelConn net.Conn) {
	defer tunnelConn.Close()

	tunnelConn.SetReadDeadline(time.Now().Add(c.config.KeepAlive + 15*time.Second))
	remoteAddr, transport, err := utils.ReceiveBinaryTransportString(tunnelConn)
	tunnelConn.SetReadDeadline(time.Time{})

	if err != nil {
		if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
			c.logger.Debugf("failed to get remote address from tunnel: %v", err)
		}
		return
	}

	if transport != utils.SG_TCP {
		c.logger.Errorf("invalid transport type received on tunnel: %d", transport)
		return
	}
	atomic.AddInt32(&c.loadConnections, 1)
	defer atomic.AddInt32(&c.loadConnections, -1)

	c.logger.Debugf("received tunnel job for: %s", remoteAddr)
	portStr, _, _ := net.SplitHostPort(remoteAddr)
	port, _ := strconv.Atoi(portStr)

	localConn, err := TcpDialer(c.ctx, remoteAddr, c.config.DialTimeOut, c.config.KeepAlive, true, 1, 32*1024, 32*1024)
	if err != nil {
		c.logger.Errorf("failed to dial local service at %s: %v", remoteAddr, err)
		return
	}

	c.logger.Debugf("successfully connected to local service: %s", remoteAddr)
	utils.TCPConnectionHandler(tunnelConn, localConn, c.logger, c.usageMonitor, port, c.config.Sniffer)
}

func (c *HttpCdnClient) handleControlChannel() {
	defer c.controlChannel.Close()

	messageChan := make(chan byte, 10)
	go func() {
		defer close(messageChan)
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
				c.controlChannel.SetReadDeadline(time.Now().Add(30 * time.Second))
				msg, err := utils.ReceiveBinaryByte(c.controlChannel)
				if err != nil {
					if opErr, ok := err.(*net.OpError); !ok || !opErr.Timeout() {
						c.logger.Debugf("error reading from control channel: %v", err)
					}
					return
				}
				messageChan <- msg
			}
		}
	}()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			utils.SendBinaryByte(c.controlChannel, utils.SG_Closed)
			return
		case <-ticker.C:
			if err := utils.SendBinaryByte(c.controlChannel, utils.SG_HB); err != nil {
				c.logger.Debugf("failed to send heartbeat: %v", err)
				return
			}
		case msg, ok := <-messageChan:
			if !ok {
				c.logger.Warn("control channel reader closed.")
				return
			}

			switch msg {
			case utils.SG_Chan:
				c.logger.Debug("received signal to create new tunnel connection.")
				go c.createAndHandleTunnel()
			case utils.SG_HB:
				c.logger.Trace("heartbeat received from server.")
			case utils.SG_Closed:
				c.logger.Warn("control channel closed by server.")
				return
			default:
				c.logger.Warnf("received unknown message type on control channel: %d", msg)
			}
		}
	}
}

func (c *HttpCdnClient) dial(path string) (net.Conn, error) {
	var conn net.Conn
	var err error

	dialer := &net.Dialer{
		Timeout:   c.config.DialTimeOut,
		KeepAlive: c.config.KeepAlive,
	}

	remoteAddr := c.config.RemoteAddr
	host := strings.Split(remoteAddr, ":")[0]
	if c.config.EdgeIP != "" {
		host = c.config.EdgeIP
	}

	if c.config.Mode == config.HTTPCDN {
		conn, err = dialer.DialContext(c.ctx, "tcp", remoteAddr)
	} else {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", remoteAddr, tlsConfig)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %w", remoteAddr, err)
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(c.config.Nodelay)
	}

	req, err := http.NewRequestWithContext(c.ctx, "POST", "http://"+host+path, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Host = host
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.config.Token))
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")
	req.Header.Set("User-Agent", "Backhaul-Client/1.0")

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to write request: %w", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("server returned unexpected status: %s", resp.Status)
	}

	return conn, nil
}
