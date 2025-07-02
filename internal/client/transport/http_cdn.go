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
	"time"

	"github.com/google/uuid"
	"github.com/sahmadiut/backhaul/internal/config"
	"github.com/sahmadiut/backhaul/internal/utils"
	"github.com/sahmadiut/backhaul/internal/web"
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
	if c.config.WebPort > 0 {
		go c.usageMonitor.Monitor()
	}

	c.config.TunnelStatus = fmt.Sprintf("Disconnected (%s)", c.config.Mode)

	go c.dialControl()
	<-c.ctx.Done()
}

func (c *HttpCdnClient) Restart() {
	if !c.restartMutex.TryLock() {
		c.logger.Warn("client restart already in progress")
		return
	}
	defer c.restartMutex.Unlock()

	c.logger.Info("restarting client...")

	// Store old log level and temporarily disable logs
	level := c.logger.Level
	c.logger.SetLevel(logrus.FatalLevel)

	if c.cancel != nil {
		c.cancel()
	}

	if c.controlChannel != nil {
		c.controlChannel.Close()
	}

	// Drain connection pool
	for {
		select {
		case conn := <-c.connPool:
			conn.Close()
		default:
			goto drained
		}
	}
drained:

	time.Sleep(c.config.RetryInterval)

	ctx, cancel := context.WithCancel(c.parentCtx)
	c.ctx = ctx
	c.cancel = cancel
	c.connPool = make(chan net.Conn, c.config.ConnPoolSize)
	c.controlChannel = nil
	c.config.TunnelStatus = fmt.Sprintf("Reconnecting (%s)", c.config.Mode)

	// Restore log level
	c.logger.SetLevel(level)

	go c.Start()
}

func (c *HttpCdnClient) dial(path string) (net.Conn, error) {
	var conn net.Conn
	var err error

	dialer := &net.Dialer{
		Timeout:   c.config.DialTimeOut,
		KeepAlive: c.config.KeepAlive,
	}

	if c.config.Mode == config.HTTPCDN {
		conn, err = dialer.Dial("tcp", c.config.RemoteAddr)
	} else { // https_cdn
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         strings.Split(c.config.RemoteAddr, ":")[0],
		}
		if c.config.EdgeIP != "" {
			tlsConfig.ServerName = c.config.EdgeIP
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", c.config.RemoteAddr, tlsConfig)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to dial: %v", err)
	}

	// Set TCP no delay for better latency
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(c.config.Nodelay)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(c.config.KeepAlive)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", path, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.config.Token))
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "tcp")
	req.Header.Set("Content-Length", "0")
	req.Header.Set("User-Agent", "Backhaul-Client/1.0")

	// Set proper host header
	host := strings.Split(c.config.RemoteAddr, ":")[0]
	if c.config.EdgeIP != "" {
		host = c.config.EdgeIP
	}
	req.Host = host

	// Set timeout for HTTP handshake
	conn.SetWriteDeadline(time.Now().Add(c.config.DialTimeOut))
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to write request: %v", err)
	}

	// Reset write deadline
	conn.SetWriteDeadline(time.Time{})

	// Set timeout for reading response
	conn.SetReadDeadline(time.Now().Add(c.config.DialTimeOut))

	// Read response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil && err != io.EOF {
		conn.Close()
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Reset read deadline
	conn.SetReadDeadline(time.Time{})

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("server returned status code: %d %s", resp.StatusCode, resp.Status)
	}

	// Ensure response body is fully consumed to complete HTTP handshake
	if resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	return conn, nil
}

func (c *HttpCdnClient) dialControl() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			c.logger.Info("attempting to establish control channel...")
			conn, err := c.dial(fmt.Sprintf("/control/%s", uuid.New().String()))
			if err != nil {
				c.logger.Errorf("failed to dial control channel: %v", err)
				time.Sleep(c.config.RetryInterval)
				continue
			}

			c.controlChannel = conn
			c.logger.Info("control channel established successfully")
			c.config.TunnelStatus = fmt.Sprintf("Connected (%s)", c.config.Mode)

			// Start connection pool maintainer
			go c.maintainConnectionPool()

			// Handle control channel - this will block until error or context cancellation
			c.handleControlChannel()

			// If we reach here, control channel was lost
			c.logger.Warn("control channel lost, attempting to reconnect...")
			c.config.TunnelStatus = fmt.Sprintf("Reconnecting (%s)", c.config.Mode)
			time.Sleep(c.config.RetryInterval)
		}
	}
}

func (c *HttpCdnClient) maintainConnectionPool() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			currentPoolSize := len(c.connPool)
			if currentPoolSize < c.config.ConnPoolSize {
				// Create new connections to fill the pool
				for i := currentPoolSize; i < c.config.ConnPoolSize; i++ {
					go func() {
						conn, err := c.dial(fmt.Sprintf("/tunnel/%s", uuid.New().String()))
						if err != nil {
							c.logger.Debugf("failed to dial for connection pool: %v", err)
							return
						}

						// Try to add to pool with timeout
						select {
						case c.connPool <- conn:
							c.logger.Debugf("added connection to pool, current size: %d", len(c.connPool))
						case <-time.After(100 * time.Millisecond):
							// Pool is full, close the connection
							conn.Close()
						case <-c.ctx.Done():
							conn.Close()
							return
						}
					}()
				}
			}
		}
	}
}

func (c *HttpCdnClient) handleControlChannel() {
	messageChan := make(chan byte, 10)

	// Goroutine to continuously read from control channel
	go func() {
		defer close(messageChan)
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
				if c.controlChannel == nil {
					return
				}

				// Set read timeout to prevent blocking indefinitely
				c.controlChannel.SetReadDeadline(time.Now().Add(30 * time.Second))
				msg, err := utils.ReceiveBinaryByte(c.controlChannel)
				if err != nil {
					if !isTimeoutError(err) {
						c.logger.Errorf("failed to read from control channel: %v", err)
					}
					return
				}

				select {
				case messageChan <- msg:
				case <-c.ctx.Done():
					return
				}
			}
		}
	}()

	// Send initial heartbeat
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				if c.controlChannel != nil {
					c.controlChannel.SetWriteDeadline(time.Now().Add(5 * time.Second))
					err := utils.SendBinaryByte(c.controlChannel, utils.SG_HB)
					c.controlChannel.SetWriteDeadline(time.Time{})
					if err != nil {
						c.logger.Debugf("failed to send heartbeat: %v", err)
						return
					}
				}
			}
		}
	}()

	for {
		select {
		case <-c.ctx.Done():
			if c.controlChannel != nil {
				utils.SendBinaryByte(c.controlChannel, utils.SG_Closed)
			}
			return
		case msg, ok := <-messageChan:
			if !ok {
				// Control channel closed
				return
			}

			switch msg {
			case utils.SG_Chan:
				// Server requesting new tunnel connection
				go func() {
					select {
					case conn := <-c.connPool:
						c.handleConnection(conn)
					case <-time.After(100 * time.Millisecond):
						// No connection available in pool, create new one
						conn, err := c.dial(fmt.Sprintf("/tunnel/%s", uuid.New().String()))
						if err != nil {
							c.logger.Errorf("failed to dial new tunnel connection: %v", err)
							return
						}
						c.handleConnection(conn)
					}
				}()
			case utils.SG_HB:
				// Heartbeat received, no action needed
				c.logger.Trace("heartbeat received from server")
			case utils.SG_Closed:
				c.logger.Warn("control channel closed by server")
				return
			default:
				c.logger.Warnf("received unknown message type: %d", msg)
			}
		}
	}
}

func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

func (c *HttpCdnClient) handleConnection(conn net.Conn) {
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	// Set timeout for receiving remote address
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	remoteAddr, transport, err := utils.ReceiveBinaryTransportString(conn)
	conn.SetReadDeadline(time.Time{})

	if err != nil {
		if err != io.EOF {
			c.logger.Errorf("failed to get remote address: %v", err)
		}
		return
	}

	if transport != utils.SG_TCP {
		c.logger.Errorf("invalid transport type: %d", transport)
		return
	}

	c.logger.Debugf("received tunnel request for: %s", remoteAddr)

	// Parse port for monitoring
	port := 0
	if portStr := strings.Split(remoteAddr, ":"); len(portStr) > 1 {
		if p, err := strconv.Atoi(portStr[1]); err == nil {
			port = p
		}
	}

	// Set timeout for local connection
	localDialer := &net.Dialer{
		Timeout:   c.config.DialTimeOut,
		KeepAlive: c.config.KeepAlive,
	}

	localConn, err := localDialer.Dial("tcp", remoteAddr)
	if err != nil {
		c.logger.Errorf("failed to dial local service at %s: %v", remoteAddr, err)
		return
	}

	// Set TCP options for local connection
	if tcpConn, ok := localConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(c.config.KeepAlive)
	}

	c.logger.Debugf("successfully connected to local service: %s", remoteAddr)

	// Use the connection handler with proper monitoring
	utils.TCPConnectionHandler(conn, localConn, c.logger, c.usageMonitor, port, c.config.Sniffer)
}
