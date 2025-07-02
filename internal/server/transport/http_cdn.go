package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sahmadiut/backhaul/internal/config"
	"github.com/sahmadiut/backhaul/internal/utils"
	"github.com/sahmadiut/backhaul/internal/web"

	"github.com/sirupsen/logrus"
)

type HttpCdnTransport struct {
	config         *HttpCdnConfig
	parentctx      context.Context
	ctx            context.Context
	cancel         context.CancelFunc
	logger         *logrus.Logger
	tunnelChannel  chan net.Conn
	localChannel   chan LocalTCPConn
	reqNewConnChan chan struct{}
	controlChannel net.Conn
	restartMutex   sync.Mutex
	usageMonitor   *web.Usage
}

type HttpCdnConfig struct {
	BindAddr     string
	SnifferLog   string
	TLSCertFile  string
	TLSKeyFile   string
	TunnelStatus string
	Token        string
	Ports        []string
	Nodelay      bool
	Sniffer      bool
	KeepAlive    time.Duration
	Heartbeat    time.Duration
	ChannelSize  int
	WebPort      int
	Mode         config.TransportType
}

func NewHttpCdnServer(parentCtx context.Context, config *HttpCdnConfig, logger *logrus.Logger) *HttpCdnTransport {
	ctx, cancel := context.WithCancel(parentCtx)

	server := &HttpCdnTransport{
		config:         config,
		parentctx:      parentCtx,
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger,
		tunnelChannel:  make(chan net.Conn, config.ChannelSize),
		localChannel:   make(chan LocalTCPConn, config.ChannelSize),
		reqNewConnChan: make(chan struct{}, config.ChannelSize),
		controlChannel: nil,
		usageMonitor:   web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, &config.TunnelStatus, logger),
	}

	return server
}

func (s *HttpCdnTransport) Start() {
	if s.config.WebPort > 0 {
		go s.usageMonitor.Monitor()
	}

	s.config.TunnelStatus = fmt.Sprintf("Disconnected (%s)", s.config.Mode)

	go s.tunnelListener()
}

func (s *HttpCdnTransport) Restart() {
	if !s.restartMutex.TryLock() {
		s.logger.Warn("server restart already in progress, skipping restart attempt")
		return
	}
	defer s.restartMutex.Unlock()

	s.logger.Info("restarting server...")

	level := s.logger.Level
	s.logger.SetLevel(logrus.FatalLevel)

	if s.cancel != nil {
		s.cancel()
	}

	if s.controlChannel != nil {
		s.controlChannel.Close()
	}

	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithCancel(s.parentctx)
	s.ctx = ctx
	s.cancel = cancel

	s.tunnelChannel = make(chan net.Conn, s.config.ChannelSize)
	s.localChannel = make(chan LocalTCPConn, s.config.ChannelSize)
	s.reqNewConnChan = make(chan struct{}, s.config.ChannelSize)
	s.controlChannel = nil
	s.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", s.config.WebPort), ctx, s.config.SnifferLog, s.config.Sniffer, &s.config.TunnelStatus, s.logger)
	s.config.TunnelStatus = ""

	s.logger.SetLevel(level)

	go s.Start()
}

func (s *HttpCdnTransport) tunnelListener() {
	addr := s.config.BindAddr

	server := &http.Server{
		Addr:        addr,
		IdleTimeout: -1,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.logger.Tracef("received http request from %s for path %s", r.RemoteAddr, r.URL.Path)

			authHeader := r.Header.Get("Authorization")
			if authHeader != fmt.Sprintf("Bearer %v", s.config.Token) {
				s.logger.Warnf("unauthorized request from %s, closing connection", r.RemoteAddr)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				s.logger.Errorf("failed to hijack connection: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			resp := "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n"
			if _, err := conn.Write([]byte(resp)); err != nil {
				conn.Close()
				return
			}

			if strings.HasPrefix(r.URL.Path, "/control") {
				if s.controlChannel != nil {
					s.logger.Warn("new control channel requested, restarting server")
					s.controlChannel.Close()
					conn.Close()
					go s.Restart()
					return
				}
				s.controlChannel = conn
				s.logger.Info("control channel established successfully")

				numCPU := runtime.NumCPU()
				if numCPU > 4 {
					numCPU = 4
				}

				go s.channelHandler()
				go s.parsePortMappings()

				s.logger.Infof("starting %d handle loops on each CPU thread", numCPU)
				for i := 0; i < numCPU; i++ {
					go s.handleLoop()
				}
				s.config.TunnelStatus = fmt.Sprintf("Connected (%s)", s.config.Mode)
			} else if strings.HasPrefix(r.URL.Path, "/tunnel") {
				select {
				case s.tunnelChannel <- conn:
					s.logger.Debugf("http cdn connection accepted from %s", conn.RemoteAddr().String())
				default:
					s.logger.Warnf("http cdn tunnel channel is full, closing connection from %s", conn.RemoteAddr().String())
					conn.Close()
				}
			} else {
				s.logger.Warnf("invalid path requested: %s", r.URL.Path)
				conn.Close()
			}
		}),
	}

	if s.config.Mode == config.HTTPCDN {
		go func() {
			s.logger.Infof("http_cdn server starting, listening on %s", addr)
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				s.logger.Fatalf("failed to listen on %s: %v", addr, err)
			}
		}()
	} else { // https_cdn
		go func() {
			s.logger.Infof("https_cdn server starting, listening on %s", addr)
			if err := server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				s.logger.Fatalf("failed to listen on %s: %v", addr, err)
			}
		}()
	}

	<-s.ctx.Done()

	s.logger.Infof("shutting down the http server on %s", addr)
	if err := server.Shutdown(context.Background()); err != nil {
		s.logger.Errorf("Failed to gracefully shutdown the server: %v", err)
	}

	if s.controlChannel != nil {
		s.controlChannel.Close()
	}
}

func (s *HttpCdnTransport) channelHandler() {
	ticker := time.NewTicker(s.config.Heartbeat)
	defer ticker.Stop()

	messageChan := make(chan byte, 1)

	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			default:
				if s.controlChannel == nil {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				message, err := utils.ReceiveBinaryByte(s.controlChannel)
				if err != nil {
					if !strings.Contains(err.Error(), "use of closed network connection") {
						s.logger.Error("failed to read from channel connection. ", err)
					}
					go s.Restart()
					return
				}
				messageChan <- message
			}
		}
	}()

	for {
		select {
		case <-s.ctx.Done():
			if s.controlChannel != nil {
				_ = utils.SendBinaryByte(s.controlChannel, utils.SG_Closed)
			}
			return

		case <-s.reqNewConnChan:
			if s.controlChannel != nil {
				err := utils.SendBinaryByte(s.controlChannel, utils.SG_Chan)
				if err != nil {
					s.logger.Error("failed to send request new connection signal. ", err)
					go s.Restart()
					return
				}
			}

		case <-ticker.C:
			if s.controlChannel != nil {
				err := utils.SendBinaryByte(s.controlChannel, utils.SG_HB)
				if err != nil {
					s.logger.Error("failed to send heartbeat signal")
					go s.Restart()
					return
				}
				s.logger.Trace("heartbeat signal sent successfully")
			}

		case message, ok := <-messageChan:
			if !ok {
				s.logger.Error("channel closed, likely due to an error in TCP read")
				return
			}

			if message == utils.SG_Closed {
				s.logger.Warn("control channel has been closed by the client")
				go s.Restart()
				return
			}
		}
	}
}

func (s *HttpCdnTransport) parsePortMappings() {
	for _, portMapping := range s.config.Ports {
		parts := strings.Split(portMapping, "=")
		var localAddr, remoteAddr string
		if len(parts) == 1 {
			localPortOrRange := strings.TrimSpace(parts[0])
			remoteAddr = localPortOrRange
			if strings.Contains(localPortOrRange, "-") {
				rangeParts := strings.Split(localPortOrRange, "-")
				startPort, _ := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				endPort, _ := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				for port := startPort; port <= endPort; port++ {
					localAddr = fmt.Sprintf(":%d", port)
					go s.localListener(localAddr, strconv.Itoa(port))
					time.Sleep(1 * time.Millisecond)
				}
				continue
			} else {
				port, _ := strconv.Atoi(localPortOrRange)
				localAddr = fmt.Sprintf(":%d", port)
			}
		} else if len(parts) == 2 {
			localPortOrRange := strings.TrimSpace(parts[0])
			remoteAddr = strings.TrimSpace(parts[1])
			if strings.Contains(localPortOrRange, "-") {
				rangeParts := strings.Split(localPortOrRange, "-")
				startPort, _ := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				endPort, _ := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				for port := startPort; port <= endPort; port++ {
					localAddr = fmt.Sprintf(":%d", port)
					go s.localListener(localAddr, remoteAddr)
					time.Sleep(1 * time.Millisecond)
				}
				continue
			} else {
				port, err := strconv.Atoi(localPortOrRange)
				if err == nil {
					localAddr = fmt.Sprintf(":%d", port)
				} else {
					localAddr = localPortOrRange
				}
			}
		}
		go s.localListener(localAddr, remoteAddr)
	}
}

func (s *HttpCdnTransport) localListener(localAddr string, remoteAddr string) {
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		s.logger.Fatalf("failed to listen on %s: %v", localAddr, err)
		return
	}
	defer listener.Close()
	s.logger.Infof("listener started successfully, listening on address: %s", listener.Addr().String())
	go s.acceptLocalConn(listener, remoteAddr)
	<-s.ctx.Done()
}

func (s *HttpCdnTransport) acceptLocalConn(listener net.Listener, remoteAddr string) {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			select {
			case s.localChannel <- LocalTCPConn{conn: conn, remoteAddr: remoteAddr, timeCreated: time.Now().UnixMilli()}:
				select {
				case s.reqNewConnChan <- struct{}{}:
				default:
					s.logger.Warn("channel is full, cannot request a new connection")
				}
			default:
				conn.Close()
			}
		}
	}
}

func (s *HttpCdnTransport) handleLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case localConn := <-s.localChannel:
			s.reqNewConnChan <- struct{}{} // Request a new tunnel connection
			s.logger.Debugf("received new local connection from %s, waiting for tunnel connection", localConn.conn.RemoteAddr().String())

			select {
			case <-s.ctx.Done():
				return
			case tunnelConn := <-s.tunnelChannel:
				s.logger.Debugf("received new tunnel connection from %s, starting to proxy", tunnelConn.RemoteAddr().String())
				// Send remote address to client
				err := utils.SendBinaryTransportString(tunnelConn, localConn.remoteAddr, utils.SG_TCP)
				if err != nil {
					s.logger.Errorf("failed to send remote address to tunnel connection: %v", err)
					tunnelConn.Close()
					localConn.conn.Close()
					return
				}
				// Handle the connection (e.g., proxy data)
				go utils.TCPConnectionHandler(tunnelConn, localConn.conn, s.logger, s.usageMonitor, 0, false)
			case <-time.After(10 * time.Second): // 10s timeout
				s.logger.Warnf("no tunnel connection received within 10 seconds for local connection from %s, closing connection", localConn.conn.RemoteAddr().String())
				localConn.conn.Close()
			}
		}
	}
}
