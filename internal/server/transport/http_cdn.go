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

type HttpCdnServer struct {
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

func NewHttpCdnServer(parentCtx context.Context, config *HttpCdnConfig, logger *logrus.Logger) *HttpCdnServer {
	ctx, cancel := context.WithCancel(parentCtx)
	server := &HttpCdnServer{
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

func (s *HttpCdnServer) Start() {
	if s.config.WebPort > 0 {
		go s.usageMonitor.Monitor()
	}

	s.config.TunnelStatus = fmt.Sprintf("Disconnected (%s)", s.config.Mode)
	go s.tunnelListener()
}

func (s *HttpCdnServer) Restart() {
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

func (s *HttpCdnServer) tunnelListener() {
	addr := s.config.BindAddr

	server := &http.Server{
		Addr:        addr,
		Handler:     http.HandlerFunc(s.handleHttpRequest),
		IdleTimeout: 0, // Disable idle timeout for long-lived hijacked connections
	}

	go func() {
		s.logger.Infof("%s server starting, listening on %s", s.config.Mode, addr)
		var err error
		if s.config.Mode == config.HTTPCDN {
			err = server.ListenAndServe()
		} else { // https_cdn
			err = server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
		}
		if err != nil && err != http.ErrServerClosed {
			s.logger.Fatalf("failed to listen on %s: %v", addr, err)
		}
	}()

	<-s.ctx.Done()

	s.logger.Infof("shutting down the http server on %s", addr)
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		s.logger.Errorf("failed to gracefully shutdown the server: %v", err)
	}
	if s.controlChannel != nil {
		s.controlChannel.Close()
	}
}

func (s *HttpCdnServer) handleHttpRequest(w http.ResponseWriter, r *http.Request) {
	s.logger.Tracef("received http request from %s for path %s", r.RemoteAddr, r.URL.Path)

	if authHeader := r.Header.Get("Authorization"); authHeader != fmt.Sprintf("Bearer %v", s.config.Token) {
		s.logger.Warnf("unauthorized request from %s, closing connection", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if !strings.EqualFold(r.Header.Get("Upgrade"), "tcp") || !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		s.logger.Warnf("bad upgrade request from %s", r.RemoteAddr)
		http.Error(w, "Bad Request: requires 'Upgrade: tcp' and 'Connection: Upgrade' headers", http.StatusBadRequest)
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

	// Manually write the 101 Switching Protocols response.
	response := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"
	if _, err := conn.Write([]byte(response)); err != nil {
		s.logger.Errorf("failed to write upgrade response: %v", err)
		conn.Close()
		return
	}

	if strings.HasPrefix(r.URL.Path, "/control") {
		s.handleControlConnection(conn)
	} else if strings.HasPrefix(r.URL.Path, "/tunnel") {
		s.handleTunnelConnection(conn)
	} else {
		s.logger.Warnf("invalid path requested: %s", r.URL.Path)
		conn.Close()
	}
}

func (s *HttpCdnServer) handleControlConnection(conn net.Conn) {
	if s.controlChannel != nil {
		s.logger.Warn("new control channel requested while one is active, restarting server")
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

	s.logger.Infof("starting %d handle loops", numCPU)
	for i := 0; i < numCPU; i++ {
		go s.handleLoop()
	}
	s.config.TunnelStatus = fmt.Sprintf("Connected (%s)", s.config.Mode)
}

func (s *HttpCdnServer) handleTunnelConnection(conn net.Conn) {
	select {
	case s.tunnelChannel <- conn:
		s.logger.Debugf("http cdn tunnel connection accepted from %s", conn.RemoteAddr().String())
	case <-s.ctx.Done():
		conn.Close()
	default:
		s.logger.Warnf("http cdn tunnel channel is full, closing new connection from %s", conn.RemoteAddr().String())
		conn.Close()
	}
}

func (s *HttpCdnServer) channelHandler() {
	ticker := time.NewTicker(s.config.Heartbeat)
	defer ticker.Stop()

	messageChan := make(chan byte, 1)
	go func() {
		defer close(messageChan)
		for {
			if s.controlChannel == nil {
				return
			}
			s.controlChannel.SetReadDeadline(time.Now().Add(s.config.Heartbeat + 5*time.Second))
			msg, err := utils.ReceiveBinaryByte(s.controlChannel)
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					s.logger.Errorf("failed to read from control channel, restarting: %v", err)
				}
				go s.Restart()
				return
			}
			s.controlChannel.SetReadDeadline(time.Time{})
			messageChan <- msg
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
					s.logger.Error("failed to send request new connection signal, restarting. ", err)
					go s.Restart()
					return
				}
			}
		case <-ticker.C:
			if s.controlChannel != nil {
				err := utils.SendBinaryByte(s.controlChannel, utils.SG_HB)
				if err != nil {
					s.logger.Error("failed to send heartbeat signal, restarting. ", err)
					go s.Restart()
					return
				}
				s.logger.Trace("heartbeat signal sent successfully")
			}
		case message, ok := <-messageChan:
			if !ok {
				return
			}
			if message == utils.SG_Closed {
				s.logger.Warn("control channel has been closed by the client, restarting.")
				go s.Restart()
				return
			} else if message == utils.SG_HB {
				s.logger.Trace("heartbeat from client received")
			}
		}
	}
}

func (s *HttpCdnServer) parsePortMappings() {
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

func (s *HttpCdnServer) localListener(localAddr string, remoteAddr string) {
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

func (s *HttpCdnServer) acceptLocalConn(listener net.Listener, remoteAddr string) {
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

func (s *HttpCdnServer) handleLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case localConn := <-s.localChannel:
			select {
			case s.reqNewConnChan <- struct{}{}:
			default:
				s.logger.Warn("request new connection channel is full, might lead to connection starvation")
			}
			s.logger.Debugf("received new local connection from %s, waiting for tunnel", localConn.conn.RemoteAddr())

			select {
			case <-s.ctx.Done():
				localConn.conn.Close()
				return
			case tunnelConn := <-s.tunnelChannel:
				s.logger.Debugf("paired local connection with tunnel from %s, starting proxy", tunnelConn.RemoteAddr())
				err := utils.SendBinaryTransportString(tunnelConn, localConn.remoteAddr, utils.SG_TCP)
				if err != nil {
					s.logger.Errorf("failed to send remote address to tunnel: %v", err)
					tunnelConn.Close()
					localConn.conn.Close()
					continue
				}
				portStr, _, _ := net.SplitHostPort(localConn.conn.LocalAddr().String())
				port, _ := strconv.Atoi(portStr)
				go utils.TCPConnectionHandler(tunnelConn, localConn.conn, s.logger, s.usageMonitor, port, s.config.Sniffer)
			case <-time.After(10 * time.Second):
				s.logger.Warnf("timeout: no tunnel connection available for local conn from %s, closing", localConn.conn.RemoteAddr())
				localConn.conn.Close()
			}
		}
	}
}
