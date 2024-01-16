package nsq

import (
	"bufio"
	"bytes"
	"compress/flate"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/snappy"
)

// IdentifyResponse represents the metadata
// returned from an IDENTIFY command to nsqd
type IdentifyResponse struct {
	// 表示消费者可以设置的最大RDY（Ready）计数，即可以同时处理的最大消息数量
	MaxRdyCount int64 `json:"max_rdy_count"`
	// 表示是否启用了TLS v1.0
	TLSv1 bool `json:"tls_v1"`
	// 表示是否启用了Deflate压缩
	Deflate bool `json:"deflate"`
	// 表示是否启用了Snappy压缩
	Snappy       bool `json:"snappy"`
	AuthRequired bool `json:"auth_required"`
}

// AuthResponse represents the metadata
// returned from an AUTH command to nsqd
type AuthResponse struct {
	Identity        string `json:"identity"`
	IdentityUrl     string `json:"identity_url"`
	PermissionCount int64  `json:"permission_count"`
}

type msgResponse struct {
	msg     *Message
	cmd     *Command
	success bool
	backoff bool
}

// Conn represents a connection to nsqd
//
// Conn exposes a set of callbacks for the
// various events that occur on a connection
// 代表客户端和 nsqd 之间的一条连接
type Conn struct {
	// 64bit atomic vars need to be first for proper alignment on 32bit platforms
	// InFlight 表示客户端已经收到消息，但还未响应服务端 ACK
	// 这里记录有多少条消息还未 ACK
	messagesInFlight int64
	// 单连接的最大 RDY 值
	maxRdyCount int64
	// 此连接的当前 RDY 值
	rdyCount int64
	// 最近一次将 RDY 更新为非 0 值的时间
	lastRdyTimestamp int64
	// 最近一次接收到消息的时间
	lastMsgTimestamp int64

	// 保护临界资源
	mtx sync.Mutex

	config *Config

	// 真正的 TCP 连接
	conn    *net.TCPConn
	tlsConn *tls.Conn
	// 连接的服务端地址
	addr string

	// 回调代理
	// 消费者和生产者有不同的回调代理，底层 Conn 从 tcp 流中读取到数据包后，会根据不同的包类型调用不同的回调函数，将底层的事件报告给消费者和生产者
	delegate ConnDelegate

	logger   []logger
	logLvl   LogLevel
	logFmt   []string
	logGuard sync.RWMutex

	// 读写的入口，其实就是底层的 TCP 连接
	r io.Reader
	w io.Writer

	// 用于接收用户指令的 channel，writeLoop 协程会从 cmdChan 取出指令数据，通过 tcp 连接发送到服务端
	cmdChan chan *Command
	// 消费者收到消息后，会对消息进行确认(FIN 和 REQ)，确认的信息暂存到 msgResponseChan，由 writeLoop 协程处理
	msgResponseChan chan *msgResponse
	// 用于控制写协程退出
	exitChan   chan int
	drainReady chan int

	closeFlag int32
	stopper   sync.Once
	// 保证所有的协程都执行结束才能关闭连接
	wg sync.WaitGroup

	readLoopRunning int32
}

// NewConn returns a new Conn instance
func NewConn(addr string, config *Config, delegate ConnDelegate) *Conn {
	if !config.initialized {
		panic("Config must be created with NewConfig()")
	}
	return &Conn{
		addr: addr,

		config:   config,
		delegate: delegate,

		maxRdyCount:      2500,
		lastMsgTimestamp: time.Now().UnixNano(),

		cmdChan:         make(chan *Command),
		msgResponseChan: make(chan *msgResponse),
		exitChan:        make(chan int),
		drainReady:      make(chan int),

		logger: make([]logger, LogLevelMax+1),
		logFmt: make([]string, LogLevelMax+1),
	}
}

// SetLogger assigns the logger to use as well as a level.
//
// The format parameter is expected to be a printf compatible string with
// a single %s argument.  This is useful if you want to provide additional
// context to the log messages that the connection will print, the default
// is '(%s)'.
//
// The logger parameter is an interface that requires the following
// method to be implemented (such as the the stdlib log.Logger):
//
//	Output(calldepth int, s string)
func (c *Conn) SetLogger(l logger, lvl LogLevel, format string) {
	c.logGuard.Lock()
	defer c.logGuard.Unlock()

	if format == "" {
		format = "(%s)"
	}
	for level := range c.logger {
		c.logger[level] = l
		c.logFmt[level] = format
	}
	c.logLvl = lvl
}

func (c *Conn) SetLoggerForLevel(l logger, lvl LogLevel, format string) {
	c.logGuard.Lock()
	defer c.logGuard.Unlock()

	if format == "" {
		format = "(%s)"
	}
	c.logger[lvl] = l
	c.logFmt[lvl] = format
}

// SetLoggerLevel sets the package logging level.
func (c *Conn) SetLoggerLevel(lvl LogLevel) {
	c.logGuard.Lock()
	defer c.logGuard.Unlock()

	c.logLvl = lvl
}

func (c *Conn) getLogger(lvl LogLevel) (logger, LogLevel, string) {
	c.logGuard.RLock()
	defer c.logGuard.RUnlock()

	return c.logger[lvl], c.logLvl, c.logFmt[lvl]
}

func (c *Conn) getLogLevel() LogLevel {
	c.logGuard.RLock()
	defer c.logGuard.RUnlock()

	return c.logLvl
}

// Connect dials and bootstraps the nsqd connection
// (including IDENTIFY) and returns the IdentifyResponse
// 客户端实际向服务端发起连接
func (c *Conn) Connect() (*IdentifyResponse, error) {
	// 向服务端发起 TCP 连接
	dialer := &net.Dialer{
		LocalAddr: c.config.LocalAddr,
		Timeout:   c.config.DialTimeout,
	}

	conn, err := dialer.Dial("tcp", c.addr)
	if err != nil {
		return nil, err
	}

	// 设置 Conn 结构重要字段
	c.conn = conn.(*net.TCPConn)
	c.r = conn
	c.w = conn

	_, err = c.Write(MagicV2)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("[%s] failed to write magic - %s", c.addr, err)
	}

	// 进行身份验证
	resp, err := c.identify()
	if err != nil {
		return nil, err
	}

	if resp != nil && resp.AuthRequired {
		if c.config.AuthSecret == "" {
			c.log(LogLevelError, "Auth Required")
			return nil, errors.New("Auth Required")
		}
		err := c.auth(c.config.AuthSecret)
		if err != nil {
			c.log(LogLevelError, "Auth Failed %s", err)
			return nil, err
		}
	}

	c.wg.Add(2)
	atomic.StoreInt32(&c.readLoopRunning, 1)

	// 这里启动两个 Loop 的优势在于:
	// 1.解耦发送和接收流程，能够更简单地实现双工通信
	// 2.通过 for-select 方式，保证两个 loop 能够在监听到退出指令时及时退出
	// 启动单独的协程接收服务端的响应
	go c.readLoop()
	// 启动单独的协程处理向服务端的请求
	go c.writeLoop()
	return resp, nil
}

// Close idempotently initiates connection close
func (c *Conn) Close() error {
	atomic.StoreInt32(&c.closeFlag, 1)
	if c.conn != nil && atomic.LoadInt64(&c.messagesInFlight) == 0 {
		return c.conn.CloseRead()
	}
	return nil
}

// IsClosing indicates whether or not the
// connection is currently in the processing of
// gracefully closing
func (c *Conn) IsClosing() bool {
	return atomic.LoadInt32(&c.closeFlag) == 1
}

// RDY returns the current RDY count
func (c *Conn) RDY() int64 {
	return atomic.LoadInt64(&c.rdyCount)
}

// LastRDY returns the previously set RDY count
func (c *Conn) LastRDY() int64 {
	return atomic.LoadInt64(&c.rdyCount)
}

// SetRDY stores the specified RDY count
func (c *Conn) SetRDY(rdy int64) {
	atomic.StoreInt64(&c.rdyCount, rdy)
	if rdy > 0 {
		atomic.StoreInt64(&c.lastRdyTimestamp, time.Now().UnixNano())
	}
}

// MaxRDY returns the nsqd negotiated maximum
// RDY count that it will accept for this connection
func (c *Conn) MaxRDY() int64 {
	return c.maxRdyCount
}

// LastRdyTime returns the time of the last non-zero RDY
// update for this connection
func (c *Conn) LastRdyTime() time.Time {
	return time.Unix(0, atomic.LoadInt64(&c.lastRdyTimestamp))
}

// LastMessageTime returns a time.Time representing
// the time at which the last message was received
func (c *Conn) LastMessageTime() time.Time {
	return time.Unix(0, atomic.LoadInt64(&c.lastMsgTimestamp))
}

// RemoteAddr returns the configured destination nsqd address
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// String returns the fully-qualified address
func (c *Conn) String() string {
	return c.addr
}

// Read performs a deadlined read on the underlying TCP connection
func (c *Conn) Read(p []byte) (int, error) {
	c.conn.SetReadDeadline(time.Now().Add(c.config.ReadTimeout))
	return c.r.Read(p)
}

// Write performs a deadlined write on the underlying TCP connection
func (c *Conn) Write(p []byte) (int, error) {
	c.conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout))
	return c.w.Write(p)
}

// WriteCommand is a goroutine safe method to write a Command
// to this connection, and flush.
func (c *Conn) WriteCommand(cmd *Command) error {
	c.mtx.Lock()

	_, err := cmd.WriteTo(c)
	if err != nil {
		goto exit
	}
	err = c.Flush()

exit:
	c.mtx.Unlock()
	if err != nil {
		c.log(LogLevelError, "IO error - %s", err)
		c.delegate.OnIOError(c, err)
	}
	return err
}

type flusher interface {
	Flush() error
}

// Flush writes all buffered data to the underlying TCP connection
func (c *Conn) Flush() error {
	if f, ok := c.w.(flusher); ok {
		return f.Flush()
	}
	return nil
}

func (c *Conn) identify() (*IdentifyResponse, error) {
	ci := make(map[string]interface{})
	ci["client_id"] = c.config.ClientID
	ci["hostname"] = c.config.Hostname
	ci["user_agent"] = c.config.UserAgent
	ci["short_id"] = c.config.ClientID // deprecated
	ci["long_id"] = c.config.Hostname  // deprecated
	ci["tls_v1"] = c.config.TlsV1
	ci["deflate"] = c.config.Deflate
	ci["deflate_level"] = c.config.DeflateLevel
	ci["snappy"] = c.config.Snappy
	ci["feature_negotiation"] = true
	if c.config.HeartbeatInterval == -1 {
		ci["heartbeat_interval"] = -1
	} else {
		ci["heartbeat_interval"] = int64(c.config.HeartbeatInterval / time.Millisecond)
	}
	ci["sample_rate"] = c.config.SampleRate
	ci["output_buffer_size"] = c.config.OutputBufferSize
	if c.config.OutputBufferTimeout == -1 {
		ci["output_buffer_timeout"] = -1
	} else {
		ci["output_buffer_timeout"] = int64(c.config.OutputBufferTimeout / time.Millisecond)
	}
	ci["msg_timeout"] = int64(c.config.MsgTimeout / time.Millisecond)
	cmd, err := Identify(ci)
	if err != nil {
		return nil, ErrIdentify{err.Error()}
	}

	err = c.WriteCommand(cmd)
	if err != nil {
		return nil, ErrIdentify{err.Error()}
	}

	frameType, data, err := ReadUnpackedResponse(c, c.config.MaxMsgSize)
	if err != nil {
		return nil, ErrIdentify{err.Error()}
	}

	if frameType == FrameTypeError {
		return nil, ErrIdentify{string(data)}
	}

	// check to see if the server was able to respond w/ capabilities
	// i.e. it was a JSON response
	// IDENTIFY 命令的响应是 json 格式
	if data[0] != '{' {
		return nil, nil
	}

	resp := &IdentifyResponse{}
	err = json.Unmarshal(data, resp)
	if err != nil {
		return nil, ErrIdentify{err.Error()}
	}

	c.log(LogLevelDebug, "IDENTIFY response: %+v", resp)

	c.maxRdyCount = resp.MaxRdyCount

	// 升级 TLS_v1
	if resp.TLSv1 {
		c.log(LogLevelInfo, "upgrading to TLS")
		err := c.upgradeTLS(c.config.TlsConfig)
		if err != nil {
			return nil, ErrIdentify{err.Error()}
		}
	}

	if resp.Deflate {
		c.log(LogLevelInfo, "upgrading to Deflate")
		err := c.upgradeDeflate(c.config.DeflateLevel)
		if err != nil {
			return nil, ErrIdentify{err.Error()}
		}
	}

	if resp.Snappy {
		c.log(LogLevelInfo, "upgrading to Snappy")
		err := c.upgradeSnappy()
		if err != nil {
			return nil, ErrIdentify{err.Error()}
		}
	}

	// now that connection is bootstrapped, enable read buffering
	// (and write buffering if it's not already capable of Flush())
	c.r = bufio.NewReader(c.r)
	if _, ok := c.w.(flusher); !ok {
		c.w = bufio.NewWriter(c.w)
	}

	return resp, nil
}

func (c *Conn) upgradeTLS(tlsConf *tls.Config) error {
	host, _, err := net.SplitHostPort(c.addr)
	if err != nil {
		return err
	}

	// create a local copy of the config to set ServerName for this connection
	conf := &tls.Config{}
	if tlsConf != nil {
		conf = tlsConf.Clone()
	}
	conf.ServerName = host

	// 将普通的 TCP 连接升级为 TLS 连接
	c.tlsConn = tls.Client(c.conn, conf)
	// 进行TLS握手
	err = c.tlsConn.Handshake()
	if err != nil {
		return err
	}
	// 替换掉原本的连接
	c.r = c.tlsConn
	c.w = c.tlsConn
	frameType, data, err := ReadUnpackedResponse(c, c.config.MaxMsgSize)
	if err != nil {
		return err
	}
	if frameType != FrameTypeResponse || !bytes.Equal(data, []byte("OK")) {
		return errors.New("invalid response from TLS upgrade")
	}
	return nil
}

func (c *Conn) upgradeDeflate(level int) error {
	conn := net.Conn(c.conn)
	if c.tlsConn != nil {
		conn = c.tlsConn
	}
	fw, _ := flate.NewWriter(conn, level)
	c.r = flate.NewReader(conn)
	c.w = fw
	frameType, data, err := ReadUnpackedResponse(c, c.config.MaxMsgSize)
	if err != nil {
		return err
	}
	if frameType != FrameTypeResponse || !bytes.Equal(data, []byte("OK")) {
		return errors.New("invalid response from Deflate upgrade")
	}
	return nil
}

func (c *Conn) upgradeSnappy() error {
	conn := net.Conn(c.conn)
	if c.tlsConn != nil {
		conn = c.tlsConn
	}
	c.r = snappy.NewReader(conn)
	c.w = snappy.NewWriter(conn)
	frameType, data, err := ReadUnpackedResponse(c, c.config.MaxMsgSize)
	if err != nil {
		return err
	}
	if frameType != FrameTypeResponse || !bytes.Equal(data, []byte("OK")) {
		return errors.New("invalid response from Snappy upgrade")
	}
	return nil
}

func (c *Conn) auth(secret string) error {
	cmd, err := Auth(secret)
	if err != nil {
		return err
	}

	err = c.WriteCommand(cmd)
	if err != nil {
		return err
	}

	frameType, data, err := ReadUnpackedResponse(c, c.config.MaxMsgSize)
	if err != nil {
		return err
	}

	if frameType == FrameTypeError {
		return errors.New("Error authenticating " + string(data))
	}

	resp := &AuthResponse{}
	err = json.Unmarshal(data, resp)
	if err != nil {
		return err
	}

	c.log(LogLevelInfo, "Auth accepted. Identity: %q %s Permissions: %d",
		resp.Identity, resp.IdentityUrl, resp.PermissionCount)

	return nil
}

func (c *Conn) readLoop() {
	delegate := &connMessageDelegate{c}
	for {
		if atomic.LoadInt32(&c.closeFlag) == 1 {
			goto exit
		}

		// 从底层TCP连接中读取响应数据，并确定消息类型、消息体
		frameType, data, err := ReadUnpackedResponse(c, c.config.MaxMsgSize)
		if err != nil {
			if err == io.EOF && atomic.LoadInt32(&c.closeFlag) == 1 {
				goto exit
			}
			if !strings.Contains(err.Error(), "use of closed network connection") {
				c.log(LogLevelError, "IO error - %s", err)
				c.delegate.OnIOError(c, err)
			}
			goto exit
		}

		// 心跳包类型(由 nsqd 服务发送给 consumer 的，生产者不会收到此类包)
		if frameType == FrameTypeResponse && bytes.Equal(data, []byte("_heartbeat_")) {
			c.log(LogLevelDebug, "heartbeat received")
			// 执行心跳消息回调，实际上 producer 和 consumer 执行的都是空操作
			c.delegate.OnHeartbeat(c)
			// 向 nsqd 响应心跳包
			err := c.WriteCommand(Nop())
			if err != nil {
				c.log(LogLevelError, "IO error - %s", err)
				c.delegate.OnIOError(c, err)
				goto exit
			}
			continue
		}

		// 其他响应消息处理
		switch frameType {
		case FrameTypeResponse:
			// 响应包类型
			// 客户端(生产者和消费者)向 nsqd 发送命令后，nsqd 服务会返回一个响应包，这里触发不同的回调
			// 对 producer，会将包的内容暂存到 responseChan 中，由 router 协程进行处理
			c.delegate.OnResponse(c, data)
		case FrameTypeMessage:
			// 消息包类型
			// nsqd 会将接收到的消息封装为此类包，发送给消费者。此处会触发 consumer 的回调(onConnMessage)，将消息暂存到 incomingMessages 中
			msg, err := DecodeMessage(data)
			if err != nil {
				c.log(LogLevelError, "IO error - %s", err)
				c.delegate.OnIOError(c, err)
				goto exit
			}
			// 设置 message 代理，msg 确认时会回调代理
			msg.Delegate = delegate
			msg.NSQDAddress = c.String()

			atomic.AddInt64(&c.messagesInFlight, 1)
			atomic.StoreInt64(&c.lastMsgTimestamp, time.Now().UnixNano())

			// 执行回调，仅限于 consumer，这里会调用 consumer 的onConnMessage方法，将解析出来的消息推入 incomingMessages
			c.delegate.OnMessage(c, msg)
		case FrameTypeError:
			// 错误包类型
			// nsqd 通过此类型包向生产者报告错误
			c.log(LogLevelError, "protocol error - %s", data)
			c.delegate.OnError(c, data)
		default:
			c.log(LogLevelError, "IO error - %s", err)
			c.delegate.OnIOError(c, fmt.Errorf("unknown frame type %d", frameType))
		}
	}

exit:
	atomic.StoreInt32(&c.readLoopRunning, 0)
	// start the connection close
	messagesInFlight := atomic.LoadInt64(&c.messagesInFlight)
	if messagesInFlight == 0 {
		// if we exited readLoop with no messages in flight
		// we need to explicitly trigger the close because
		// writeLoop won't
		c.close()
	} else {
		c.log(LogLevelWarning, "delaying close, %d outstanding messages", messagesInFlight)
	}
	c.wg.Done()
	c.log(LogLevelInfo, "readLoop exiting")
}

// 负责向服务端发送指令的常驻协程
func (c *Conn) writeLoop() {
	for {
		select {
		case <-c.exitChan:
			c.log(LogLevelInfo, "breaking out of writeLoop")
			// Indicate drainReady because we will not pull any more off msgResponseChan
			close(c.drainReady)
			goto exit
		case cmd := <-c.cmdChan:
			// 客户端发送的命令会写到 cmdChan 中，这里从中取出通过 TCP 连接发送到对端(只有 TOUCH 指令会通过 cmdChan 发送，其他指令都是直接写入到 TCP 流中)
			err := c.WriteCommand(cmd)
			if err != nil {
				c.log(LogLevelError, "error sending command %s - %s", cmd, err)
				c.close()
				continue
			}
		case resp := <-c.msgResponseChan:
			// 调用 Message.OnFinish/Message.Requeue 后，message 会回调代理的方法，最终调到 Conn 的方法，将  FIN/REQ 消息写入 msgResponseChan
			msgsInFlight := atomic.AddInt64(&c.messagesInFlight, -1)

			// success == true 表示 FIN 消息，success == false 表示 REQ 消息，这里根据不同类型选择调用不同的回调函数，如 OnMessageFinished 或者 OnMessageRequeued
			// 回调函数中会对计数值进行修改，如 OnMessageFinished 中会将 messagesFinished 计数赠加 1
			if resp.success {
				c.log(LogLevelDebug, "FIN %s", resp.msg.ID)
				c.delegate.OnMessageFinished(c, resp.msg)
				c.delegate.OnResume(c)
			} else {
				c.log(LogLevelDebug, "REQ %s", resp.msg.ID)
				c.delegate.OnMessageRequeued(c, resp.msg)
				if resp.backoff {
					c.delegate.OnBackoff(c)
				} else {
					c.delegate.OnContinue(c)
				}
			}

			// 将指令发往服务端
			err := c.WriteCommand(resp.cmd)
			if err != nil {
				c.log(LogLevelError, "error sending command %s - %s", resp.cmd, err)
				c.close()
				continue
			}

			if msgsInFlight == 0 &&
				atomic.LoadInt32(&c.closeFlag) == 1 {
				c.close()
				continue
			}
		}
	}

exit:
	c.wg.Done()
	c.log(LogLevelInfo, "writeLoop exiting")
}

func (c *Conn) close() {
	// a "clean" connection close is orchestrated as follows:
	//
	//     1. CLOSE cmd sent to nsqd
	//     2. CLOSE_WAIT response received from nsqd
	//     3. set c.closeFlag
	//     4. readLoop() exits
	//         a. if messages-in-flight > 0 delay close()
	//             i. writeLoop() continues receiving on c.msgResponseChan chan
	//                 x. when messages-in-flight == 0 call close()
	//         b. else call close() immediately
	//     5. c.exitChan close
	//         a. writeLoop() exits
	//             i. c.drainReady close
	//     6a. launch cleanup() goroutine (we're racing with intraprocess
	//        routed messages, see comments below)
	//         a. wait on c.drainReady
	//         b. loop and receive on c.msgResponseChan chan
	//            until messages-in-flight == 0
	//            i. ensure that readLoop has exited
	//     6b. launch waitForCleanup() goroutine
	//         b. wait on waitgroup (covers readLoop() and writeLoop()
	//            and cleanup goroutine)
	//         c. underlying TCP connection close
	//         d. trigger Delegate OnClose()
	//
	c.stopper.Do(func() {
		c.log(LogLevelInfo, "beginning close")
		close(c.exitChan)
		c.conn.CloseRead()

		c.wg.Add(1)
		go c.cleanup()

		go c.waitForCleanup()
	})
}

func (c *Conn) cleanup() {
	<-c.drainReady
	ticker := time.NewTicker(100 * time.Millisecond)
	lastWarning := time.Now()
	// writeLoop has exited, drain any remaining in flight messages
	for {
		// we're racing with readLoop which potentially has a message
		// for handling so infinitely loop until messagesInFlight == 0
		// and readLoop has exited
		var msgsInFlight int64
		select {
		case <-c.msgResponseChan:
			msgsInFlight = atomic.AddInt64(&c.messagesInFlight, -1)
		case <-ticker.C:
			msgsInFlight = atomic.LoadInt64(&c.messagesInFlight)
		}
		if msgsInFlight > 0 {
			if time.Since(lastWarning) > time.Second {
				c.log(LogLevelWarning, "draining... waiting for %d messages in flight", msgsInFlight)
				lastWarning = time.Now()
			}
			continue
		}
		// until the readLoop has exited we cannot be sure that there
		// still won't be a race
		if atomic.LoadInt32(&c.readLoopRunning) == 1 {
			if time.Since(lastWarning) > time.Second {
				c.log(LogLevelWarning, "draining... readLoop still running")
				lastWarning = time.Now()
			}
			continue
		}
		goto exit
	}

exit:
	ticker.Stop()
	c.wg.Done()
	c.log(LogLevelInfo, "finished draining, cleanup exiting")
}

func (c *Conn) waitForCleanup() {
	// this blocks until readLoop and writeLoop
	// (and cleanup goroutine above) have exited
	c.wg.Wait()
	c.conn.CloseWrite()
	c.log(LogLevelInfo, "clean close complete")
	c.delegate.OnClose(c)
}

func (c *Conn) onMessageFinish(m *Message) {
	c.msgResponseChan <- &msgResponse{msg: m, cmd: Finish(m.ID), success: true}
}

func (c *Conn) onMessageRequeue(m *Message, delay time.Duration, backoff bool) {
	// delay == -1 时，根据当前的尝试发送次数计算一个合适的退避时间
	if delay == -1 {
		// linear delay
		delay = c.config.DefaultRequeueDelay * time.Duration(m.Attempts)
		// bound the requeueDelay to configured max
		if delay > c.config.MaxRequeueDelay {
			delay = c.config.MaxRequeueDelay
		}
	}
	// 否则使用指定的退避时间
	c.msgResponseChan <- &msgResponse{msg: m, cmd: Requeue(m.ID, delay), success: false, backoff: backoff}
}

func (c *Conn) onMessageTouch(m *Message) {
	select {
	case c.cmdChan <- Touch(m.ID):
	case <-c.exitChan:
	}
}

func (c *Conn) log(lvl LogLevel, line string, args ...interface{}) {
	logger, logLvl, logFmt := c.getLogger(lvl)

	if logger == nil {
		return
	}

	if logLvl > lvl {
		return
	}

	logger.Output(2, fmt.Sprintf("%-4s %s %s", lvl,
		fmt.Sprintf(logFmt, c.String()),
		fmt.Sprintf(line, args...)))
}
