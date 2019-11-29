package wsproxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 102400
)

// MethodOverrideParam defines the special URL parameter that is translated into the subsequent proxied streaming http request's method.
//
// Deprecated: it is preferable to use the Options parameters to WebSocketProxy to supply parameters.
var MethodOverrideParam = "method"

// TokenCookieName defines the cookie name that is translated to an 'Authorization: Bearer' header in the streaming http request's headers.
//
// Deprecated: it is preferable to use the Options parameters to WebSocketProxy to supply parameters.
var TokenCookieName = "token"

// RequestMutatorFunc can supply an alternate outgoing request.
type RequestMutatorFunc func(incoming *http.Request, outgoing *http.Request) *http.Request

type RequestParamsToBodyFunc func(incoming *http.Request, outgoing *http.Request) []byte

// Proxy provides websocket transport upgrade to compatible endpoints.
type Proxy struct {
	h                   http.Handler
	logger              Logger
	methodOverrideParam string
	tokenCookieName     string
	requestMutator      RequestMutatorFunc
	requestParamsToBody RequestParamsToBodyFunc
	headerForwarder     func(header string) bool
}

// Logger collects log messages.
type Logger interface {
	Warnln(...interface{})
	Debugln(...interface{})
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !websocket.IsWebSocketUpgrade(r) {
		p.h.ServeHTTP(w, r)
		return
	}
	p.proxy(w, r)
}

// Option allows customization of the proxy.
type Option func(*Proxy)

// WithMethodParamOverride allows specification of the special http parameter that is used in the proxied streaming request.
func WithMethodParamOverride(param string) Option {
	return func(p *Proxy) {
		p.methodOverrideParam = param
	}
}

// WithTokenCookieName allows specification of the cookie that is supplied as an upstream 'Authorization: Bearer' http header.
func WithTokenCookieName(param string) Option {
	return func(p *Proxy) {
		p.tokenCookieName = param
	}
}

// WithRequestMutator allows a custom RequestMutatorFunc to be supplied.
func WithRequestMutator(fn RequestMutatorFunc) Option {
	return func(p *Proxy) {
		p.requestMutator = fn
	}
}

// WithLogger allows a custom FieldLogger to be supplied
func WithRequestParamsToBody(fn RequestParamsToBodyFunc) Option {
	return func(p *Proxy) {
		p.requestParamsToBody = fn
	}
}

// WithForwardedHeaders allows controlling which headers are forwarded.
func WithForwardedHeaders(fn func(header string) bool) Option {
	return func(p *Proxy) {
		p.headerForwarder = fn
	}
}

// WithLogger allows a custom FieldLogger to be supplied
func WithLogger(logger Logger) Option {
	return func(p *Proxy) {
		p.logger = logger
	}
}

var defaultHeadersToForward = map[string]bool{
	"Origin":  true,
	"origin":  true,
	"Referer": true,
	"referer": true,
}

func defaultHeaderForwarder(header string) bool {
	return defaultHeadersToForward[header]
}

// WebsocketProxy attempts to expose the underlying handler as a bidi websocket stream with newline-delimited
// JSON as the content encoding.
//
// The HTTP Authorization header is either populated from the Sec-Websocket-Protocol field or by a cookie.
// The cookie name is specified by the TokenCookieName value.
//
// example:
//   Sec-Websocket-Protocol: Bearer, foobar
// is converted to:
//   Authorization: Bearer foobar
//
// Method can be overwritten with the MethodOverrideParam get parameter in the requested URL
func WebsocketProxy(h http.Handler, opts ...Option) http.Handler {
	p := &Proxy{
		h:                   h,
		logger:              logrus.New(),
		methodOverrideParam: MethodOverrideParam,
		tokenCookieName:     TokenCookieName,
		headerForwarder:     defaultHeaderForwarder,
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// TODO(tmc): allow modification of upgrader settings?
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func isClosedConnError(err error) bool {
	str := err.Error()
	if strings.Contains(str, "use of closed network connection") {
		return true
	}
	return websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway)
}

func (p *Proxy) proxy(w http.ResponseWriter, r *http.Request) {
	var responseHeader http.Header
	// If Sec-WebSocket-Protocol starts with "Bearer", respond in kind.
	// TODO(tmc): consider customizability/extension point here.
	if strings.HasPrefix(r.Header.Get("Sec-WebSocket-Protocol"), "Bearer") {
		responseHeader = http.Header{
			"Sec-WebSocket-Protocol": []string{"Bearer"},
		}
	}
	conn, err := upgrader.Upgrade(w, r, responseHeader)
	if err != nil {
		p.logger.Warnln("error upgrading websocket:", err)
		return
	}
	defer func() {
		p.logger.Debugln("closing connection")
		conn.Close()
	}()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	requestBodyR, requestBodyW := io.Pipe()
	request, err := http.NewRequest(r.Method, r.URL.String(), requestBodyR)
	if err != nil {
		p.logger.Warnln("error preparing request:", err)
		return
	}

	request = request.WithContext(ctx)

	if swsp := r.Header.Get("Sec-WebSocket-Protocol"); swsp != "" {
		request.Header.Set("Authorization", transformSubProtocolHeader(swsp))
	}
	for header := range r.Header {
		if p.headerForwarder(header) {
			request.Header.Set(header, r.Header.Get(header))
		}
	}
	// If token cookie is present, populate Authorization header from the cookie instead.
	if cookie, err := r.Cookie(p.tokenCookieName); err == nil {
		request.Header.Set("Authorization", "Bearer "+cookie.Value)
	}
	if m := r.URL.Query().Get(p.methodOverrideParam); m != "" {
		request.Method = m
	}

	if p.requestMutator != nil {
		request = p.requestMutator(r, request)
	}

	if p.requestParamsToBody != nil {
		//Write is blocking operation and it must be done in another routine
		//Unfortunately this breaks bidirectional streaming
		go func() {
			//JSONIZE PARAMS
			bytes := p.requestParamsToBody(r, request)
			p.logger.Debugln("Writing params in body as", string(bytes))
			requestBodyW.Write(bytes)
			requestBodyW.Write([]byte("\n"))
			p.logger.Debugln("Writing finished")
			// requestBodyW.Close() //You must close it if is a single stream
		}()
	}

	responseBodyR, responseBodyW := io.Pipe()
	response := newInMemoryResponseWriter(responseBodyW)
	go func() {
		<-ctx.Done()
		p.logger.Debugln("closing pipes")
		requestBodyW.CloseWithError(io.EOF)
		responseBodyW.CloseWithError(io.EOF)
		response.closed <- true
	}()

	go func() {
		defer cancelFn()

		p.logger.Debugln("serving http...")
		p.h.ServeHTTP(response, request)
		p.logger.Debugln("serving http...done")
	}()

	// read loop -- take messages from websocket and write to http request
	go func() {
		defer func() {
			cancelFn()
		}()

		// conn.SetReadLimit(wsc.MaxMessageSize)
		conn.SetReadDeadline(time.Now().Add(pongWait))
		conn.SetPongHandler(func(string) error {
			p.logger.Debugln("[read] pong")
			conn.SetReadDeadline(time.Now().Add(pongWait))
			return nil
		})

		for {
			select {
			case <-ctx.Done():
				p.logger.Debugln("read loop done")
				return
			default:
			}
			p.logger.Debugln("[read] reading from socket.")

			_, payload, err := conn.ReadMessage()
			if err != nil {
				if isClosedConnError(err) {
					p.logger.Debugln("[read] websocket closed:", err)
					return
				}
				p.logger.Warnln("error reading websocket message:", err)
				return
			}

			p.logger.Debugln("[read] read payload:", string(payload))
			if len(payload) == 0 {
				p.logger.Debugln("[read] skiping empty payload")
				continue
			}

			p.logger.Debugln("[read] writing to requestBody:")
			n, err := requestBodyW.Write(payload)
			requestBodyW.Write([]byte("\n"))
			p.logger.Debugln("[read] wrote to requestBody", n)
			if err != nil {
				p.logger.Warnln("[read] error writing message to upstream http server:", err)
				return
			}
		}
	}()
	// write loop -- take messages from response and write to websocket
	scanner := bufio.NewScanner(responseBodyR)
	ticker := time.NewTicker(pingPeriod)
	writechan := make(chan []byte)

	go func() {
		for scanner.Scan() {
			if len(scanner.Bytes()) == 0 {
				p.logger.Warnln("[scan] empty scan")
				continue
			}

			errgrpc := struct {
				Error interface{} `json:"error"`
			}{}

			if err := json.Unmarshal(scanner.Bytes(), &errgrpc); err != nil && errgrpc.Error != nil {
				p.logger.Warnln("[write] grpc error detected :", errgrpc.Error)
				break
			}

			p.logger.Debugln("[scan] scanned", scanner.Text())
			writechan <- scanner.Bytes()
		}

		if err := scanner.Err(); err != nil {
			p.logger.Warnln("scanner err:", err)
		}
		close(writechan)
	}()

	for {
		select {
		case bytes, more := <-writechan:
			if !more {
				return
			}
			conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err = conn.WriteMessage(websocket.TextMessage, bytes); err != nil {
				p.logger.Warnln("[write] error writing websocket message:", err)
				return
			}
		case <-ticker.C:
			p.logger.Debugln("[write] ping")
			conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := conn.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				return
			}
		}
	}
}

type inMemoryResponseWriter struct {
	io.Writer
	header http.Header
	code   int
	closed chan bool
}

func newInMemoryResponseWriter(w io.Writer) *inMemoryResponseWriter {
	return &inMemoryResponseWriter{
		Writer: w,
		header: http.Header{},
		closed: make(chan bool, 1),
	}
}

// IE and Edge do not delimit Sec-WebSocket-Protocol strings with spaces
func transformSubProtocolHeader(header string) string {
	tokens := strings.SplitN(header, "Bearer,", 2)

	if len(tokens) < 2 {
		return ""
	}

	return fmt.Sprintf("Bearer %v", strings.Trim(tokens[1], " "))
}

func (w *inMemoryResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}
func (w *inMemoryResponseWriter) Header() http.Header {
	return w.header
}
func (w *inMemoryResponseWriter) WriteHeader(code int) {
	w.code = code
}
func (w *inMemoryResponseWriter) CloseNotify() <-chan bool {
	return w.closed
}
func (w *inMemoryResponseWriter) Flush() {}
