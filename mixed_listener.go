package main

import (
	"bufio"
	"fmt"
	"net"
	"time"
)

// bufferedConn 允许我们读取并缓存前几个字节，以便后续代理逻辑无缝消费整个流。
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// mixedListener 接受一个原始的监听器，并将其细分为 SOCKS5 和 HTTP/GUI 两个虚拟监听器。
type mixedListener struct {
	net.Listener
	socksChan chan net.Conn
	httpChan  chan net.Conn
	done      chan struct{}
}

func newMixedListener(inner net.Listener) *mixedListener {
	ml := &mixedListener{
		Listener:  inner,
		socksChan: make(chan net.Conn, 1024),
		httpChan:  make(chan net.Conn, 1024),
		done:      make(chan struct{}),
	}
	go ml.sniffLoop()
	return ml
}

func (ml *mixedListener) sniffLoop() {
	for {
		conn, err := ml.Listener.Accept()
		if err != nil {
			select {
			case <-ml.done:
				return
			default:
				// 如果外部 Listener 关闭了，在此退出
				return
			}
		}

		go ml.sniff(conn)
	}
}

func (ml *mixedListener) sniff(conn net.Conn) {
	// 设置嗅探超时，避免挂起客户端
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	br := bufio.NewReader(conn)
	firstByte, err := br.Peek(1)
	_ = conn.SetReadDeadline(time.Time{}) // 重置超时

	if err != nil {
		conn.Close()
		return
	}

	bconn := &bufferedConn{
		Conn:   conn,
		reader: br,
	}

	// SOCKS5 握手包以 0x05 开始
	if firstByte[0] == 0x05 {
		select {
		case ml.socksChan <- bconn:
		default:
			bconn.Close()
		}
	} else {
		// HTTP 动词 (GET, POST, CONNECT) 或者其他，交给 HTTP/GUI 处理
		select {
		case ml.httpChan <- bconn:
		default:
			bconn.Close()
		}
	}
}

// Close 关闭混合侦听器
func (ml *mixedListener) Close() error {
	close(ml.done)
	err := ml.Listener.Close()
	// 关闭内部通道以唤醒 Accept
	close(ml.socksChan)
	close(ml.httpChan)
	return err
}

// SOCKSListener 返回一个专门生产 SOCKS5 连接的 net.Listener
func (ml *mixedListener) SOCKSListener() net.Listener {
	return &virtualListener{
		addr:      ml.Listener.Addr(),
		connChan:  ml.socksChan,
		closeChan: ml.done,
	}
}

// HTTPListener 返回一个专门生产 HTTP/GUI 连接的 net.Listener
func (ml *mixedListener) HTTPListener() net.Listener {
	return &virtualListener{
		addr:      ml.Listener.Addr(),
		connChan:  ml.httpChan,
		closeChan: ml.done,
	}
}

// virtualListener 实现了 net.Listener 接口，提供给各自 Server
type virtualListener struct {
	addr      net.Addr
	connChan  chan net.Conn
	closeChan chan struct{}
}

func (vl *virtualListener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-vl.connChan:
		if !ok {
			return nil, fmt.Errorf("listener closed")
		}
		return conn, nil
	case <-vl.closeChan:
		return nil, fmt.Errorf("listener closed")
	}
}

func (vl *virtualListener) Close() error {
	return nil
}

func (vl *virtualListener) Addr() net.Addr {
	return vl.addr
}
