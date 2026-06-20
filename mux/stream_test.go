package mux

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	"time"
)

// --- 生命周期 / 边界用例 ---

// 1. Close 唤醒阻塞中的 Read，并返回 EOF。
func TestCloseWakesRead(t *testing.T) {
	s := NewStream(nil, Config{})
	res := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := s.Read(buf)
		res <- err
	}()
	time.Sleep(50 * time.Millisecond) // 确保已阻塞在 Read
	_ = s.Close()
	select {
	case err := <-res:
		if err != io.EOF {
			t.Fatalf("expected io.EOF, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close 未唤醒阻塞的 Read")
	}
}

// 2. Close 唤醒阻塞中的 Write，返回已写字节数 + ErrClosedPipe。
func TestCloseWakesWrite(t *testing.T) {
	const window = 4096
	s := NewStream(nil, Config{WindowSize: window, MaxChunk: window, SendData: func([]byte) {}})

	type wr struct {
		n   int
		err error
	}
	res := make(chan wr, 1)
	go func() {
		n, err := s.Write(make([]byte, window*2)) // 第一个窗口写满后阻塞
		res <- wr{n, err}
	}()
	time.Sleep(50 * time.Millisecond)
	_ = s.Close()
	select {
	case r := <-res:
		if r.err != io.ErrClosedPipe {
			t.Fatalf("expected ErrClosedPipe, got %v", r.err)
		}
		if r.n != window {
			t.Fatalf("expected written=%d, got %d", window, r.n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close 未唤醒阻塞的 Write")
	}
}

// 3. Produce 在关闭后返回错误；空数据是 no-op。
func TestProduceAfterCloseAndEmpty(t *testing.T) {
	s := NewStream(nil, Config{})
	if err := s.Produce(nil); err != nil {
		t.Fatalf("Produce(nil) 应为 no-op，got %v", err)
	}
	if err := s.Produce([]byte{}); err != nil {
		t.Fatalf("Produce(empty) 应为 no-op，got %v", err)
	}
	_ = s.Close()
	if err := s.Produce([]byte("x")); err != io.ErrClosedPipe {
		t.Fatalf("关闭后 Produce 应返回 ErrClosedPipe，got %v", err)
	}
}

// 4. 窗口更新按阈值（半窗）触发：不到半窗不发，过半才发一次累计值。
func TestWindowUpdateThreshold(t *testing.T) {
	const window = 8192 // 半窗 = 4096
	var updates []uint32
	s := NewStream(nil, Config{WindowSize: window, MaxChunk: window})
	s.SetSendWindowUpdateFn(func(n uint32) { updates = append(updates, n) })

	buf := make([]byte, window)

	_ = s.Produce(make([]byte, 3000))
	if _, err := s.Read(buf); err != nil { // 消费 3000 < 4096
		t.Fatal(err)
	}
	if len(updates) != 0 {
		t.Fatalf("不到半窗不应发更新，got %v", updates)
	}

	_ = s.Produce(make([]byte, 2000))
	if _, err := s.Read(buf); err != nil { // 累计 5000 >= 4096
		t.Fatal(err)
	}
	if len(updates) != 1 || updates[0] != 5000 {
		t.Fatalf("过半应发一次累计更新 [5000]，got %v", updates)
	}
}

// 5. 分块读：p 比单个 chunk 小时，剩余数据保留在队列里继续读。
func TestPartialRead(t *testing.T) {
	s := NewStream(nil, Config{WindowSize: 65536, MaxChunk: 4096})
	_ = s.Produce([]byte("HELLOWORLD"))

	got := make([]byte, 0, 10)
	buf := make([]byte, 4)
	for len(got) < 10 {
		n, err := s.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got = append(got, buf[:n]...)
	}
	if string(got) != "HELLOWORLD" {
		t.Fatalf("partial read 拼接错误: %q", got)
	}
}

// 6. 半关闭：收到 FIN（RemoteFin）只关读端，写端仍可继续写。
func TestHalfCloseRemoteFin(t *testing.T) {
	var sent [][]byte
	s := NewStream(nil, Config{SendData: func(b []byte) { sent = append(sent, b) }})

	s.RemoteFin()

	// 读端：EOF
	buf := make([]byte, 4)
	if _, err := s.Read(buf); err != io.EOF {
		t.Fatalf("RemoteFin 后 Read 应为 EOF，got %v", err)
	}
	// 写端：仍可写
	if _, err := s.Write([]byte("still-writable")); err != nil {
		t.Fatalf("RemoteFin 后写端应仍可用，got %v", err)
	}
	if len(sent) == 0 {
		t.Fatal("写端数据未发出")
	}
}

// 7. CloseWrite 发送一次 FIN，之后 Write 报错；读端仍可继续接收。
func TestCloseWriteSendsFin(t *testing.T) {
	finCount := 0
	s := NewStream(nil, Config{
		SendData: func([]byte) {},
		SendFin:  func() { finCount++ },
	})

	_ = s.CloseWrite()
	_ = s.CloseWrite() // 幂等
	if finCount != 1 {
		t.Fatalf("FIN 应只发一次，got %d", finCount)
	}
	if _, err := s.Write([]byte("x")); err != io.ErrClosedPipe {
		t.Fatalf("CloseWrite 后 Write 应返回 ErrClosedPipe，got %v", err)
	}
	// 读端仍可用：Produce 后能读到
	if err := s.Produce([]byte("hi")); err != nil {
		t.Fatalf("CloseWrite 后读端应仍可接收，got %v", err)
	}
	got := make([]byte, 2)
	if _, err := s.Read(got); err != nil || string(got) != "hi" {
		t.Fatalf("CloseWrite 后读取失败: %q err=%v", got, err)
	}
}

// 8. 读写两端都关闭后，OnClose 恰好触发一次。
func TestOnCloseFiresOnce(t *testing.T) {
	closeCount := 0
	s := NewStream(nil, Config{
		SendData: func([]byte) {},
		SendFin:  func() {},
		OnClose:  func() { closeCount++ },
	})

	s.RemoteFin() // 只关读端，不应触发
	if closeCount != 0 {
		t.Fatalf("仅 RemoteFin 不应触发 OnClose，got %d", closeCount)
	}
	_ = s.CloseWrite() // 两端都关 → 触发一次
	_ = s.Close()      // 再次关闭不应重复触发
	if closeCount != 1 {
		t.Fatalf("OnClose 应只触发一次，got %d", closeCount)
	}
}

// wirePair 把两条 Stream 单向连起来：src 写出的数据进入 dst 的接收缓冲，
// dst 消费后回发的窗口更新补充 src 的发送窗口。用于在不依赖任何外部包的情况下
// 验证滑动窗口 + 背压 + 阈值更新。
func wirePair(windowSize uint32, maxChunk int) (src, dst *Stream) {
	dst = NewStream(nil, Config{WindowSize: windowSize, MaxChunk: maxChunk})
	src = NewStream(nil, Config{
		WindowSize: windowSize,
		MaxChunk:   maxChunk,
		SendData:   func(b []byte) { _ = dst.Produce(b) },
	})
	dst.SetSendWindowUpdateFn(func(n uint32) { src.HandleWindowUpdate(n) })
	return
}

func TestStreamRoundtrip(t *testing.T) {
	src, dst := wirePair(64*1024, 4096)

	const size = 1024 * 1024
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	readDone := make(chan []byte, 1)
	go func() {
		got := make([]byte, 0, size)
		buf := make([]byte, 8192)
		for len(got) < size {
			n, err := dst.Read(buf)
			if n > 0 {
				got = append(got, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		readDone <- got
	}()

	if _, err := src.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case got := <-readDone:
		if !bytes.Equal(got, payload) {
			t.Fatalf("roundtrip mismatch: got %d bytes want %d", len(got), size)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout")
	}
}

// TestWriteBackpressure 验证：窗口耗尽时 Write 阻塞，收到窗口更新后才继续。
func TestWriteBackpressure(t *testing.T) {
	const window = 8 * 1024
	dst := NewStream(nil, Config{WindowSize: window, MaxChunk: 4096})
	src := NewStream(nil, Config{
		WindowSize: window,
		MaxChunk:   4096,
		SendData:   func(b []byte) { _ = dst.Produce(b) },
	})

	done := make(chan struct{})
	go func() {
		// 写两个窗口大小：第一个窗口写满后必然阻塞，直到我们补窗口。
		_, _ = src.Write(make([]byte, window*2))
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("Write 在窗口耗尽时未阻塞")
	case <-time.After(150 * time.Millisecond):
		// 预期：仍在阻塞
	}

	// 补满一个窗口的额度，Write 应能完成剩余写入。
	src.HandleWindowUpdate(window * 2)

	select {
	case <-done:
		// ok
	case <-time.After(5 * time.Second):
		t.Fatal("补窗口后 Write 未恢复")
	}
	_ = io.EOF
}
