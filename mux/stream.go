// Package mux 提供一个与具体协议、cid 类型解耦的多路复用流实现，
// 供 abc / bbk 等项目复用。它只负责"逐流滑动窗口 + 背压 + 接收缓冲 + 半关闭"这部分通用逻辑，
// 不关心 cid 如何编码、底层如何发送——这些通过回调注入。
package mux

import (
	"io"
	"sync"
)

// DefaultWindowSize 是每条流默认的滑动窗口大小。
// 32KB 在高 BDP 链路上会把单流吞吐钳死在 windowSize/RTT，参考 yamux 提高到 256KB。
const DefaultWindowSize uint32 = 256 * 1024

// defaultMaxChunk 是单个数据分片的默认上限（未配置时使用）。
const defaultMaxChunk = 4 * 1024

// Config 配置一条 Stream 的行为，把"如何发送/cid 是什么/如何释放"通过回调注入，
// 从而让 Stream 与具体的 TunnelStub、cid 类型完全解耦。
type Config struct {
	// WindowSize 每条流的接收/发送窗口，0 表示使用 DefaultWindowSize。
	WindowSize uint32
	// MaxChunk 单个数据分片上限，<=0 表示使用 defaultMaxChunk。
	MaxChunk int
	// SendData 发送一个数据分片。调用方应在闭包中捕获 cid 并完成实际发送。
	SendData func([]byte)
	// SendFin 在本地写端关闭（CloseWrite）时发送一个 FIN 帧，可为 nil。
	SendFin func()
	// OnClose 在流"读写两端都关闭"后回调一次，供上层从映射表移除该流，可为 nil。
	OnClose func()
}

type Stream struct {
	Addr []byte

	mu    sync.Mutex
	rcond *sync.Cond // 接收侧：有数据可读 / 读端关闭
	wcond *sync.Cond // 发送侧：窗口可用 / 写端关闭

	recvQueue   [][]byte // 接收缓冲，由 Produce 追加、Read 消费
	readClosed  bool     // 读端关闭：对端不再发送数据（收到 FIN/RST）
	writeClosed bool     // 写端关闭：本端不再发送数据（CloseWrite/RST）
	closeFired  bool     // OnClose 是否已触发（只触发一次）
	readErr     error    // 读端关闭后 Read 返回的错误

	windowSize  uint32
	maxChunk    int
	sendWindow  int64  // 发送侧剩余可发字节，<=0 时 Write 阻塞形成背压
	readUnacked uint32 // 已消费但尚未回发 WINDOW_UPDATE 的字节数

	sendData           func([]byte)
	sendFin            func()
	onClose            func()
	sendWindowUpdateFn func(uint32)
}

func NewStream(addr []byte, cfg Config) *Stream {
	ws := cfg.WindowSize
	if ws == 0 {
		ws = DefaultWindowSize
	}
	mc := cfg.MaxChunk
	if mc <= 0 {
		mc = defaultMaxChunk
	}
	s := &Stream{
		Addr:       addr,
		windowSize: ws,
		maxChunk:   mc,
		sendData:   cfg.SendData,
		sendFin:    cfg.SendFin,
		onClose:    cfg.OnClose,
	}
	s.rcond = sync.NewCond(&s.mu)
	s.wcond = sync.NewCond(&s.mu)
	s.sendWindow = int64(ws)
	return s
}

// markClosedLocked 在持锁状态下更新读/写端关闭标记，并返回是否应当（在锁外）触发 OnClose。
func (s *Stream) markClosedLocked(read, write bool, err error) bool {
	if read && !s.readClosed {
		s.readClosed = true
		if s.readErr == nil {
			s.readErr = err
		}
		s.rcond.Broadcast()
	}
	if write && !s.writeClosed {
		s.writeClosed = true
		s.wcond.Broadcast()
	}
	if s.readClosed && s.writeClosed && !s.closeFired {
		s.closeFired = true
		return true
	}
	return false
}

// Produce 由读循环在收到数据帧时调用。
// 关键：必须非阻塞——否则一条流的慢消费者会卡住唯一的读循环，
// 进而阻塞其它所有流以及 PING/WINDOW_UPDATE（跨流队头阻塞）。
// 接收缓冲的总量天然被对端遵守的窗口（windowSize）所约束，不会无界增长。
func (s *Stream) Produce(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readClosed {
		return io.ErrClosedPipe
	}
	if len(data) > 0 {
		buf := make([]byte, len(data))
		copy(buf, data)
		s.recvQueue = append(s.recvQueue, buf)
		s.rcond.Signal()
	}
	return nil
}

func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	for len(s.recvQueue) == 0 && !s.readClosed {
		s.rcond.Wait()
	}
	if len(s.recvQueue) == 0 {
		err := s.readErr
		s.mu.Unlock()
		if err != nil {
			return 0, err
		}
		return 0, io.EOF
	}

	chunk := s.recvQueue[0]
	n := copy(p, chunk)
	if n < len(chunk) {
		s.recvQueue[0] = chunk[n:]
	} else {
		s.recvQueue = s.recvQueue[1:]
	}

	// 按"真实被消费的字节数"记账，并按阈值（半个窗口）才回发一次 WINDOW_UPDATE，
	// 避免每次 Read 都发一帧导致 update 帧过于频繁（chatty）。
	s.readUnacked += uint32(n)
	var delta uint32
	if s.readUnacked >= s.windowSize/2 {
		delta = s.readUnacked
		s.readUnacked = 0
	}
	fn := s.sendWindowUpdateFn
	s.mu.Unlock()

	if delta > 0 && fn != nil {
		fn(delta)
	}
	return n, nil
}

func (s *Stream) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		s.mu.Lock()
		// 窗口耗尽时阻塞，把背压真正传导给上游 io.Copy，
		// 而不是像旧实现那样塞进无界的缓存立即返回成功。
		for s.sendWindow <= 0 && !s.writeClosed {
			s.wcond.Wait()
		}
		if s.writeClosed {
			s.mu.Unlock()
			return written, io.ErrClosedPipe
		}
		n := len(p) - written
		if int64(n) > s.sendWindow {
			n = int(s.sendWindow)
		}
		if n > s.maxChunk {
			n = s.maxChunk
		}
		chunk := make([]byte, n)
		copy(chunk, p[written:written+n])
		s.sendWindow -= int64(n)
		s.mu.Unlock()

		// 锁外发送：发送可能阻塞（有界队列满），若持锁阻塞在此，
		// 收到的 WINDOW_UPDATE 将无法拿到锁更新窗口，造成死锁。
		if s.sendData != nil {
			s.sendData(chunk)
		}
		written += n
	}
	return written, nil
}

// HandleWindowUpdate 处理对端回发的窗口更新（确认已消费 n 字节），补充发送窗口。
func (s *Stream) HandleWindowUpdate(n uint32) {
	s.mu.Lock()
	s.sendWindow += int64(n)
	s.wcond.Signal()
	s.mu.Unlock()
}

// RemoteFin 在收到对端 FIN 时调用：只关闭读端（Read 排空后返回 EOF），
// 本端写端仍可继续发送，实现半关闭。
func (s *Stream) RemoteFin() {
	s.mu.Lock()
	fire := s.markClosedLocked(true, false, io.EOF)
	s.mu.Unlock()
	if fire && s.onClose != nil {
		s.onClose()
	}
}

// CloseWrite 关闭本端写端：发送 FIN 通知对端"我不再发了"，但仍可继续接收。
// 幂等，FIN 只发一次。
func (s *Stream) CloseWrite() error {
	s.mu.Lock()
	if s.writeClosed {
		s.mu.Unlock()
		return nil
	}
	fire := s.markClosedLocked(false, true, nil)
	sendFin := s.sendFin
	s.mu.Unlock()

	if sendFin != nil {
		sendFin()
	}
	if fire && s.onClose != nil {
		s.onClose()
	}
	return nil
}

// Close 整条流硬关闭（读写两端），用于 RST 或强制拆除；不发送 FIN。
func (s *Stream) Close() error {
	s.mu.Lock()
	fire := s.markClosedLocked(true, true, io.EOF)
	s.mu.Unlock()
	if fire && s.onClose != nil {
		s.onClose()
	}
	return nil
}

// SetSendWindowUpdateFn 注册"回发窗口更新"的回调（cid 在闭包中捕获）。
func (s *Stream) SetSendWindowUpdateFn(fn func(n uint32)) {
	s.mu.Lock()
	s.sendWindowUpdateFn = fn
	s.mu.Unlock()
}
