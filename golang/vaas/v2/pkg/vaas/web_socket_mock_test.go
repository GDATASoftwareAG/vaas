package vaas

import "time"

var _ websocketConnection = (*mockWebSocket)(nil)

type mockWebSocket struct {
	closeFunc            func() error
	readJSONFunc         func(data any) error
	writeJSONFunc        func(data any) error
	setWriteDeadlineFunc func(add time.Time) error
	writeMessageFunc     func(messageType int, data []byte) error
	setReadDeadline      func(t time.Time) error
	setPongHandler       func(h func(appData string) error)
}

func (m mockWebSocket) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func (m mockWebSocket) ReadJSON(data any) error {
	if m.readJSONFunc != nil {
		return m.readJSONFunc(data)
	}
	return nil
}

func (m mockWebSocket) WriteJSON(data any) error {
	if m.writeJSONFunc != nil {
		return m.writeJSONFunc(data)
	}
	return nil
}

func (m mockWebSocket) SetWriteDeadline(add time.Time) error {
	if m.setWriteDeadlineFunc != nil {
		return m.setWriteDeadlineFunc(add)
	}
	return nil
}

func (m mockWebSocket) WriteMessage(messageType int, data []byte) error {
	if m.writeMessageFunc != nil {
		return m.writeMessageFunc(messageType, data)
	}
	return nil
}

func (m mockWebSocket) SetReadDeadline(t time.Time) error {
	if m.setReadDeadline != nil {
		return m.setReadDeadline(t)
	}
	return nil
}

func (m mockWebSocket) SetPongHandler(h func(appData string) error) {
	if m.setPongHandler != nil {
		m.setPongHandler(h)
	}
}
