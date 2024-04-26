package main

import (
	"bytes"
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
)

// logrusWriter is an adaptor that turns logrus log entries into slog log entries

type logrusWriter struct {
	handler slog.Handler
}

func newLogrusWriter(logger *slog.Logger) *logrusWriter {
	return &logrusWriter{
		handler: logger.Handler(),
	}
}

func logrusLineToSlogRecord(p []byte) slog.Record {
	level := slog.LevelInfo
	parsed, ok := bytes.CutPrefix(p, []byte("level=")) // parsed == p if !ok
	if ok {
		if levelBytes, rest, ok := bytes.Cut(parsed, []byte(" ")); ok {
			var ll logrus.Level
			if err := ll.UnmarshalText(levelBytes); err == nil {
				switch ll {
				case logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel: // We don’t care to distinguish panic/fatal, that’s going to be visible by behavior
					level = slog.LevelError
				case logrus.WarnLevel:
					level = slog.LevelWarn
				case logrus.InfoLevel:
					level = slog.LevelInfo
				case logrus.DebugLevel:
					level = slog.LevelDebug
				case logrus.TraceLevel:
					level = slog.LevelDebug - 1
				}
				parsed = rest
			}
		}
	}

	// Try to unquote the message
	parsed, ok = bytes.CutPrefix(parsed, []byte("msg=")) // parsed is unchanged if !ok
	if ok {
		if bytes.HasPrefix(parsed, []byte(`"`)) {
			parsedString := string(parsed)
			if quotedMsg, err := strconv.QuotedPrefix(parsedString); err == nil {
				if msg, err := strconv.Unquote(quotedMsg); err == nil {
					parsed = append([]byte(msg), parsed[len(quotedMsg):]...)
				}
			}
			// If any of the above fails, parsed is something like, but not quite, "..." other-fields, not ideal but good enough
		} // else parsed starts with the message text as is, and continues with other fields, just the way we want.
	}

	// This loses a bit of a precision in the timestamp, but it’s easier than parsing the value.
	// We don’t care about pc, we are not including it in the output.
	return slog.NewRecord(time.Now(), level, string(parsed), 0)
}

// Write processes one logrus entry.
// This relies on the fact that logrus submits the entry as a single Write
// (which makes sense, to avoid log interleaving with other output; and anyway
// logrus is not changing much nowadays)
func (w *logrusWriter) Write(p []byte) (int, error) {
	record := logrusLineToSlogRecord(p)

	ctx := context.Background()
	var err error = nil
	if w.handler.Enabled(ctx, record.Level) {
		err = w.handler.Handle(ctx, record)
	}
	return len(p), err
}
