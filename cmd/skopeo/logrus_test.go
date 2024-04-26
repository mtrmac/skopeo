package main

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogrusLineToSlogRecord(t *testing.T) {
	for _, c := range []struct {
		input string
		level slog.Level
		msg   string
	}{
		{
			`level=warning msg=hello`,
			slog.LevelWarn, `hello`,
		},
		{
			`level=warning msg="hello world"`,
			slog.LevelWarn, `hello world`,
		},
		{
			`level=warning msg="hello fields" a=b c=1`,
			slog.LevelWarn, `hello fields a=b c=1`,
		},
	} {
		r := logrusLineToSlogRecord([]byte(c.input))
		assert.Equal(t, c.level, r.Level, c.input)
		assert.Equal(t, c.msg, r.Message, c.input)
	}
}
