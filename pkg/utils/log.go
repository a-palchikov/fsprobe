package utils

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// FileField is a field with code file added to structured traces
	FileField = "file"
	// FunctionField is a field with function name
	FunctionField = "func"
	// LevelField returns logging level as set by logrus
	LevelField = "level"
	// Component is a field that represents component - e.g. service or
	// function
	Component = "trace.component"
	// ComponentFields is a fields component
	ComponentFields = "trace.fields"
	// DefaultComponentPadding is a default padding for component field
	DefaultComponentPadding = 11
	// DefaultLevelPadding is a default padding for level field
	DefaultLevelPadding = 4
)

// TextFormatter is logrus-compatible formatter and adds
// file and line details to every logged entry.
type TextFormatter struct {
	// DisableTimestamp disables timestamp output (useful when outputting to
	// systemd logs)
	DisableTimestamp bool
	// ComponentPadding is a padding to pick when displaying
	// and formatting component field, defaults to DefaultComponentPadding
	ComponentPadding int
	// FormatCaller is a function to return (part) of source file path for output.
	// Defaults to filePathAndLine() if unspecified
	FormatCaller func() (caller string)
}

// Format implements logrus.Formatter interface and adds file and line
func (tf *TextFormatter) Format(e *logrus.Entry) (data []byte, err error) {
	formatCaller := tf.FormatCaller
	if formatCaller == nil {
		formatCaller = func() string { return "" }
	}

	caller := formatCaller()
	w := &writer{}

	// time
	if !tf.DisableTimestamp {
		w.writeField(e.Time.Format(time.RFC3339), noColor)
	}

	color := noColor
	w.writeField(strings.ToUpper(padMax(e.Level.String(), DefaultLevelPadding)), color)

	// always output the component field if available
	padding := DefaultComponentPadding
	if tf.ComponentPadding != 0 {
		padding = tf.ComponentPadding
	}
	if w.Len() > 0 {
		w.WriteByte(' ')
	}
	value := e.Data[Component]
	var component string
	if reflect.ValueOf(value).IsValid() {
		component = fmt.Sprintf("[%v]", value)
	}
	component = strings.ToUpper(padMax(component, padding))
	if component[len(component)-1] != ' ' {
		component = component[:len(component)-1] + "]"
	}
	w.WriteString(component)

	if e.Message != "" {
		w.writeField(e.Message, noColor)
	}

	if len(e.Data) > 0 {
		w.writeMap(e.Data)
	}

	if caller != "" {
		w.writeField(caller, noColor)
	}

	w.WriteByte('\n')
	data = w.Bytes()
	return
}

const noColor = -1

type writer struct {
	bytes.Buffer
}

func (w *writer) writeField(value interface{}, color int) {
	if w.Len() > 0 {
		w.WriteByte(' ')
	}
	w.writeValue(value, color)
}

func (w *writer) writeValue(value interface{}, color int) {
	var s string
	switch v := value.(type) {
	case string:
		s = v
		if needsQuoting(s) {
			s = fmt.Sprintf("%q", v)
		}
	default:
		s = fmt.Sprintf("%v", v)
	}
	w.WriteString(s)
}

func (w *writer) writeError(value interface{}) {
	w.WriteString(fmt.Sprintf("[%v]", value))
}

func (w *writer) writeKeyValue(key string, value interface{}) {
	if w.Len() > 0 {
		w.WriteByte(' ')
	}
	w.WriteString(key)
	w.WriteByte(':')
	if key == logrus.ErrorKey {
		w.writeError(value)
		return
	}
	w.writeValue(value, noColor)
}

func (w *writer) writeMap(m map[string]interface{}) {
	if len(m) == 0 {
		return
	}
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key == Component {
			continue
		}
		switch value := m[key].(type) {
		case logrus.Fields:
			w.writeMap(value)
		default:
			w.writeKeyValue(key, value)
		}
	}
}

func needsQuoting(text string) bool {
	for _, r := range text {
		if !strconv.IsPrint(r) {
			return true
		}
	}
	return false
}

func padMax(in string, chars int) string {
	switch {
	case len(in) < chars:
		return in + strings.Repeat(" ", chars-len(in))
	default:
		return in[:chars]
	}
}
