// Copyright (c) 2018 YouDealChain Authors.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package log

import (
	"fmt"
	"io"
	l "log"
	"os"
	"sync"

	"github.com/spf13/viper"
)

// golang log impl
type gologger struct {
	logger *l.Logger
	level  Level
}

// defaultGologLevel is the default log level for new created logger
var defaultGologLevel = LevelDebug
var defaultGologWriter io.Writer = os.Stdout
var defaultGologFlags = l.LstdFlags | l.Lshortfile
var allGologLoggers = make(map[string]*gologger)

var mutex sync.Mutex

var _ Logger = (*gologger)(nil)

// levelValue is the map from name to value
var levelValue = map[string]Level{
	"fatal":   LevelFatal,
	"error":   LevelError,
	"warn":    LevelWarn,
	"warning": LevelWarn,
	"info":    LevelInfo,
	"debug":   LevelDebug,
	"f":       LevelFatal,
	"e":       LevelError,
	"w":       LevelWarn,
	"i":       LevelInfo,
	"d":       LevelDebug,
}

// GologConfig define struct
type GologConfig struct {
	Level string `mapstructure:"level" json:"level"`
}

// Setup loggers globally
func gologSetup(v *viper.Viper) {
	var config GologConfig
	v.Unmarshal(&config)
	if loglevel, ok := levelValue[config.Level]; ok {
		gologSetLevel(Level(loglevel))
	}
}

// SetLevel sets the log level of all loggers
func gologSetLevel(level Level) {
	mutex.Lock()

	defaultGologLevel = level
	for _, logger := range allGologLoggers {
		logger.level = defaultGologLevel
	}

	mutex.Unlock()
}

// SetFlags sets the log flags
func gologSetFlags(flags int) {
	mutex.Lock()
	defaultGologFlags = flags
	for _, logger := range allGologLoggers {
		logger.logger.SetFlags(defaultGologFlags)
	}
	mutex.Unlock()
}

// SetWriter updates all loggers' output writer.
func gologSetWriter(writer io.Writer) {
	mutex.Lock()
	defaultGologWriter = writer
	for tag, logger := range allGologLoggers {
		logger.logger = l.New(defaultGologWriter, formatPrefix(tag), defaultGologFlags)
	}
	mutex.Unlock()
}

// NewLogger creates a new logger.
func gologNewLogger(tag string) Logger {
	mutex.Lock()
	defer mutex.Unlock()

	log, ok := allGologLoggers[tag]
	if !ok {
		log = &gologger{
			logger: l.New(defaultGologWriter, formatPrefix(tag), defaultGologFlags),
			level:  defaultGologLevel,
		}
		allGologLoggers[tag] = log
	}

	return log
}

func formatPrefix(tag string) string {
	return fmt.Sprintf("%s\t", tag)
}

// Debugf prints Debug level log
func (log *gologger) Debugf(f string, v ...interface{}) {
	mutex.Lock()
	if log.level >= LevelDebug {
		log.logger.Output(2, log.sprintf(log.level, f, v...))
	}
	mutex.Unlock()
}

// Debug prints Debug level log
func (log *gologger) Debug(v ...interface{}) {
	mutex.Lock()
	if log.level >= LevelDebug {
		log.logger.Output(2, log.sprint(log.level, v...))
	}
	mutex.Unlock()
}

// Infof prints Info level log
func (log *gologger) Infof(f string, v ...interface{}) {
	mutex.Lock()
	if log.level >= LevelInfo {
		log.logger.Output(2, log.sprintf(log.level, f, v...))
	}
	mutex.Unlock()
}

// Info prints Info level log
func (log *gologger) Info(v ...interface{}) {
	mutex.Lock()
	if log.level >= LevelInfo {
		log.logger.Output(2, log.sprint(log.level, v...))
	}
	mutex.Unlock()
}

// Warnf prints Warn level log
func (log *gologger) Warnf(f string, v ...interface{}) {
	mutex.Lock()
	if log.level >= LevelWarn {
		log.logger.Output(2, log.sprintf(log.level, f, v...))
	}
	mutex.Unlock()
}

// Warn prints Warn level log
func (log *gologger) Warn(v ...interface{}) {
	mutex.Lock()
	if log.level >= LevelWarn {
		log.logger.Output(2, log.sprint(log.level, v...))
	}
	mutex.Unlock()
}

// Errorf prints Error level log
func (log *gologger) Errorf(f string, v ...interface{}) {
	mutex.Lock()
	if log.level >= LevelError {
		log.logger.Output(2, log.sprintf(log.level, f, v...))
	}
	mutex.Unlock()
}

// Error prints Error level log
func (log *gologger) Error(v ...interface{}) {
	mutex.Lock()
	if log.level >= LevelError {
		log.logger.Output(2, log.sprint(log.level, v...))
	}
	mutex.Unlock()
}

// Fatalf prints Fatal level log
func (log *gologger) Fatalf(f string, v ...interface{}) {
	mutex.Lock()
	defer mutex.Unlock()

	if log.level >= LevelFatal {
		log.logger.Output(2, log.sprintf(log.level, f, v...))
		os.Exit(1)
	}
}

// Fatal prints Fatal level log
func (log *gologger) Fatal(v ...interface{}) {
	mutex.Lock()
	defer mutex.Unlock()

	if log.level >= LevelFatal {
		log.logger.Output(2, log.sprint(log.level, v...))
		os.Exit(1)
	}
}

// Panicf prints Panic level log
func (log *gologger) Panicf(f string, v ...interface{}) {
	mutex.Lock()
	defer mutex.Unlock()

	if log.level >= LevelPanic {
		var s = log.sprintf(log.level, f, v...)
		log.logger.Output(2, s)
		panic(s)
	}
}

// Panic prints Panic level log
func (log *gologger) Panic(v ...interface{}) {
	mutex.Lock()
	defer mutex.Unlock()

	if log.level >= LevelPanic {
		var s = log.sprint(log.level, v...)
		log.logger.Output(2, s)
		panic(s)
	}
}

func (log *gologger) sprintf(level Level, f string, v ...interface{}) string {
	return fmt.Sprintf("%s\t%s", log.tag(level), fmt.Sprintf(f, v...))
}

func (log *gologger) sprint(level Level, v ...interface{}) string {

	return fmt.Sprintf("%s\t%s", log.tag(level), fmt.Sprint(v...))
}

func (log *gologger) tag(level Level) string {
	switch level {
	case LevelDebug:
		return "[D]"
	case LevelInfo:
		return "[I]"
	case LevelWarn:
		return "[W]"
	case LevelError:
		return "[E]"
	case LevelFatal:
		return "[F]"
	case LevelPanic:
		return "[P]"
	default:
		return "[*]"
	}
}
