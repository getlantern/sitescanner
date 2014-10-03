// +build debug

package log

import (
	"log"
)

func Debugf(fmt string, args ...interface{}) {
	log.Printf(fmt, args...)
}

func Debugln(args ...interface{}) {
	log.Println(args...)
}
