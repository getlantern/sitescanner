// +build debug

package log

import (
	"log"
)

func Debug(fmt string, args ...interface{}) {
	log.Printf(fmt, args...)
}
