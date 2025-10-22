package tun

import (
	"log"
	"time"

	singTun "github.com/jabberwocky238/sing-tun"
)

func tunNew(options singTun.Options) (tunIf singTun.Tun, err error) {
	options.FileDescriptor = 0
	maxRetry := 3
	for i := 0; i < maxRetry; i++ {
		timeBegin := time.Now()
		tunIf, err = singTun.New(options)
		if err == nil {
			return
		}
		timeEnd := time.Now()
		if timeEnd.Sub(timeBegin) < 1*time.Second { // retrying for "Cannot create a file when that file already exists."
			return
		}
		log.Printf("Start Tun interface timeout: %s [retrying %d/%d]", err, i+1, maxRetry)
	}
	return
}
