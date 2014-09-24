// for each target domain in the given prioritized list:
//     for front candidate in the given prioritized list:
//        check whether we can reach the target domain by attempting domain
//        fronting through the front candidate.  Log successfully proxied pairs
//        to stdout.  Log detected errors to stderr.

// XXX: record where we left off, to enable resuming an interrupted scan.

package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"sync"
	"time"

	"gopkg.in/getlantern/tlsdialer.v1"
)

const workers = 10

var titleRe *regexp.Regexp = regexp.MustCompile("<title>(.*)</title>")

type Pairing struct {
	Target string
	Front string
	Hash string
}

func main() {
	start := time.Now()
	runtime.GOMAXPROCS(8)
	main_()
	fmt.Println("**************** COMPLETE ******************")
	fmt.Printf("Scan took %.2fs\n", time.Since(start).Seconds())
}

func main_() {

	tasksChan := make(chan Pairing, workers)
	resultsChan := make(chan Pairing, workers)

	workersWg := sync.WaitGroup{}

	// Size of work queue is O(n^2) on the size of the input lists, so we
	// generate it lazily.
	go feedTasks(tasksChan)


	workersWg.Add(workers)
	for i := 0; i < workers; i++ {
		go work(tasksChan, resultsChan, &workersWg)
	}

	// Task completion handling:
	//
	// The feedTasks goroutine will close tasksChan when it has processed all
	// input.  Each worker reports workersWg.Done() when it learns that
	// tasksChan is closed.  By that time, the worker has sent all its results
	// to the resultsChan.  Therefore, by the time workersWg.Wait() returns,
	// all `Pairing`s have been checked and all the successful ones are in
	// resultsChan.  Thus, the main goroutine will get all these before it's
	// notified that resultsChan has been closed.

	go func() {
		workersWg.Wait()
		logDebug("All workers done.")
		close(resultsChan)
	}()

	for result := range(resultsChan) {
		fmt.Printf("Can reach %v through %v\n", result.Target, result.Front)
	}
}

func work(tasksChan <-chan Pairing, resultsChan chan<- Pairing, workersWg *sync.WaitGroup) {
	for task := range(tasksChan) {
		if canProxy(task) {
			resultsChan <- task
		}
	}
	logDebug("One worker done")
	workersWg.Done()
}

func canProxy(p Pairing) bool {
	logDebug("canProxy", p)
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (conn net.Conn, err error) {
				return tlsdialer.Dial(
					"tcp",
					p.Target + ":443",
					// We can't use a domain front that requires a properly
					// populated SNI, so let's make those fail.
					false,
					&tls.Config{InsecureSkipVerify: true},
				)
			},
		},
		CheckRedirect: noRedirect,
	}
	req, err := http.NewRequest("GET", "http://" + p.Front, nil)
	if err != nil {
		logErr("building GET request", err)
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		logErr("performing GET request", err)
		return false
	}
	hash, err := bodyHash(resp)
	if err != nil {
		logErr("getting body hash", err)
		return false
	}
	logDebug("For pairing", p, hash == p.Hash)
	return hash == p.Hash
}

// feedTasks reads input files, enqueues testing tasks in taskChan, and closes
// taskChan when done.
func feedTasks(taskChan chan<- Pairing) {
	//XXX: -fronts command line parameter
	fronts, err := readLines("fronts.txt")
	if err != nil {
		panic(err)
	}
	//XXX: -targets command line parameter
	targets, err := readLines("targets.txt")
	if err != nil {
		panic(err)
	}
	for _, target := range(targets) {
		logDebug("Trying", target)
		resp, err := http.Get("https://" + target)
		if err != nil {
			logErr("can't reach " + target + " *without* a proxy", err)
			continue
		}
		hash, err := bodyHash(resp)
		if err != nil {
			logErr("can't hash " + target + "'s response *without* a proxy", err)
			continue
		}
		for _, front := range(fronts) {
			logDebug("Enqueuing pairing:", front, target)
			taskChan <- Pairing{Target: target, Front: front, Hash: hash}
		}
	}
	logDebug("Enqueued all input")
	close(taskChan)
}

func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(file)
	ret := make([]string, 0)
	for scanner.Scan() {
		ret = append(ret, scanner.Text())
	}
	return ret, scanner.Err()
}

func noRedirect(req *http.Request, via []*http.Request) error {
	return errors.New("Don't redirect!")
}

func logErr(msg string, err error) {
	if err != nil {
		log.Printf("ERROR %s: %v\n", msg, err)
	}
}

func logDebug(vs ...interface{}) {
	//log.Println(vs...)
}

func bodyHash(resp *http.Response) (string, error) {
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return "", err
	}
	h := sha1.New()
	h.Write(body)
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs), nil
}
