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
	"runtime"
	"sync"
	"time"

	"gopkg.in/getlantern/tlsdialer.v1"
)

var workers = runtime.NumCPU()

type Pairing struct {
	// The domain we're trying to reach.
	Target string
	// The path that we're requesting in the target domain.  This will be ""
	// unless a request to the naked domain would redirect.
	Path string
	// Hash of the body obtained in response to a request for Url.
	Hash string
	// The domain we're trying to domain front through.
	Front string
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	start := time.Now()
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

	for result := range resultsChan {
		fmt.Printf("Can reach %v through %v\n", result.Target, result.Front)
	}
}

func work(tasksChan <-chan Pairing, resultsChan chan<- Pairing, workersWg *sync.WaitGroup) {
	for task := range tasksChan {
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
					p.Target+":443",
					// We can't use a domain front that requires a properly
					// populated SNI, so let's make those fail.
					false,
					&tls.Config{InsecureSkipVerify: true},
				)
			},
		},
		CheckRedirect: noRedirect,
	}
	req, err := http.NewRequest("GET", "http://"+p.Front+p.Path, nil)
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
	for _, target := range targets {
		logDebug("Trying", target)
		path, hash, err := fetchTarget(target)
		if err != nil {
			logErr("can't reach "+target+" *without* a proxy", err)
			continue
		}
		for _, front := range fronts {
			logDebug("Enqueuing pairing:", front, target)
			taskChan <- Pairing{Target: target, Path: path, Hash: hash, Front: front}
		}
	}
	logDebug("Enqueued all input")
	close(taskChan)
}

// fetchTarget makes a request for the given target *without* domain fronting,
// returning a path that will hopefully not redirect, and the hash of the
// response body.
func fetchTarget(target string) (path string, hash string, err error) {
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (conn net.Conn, err error) {
				return tlsdialer.Dial(
					"tcp",
					target+":443",
					// We're doing, not front candidates, here, so no need to
					// filter out those that will require a properly populated
					// SNI.
					true,
					&tls.Config{InsecureSkipVerify: true},
				)
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			path = via[len(via)-1].URL.Path
			logDebug("(re)setting path to", path)
			return nil
		},
	}
	req, err := http.NewRequest("GET", "http://"+target, nil)
	if err != nil {
		logErr("building GET request", err)
		return "", "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		logErr("performing GET request", err)
		return "", "", err
	}
	hash, err = bodyHash(resp)
	if err != nil {
		logErr("getting body hash", err)
		return "", "", err
	}
	return
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
	return errors.New("Don't redirect!: " + via[len(via)-1].URL.String())
}

func logErr(msg string, err error) {
	if err != nil {
		log.Printf("ERROR %s: %v\n", msg, err)
	}
}

func logDebug(vs ...interface{}) {
	log.Println(vs...)
}
