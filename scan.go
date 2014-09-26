// for each target domain in the given prioritized list:
//     for front candidate in the given prioritized list:
//        check whether we can reach the target domain by attempting domain
//        fronting through the front candidate.  Log successfully proxied pairs
//        to stdout.  Log detected errors to stderr.

// XXX: in addition to checking the hash of the response <body>, check the hash
// of the response <head>, and whether we get a 200-OK response at all.  Use
// these for more nuanced reports.

// XXX: record where we left off, to enable resuming an interrupted scan.

package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sync"
	"time"

	"gopkg.in/getlantern/tlsdialer.v1"
)

var workers = runtime.NumCPU()

//XXX: use this instead of, or in addition to, the hash.
var headRe *regexp.Regexp = regexp.MustCompile("<head>(.*)</head>")

type Pairing struct {
	// The domain we're trying to reach.
	Target string
	// A URL where we can hopefully reach Target without redirects.
	TargetURL url.URL
	// Hash of the body obtained in response to a GET request for
	// TargetURL.
	Hash string
	// The domain we're trying to domain front through.
	Front string
	// A URL where we can hopefully reach Front without redirects.
	FrontURL url.URL
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

	workersWg := sync.WaitGroup{}

	// Size of work queue is O(n^2) on the size of the input lists, so we
	// generate it lazily.
	go feedTasks(tasksChan)

	workersWg.Add(workers)
	for i := 0; i < workers; i++ {
		go work(tasksChan, &workersWg)
	}

	// Task completion handling:
	//
	// The feedTasks goroutine will close tasksChan when it has processed all
	// input.  Each worker reports workersWg.Done() when it learns that
	// tasksChan is closed.  By that time, the worker has sent all its results
	// to the resultsChan.  Therefore, by the time workersWg.Wait() returns,
	// all `Pairing`s have been checked and all the successful ones have been
	// printed out.
	workersWg.Wait()
}

func work(tasksChan <-chan Pairing, workersWg *sync.WaitGroup) {
	for task := range tasksChan {
		if canProxy(task) {
			fmt.Printf("We can reach %v through %v\n", task.Target, task.Front)
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
					// These should have been filtered out already, but let's
					// check anyway for robustness to change.
					false,
					&tls.Config{InsecureSkipVerify: true},
				)
			},
		},
		CheckRedirect: noRedirect,
	}
	u := p.TargetURL
	u.Host = p.FrontURL.Host
	logDebug("Trying to hit", p.Target, "through", u.String())
	req, err := http.NewRequest("GET", u.String(), nil)
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

	// Domains for which we can't get a hash, even without domain fronting.
	badDomains := make(map[string]bool)

	// No-redirect URLs
	nru := make(map[string]url.URL)

	// No-redirect hashes
	nrh := make(map[string]string)

	urlAndHash := func(domain string) (u url.URL, hash string) {
		if _, ok := badDomains[domain]; ok {
			return url.URL{}, ""
		}
		u, ok := nru[domain]
		if ok {
			hash = nrh[domain]
		} else {
			u, hash, err := followRedirects(domain)
			if err != nil {
				logErr("can't reach "+domain+" *without* a proxy", err)
				badDomains[domain] = true
				return url.URL{}, ""
			} else {
				nru[domain] = u
				nrh[domain] = hash
			}
		}
		return
	}

	nilURL := url.URL{}
	for _, target := range targets {
		logDebug("Trying", target)
		targetURL, hash := urlAndHash(target)
		if targetURL == nilURL {
			continue
		}
		for _, front := range fronts {
			logDebug("Enqueuing pairing:", front, target)
			frontURL, _ := urlAndHash(target)
			if frontURL == nilURL {
				continue
			}
			taskChan <- Pairing{
				Target:    target,
				TargetURL: targetURL,
				Hash:      hash,
				Front:     front,
				FrontURL:  frontURL,
			}
		}
	}
	logDebug("Enqueued all input")
	close(taskChan)
}

// followRedirects makes a request for the given domain without domain fronting,
// returning an URL that will hopefully not redirect, and the hash
// of the response body.
func followRedirects(domain string) (u url.URL, hash string, err error) {
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (conn net.Conn, err error) {
				return tlsdialer.Dial(
					"tcp",
					domain+":443",
					// We don't filter out potential domain fronts at this
					// point, since this is used for targets too.
					true,
					&tls.Config{InsecureSkipVerify: true},
				)
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			u = *req.URL
			logDebug("(re)setting URL to", u.String())
			return nil
		},
	}
	req, err := http.NewRequest("GET", "https://"+domain, nil)
	if err != nil {
		logErr("building GET request", err)
		return url.URL{}, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		logErr("performing GET request", err)
		return url.URL{}, "", err
	}
	hash, err = bodyHash(resp)
	if err != nil {
		logErr("getting body hash", err)
		return url.URL{}, "", err
	}
	return
}

func bodyHash(resp *http.Response) (string, error) {
	h := sha1.New()
	_, err := io.Copy(h, resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return "", err
	}
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
	return errors.New("Don't redirect!: " + req.URL.String())
}

func logErr(msg string, err error) {
	if err != nil {
		log.Printf("ERROR %s: %v\n", msg, err)
	}
}

// Poor man's debug level switch.  Comment out the body to suppress noise.
// XXX: learn about the idiomatic way to do this in Go
func logDebug(vs ...interface{}) {
	log.Println(vs...)
}
