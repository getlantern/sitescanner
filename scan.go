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
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sync"
	"time"

	debuglog "github.com/getlantern/sitescanner/log"
	"gopkg.in/getlantern/tlsdialer.v1"
)

var workers = runtime.NumCPU()

var headRe *regexp.Regexp = regexp.MustCompile("(?s)<head>(.*)</head>")

const reportFmt = "%-24s %-24s %-12s %-12s\n"

var dialTimeout = 10 * time.Second

// ResponseFeatures contains the characteristics we'll use when comparing
// direct vs domain fronted Responses, to estimate the likelihood that we are
// successfully fronting to a target.
//
// We are also checking whether we get a 200 OK response from the site at all,
// but we don't include this in ResponseFeatures becouse we are not reporting
// sites for which we don't get a 200 OK through domain fronting.
type ResponseFeatures struct {
	// Hash of the body's <head> element, or "" if the body has none
	HeadHash string
	// Hash of the whole body, or "" if the body is the empty string
	BodyHash string
}

type Pairing struct {
	// The domain we're trying to reach.
	Target string
	// A URL where we can hopefully reach Target without redirects.
	TargetURL url.URL
	// The domain we're trying to domain front through.
	Front string
	// A URL where we can hopefully reach Front without redirects.
	FrontURL url.URL

	Features ResponseFeatures
}

func main() {
	debuglog.Debug("I'm debugging stuff!")
	runtime.GOMAXPROCS(runtime.NumCPU() * 10)
	start := time.Now()
	fmt.Println()
	fmt.Printf(reportFmt, "TARGET", "FRONT", "BODIES", "HEADS")
	fmt.Printf(reportFmt, "======", "=====", "======", "=====")
	fmt.Println()
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
		features, err := proxiedResponseFeatures(task)
		if err != nil {
			logDebug("proxiedResponseFeatures error:", err)
			continue
		}
		fmt.Printf(
			reportFmt,
			task.Target,
			task.Front,
			matchReport(task.Features.BodyHash, features.BodyHash),
			matchReport(task.Features.HeadHash, features.HeadHash),
		)
	}
	logDebug("One worker done")
	workersWg.Done()
}

func proxiedResponseFeatures(p Pairing) (ResponseFeatures, error) {
	logDebug("canProxy", p)
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (conn net.Conn, err error) {
				return tlsdialer.DialWithDialer(
					&net.Dialer{Timeout: dialTimeout},
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
	u := p.TargetURL
	u.Host = p.FrontURL.Host
	logDebug("Trying to hit", p.Target, "through", u.String())
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		logErr("building GET request", err)
		return ResponseFeatures{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		logErr("performing GET request", err)
		return ResponseFeatures{}, err
	}
	return responseFeatures(resp)
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

	// No-redirect response features
	nrf := make(map[string]ResponseFeatures)

	nilURL := url.URL{}
	nilRF := ResponseFeatures{}

	// URLnRF just provides caching and some logging on top of followRedirects.
	URLnRF := func(domain string) (url.URL, ResponseFeatures) {
		if _, ok := badDomains[domain]; ok {
			logDebug("Known bad domain", domain)
			return nilURL, nilRF
		}
		u, ok := nru[domain]
		if ok {
			logDebug("Cached domain", domain, u.String())
			return u, nrf[domain]
		} else {
			u, rf, err := followRedirects(domain)
			if err != nil {
				logErr("can't reach "+domain+" *without* a proxy", err)
				badDomains[domain] = true
				return nilURL, nilRF
			} else {
				logDebug("Got new url", u.String(), "features", rf)
				nru[domain] = u
				nrf[domain] = rf
				return u, rf
			}
		}
	}

	for _, target := range targets {
		logDebug("Trying", target)
		targetURL, features := URLnRF(target)
		if targetURL == nilURL {
			logDebug("Got null URL for", target)
			continue
		}
		for _, front := range fronts {
			logDebug("Enqueuing pairing:", front, target)
			frontURL, _ := URLnRF(front)
			if frontURL == nilURL {
				// Some CDNs like akamai or Fastly don't like to have their /s
				// requested, but will still domain front.
				frontURL = url.URL{Scheme: "http", Host: front}
			}
			taskChan <- Pairing{
				Target:    target,
				TargetURL: targetURL,
				Front:     front,
				FrontURL:  frontURL,
				Features:  features,
			}
		}
	}
	logDebug("Enqueued all input")
	close(taskChan)
}

// followRedirects makes a request for the given domain without domain fronting,
// returning a URL that will hopefully not redirect, and the relevant features
// of the response.
func followRedirects(domain string) (u url.URL, rf ResponseFeatures, err error) {
	retriesLeft := 10
	// use http scheme to avoid getting double-TLSed
	u = url.URL{Scheme: "http", Host: domain}
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (conn net.Conn, err error) {
				logDebug("** trying to get", addr)
				return tls.DialWithDialer(
					&net.Dialer{Timeout: dialTimeout},
					"tcp",
					domain+":443",
					&tls.Config{InsecureSkipVerify: true},
				)
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			retriesLeft--
			if retriesLeft == 0 {
				return errors.New("Too many redirects")
			}
			// use http scheme to avoid getting double-TLSed
			req.URL.Scheme = "http"
			u = *req.URL
			logDebug("(re)setting URL to", u.String())
			return nil
		},
	}
	// use http scheme to avoid getting double-TLSed
	req, err := http.NewRequest("GET", "http://"+domain, nil)
	if err != nil {
		logErr("building GET request", err)
		return url.URL{}, rf, err
	}
	resp, err := client.Do(req)
	if err != nil {
		logErr("performing GET request", err)
		return url.URL{}, rf, err
	}
	if resp.StatusCode != 200 {
		return url.URL{}, rf, errors.New("Non-200 response:" + resp.Status)
	}
	rf, err = responseFeatures(resp)
	if err != nil {
		logErr("getting response features", err)
		return url.URL{}, rf, err
	}
	return
}

func responseFeatures(resp *http.Response) (ret ResponseFeatures, err error) {
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return ret, err
	}
	if body == nil {
		ret.BodyHash = ""
		ret.HeadHash = ""
		return ret, nil
	}
	ret.BodyHash = hash(body)
	headMatches := headRe.FindSubmatch(body)
	if headMatches == nil {
		ret.HeadHash = ""
	} else {
		ret.HeadHash = hash(headMatches[1])
	}
	return
}

func hash(s []byte) string {
	h := sha1.New()
	h.Write(s)
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func matchReport(expected, actual string) string {
	if actual == expected {
		if actual == "" {
			return "both empty"
		} else {
			return "match"
		}
	} else {
		if actual == "" {
			return "actual empty"
		} else {
			return "differ"
		}
	}
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
	//log.Println(vs...)
}
