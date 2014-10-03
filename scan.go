// for each target domain in the given prioritized list:
//     for front candidate in the given prioritized list:
//        check whether we can reach the target domain by attempting domain
//        fronting through the front candidate.  Log successfully proxied pairs
//        to stdout.  Log detected errors to stderr.
//
// run with `-tags debug` to enable debug logging.  See `-help` for other
// options.

// XXX: record where we left off, to enable resuming an interrupted scan.

package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"errors"
	"flag"
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

	dbg "github.com/getlantern/sitescanner/log"
	"gopkg.in/getlantern/tlsdialer.v1"
)

var workers = runtime.NumCPU()

var headRe *regexp.Regexp = regexp.MustCompile("(?s)<head>(.*)</head>")

var titleRe *regexp.Regexp = regexp.MustCompile("(?s)<title>(.*)</title>")

const reportFmt = "%-24s %-24s %-12s %-12s %-12s %s\n"

var dialTimeout = 10 * time.Second

var fronts = flag.String("fronts", "fronts.txt", "Path to the file containing front candidates, one domain per line.")

var targets = flag.String("targets", "targets.txt", "Path to the file containing fronting targets, one domain per line.")


// ResponseFeatures contains the characteristics we'll use when comparing
// direct vs domain fronted Responses, to estimate the likelihood that we are
// successfully fronting to a target.
//
// We are also checking whether we get a 200 OK response from the site at all,
// but we don't include this in ResponseFeatures becouse we are not reporting
// sites for which we don't get a 200 OK through domain fronting.
type ResponseFeatures struct {
	// Hash of the whole body, or "" if the body is the empty string
	BodyHash string
	// Hash of the response body's <head> element, or "" if it has none
	HeadHash string
	// Hash of the <title> element, or "" if the response body has none.
	TitleHash string
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
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU() * 10)
	start := time.Now()
	fmt.Println()
	fmt.Printf(reportFmt, "TARGET", "FRONT", "BODIES", "HEADS", "TITLES", "REDIRECTED URL")
	fmt.Printf(reportFmt, "======", "=====", "======", "=====", "======", "==============")
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
			dbg.Debugln("proxiedResponseFeatures error:", err)
			continue
		}
		bodiesMatch := matchReport(task.Features.BodyHash, features.BodyHash)
		headsMatch := matchReport(task.Features.HeadHash, features.HeadHash)
		titlesMatch := matchReport(task.Features.TitleHash, features.TitleHash)
		if bodiesMatch != "match" && headsMatch != "match" && titlesMatch != "match" {
			dbg.Debugln("Got an OK response fronting", task.Target, "through", task.Front, "but nothing matches.")
			continue
		}
		fmt.Printf(
			reportFmt,
			task.Target,
			task.Front,
			bodiesMatch,
			headsMatch,
			titlesMatch,
			task.TargetURL.String(),
		)
	}
	dbg.Debugln("One worker done")
	workersWg.Done()
}

func proxiedResponseFeatures(p Pairing) (ResponseFeatures, error) {
	dbg.Debugln("canProxy", p)
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (conn net.Conn, err error) {
				return tlsdialer.DialWithDialer(
					&net.Dialer{Timeout: dialTimeout},
					"tcp",
					p.FrontURL.Host+":443",
					// We can't use a domain front that requires a properly
					// populated SNI, so let's make those fail.
					false,
					&tls.Config{InsecureSkipVerify: true},
				)
			},
		},
		CheckRedirect: noRedirect,
	}
	req, err := http.NewRequest("GET", p.TargetURL.String(), nil)
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
	fronts, err := readLines(*fronts)
	if err != nil {
		panic(err)
	}
	targets, err := readLines(*targets)
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
			dbg.Debugln("Known bad domain", domain)
			return nilURL, nilRF
		}
		u, ok := nru[domain]
		if ok {
			dbg.Debugln("Cached domain", domain, u.String())
			return u, nrf[domain]
		} else {
			u, rf, err := followRedirects(domain)
			if err != nil {
				logErr("can't reach "+domain+" *without* a proxy", err)
				badDomains[domain] = true
				return nilURL, nilRF
			} else {
				dbg.Debugln("Got new url", u.String(), "features", rf)
				nru[domain] = u
				nrf[domain] = rf
				return u, rf
			}
		}
	}

	for _, target := range targets {
		dbg.Debugln("Trying", target)
		targetURL, features := URLnRF(target)
		if targetURL == nilURL {
			dbg.Debugln("Got null URL for", target)
			// This works for Baidu at least.  Worth trying, should there be
			// more sites for which www. works, the naked domain doesn't, and
			// which won't automatically redirect.
			targetURL, features = URLnRF("www." + target)
			if targetURL == nilURL {
				continue
			}
		}
		for _, front := range fronts {
			dbg.Debugln("Enqueuing pairing:", front, target)
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
	dbg.Debugln("Enqueued all input")
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
				dbg.Debugln("** trying to get", addr)
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
			dbg.Debugln("(re)setting URL to", u.String())
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
	// In what follows, we take advantage of the fact that all ret fields start
	// at their zero value (in particular, "" for strings).
	if body == nil {
		return ret, nil
	}
	ret.BodyHash = hash(body)
	if headMatches := headRe.FindSubmatch(body); headMatches != nil {
		ret.HeadHash = hash(headMatches[1])
	}
	if titleMatches := titleRe.FindSubmatch(body); titleMatches != nil {
		dbg.Debugln("Title:", string(titleMatches[1]))
		ret.TitleHash = hash(titleMatches[1])
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
