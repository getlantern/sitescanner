// This is a scanner that attempts to use domain fronting through CloudFlare to hit
// our geo-ip server. Any sites that work to do so have working CloudFlare tunneling.
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
	"sync"
	"time"

	"gopkg.in/getlantern/tlsdialer.v1"
)

var cloudflare = make([]string, 5)

type sitebody struct {
	domain string
	page   []byte
}

func noRedirect(req *http.Request, via []*http.Request) error {
	return errors.New("Don't redirect!")
}

func testsite(site string, wg *sync.WaitGroup, sha1tolookfor string) (string, error) {

	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (conn net.Conn, err error) {
				return tlsdialer.Dial(
					"tcp",
					site+":443",
					false,
					&tls.Config{InsecureSkipVerify: true},
				)
			},
		},
		CheckRedirect: noRedirect,
	}

	defer wg.Done()
	req, _ := http.NewRequest("GET", "http://geo.getiantem.org/lookup", nil)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return "", err
	}

	h := sha1.New()
	h.Write(body)
	bs := h.Sum(nil)

	sha := fmt.Sprintf("%x", bs)
	if sha1tolookfor != "" && sha == sha1tolookfor {
		log.Println("MATCH FOR: " + site)
		cloudflare = append(cloudflare, site)
	}
	return sha, nil
}

func workingsha1() (string, error) {
	var wg sync.WaitGroup
	wg.Add(1)
	return testsite("elance.com", &wg, "")

}

func processbatch(batch []string, sha1tolookfor string) {
	var wg sync.WaitGroup
	for i := 0; i < len(batch); i++ {
		var site = batch[i]
		wg.Add(1)
		go testsite(site, &wg, sha1tolookfor)
	}

	wg.Wait()
}

func main() {

	start := time.Now()
	file, err := os.Open("sites.txt")
	if err != nil {
		panic(err)
	}

	scanner := bufio.NewScanner(file)

	var sitesPerBatch = 100
	var batchindex = 0
	var index = 0

	// This allows us to handle up to 10000 sites.
	var batches = make([][]string, 100)
	for scanner.Scan() {
		if index%sitesPerBatch == 0 {
			batches[batchindex] = make([]string, sitesPerBatch)
			batchindex++
			index = 0
		}
		batches[batchindex-1][index] = scanner.Text()
		index++
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading file input: ", err)
	}

	sha1tolookfor, err := workingsha1()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error getting sha1", err)
		return
	}

	for i := 0; i < len(batches); i++ {
		fmt.Println("Processing batch", i)
		processbatch(batches[i][:], sha1tolookfor)
		fmt.Println("Sites after batch: ", cloudflare)
	}

	fmt.Println("**************** COMPLETE ******************", cloudflare)
	fmt.Println("FINAL SITES:", cloudflare)
	fmt.Printf("Scan took %.2fs\n", time.Since(start).Seconds())

}
