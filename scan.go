// This is a scanner that attempts to use host spoofing through CloudFlare to hit 
// our geo-ip server. Any sites that work to do so have working CloudFlare tunneling.
package main

import (
	"bufio"
	"crypto/sha1"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/getlantern/tls"
)

var cloudflare = make([]string, 5)

type sitebody struct {
	domain string
	page   []byte
}

func noRedirect(req *http.Request, via []*http.Request) error {
	return errors.New("Don't redirect!")
}

func testsite(site string, wg *sync.WaitGroup) {

	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (conn net.Conn, err error) {
				return tls.Dial("tcp", site+":443", &tls.Config{
					SuppressServerNameInClientHandshake: true,
				})
			},
		},
		CheckRedirect: noRedirect,
	}

	req, _ := http.NewRequest("GET", "http://geo.getiantem.org/lookup", nil)
	resp, err := client.Do(req)
	if err != nil {
	} else {
		body, err := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		if err != nil {
			//log.Println(err)
		} else {
			h := sha1.New()
			h.Write(body)
			bs := h.Sum(nil)

			sha := fmt.Sprintf("%x", bs)
			if sha == "f38a3c79bb1aee035200ef0c759b4f961406c1fc" {
				log.Println("MATCH FOR: " + site)
				cloudflare = append(cloudflare, site)
			}
		}

	}
	wg.Done()
}

func processbatch(batch []string) {
	var wg sync.WaitGroup
	for i := 0; i < len(batch); i++ {
		var site = batch[i]
		wg.Add(1)
		go testsite(site, &wg)
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
	var batches [5][100]string

	var batchindex = 0
	var index = 0
	for scanner.Scan() {
		if index%sitesPerBatch == 0 {
			batchindex++
			index = 0
		}

		site := scanner.Text
		batches[batchindex-1][index] = site
		index++=
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading file input: ", err)
	}

	for i := 0; i < len(batches); i++ {
		fmt.Println("Processing batch %s", i)
		processbatch(batches[i][:])
		fmt.Println("cur sites:", cloudflare)
	}

	fmt.Println("FINAL SITES:", cloudflare)
	fmt.Printf("Scan took %.2fs\n", time.Since(start).Seconds())

}
