package main

import (
	"bufio"
	//"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sync"

	"github.com/getlantern/tls"
)

type sitebody struct {
	domain string
	page   []byte
}

func whois(site string, c chan sitebody, wg sync.WaitGroup) {
	whois := "http://www.port43whois.com/index.php?query=" + site
	fmt.Println(whois)
	resp, err := http.Get(whois)

	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	sb := sitebody{domain: site, page: body}
	c <- sb
	wg.Done()
}

func testsite(site string) {
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (conn net.Conn, err error) {
				return tls.Dial("tcp", site+":443", &tls.Config{
					SuppressServerNameInClientHandshake: true,
				})
			},
		},
	}

	req, _ := http.NewRequest("GET", "http://geo.getiantem.org/lookup", nil)
	resp, err := client.Do(req)
	log.Println("Made request")
	if err != nil {
		log.Fatalf("Unable to do GET: %s", err)
	}
	defer resp.Body.Close()
	io.Copy(os.Stdout, resp.Body)
}

func main() {

	file, err := os.Open("sites.txt")
	if err != nil {
		panic(err)
	}

	var wg sync.WaitGroup
	c := make(chan sitebody)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		site := scanner.Text()
		fmt.Println(site) // Println will add back the final '\n'

		wg.Add(1)
		go whois(site, c, wg)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading file input: ", err)
	}
	go func() {
		wg.Wait()
		close(c)
	}()

	for sb := range c {
		fmt.Println()
		fmt.Println()
		fmt.Println()
		//fmt.Printf("%s", body)
		fmt.Println()
		fmt.Println()
		fmt.Println()

		re := regexp.MustCompile("(?i)cloudflare")
		cf := re.Match(sb.page)
		fmt.Printf("%q\n", cf)

		if cf {
			fmt.Printf("Found CloudFlare\n")
			testsite(sb.domain)
		}
	}

}
