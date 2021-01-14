package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/mmcdole/gofeed"
	"html"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
)

type USN struct {
	Title            string   `json:"title"`
	Link             string   `json:"link"`
	CveArray         []CVE    `json:"cves"`
	AffectedPackages []string `json:"affected_packages"`
}

type CVE struct {
	Title       string `json:"title"`
	Link        string `json:"link"`
	Description string `json:"description"`
}

func main() {
	var (
		usnListPath string
		rssURL      string
	)

	flag.StringVar(&usnListPath, "usn-path", "", "Path to USN list")
	flag.StringVar(&rssURL, "rss-url", "https://ubuntu.com/security/notices/rss.xml", "URL of RSS feed")

	flag.Parse()

	if usnListPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	err := updateUSNs(usnListPath, rssURL)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error updating USNs: %s\n", err.Error())
		os.Exit(1)
	}
}

func updateUSNs(usnListPath, rssURL string) error {
	feedUSNs, err := getUSNsFromFeed(rssURL)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error finding new USNs: %s\n", err.Error())
		os.Exit(1)
	}

	usnListBytes, err := ioutil.ReadFile(usnListPath)
	if err != nil {
		return fmt.Errorf("error reading USN file: %w", err)
	}

	var existingUSNs []USN
	err = json.Unmarshal(usnListBytes, &existingUSNs)
	if err != nil {
		return fmt.Errorf("error unmarshalling existing USN list: %w", err)
	}

	updatedUSNs := resolveUSNs(feedUSNs, existingUSNs)

	return writeUSNFile(usnListPath, updatedUSNs)
}

func getUSNsFromFeed(rssURL string) ([]USN, error) {
	fp := gofeed.NewParser()
	feed, err := fp.ParseURL(rssURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing rss feed: %w", err)
	}

	var feedUSNs []USN
	for _, item := range feed.Items {
		usnBody, code, err := get(item.Link)
		if err != nil || code != http.StatusOK {
			return nil, fmt.Errorf("error getting USN: %w", err)
		}

		cves, err := extractCVEs(usnBody)
		if err != nil {
			return nil, fmt.Errorf("error extracting CVEs from USN %s: %w", item.Title, err)
		}

		feedUSNs = append(feedUSNs, USN{
			Title:            item.Title,
			Link:             item.Link,
			CveArray:         cves,
			AffectedPackages: getAffectedPackages(usnBody),
		})
	}

	return feedUSNs, nil
}

func resolveUSNs(feedUSNs, recordedUSNs []USN) []USN {
	existingUSNMap := make(map[string]int, 0)
	for i, usn := range recordedUSNs {
		existingUSNMap[strings.Split(usn.Title, ":")[0]] = i
	}

	var newUSNs []USN
	for _, usn := range feedUSNs {
		if i, ok := existingUSNMap[strings.Split(usn.Title, ":")[0]]; ok {
			recordedUSNs[i] = usn
		} else {
			newUSNs = append(newUSNs, usn)
		}
	}
	return append(newUSNs, recordedUSNs...)
}

func get(url string) (string, int, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", 0, err
	}

	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}

	body := html.UnescapeString(string(respBody))
	body = strings.ReplaceAll(body, "\n", " ")
	body = strings.ReplaceAll(body, "<br />", " ")
	body = strings.ReplaceAll(body, "<br>", " ")
	body = strings.ReplaceAll(body, "</br>", " ")

	return body, resp.StatusCode, nil
}

func getAffectedPackages(usnBody string) []string {
	re := regexp.MustCompile("Update instructions</h2>(.*?)References")
	packagesList := re.FindString(usnBody)

	re = regexp.MustCompile("18\\.04.*?</ul>")
	bioinicPackages := re.FindString(packagesList)

	re = regexp.MustCompile(`(__item">)(.*?>)(.*?)</a>`)
	packageMatches := re.FindAllStringSubmatch(bioinicPackages, -1)

	packages := make([]string, 0)
	for _, p := range packageMatches {
		packages = append(packages, p[3])
	}

	return packages
}

func extractCVEs(usnBody string) ([]CVE, error) {
	re := regexp.MustCompile(`.*?href="([\S]*?cve/CVE.*?)">(.*?)</a.*?`)
	cves := re.FindAllStringSubmatch(usnBody, -1)

	re = regexp.MustCompile(`.*?href="([\S]*?launchpad\.net/bugs.*?)">(.*?)</li`)
	lps := re.FindAllStringSubmatch(usnBody, -1)

	var cveArray []CVE
	for _, cve := range cves {
		description, err := getCVEDescription(cve[1])
		if err != nil {
			return nil, fmt.Errorf("error getting description for CVE %s: %w", cve[2], err)
		}

		cveArray = append(cveArray, CVE{
			Title:       cve[2],
			Link:        cve[1],
			Description: description,
		})
	}

	for _, lp := range lps {
		description, err := getLPDescription(lp[1])
		if err != nil {
			return nil, fmt.Errorf("error getting description for launchpad bug %s: %w", lp[2], err)
		}

		cveArray = append(cveArray, CVE{
			Title:       lp[2],
			Link:        lp[1],
			Description: description,
		})
	}

	return cveArray, nil
}

func getCVEDescription(url string) (string, error) {
	body, code, err := get(url)
	if err != nil {
		return "", err
	}

	if code != http.StatusOK {
		return "", nil
	}

	re := regexp.MustCompile(`Published: <strong.*?<p>(.*?)</p>`)
	desc := re.FindStringSubmatch(body)
	if len(desc) >= 2 {
		description := desc[1]
		return strings.TrimSpace(description), nil
	}

	return "", nil
}

func getLPDescription(url string) (string, error) {
	body, code, err := get(url)
	if err != nil {
		return "", err
	}

	if code != http.StatusOK {
		return "", nil
	}

	re := regexp.MustCompile(`"edit-title">.*?<span.*?>(.*?)</span>`)
	title := re.FindStringSubmatch(body)
	return strings.TrimSpace(title[1]), nil
}

func writeUSNFile(usnListPath string, usns []USN) error {
	usnBytes, err := json.MarshalIndent(usns, "", "    ")
	if err != nil {
		return fmt.Errorf("error marshalling USN array: %w", err)
	}

	newUSNFile, err := os.Create(usnListPath)
	if err != nil {
		return fmt.Errorf("error creating new USN file: %w", err)
	}
	defer newUSNFile.Close()

	_, err = newUSNFile.Write(usnBytes)
	if err != nil {
		return fmt.Errorf("error writing USN file: %w", err)
	}

	return nil
}
