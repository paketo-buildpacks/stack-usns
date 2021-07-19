package main

import (
	"encoding/json"
	"fmt"
	"html"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/jessevdk/go-flags"
	"github.com/mmcdole/gofeed"
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
	var opts struct {
		USNListPath string `short:"u" long:"usn-path" description:"Path to USN list" required:"true"`
		RSSURL      string `short:"r" long:"rss-url" description:"URL of RSS feed" default:"https://ubuntu.com/security/notices/rss.xml"`
	}

	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}

	err = UpdateUSNs(opts.USNListPath, opts.RSSURL)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error updating USNs: %s\n", err.Error())
		os.Exit(1)
	}
}

func UpdateUSNs(usnListPath, rssURL string) error {
	feedUSNs, err := getUSNsFromFeed(rssURL)
	if err != nil {
		return fmt.Errorf("error finding new USNs: %w\n", err)
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
	bionicPackages := re.FindString(packagesList)

	re = regexp.MustCompile(`<li class="p-list__item">(.*?)</li>`)
	listMatches := re.FindAllStringSubmatch(bionicPackages, -1)

	packages := make([]string, 0)
	for _, listItem := range listMatches {
		packages = append(packages, getPackageNameFromHTML(strings.TrimSpace(listItem[1])))
	}

	return packages
}

func getPackageNameFromHTML(listItem string) string {
	if strings.HasPrefix(listItem, "<a href=") {
		re := regexp.MustCompile(`<a href=".*?">(.*?)</a>`)
		packageMatch := re.FindStringSubmatch(listItem)
		return packageMatch[1]
	} else {
		return strings.Split(listItem, " ")[0]
	}
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
	newUSNFile, err := os.Create(usnListPath)
	if err != nil {
		return fmt.Errorf("error creating new USN file: %w", err)
	}
	defer newUSNFile.Close()

	enc := json.NewEncoder(newUSNFile)
	enc.SetIndent("", "    ")
	enc.SetEscapeHTML(false)

	err = enc.Encode(usns)
	if err != nil {
		return fmt.Errorf("error encoding USN array to file: %w", err)
	}

	return nil
}
