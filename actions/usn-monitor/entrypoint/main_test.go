package main_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/sclevine/spec"

	// "github.com/stretchr/testify/assert"
	// "github.com/stretchr/testify/require"

	. "github.com/onsi/gomega"
	. "github.com/paketo-buildpacks/stack-usns/actions/usn-monitor/entrypoint"
)

func testUpdateUSNs(t *testing.T, context spec.G, it spec.S) {
	var (
		Expect = NewWithT(t).Expect

		cliPath     string
		testRSSFeed *httptest.Server
		usnList     *os.File
	)

	it.Before(func() {
		testRSSFeed = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead {
				http.Error(w, "NotFound", http.StatusNotFound)
				return
			}

			switch r.URL.Path {
			case "/":
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, fmt.Sprintf(`<?xml version='1.0' encoding='UTF-8'?>
<rss xmlns:atom="http://www.w3.org/2005/Atom" xmlns:content="http://purl.org/rss/1.0/modules/content/" version="2.0"><channel><title>Ubuntu security notices</title><link>https://ubuntu.com/security/notices/rss.xml</link><description>Recent content on Ubuntu security notices</description><atom:link href="https://ubuntu.com/security/notices/rss.xml" rel="self"/><copyright>2020 Canonical Ltd. Ubuntu and Canonical are registered trademarks of Canonical Ltd.</copyright><docs>http://www.rssboard.org/rss-specification</docs><generator>Feedgen</generator><lastBuildDate>Wed, 16 Sep 2020 15:54:06 +0000</lastBuildDate>

<item><title>USN-4505-1: OpenSSL vulnerabilities</title><link>%s/USN-4505-1</link>
<description>Robert Merget, Marcus Brinkmann, Nimrod Aviram, and Juraj Somorovsky
discovered that certain Diffie-Hellman ciphersuites in the TLS
specification and implemented by OpenSSL contained a flaw. A remote
attacker could possibly use this issue to eavesdrop on encrypted
communications. This was fixed in this update by removing the insecure
ciphersuites from OpenSSL. (CVE-2020-1968)

Cesar Pereida García, Sohaib ul Hassan, Nicola Tuveri, Iaroslav Gridin,
Alejandro Cabrera Aldaya, and Billy Brumley discovered that OpenSSL
incorrectly handled ECDSA signatures. An attacker could possibly use this
issue to perform a timing side-channel attack and recover private ECDSA
keys. This issue only affected Ubuntu 18.04 LTS. (CVE-2019-1547)

Guido Vranken discovered that OpenSSL incorrectly performed the x86_64
Montgomery squaring procedure. While unlikely, a remote attacker could
possibly use this issue to recover private keys. This issue only affected
Ubuntu 18.04 LTS. (CVE-2019-1551)

Bernd Edlinger discovered that OpenSSL incorrectly handled certain
decryption functions. In certain scenarios, a remote attacker could
possibly use this issue to perform a padding oracle attack and decrypt
traffic. This issue only affected Ubuntu 18.04 LTS. (CVE-2019-1563)
</description><guid isPermaLink="false">https://ubuntu.com/security/notices/USN-4505-1</guid><pubDate>Wed, 16 Sep 2020 13:58:04 +0000</pubDate>
</item>
<item><title>USN-4499-1: MilkyTracker vulnerabilities</title><link>%s/USN-4499-1</link>
<description>It was discovered that MilkyTracker did not properly handle certain input. If
a user were tricked into opening a malicious file, an attacker could cause
MilkyTracker to crash or potentially execute arbitrary code.
</description><guid isPermaLink="false">https://ubuntu.com/security/notices/USN-4499-1</guid><pubDate>Tue, 15 Sep 2020 19:00:53 +0000</pubDate>
</item>
</channel></rss>`, testRSSFeed.URL, testRSSFeed.URL))

			//body
			case "/USN-4505-1":
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, fmt.Sprintf(`<a href="%s/cve/CVE-2021-3468">CVE-2021-3468</a>
<li href="%s/launchpad.net/bugs/cve/CVE-2021-3468">launchpad-bugs-2021-3468</li>
<h2>Update instructions</h2>
<h5>Ubuntu 18.04</h5>
<ul class="p-list">
<li class="p-list__item">affected_package_1</li>
<li class="p-list__item">affected_package_2</li>
</ul>
<h5>Ubuntu 16.02</h5>
<ul class="p-list">
<li class="p-list__item">affected_package_3</li>
</ul>
References`, testRSSFeed.URL, testRSSFeed.URL))

			case "/cve/CVE-2021-3468":
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `Published: <strong><p>Main CVE Description</p>`)

			case "/launchpad.net/bugs/cve/CVE-2021-3468":
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `<"edit-title"><span>Launchpad Description</span>`)

			case "/USN-4499-1":
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, ``)

			case "/bad-URL":
				w.WriteHeader(http.StatusBadRequest)

			default:
				t.Fatal(fmt.Sprintf("unknown path: %s", r.URL.Path))
			}
		}))

		tempFile, err := ioutil.TempFile("", "entrypoint")
		Expect(err).ToNot(HaveOccurred())

		usnList, err = ioutil.TempFile("", "usnList")
		Expect(err).ToNot(HaveOccurred())

		cliPath = tempFile.Name()
		Expect(err).ToNot(HaveOccurred())
	})

	it.After(func() {
		testRSSFeed.Close()
		_ = os.Remove(cliPath)
	})

	context("updateUSNs", func() {
		context("given an USNs file and RSS feed", func() {
			it("updates the USNs file with all entries", func() {
				_, err := usnList.Write([]byte("[]"))
				Expect(err).ToNot(HaveOccurred())

				err = UpdateUSNs(usnList.Name(), testRSSFeed.URL)
				Expect(err).ToNot(HaveOccurred())

				expectedUSNArray := []USN{
					{
						Title: "USN-4505-1: OpenSSL vulnerabilities",
						Link:  fmt.Sprintf("%s/USN-4505-1", testRSSFeed.URL),
						CveArray: []CVE{
							{
								Title:       "CVE-2021-3468",
								Link:        fmt.Sprintf("%s/cve/CVE-2021-3468", testRSSFeed.URL),
								Description: "Main CVE Description",
							},
							{
								Title:       "launchpad-bugs-2021-3468",
								Link:        fmt.Sprintf("%s/launchpad.net/bugs/cve/CVE-2021-3468", testRSSFeed.URL),
								Description: "Launchpad Description",
							},
						},
						AffectedPackages: []string{"affected_package_1", "affected_package_2"},
					},
					{
						Title:            "USN-4499-1: MilkyTracker vulnerabilities",
						Link:             fmt.Sprintf("%s/USN-4499-1", testRSSFeed.URL),
						CveArray:         nil,
						AffectedPackages: []string{},
					},
				}

				contents, err := ioutil.ReadFile(usnList.Name())
				Expect(err).ToNot(HaveOccurred())

				var actualUSNArray []USN
				err = json.Unmarshal(contents, &actualUSNArray)
				Expect(err).ToNot(HaveOccurred())

				Expect(actualUSNArray).To(Equal(expectedUSNArray))
			})
		})

		context("given a partially filled out USNs file and RSS feed", func() {
			it("prepends new USN entries onto the file", func() {
				preExistentUSNs := []USN{
					{
						Title: "USN-1234-1: Random USN",
						Link:  "https://ubuntu.com/security/notices/random-USN-1234-1",
						CveArray: []CVE{
							{
								Title:       "CVE-1234-1",
								Link:        "CVE-1234-1-link",
								Description: "CVE-1234-1 description",
							},
						},
						AffectedPackages: []string{"package1", "package2"},
					},
				}

				jsonUSNArray, err := json.Marshal(preExistentUSNs)
				Expect(err).ToNot(HaveOccurred())
				_, err = usnList.Write(jsonUSNArray)
				Expect(err).ToNot(HaveOccurred())

				err = UpdateUSNs(usnList.Name(), testRSSFeed.URL)
				Expect(err).ToNot(HaveOccurred())

				expectedUSNArray := []USN{
					{
						Title: "USN-4505-1: OpenSSL vulnerabilities",
						Link:  fmt.Sprintf("%s/USN-4505-1", testRSSFeed.URL),
						CveArray: []CVE{
							{
								Title:       "CVE-2021-3468",
								Link:        fmt.Sprintf("%s/cve/CVE-2021-3468", testRSSFeed.URL),
								Description: "Main CVE Description",
							},
							{
								Title:       "launchpad-bugs-2021-3468",
								Link:        fmt.Sprintf("%s/launchpad.net/bugs/cve/CVE-2021-3468", testRSSFeed.URL),
								Description: "Launchpad Description",
							},
						},
						AffectedPackages: []string{"affected_package_1", "affected_package_2"},
					},
					{
						Title:            "USN-4499-1: MilkyTracker vulnerabilities",
						Link:             fmt.Sprintf("%s/USN-4499-1", testRSSFeed.URL),
						CveArray:         nil,
						AffectedPackages: []string{},
					},
					{
						Title: "USN-1234-1: Random USN",
						Link:  "https://ubuntu.com/security/notices/random-USN-1234-1",
						CveArray: []CVE{
							{
								Title:       "CVE-1234-1",
								Link:        "CVE-1234-1-link",
								Description: "CVE-1234-1 description",
							},
						},
						AffectedPackages: []string{"package1", "package2"},
					},
				}

				contents, err := ioutil.ReadFile(usnList.Name())
				Expect(err).ToNot(HaveOccurred())

				var actualUSNArray []USN
				err = json.Unmarshal(contents, &actualUSNArray)
				Expect(err).ToNot(HaveOccurred())

				Expect(actualUSNArray).To(Equal(expectedUSNArray))
			})
		})

		context("given a USNs file with entries and RSS feed with the same entries", func() {
			it("updates the pre-existent USN entries", func() {
				preExistentUSNs := []USN{
					{
						Title: "USN-1234-1: Random USN",
						Link:  "https://ubuntu.com/security/notices/random-USN-1234-1",
						CveArray: []CVE{
							{
								Title:       "CVE-1234-1",
								Link:        "CVE-1234-1-link",
								Description: "CVE-1234-1 description",
							},
						},
						AffectedPackages: []string{"package1", "package2"},
					},
				}

				jsonUSNArray, err := json.Marshal(preExistentUSNs)
				Expect(err).ToNot(HaveOccurred())
				_, err = usnList.Write(jsonUSNArray)
				Expect(err).ToNot(HaveOccurred())

				err = UpdateUSNs(usnList.Name(), testRSSFeed.URL)
				Expect(err).ToNot(HaveOccurred())

				expectedUSNArray := []USN{
					{
						Title: "USN-4505-1: OpenSSL vulnerabilities",
						Link:  fmt.Sprintf("%s/USN-4505-1", testRSSFeed.URL),
						CveArray: []CVE{
							{
								Title:       "CVE-2021-3468",
								Link:        fmt.Sprintf("%s/cve/CVE-2021-3468", testRSSFeed.URL),
								Description: "Main CVE Description",
							},
							{
								Title:       "launchpad-bugs-2021-3468",
								Link:        fmt.Sprintf("%s/launchpad.net/bugs/cve/CVE-2021-3468", testRSSFeed.URL),
								Description: "Launchpad Description",
							},
						},
						AffectedPackages: []string{"affected_package_1", "affected_package_2"},
					},
					{
						Title:            "USN-4499-1: MilkyTracker vulnerabilities",
						Link:             fmt.Sprintf("%s/USN-4499-1", testRSSFeed.URL),
						CveArray:         nil,
						AffectedPackages: []string{},
					},
					{
						Title: "USN-1234-1: Random USN",
						Link:  "https://ubuntu.com/security/notices/random-USN-1234-1",
						CveArray: []CVE{
							{
								Title:       "CVE-1234-1",
								Link:        "CVE-1234-1-link",
								Description: "CVE-1234-1 description",
							},
						},
						AffectedPackages: []string{"package1", "package2"},
					},
				}
				contents, err := ioutil.ReadFile(usnList.Name())
				Expect(err).ToNot(HaveOccurred())

				var actualUSNArray []USN
				err = json.Unmarshal(contents, &actualUSNArray)
				Expect(err).ToNot(HaveOccurred())

				Expect(actualUSNArray).To(Equal(expectedUSNArray))
			})
		})

		context("failure cases", func() {
			context("RSS feed cannot be queried", func() {
				it("returns an error", func() {
					_, err := usnList.Write([]byte("[]"))
					Expect(err).ToNot(HaveOccurred())

					err = UpdateUSNs(usnList.Name(), fmt.Sprintf("%s/bad-URL", testRSSFeed.URL))
					Expect(err).To(HaveOccurred())
					Expect(err).To(MatchError(ContainSubstring("error finding new USNs")))
				})
			})

			context("the USNs file cannot be read", func() {
				it.Before(func() {
					Expect(os.Chmod(usnList.Name(), 0000)).To(Succeed())
				})

				it.After(func() {
					Expect(os.Chmod(usnList.Name(), 0644)).To(Succeed())
				})
				it("returns an error", func() {
					_, err := usnList.Write([]byte("[]"))
					Expect(err).ToNot(HaveOccurred())

					err = UpdateUSNs(usnList.Name(), testRSSFeed.URL)
					Expect(err).To(HaveOccurred())
					Expect(err).To(MatchError(ContainSubstring("error reading USN file")))
				})
			})

			context("existing USN file cannot be unmarshaled", func() {
				it("returns an error", func() {
					_, err := usnList.Write([]byte("bad JSON content"))
					Expect(err).ToNot(HaveOccurred())

					err = UpdateUSNs(usnList.Name(), testRSSFeed.URL)
					Expect(err).To(HaveOccurred())
					Expect(err).To(MatchError(ContainSubstring("error unmarshalling existing USN list")))
				})
			})

		})
	})
}
