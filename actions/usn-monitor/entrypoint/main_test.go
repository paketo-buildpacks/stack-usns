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
<item><title>USN-4594-1: Quassel vulnerabilities</title> <link>%s/USN-4594-1</link>
<description>It was discovered that Quassel incorrectly handled Qdatastream protocol.
(CVE-2018-1000179) </description> <guid isPermaLink="false">https://ubuntu.com/security/notices/USN-4594-1</guid> <pubDate>Tue, 20 Oct 2020 18:56:12 +0000</pubDate>
</item>
</channel></rss>`, testRSSFeed.URL, testRSSFeed.URL, testRSSFeed.URL))

			//body
			case "/USN-4505-1":
				w.WriteHeader(http.StatusOK)

				fmt.Fprint(w, fmt.Sprintf(`<a href="%s/cve/CVE-2021-3468">CVE-2021-3468</a>`, testRSSFeed.URL))

			case "/USN-4499-1":
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, ``)

			case "/USN-4594-1":
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, ``)

			case "/cve/CVE-2021-3468":
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, fmt.Sprintf(`<a href="%s/CVE-2021-3468">CVE-2021-3468</a> 
<a href="%s/launchpad.net/bugs/cve/CVE-2021-3468">Launchpad</a></li>`, testRSSFeed.URL, testRSSFeed.URL))

			case "/launchpad.net/bugs/cve/CVE-2021-3468":
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, fmt.Sprintf(`<a href="%s/CVE-2021-3468">CVE-2021-3468</a> 
<a href="%s/launchpad.net/bugs/cve/CVE-2021-3468">Launchpad</a>`, testRSSFeed.URL, testRSSFeed.URL))

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
			it.Focus("updates the USNs file with all entries", func() {
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
								Description: "",
							},
						},
						AffectedPackages: []string{},
					},
					{
						Title:            "USN-4499-1: MilkyTracker vulnerabilities",
						Link:             fmt.Sprintf("%s/USN-4499-1", testRSSFeed.URL),
						CveArray:         nil,
						AffectedPackages: []string{},
					},
					{
						Title:            "USN-4594-1: Quassel vulnerabilities",
						Link:             fmt.Sprintf("%s/USN-4594-1", testRSSFeed.URL),
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

	})

	// it("successfully populates empty USN file with content from rss feed", func() {
	// 	_, err := usnList.Write([]byte("[]"))
	// 	require.NoError(err)

	// 	cmd := exec.Command(cliPath, "--usn-path", usnList.Name(), "--rss-url", testRSSFeed.URL)
	// 	output, err := cmd.CombinedOutput()
	// 	require.NoError(err, string(output))

	// 	contents, err := ioutil.readfile(usnlist.name())
	// 	require.NoError(err)

	// 	assert.NotContains(string(contents), "\\u003c")
	// 	assert.NotContains(string(contents), "\\u003e")
	// 	assert.NotContains(string(contents), "\\u0026")

	// 	var actualUSNArray []USN
	// 	err = json.Unmarshal(contents, &actualUSNArray)
	// 	require.NoError(err)

	// 	assert.Equal(expectedUSNArray, actualUSNArray)
	// })

	// it("successfully prepends USN into USNs file with content from rss feed", func() {
	// 	oldUSNArray := []USN{
	// 		{
	// 			Title: "USN-4594-1: Quassel vulnerabilities",
	// 			Link:  "https://ubuntu.com/security/notices/USN-4594-1",
	// 			CveArray: []CVE{
	// 				{
	// 					Title:       "CVE-2018-1000178",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2018-1000178",
	// 					Description: "A heap corruption of type CWE-120 exists in quassel version 0.12.4 in quasselcore in void DataStreamPeer::processMessage(const QByteArray &msg) datastreampeer.cpp line 62 that allows an attacker to execute code remotely.",
	// 				},
	// 				{
	// 					Title:       "CVE-2018-1000179",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2018-1000179",
	// 					Description: "A NULL Pointer Dereference of CWE-476 exists in quassel version 0.12.4 in the quasselcore void CoreAuthHandler::handle(const Login &msg) coreauthhandler.cpp line 235 that allows an attacker to cause a denial of service.",
	// 				},
	// 			},
	// 			AffectedPackages: []string{"quassel", "quassel-core"},
	// 		},
	// 		{
	// 			Title: "USN-4499-1: MilkyTracker vulnerabilities",
	// 			Link:  "https://ubuntu.com/security/notices/USN-4499-1",
	// 			CveArray: []CVE{
	// 				{
	// 					Title:       "CVE-2019-14464",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-14464",
	// 					Description: "XMFile::read in XMFile.cpp in milkyplay in MilkyTracker 1.02.00 has a heap-based buffer overflow.",
	// 				},
	// 				{
	// 					Title:       "CVE-2019-14496",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-14496",
	// 					Description: "LoaderXM::load in LoaderXM.cpp in milkyplay in MilkyTracker 1.02.00 has a stack-based buffer overflow.",
	// 				},
	// 				{
	// 					Title:       "CVE-2019-14497",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-14497",
	// 					Description: "ModuleEditor::convertInstrument in tracker/ModuleEditor.cpp in MilkyTracker 1.02.00 has a heap-based buffer overflow.",
	// 				},
	// 			},
	// 			AffectedPackages: []string{},
	// 		},
	// 		{
	// 			Title: "USN-4505-1: OpenSSL vulnerabilities",
	// 			Link:  "https://ubuntu.com/security/notices/USN-4505-1",
	// 			CveArray: []CVE{
	// 				{
	// 					Title:       "CVE-2019-1547",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-1547",
	// 					Description: "Normally in OpenSSL EC groups always have a co-factor present and this is used in side channel resistant code paths. However, in some cases, it is possible to construct a group using explicit parameters (instead of using a named curve). In those cases it is possible that such a group does not have the cofactor present. This can occur even where all the parameters match a known named curve. If such a curve is used then OpenSSL falls back to non-side channel resistant code paths which may result in full key recovery during an ECDSA signature operation. In order to be vulnerable an attacker would have to have the ability to time the creation of a large number of signatures where explicit parameters with no co-factor present are in use by an application using libcrypto. For the avoidance of doubt libssl is not vulnerable because explicit parameters are never used. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). Fixed in OpenSSL 1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s).",
	// 				},
	// 				{
	// 					Title:       "CVE-2019-1551",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-1551",
	// 					Description: "There is an overflow bug in the x64_64 Montgomery squaring procedure used in exponentiation with 512-bit moduli. No EC algorithms are affected. Analysis suggests that attacks against 2-prime RSA1024, 3-prime RSA1536, and DSA1024 as a result of this defect would be very difficult to perform and are not believed likely. Attacks against DH512 are considered just feasible. However, for an attack the target would have to re-use the DH512 private key, which is not recommended anyway. Also applications directly using the low level API BN_mod_exp may be affected if they use BN_FLG_CONSTTIME. Fixed in OpenSSL 1.1.1e (Affected 1.1.1-1.1.1d). Fixed in OpenSSL 1.0.2u (Affected 1.0.2-1.0.2t).",
	// 				},
	// 				{
	// 					Title:       "CVE-2019-1563",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-1563",
	// 					Description: "In situations where an attacker receives automated notification of the success or failure of a decryption attempt an attacker, after sending a very large number of messages to be decrypted, can recover a CMS/PKCS7 transported encryption key or decrypt any RSA encrypted message that was encrypted with the public RSA key, using a Bleichenbacher padding oracle attack. Applications are not affected if they use a certificate together with the private RSA key to the CMS_decrypt or PKCS7_decrypt functions to select the correct recipient info to decrypt. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). Fixed in OpenSSL 1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s).",
	// 				},
	// 				{
	// 					Title:       "CVE-2020-1968",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2020-1968",
	// 					Description: "The Raccoon attack exploits a flaw in the TLS specification which can lead to an attacker being able to compute the pre-master secret in connections which have used a Diffie-Hellman (DH) based ciphersuite. In such a case this would result in the attacker being able to eavesdrop on all encrypted communications sent over that TLS connection. The attack can only be exploited if an implementation re-uses a DH secret across multiple TLS connections. Note that this issue only impacts DH ciphersuites and not ECDH ciphersuites. This issue affects OpenSSL 1.0.2 which is out of support and no longer receiving public updates. OpenSSL 1.1.1 is not vulnerable to this issue. Fixed in OpenSSL 1.0.2w (Affected 1.0.2-1.0.2v).",
	// 				},
	// 			},
	// 			AffectedPackages: []string{"libssl1.0.0"},
	// 		},
	// 		{
	// 			Title: "USN-4916-2: Linux kernel regression",
	// 			Link:  "https://ubuntu.com/security/notices/USN-4916-2",
	// 			CveArray: []CVE{
	// 				{
	// 					Title:       "https://launchpad.net/bugs/1924611",
	// 					Link:        "https://launchpad.net/bugs/1924611",
	// 					Description: "setting extended attribute may cause memory leak",
	// 				},
	// 			},
	// 			AffectedPackages: []string{
	// 				"linux-image-gkeop-5.3",
	// 				"linux-image-gke-5.3",
	// 				"linux-image-5.3.0-74-lowlatency",
	// 				"linux-image-5.3.0-1040-raspi2",
	// 				"linux-image-5.3.0-74-generic",
	// 				"linux-image-5.3.0-1043-gke",
	// 				"linux-image-raspi2-hwe-18.04",
	// 			},
	// 		},
	// 		{
	// 			Title: "USN-4906-1: Nettle vulnerability",
	// 			Link:  "https://ubuntu.com/security/notices/USN-4906-1",
	// 			CveArray: []CVE{
	// 				{
	// 					Title:       "CVE-2021-20305",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2021-20305",
	// 					Description: "A flaw was found in Nettle in versions before 3.7.2, where several Nettle signature verification functions (GOST DSA, EDDSA & ECDSA) result in the Elliptic Curve Cryptography point (ECC) multiply function being called with out-of-range scalers, possibly resulting in incorrect results. This flaw allows an attacker to force an invalid signature, causing an assertion failure or possible validation. The highest threat to this vulnerability is to confidentiality, integrity, as well as system availability.",
	// 				},
	// 			},
	// 			AffectedPackages: []string{
	// 				"libnettle6",
	// 			},
	// 		},
	// 	}

	// 	jsonUSNArray, err := json.Marshal(oldUSNArray)
	// 	require.NoError(err)
	// 	_, err = usnList.Write(jsonUSNArray)
	// 	require.NoError(err)

	// 	cmd := exec.Command(cliPath, "--usn-path", usnList.Name(), "--rss-url", testRSSFeed.URL)
	// 	output, err := cmd.CombinedOutput()
	// 	require.NoError(err, string(output))

	// 	newUSN := []USN{
	// 		{
	// 			Title: "USN-4599-1: Firefox vulnerabilities",
	// 			Link:  "https://ubuntu.com/security/notices/USN-4599-1",
	// 			CveArray: []CVE{
	// 				{
	// 					Title:       "CVE-2020-15680",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2020-15680",
	// 					Description: "If a valid external protocol handler was referenced in an image tag, the resulting broken image size could be distinguished from a broken image size of a non-existent protocol handler. This allowed an attacker to successfully probe whether an external protocol handler was registered. This vulnerability affects Firefox < 82.",
	// 				},
	// 				{
	// 					Title:       "CVE-2020-15682",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2020-15682",
	// 					Description: "When a link to an external protocol was clicked, a prompt was presented that allowed the user to choose what application to open it in. An attacker could induce that prompt to be associated with an origin they didn't control, resulting in a spoofing attack. This was fixed by changing external protocol prompts to be tab-modal while also ensuring they could not be incorrectly associated with a different origin. This vulnerability affects Firefox < 82.",
	// 				},
	// 				{
	// 					Title:       "CVE-2020-15681",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2020-15681",
	// 					Description: "When multiple WASM threads had a reference to a module, and were looking up exported functions, one WASM thread could have overwritten another's entry in a shared stub table, resulting in a potentially exploitable crash. This vulnerability affects Firefox < 82.",
	// 				},
	// 				{
	// 					Title:       "CVE-2020-15683",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2020-15683",
	// 					Description: "Mozilla developers and community members reported memory safety bugs present in Firefox 81 and Firefox ESR 78.3. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox ESR < 78.4, Firefox < 82, and Thunderbird < 78.4.",
	// 				},
	// 				{
	// 					Title:       "CVE-2020-15684",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2020-15684",
	// 					Description: "Mozilla developers reported memory safety bugs present in Firefox 81. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 82.",
	// 				},
	// 				{
	// 					Title:       "CVE-2020-15254",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2020-15254",
	// 					Description: "Crossbeam is a set of tools for concurrent programming. In crossbeam-channel before version 0.4.4, the bounded channel incorrectly assumes that `Vec::from_iter` has allocated capacity that same as the number of iterator elements. `Vec::from_iter` does not actually guarantee that and may allocate extra memory. The destructor of the `bounded` channel reconstructs `Vec` from the raw pointer based on the incorrect assumes described above. This is unsound and causing deallocation with the incorrect capacity when `Vec::from_iter` has allocated different sizes with the number of iterator elements. This has been fixed in crossbeam-channel 0.4.4.",
	// 				},
	// 				{
	// 					Title:       "CVE-2020-15969",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2020-15969",
	// 					Description: "Use after free in WebRTC in Google Chrome prior to 86.0.4240.75 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.",
	// 				},
	// 			},
	// 			AffectedPackages: []string{"firefox"},
	// 		},
	// 	}

	// 	expectedUSNArray := append(newUSN, oldUSNArray...)

	// 	content, err := ioutil.ReadFile(usnList.Name())
	// 	require.NoError(err)

	// 	var actualUSNArray []USN
	// 	err = json.Unmarshal(content, &actualUSNArray)
	// 	assert.NoError(err)

	// 	assert.Equal(expectedUSNArray, actualUSNArray)
	// })

	// context("an existing USN is updated", func() {
	// 	it("updates the existing recorded USN", func() {
	// 		oldUSNArray := []USN{
	// 			{
	// 				Title: "USN-4594-1: Quassel Vulnerability vulnerabilities",
	// 				Link:  "https://ubuntu.com/security/notices/USN-4594-1",
	// 				CveArray: []CVE{
	// 					{
	// 						Title:       "CVE-2018-1000178",
	// 						Link:        "https://people.canonical.com/~ubuntu-security/cve/2018/CVE-2018-1000178.html",
	// 						Description: "A heap corruption of type CWE-120 exists in quassel version 0.12.4 in quasselcore in void DataStreamPeer::processMessage(const QByteArray &msg) datastreampeer.cpp line 62 that allows an attacker to execute code remotely.",
	// 					},
	// 					{
	// 						Title:       "CVE-2018-1000179",
	// 						Link:        "https://people.canonical.com/~ubuntu-security/cve/2018/CVE-2018-1000179",
	// 						Description: "",
	// 					},
	// 				},
	// 				AffectedPackages: []string{"quassel", "quassel-core"},
	// 			},
	// 		}

	// 		jsonUSNArray, err := json.Marshal(oldUSNArray)
	// 		require.NoError(err)
	// 		_, err = usnList.Write(jsonUSNArray)
	// 		require.NoError(err)

	// 		cmd := exec.Command(cliPath, "--usn-path", usnList.Name(), "--rss-url", testRSSFeed.URL)
	// 		output, err := cmd.CombinedOutput()
	// 		require.NoError(err, string(output))

	// 		updatedUSN := USN{
	// 			Title: "USN-4594-1: Quassel vulnerabilities",
	// 			Link:  "https://ubuntu.com/security/notices/USN-4594-1",
	// 			CveArray: []CVE{
	// 				{
	// 					Title:       "CVE-2018-1000178",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2018-1000178",
	// 					Description: "A heap corruption of type CWE-120 exists in quassel version 0.12.4 in quasselcore in void DataStreamPeer::processMessage(const QByteArray &msg) datastreampeer.cpp line 62 that allows an attacker to execute code remotely.",
	// 				},
	// 				{
	// 					Title:       "CVE-2018-1000179",
	// 					Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2018-1000179",
	// 					Description: "A NULL Pointer Dereference of CWE-476 exists in quassel version 0.12.4 in the quasselcore void CoreAuthHandler::handle(const Login &msg) coreauthhandler.cpp line 235 that allows an attacker to cause a denial of service.",
	// 				},
	// 			},
	// 			AffectedPackages: []string{"quassel", "quassel-core"},
	// 		}

	// 		content, err := ioutil.ReadFile(usnList.Name())
	// 		require.NoError(err)

	// 		var actualUSNArray []USN
	// 		err = json.Unmarshal(content, &actualUSNArray)
	// 		assert.NoError(err)

	// 		assert.Contains(actualUSNArray, updatedUSN)
	// 		assert.NotContains(actualUSNArray, oldUSNArray[0])
	// 	})
	// })
}
