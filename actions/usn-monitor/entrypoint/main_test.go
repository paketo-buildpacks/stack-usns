package main_test

import (
	"encoding/json"
	"fmt"
	. "github.com/paketo-buildpacks/stack-usns/actions/usn-monitor/entrypoint"
	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
)

func TestEntrypoint(t *testing.T) {
	spec.Run(t, "Entrypoint", testEntrypoint, spec.Report(report.Terminal{}))
}

func testEntrypoint(t *testing.T, when spec.G, it spec.S) {
	var (
		cliPath     string
		testRSSFeed *httptest.Server
		usnList     *os.File
		require     = require.New(t)
		assert      = assert.New(t)
	)

	it.Before(func() {
		testRSSFeed = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprintln(w, `<?xml version='1.0' encoding='UTF-8'?>
<rss xmlns:atom="http://www.w3.org/2005/Atom" xmlns:content="http://purl.org/rss/1.0/modules/content/" version="2.0"><channel><title>Ubuntu security notices</title><link>https://ubuntu.com/security/notices/rss.xml</link><description>Recent content on Ubuntu security notices</description><atom:link href="https://ubuntu.com/security/notices/rss.xml" rel="self"/><copyright>2020 Canonical Ltd. Ubuntu and Canonical are registered trademarks of Canonical Ltd.</copyright><docs>http://www.rssboard.org/rss-specification</docs><generator>Feedgen</generator><lastBuildDate>Wed, 16 Sep 2020 15:54:06 +0000</lastBuildDate><item><title>USN-4504-1: OpenSSL vulnerabilities</title><link>https://ubuntu.com/security/notices/USN-4504-1</link><description>Robert Merget, Marcus Brinkmann, Nimrod Aviram, and Juraj Somorovsky
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

</description><guid isPermaLink="false">https://ubuntu.com/security/notices/USN-4504-1</guid><pubDate>Wed, 16 Sep 2020 13:58:04 +0000</pubDate></item><item><title>USN-4498-1: Loofah vulnerability</title><link>https://ubuntu.com/security/notices/USN-4498-1</link><description>It was discovered that Loofah does not properly sanitize JavaScript in 
sanitized output. An attacker could possibly use this issue to perform 
XSS attacks. (CVE-2019-15587)
</description><guid isPermaLink="false">https://ubuntu.com/security/notices/USN-4498-1</guid><pubDate>Tue, 15 Sep 2020 19:25:01 +0000</pubDate></item><item><title>USN-4499-1: MilkyTracker vulnerabilities</title><link>https://ubuntu.com/security/notices/USN-4499-1</link><description>It was discovered that MilkyTracker did not properly handle certain input. If
a user were tricked into opening a malicious file, an attacker could cause
MilkyTracker to crash or potentially execute arbitrary code.
</description><guid isPermaLink="false">https://ubuntu.com/security/notices/USN-4499-1</guid><pubDate>Tue, 15 Sep 2020 19:00:53 +0000</pubDate></item></channel></rss>`)
		}))

		tempFile, err := ioutil.TempFile("", "entrypoint")
		require.NoError(err)

		usnList, err = ioutil.TempFile("", "usnList")
		require.NoError(err)

		cliPath = tempFile.Name()
		require.NoError(tempFile.Close())

		goBuild := exec.Command("go", "build", "-o", cliPath, ".")
		output, err := goBuild.CombinedOutput()
		require.NoError(err, "failed to build CLI: %s", string(output))
	})

	it.After(func() {
		testRSSFeed.Close()
		_ = os.Remove(cliPath)
	})

	it("successfully populates empty USN file with content from rss feed", func() {
		_, err := usnList.Write([]byte("[]"))
		require.NoError(err)

		cmd := exec.Command(cliPath, "--usn-path", usnList.Name(), "--rss-url", testRSSFeed.URL)
		output, err := cmd.CombinedOutput()
		require.NoError(err, string(output))

		expectedUSNArray := []USN{
			{
				Title: "USN-4504-1: OpenSSL vulnerabilities",
				Link:  "https://ubuntu.com/security/notices/USN-4504-1",
				CveArray: []CVE{
					{
						Title:       "CVE-2019-1547",
						Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-1547",
						Description: "Normally in OpenSSL EC groups always have a co-factor present and this is used in side channel resistant code paths. However, in some cases, it is possible to construct a group using explicit parameters (instead of using a named curve). In those cases it is possible that such a group does not have the cofactor present. This can occur even where all the parameters match a known named curve. If such a curve is used then OpenSSL falls back to non-side channel resistant code paths which may result in full key recovery during an ECDSA signature operation. In order to be vulnerable an attacker would have to have the ability to time the creation of a large number of signatures where explicit parameters with no co-factor present are in use by an application using libcrypto. For the avoidance of doubt libssl is not vulnerable because explicit parameters are never used. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). Fixed in OpenSSL 1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s).",
					},
					{
						Title:       "CVE-2019-1551",
						Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-1551",
						Description: "There is an overflow bug in the x64_64 Montgomery squaring procedure used in exponentiation with 512-bit moduli. No EC algorithms are affected. Analysis suggests that attacks against 2-prime RSA1024, 3-prime RSA1536, and DSA1024 as a result of this defect would be very difficult to perform and are not believed likely. Attacks against DH512 are considered just feasible. However, for an attack the target would have to re-use the DH512 private key, which is not recommended anyway. Also applications directly using the low level API BN_mod_exp may be affected if they use BN_FLG_CONSTTIME. Fixed in OpenSSL 1.1.1e (Affected 1.1.1-1.1.1d). Fixed in OpenSSL 1.0.2u (Affected 1.0.2-1.0.2t).",
					},
					{
						Title:       "CVE-2019-1563",
						Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-1563",
						Description: "In situations where an attacker receives automated notification of the success or failure of a decryption attempt an attacker, after sending a very large number of messages to be decrypted, can recover a CMS/PKCS7 transported encryption key or decrypt any RSA encrypted message that was encrypted with the public RSA key, using a Bleichenbacher padding oracle attack. Applications are not affected if they use a certificate together with the private RSA key to the CMS_decrypt or PKCS7_decrypt functions to select the correct recipient info to decrypt. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). Fixed in OpenSSL 1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s).",
					},
					{
						Title:       "CVE-2020-1968",
						Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2020-1968",
						Description: "The Raccoon attack exploits a flaw in the TLS specification which can lead to an attacker being able to compute the pre-master secret in connections which have used a Diffie-Hellman (DH) based ciphersuite. In such a case this would result in the attacker being able to eavesdrop on all encrypted communications sent over that TLS connection. The attack can only be exploited if an implementation re-uses a DH secret across multiple TLS connections. Note that this issue only impacts DH ciphersuites and not ECDH ciphersuites. This issue affects OpenSSL 1.0.2 which is out of support and no longer receiving public updates. OpenSSL 1.1.1 is not vulnerable to this issue. Fixed in OpenSSL 1.0.2w (Affected 1.0.2-1.0.2v).",
					},
				},
				AffectedPackages: []string{"openssl", "openssl1.0"},
			},
			{
				Title: "USN-4498-1: Loofah vulnerability",
				Link:  "https://ubuntu.com/security/notices/USN-4498-1",
				CveArray: []CVE{
					{
						Title:       "CVE-2019-15587",
						Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-15587",
						Description: "In the Loofah gem for Ruby through v2.3.0 unsanitized JavaScript may occur in sanitized output when a crafted SVG element is republished.",
					},
				},
				AffectedPackages: []string{"ruby-loofah"},
			},
			{
				Title: "USN-4499-1: MilkyTracker vulnerabilities",
				Link:  "https://ubuntu.com/security/notices/USN-4499-1",
				CveArray: []CVE{
					{
						Title:       "CVE-2019-14464",
						Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-14464",
						Description: "XMFile::read in XMFile.cpp in milkyplay in MilkyTracker 1.02.00 has a heap-based buffer overflow.",
					},
					{
						Title:       "CVE-2019-14496",
						Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-14496",
						Description: "LoaderXM::load in LoaderXM.cpp in milkyplay in MilkyTracker 1.02.00 has a stack-based buffer overflow.",
					},
					{
						Title:       "CVE-2019-14497",
						Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-14497",
						Description: "ModuleEditor::convertInstrument in tracker/ModuleEditor.cpp in MilkyTracker 1.02.00 has a heap-based buffer overflow.",
					},
				},
				AffectedPackages: []string{"milkytracker"},
			},
		}

		contents, err := ioutil.ReadFile(usnList.Name())
		require.NoError(err)

		var actualUSNArray []USN
		err = json.Unmarshal(contents, &actualUSNArray)
		require.NoError(err)

		assert.Equal(expectedUSNArray, actualUSNArray)
	})

	it("successfully prepends USN into USNs file with content from rss feed", func() {
		oldUSNArray := []USN{
			{
				Title: "USN-4498-1: Loofah vulnerability",
				Link:  "https://ubuntu.com/security/notices/USN-4498-1",
				CveArray: []CVE{
					{
						Title:       "CVE-2019-15587",
						Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-15587",
						Description: "In the Loofah gem for Ruby through v2.3.0 unsanitized JavaScript may occur in sanitized output when a crafted SVG element is republished.",
					},
				},
				AffectedPackages: []string{"ruby-loofah"},
			},
			{
				Title: "USN-4499-1: MilkyTracker vulnerabilities",
				Link:  "https://ubuntu.com/security/notices/USN-4499-1",
				CveArray: []CVE{
					{
						Title:       "CVE-2019-14464",
						Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-14464",
						Description: "XMFile::read in XMFile.cpp in milkyplay in MilkyTracker 1.02.00 has a heap-based buffer overflow.",
					},
					{
						Title:       "CVE-2019-14496",
						Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-14496",
						Description: "LoaderXM::load in LoaderXM.cpp in milkyplay in MilkyTracker 1.02.00 has a stack-based buffer overflow.",
					},
					{
						Title:       "CVE-2019-14497",
						Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-14497",
						Description: "ModuleEditor::convertInstrument in tracker/ModuleEditor.cpp in MilkyTracker 1.02.00 has a heap-based buffer overflow.",
					},
				},
				AffectedPackages: []string{"milkytracker"},
			},
		}

		jsonUSNArray, err := json.Marshal(oldUSNArray)
		require.NoError(err)
		_, err = usnList.Write(jsonUSNArray)
		require.NoError(err)

		cmd := exec.Command(cliPath, "--usn-path", usnList.Name(), "--rss-url", testRSSFeed.URL)
		output, err := cmd.CombinedOutput()
		require.NoError(err, string(output))

		newUSN := []USN{
			{
				Title: "USN-4504-1: OpenSSL vulnerabilities",
				Link:  "https://ubuntu.com/security/notices/USN-4504-1",
				CveArray: []CVE{
					{
						Title:       "CVE-2019-1547",
						Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-1547",
						Description: "Normally in OpenSSL EC groups always have a co-factor present and this is used in side channel resistant code paths. However, in some cases, it is possible to construct a group using explicit parameters (instead of using a named curve). In those cases it is possible that such a group does not have the cofactor present. This can occur even where all the parameters match a known named curve. If such a curve is used then OpenSSL falls back to non-side channel resistant code paths which may result in full key recovery during an ECDSA signature operation. In order to be vulnerable an attacker would have to have the ability to time the creation of a large number of signatures where explicit parameters with no co-factor present are in use by an application using libcrypto. For the avoidance of doubt libssl is not vulnerable because explicit parameters are never used. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). Fixed in OpenSSL 1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s).",
					},
					{
						Title:       "CVE-2019-1551",
						Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-1551",
						Description: "There is an overflow bug in the x64_64 Montgomery squaring procedure used in exponentiation with 512-bit moduli. No EC algorithms are affected. Analysis suggests that attacks against 2-prime RSA1024, 3-prime RSA1536, and DSA1024 as a result of this defect would be very difficult to perform and are not believed likely. Attacks against DH512 are considered just feasible. However, for an attack the target would have to re-use the DH512 private key, which is not recommended anyway. Also applications directly using the low level API BN_mod_exp may be affected if they use BN_FLG_CONSTTIME. Fixed in OpenSSL 1.1.1e (Affected 1.1.1-1.1.1d). Fixed in OpenSSL 1.0.2u (Affected 1.0.2-1.0.2t).",
					},
					{
						Title:       "CVE-2019-1563",
						Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2019-1563",
						Description: "In situations where an attacker receives automated notification of the success or failure of a decryption attempt an attacker, after sending a very large number of messages to be decrypted, can recover a CMS/PKCS7 transported encryption key or decrypt any RSA encrypted message that was encrypted with the public RSA key, using a Bleichenbacher padding oracle attack. Applications are not affected if they use a certificate together with the private RSA key to the CMS_decrypt or PKCS7_decrypt functions to select the correct recipient info to decrypt. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). Fixed in OpenSSL 1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s).",
					},
					{
						Title:       "CVE-2020-1968",
						Link:        "https://people.canonical.com/~ubuntu-security/cve/CVE-2020-1968",
						Description: "The Raccoon attack exploits a flaw in the TLS specification which can lead to an attacker being able to compute the pre-master secret in connections which have used a Diffie-Hellman (DH) based ciphersuite. In such a case this would result in the attacker being able to eavesdrop on all encrypted communications sent over that TLS connection. The attack can only be exploited if an implementation re-uses a DH secret across multiple TLS connections. Note that this issue only impacts DH ciphersuites and not ECDH ciphersuites. This issue affects OpenSSL 1.0.2 which is out of support and no longer receiving public updates. OpenSSL 1.1.1 is not vulnerable to this issue. Fixed in OpenSSL 1.0.2w (Affected 1.0.2-1.0.2v).",
					},
				},
				AffectedPackages: []string{"openssl", "openssl1.0"},
			},
		}

		expectedUSNArray := append(newUSN, oldUSNArray...)

		content, err := ioutil.ReadFile(usnList.Name())
		require.NoError(err)

		var actualUSNArray []USN
		err = json.Unmarshal(content, &actualUSNArray)
		assert.NoError(err)

		assert.Equal(expectedUSNArray, actualUSNArray)
	})
}
