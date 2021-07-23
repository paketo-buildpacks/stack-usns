package main_test

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"

	"github.com/sclevine/spec"

	. "github.com/onsi/gomega"
	. "github.com/paketo-buildpacks/stack-usns/actions/usn-monitor/entrypoint"
)

func testQueryRSSFeed(t *testing.T, context spec.G, it spec.S) {
	var (
		Expect = NewWithT(t).Expect

		cliPath string
		usnList *os.File
	)

	it.Before(func() {
		tempFile, err := ioutil.TempFile("", "entrypoint")
		Expect(err).ToNot(HaveOccurred())

		usnList, err = ioutil.TempFile("", "usnList")
		Expect(err).ToNot(HaveOccurred())

		cliPath = tempFile.Name()
		Expect(err).ToNot(HaveOccurred())

		goBuild := exec.Command("go", "build", "-o", cliPath, ".")
		_, err = goBuild.CombinedOutput()
		Expect(err).ToNot(HaveOccurred())
	})

	it.After(func() {
		_ = os.Remove(cliPath)
	})

	context("the real RSS feed is queried", func() {
		it("successfully gets XML of expected structure", func() {
			_, err := usnList.Write([]byte("[]"))
			Expect(err).ToNot(HaveOccurred())

			// No URL provided,  use the default of ubuntu.com/security/notices/rss.xml
			cmd := exec.Command(cliPath, "--usn-path", usnList.Name())
			_, err = cmd.CombinedOutput()
			Expect(err).ToNot(HaveOccurred())

			contents, err := ioutil.ReadFile(usnList.Name())
			Expect(err).ToNot(HaveOccurred())

			var actualUSNArray []USN
			err = json.Unmarshal(contents, &actualUSNArray)
			Expect(err).ToNot(HaveOccurred())

			Expect(len(actualUSNArray) > 0).To(BeTrue())
			Expect(actualUSNArray[0].Title).ToNot(Equal(""))
			Expect(actualUSNArray[0].Link).ToNot(Equal(""))
			Expect(len(actualUSNArray[0].CveArray)).ToNot(Equal(0))
		})
	})

}
