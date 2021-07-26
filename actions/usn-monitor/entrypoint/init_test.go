package main_test

import (
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"

	. "github.com/onsi/gomega"
)

func TestUSNMonitor(t *testing.T) {
	SetDefaultEventuallyTimeout(5 * time.Second)

	suite := spec.New("usnMonitor", spec.Report(report.Terminal{}))
	suite("UpdateUSNs", testUpdateUSNs)
	suite("QueryRSSFeed", testQueryRSSFeed)
	suite.Run(t)
}
