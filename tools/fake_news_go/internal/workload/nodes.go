package workload

import (
	"fmt"
	"math/rand"

	"github.com/google/uuid"
	"github.com/jmpsec/osctrl/tools/fake_news_go/internal/model"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	platforms = []string{
		"ubuntu14", "ubuntu16", "ubuntu18",
		"centos6", "centos7",
		"debian8", "debian9",
		"freebsd", "darwin", "windows",
	}
	osqueryVersions = []string{
		"5.0.1", "4.9.0", "3.3.1", "3.3.2",
		"5.1.0", "5.3.0", "4.8.2", "5.23.1",
	}
)

func GenerateRandomNodes(n int, r *rand.Rand) []model.Node {
	if r == nil {
		r = rand.New(rand.NewSource(1))
	}

	nodes := make([]model.Node, n)
	for i := 0; i < n; i++ {
		nodes[i] = GenerateRandomNode(r)
	}
	return nodes
}

func GenerateRandomNode(r *rand.Rand) model.Node {
	if r == nil {
		r = rand.New(rand.NewSource(1))
	}

	platform := platforms[r.Intn(len(platforms))]
	return model.Node{
		Target:     platform,
		IP:         generateRandomIP(r),
		Name:       generateHostname(platform, r),
		Version:    osqueryVersions[r.Intn(len(osqueryVersions))],
		Identifier: uuid.New().String(),
		Key:        "",
	}
}

func generateRandomIP(r *rand.Rand) string {
	return fmt.Sprintf(
		"%d.%d.%d.%d",
		r.Intn(256),
		r.Intn(256),
		r.Intn(256),
		r.Intn(256),
	)
}

func generateHostname(platform string, r *rand.Rand) string {
	suffixes := []string{"Prod", "Legacy", "Test", "Dev", "PC"}
	suffix := suffixes[r.Intn(len(suffixes))]
	titleCaser := cases.Title(language.English)
	return fmt.Sprintf("%s-%s", titleCaser.String(platform), suffix)
}
