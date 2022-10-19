package weakkey

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	logger "github.com/jsandas/gologger"
)

var commonKeySizes = []int{512, 1024, 2048, 4096}

/*
	Debian Weak Key checking is an old vulnerability.
	This check compares the sha1 hash of the certificate modulus
	a list of known weak keys based on keysize

	Note: because this require referencing binary files a hack
	was added to detect if running locally which overrides the
	value of bpath
*/

const (
	notVulnerable = "no"
	vulnerable    = "yes"
	uncommonKey   = "uncommonKey"
	testFailed    = "error"
)

type DebianWeakKey struct {
	Vulnerable string `json:"vulnerable"`
}

// WeakKey detects if key was generated with weak Debian openssl
func (w *DebianWeakKey) Check(keysize int, modulus string) error {
	w.Vulnerable = notVulnerable

	// only test if common keysize
	var found bool
	for _, ks := range commonKeySizes {
		if keysize == ks {
			found = true
		}
	}
	if !found {
		w.Vulnerable = uncommonKey
		return nil
	}

	// bpath is the location of weakkeys binaries
	// these are copied there during the docker build
	p, _ := os.Executable()
	bpath := path.Dir(p) + "/../resources/weakkeys"

	mod := fmt.Sprintf("Modulus=%s\n", strings.ToUpper(modulus))
	ks := strconv.Itoa(keysize)
	h := sha1.New()
	h.Write([]byte(mod))
	bs := h.Sum(nil)

	sh := hex.EncodeToString(bs)

	// Test overrides
	// ks = "2048"
	// sh = "24a319be7f63b8b46e9cd10d992069d592fe1766"

	// override bpath if running go test
	// or go run
	cwd, _ := os.Getwd()
	_, dir := path.Split(cwd)
	if dir == "weakkey" {
		bpath = "../../../resources/weakkeys"
	}

	// load weak key file
	file, err := os.Open(bpath + "/blacklist.RSA-" + ks)
	if err != nil {
		logger.Errorf("event_id=weak_key_failed_read path=%s file=blacklist.RSA-%s", bpath, ks)
		w.Vulnerable = testFailed
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if sh[20:] == scanner.Text() {
			w.Vulnerable = vulnerable
		}
	}

	return nil
}
