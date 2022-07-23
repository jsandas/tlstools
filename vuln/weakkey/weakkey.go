package weakkey

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/jsandas/tlstools/logger"
)

/*
	Debian Weak Key checking is an old vulnerability.
	This check compares the sha1 hash of the certificate modulus
	a list of known weak keys based on keysize

	Note: because this require referencing binary files a hack
	was added to detect if running locally which overrides the
	value of bpath
*/

type DebianWeakKey struct {
	Vulnerable bool `json:"vulnerable"`
}

// WeakKey detects if key was generated with weak Debian openssl
func (w *DebianWeakKey) Check(keysize int, modulus string) error {

	// bpath is the location of weakkeys binaries
	// these are copied there during the docker build
	p, _ := os.Executable()
	bpath := path.Dir(p)

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
		bpath = "bin"
	} else if dir == "tlstools" {
		bpath = "vuln/weakkey/bin"
	}

	// load weak key file
	b, err := ioutil.ReadFile(bpath + "/weak_keysize_" + ks)
	if err != nil {
		logger.Errorf("event_id=file_read_error msg\"%v\"", err)
		return err
	}

	// the hashes in the weak_key files are offset by 20 bytes
	for i := 0; i < len(b); i = i + 20 {
		bs := hex.EncodeToString(b[i : i+20])
		if sh == bs {
			logger.Warnf("event_id=weak_key_found %s %d:%d\n", bs, i, i+20)
			w.Vulnerable = true
		}
	}

	return nil
}
