package ssl

import (
	"bufio"
	"errors"
	"net"
	"regexp"
	"strings"

	logger "github.com/jsandas/gologger"
	"github.com/jsandas/tlstools/utils"
)

type startTLSmsg struct {
	greet string
	req   string
	resp  string
}

var msg = map[string]startTLSmsg{
	"ftp": {
		greet: "^220 ",
		req:   "AUTH TLS\r\n",
		resp:  "^234 ",
	},
	"pop3": {
		greet: "^\\+OK ",
		req:   "STLS\r\n",
		resp:  "^\\+OK ",
	},
	"imap": {
		greet: "^\\* ",
		req:   "a001 STARTTLS\r\n",
		resp:  "^a001 OK ",
	},
	"smtp": {
		greet: "^220 ",
		req:   "STARTTLS\r\n",
		resp:  "^220 ",
	},
}

func ehlo(w *bufio.Writer, r *bufio.Reader) (err error) {
	var ehloStr = "ehlo TLSscanner\r\n"
	var res = "^250"
	var line string

	if _, err = w.WriteString(ehloStr); err != nil {
		return
	}
	w.Flush()

	for {
		if line, err = r.ReadString('\n'); err != nil {
			return
		}

		rgx := regexp.MustCompile(res)
		if !rgx.MatchString(line) {
			return
		}

		left := r.Buffered()
		if left == 0 {
			break
		}
	}

	return
}

func run(w *bufio.Writer, r *bufio.Reader, proto string) (err error) {
	var line string

	rgx := regexp.MustCompile(msg[proto].greet)
	for {
		if line, err = r.ReadString('\n'); err != nil {
			logger.Debugf("event_id=tcp_read_failed type=%s line=%s msg=\"%v\"", proto, strings.TrimSpace(line), err)
			return
		}

		if rgx.MatchString(line) {
			break
		}
	}

	if err = ehlo(w, r); err != nil {
		logger.Debugf("event_id=tcp_write_failed type=%s msg=\"%v\"", proto, err)
		return
	}

	if _, err = w.WriteString(msg[proto].req); err != nil {
		logger.Debugf("event_id=tcp_write_failed type=%s msg=\"%v\"", proto, err)
		return
	}
	w.Flush()

	if line, err = r.ReadString('\n'); err != nil {
		logger.Debugf("event_id=tcp_read_failed type=%s msg=\"%v\"", proto, err)
		return
	}

	rgx = regexp.MustCompile(msg[proto].resp)
	if !rgx.MatchString(line) {
		logger.Debugf("event_id=starttls_not_supported server=%s line=%s msg=\"%v\"", proto, strings.TrimSpace(line), err)
		return errors.New("starttls_not_supported")
	}

	return
}

// StartTLS for non-http servers
func StartTLS(conn net.Conn, port string) (err error) {
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	proto := utils.GetService(port)

	// "https", "imapSSL", "pop3SSL", "rdp", "smtpSSL" use regular TLS connections
	// and are not processed further
	switch proto {
	case "ftp", "imap", "pop3", "smtp":
		return run(w, r, proto)
	}

	return
}
