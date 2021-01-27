package ssl

import (
	"bufio"
	"errors"
	"net"
	"regexp"
	"strings"

	"github.com/jsandas/tlstools/logger"
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
		req:   "AUTH TLS",
		resp:  "^234 ",
	},
	"pop3": {
		greet: "^\\+OK ",
		req:   "STLS",
		resp:  "^\\+OK ",
	},
	"imap": {
		greet: "^\\* ",
		req:   "a001 STARTTLS",
		resp:  "^a001 OK ",
	},
	"smtp": {
		greet: "^220 ",
		req:   "STARTTLS",
		resp:  "^220 ",
	},
}

func ehlo(w *bufio.Writer, r *bufio.Reader) (err error) {
	var ehloStr = "ehlo TLSscanner"
	var res = "^250"
	var line string

	if _, err = w.WriteString(ehloStr + "\r\n"); err != nil {
		return
	}
	if err = w.Flush(); err != nil {
		return
	}

	for {
		if line, err = r.ReadString('\n'); err != nil {
			return
		}
		line = strings.TrimRight(line, "\r")

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

		line = strings.TrimRight(line, "\r")

		if rgx.MatchString(line) {
			break
		}
	}

	if err = ehlo(w, r); err != nil {
		logger.Debugf("event_id=tcp_write_failed type=%s msg=\"%v\"", proto, err)
		return
	}

	if _, err = w.WriteString(msg[proto].req + "\r\n"); err != nil {
		logger.Debugf("event_id=tcp_write_failed type=%s msg=\"%v\"", proto, err)
		return
	}
	if err = w.Flush(); err != nil {
		logger.Debugf("event_id=tcp_write_failed type=%s msg=\"%v\"", proto, err)
		return
	}

	if line, err = r.ReadString('\n'); err != nil {
		logger.Debugf("event_id=tcp_read_failed type=%s msg=\"%v\"", proto, err)
		return
	}
	line = strings.TrimRight(line, "\r")

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

	if proto == "https" || strings.HasSuffix(proto, "SSL") {
		return
	}

	return run(w, r, proto)
}
