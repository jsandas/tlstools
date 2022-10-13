package ssl

import (
	"bufio"
	"errors"
	"net"
	"regexp"
	"strings"

	logger "github.com/jsandas/gologger"
	"github.com/jsandas/tlstools/pkg/utils"
)

type startTLSmsg struct {
	protocol string
	greetMSG string
	authMSG  string
	respMSG  string
}

func smtpEHLO(w *bufio.Writer, r *bufio.Reader) (err error) {
	var ehloStr = "ehlo tlstools.com\r\n"
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

func (s *startTLSmsg) connect(w *bufio.Writer, r *bufio.Reader) (err error) {
	var line string

	rgx := regexp.MustCompile(s.greetMSG)
	for {
		if line, err = r.ReadString('\n'); err != nil {
			logger.Debugf("event_id=greetMSG_read_failed type=%s line=%s msg=\"%v\"", s.protocol, strings.TrimSpace(line), err)
			return
		}

		if rgx.MatchString(line) {
			break
		}
	}

	if s.protocol == "smtp" {
		if err = smtpEHLO(w, r); err != nil {
			logger.Debugf("event_id=ehlo_write_failed type=%s msg=\"%v\"", s.protocol, err)
			return
		}
	}

	if _, err = w.WriteString(s.authMSG); err != nil {
		logger.Debugf("event_id=authMSG_write_failed type=%s msg=\"%v\"", s.protocol, err)
		return
	}
	w.Flush()

	if line, err = r.ReadString('\n'); err != nil {
		logger.Debugf("event_id=respMSG_read_failed type=%s msg=\"%v\"", s.protocol, err)
		return
	}

	rgx = regexp.MustCompile(s.respMSG)
	if !rgx.MatchString(line) {
		logger.Debugf("event_id=starttls_not_supported server=%s line=%s msg=\"%v\"", s.protocol, strings.TrimSpace(line), err)
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
	case "ftp":
		msg := startTLSmsg{
			protocol: proto,
			greetMSG: "^220 ",
			authMSG:  "AUTH TLS\r\n",
			respMSG:  "^234 ",
		}
		err = msg.connect(w, r)
	case "imap":
		msg := startTLSmsg{
			protocol: proto,
			greetMSG: "^\\* ",
			authMSG:  "a001 STARTTLS\r\n",
			respMSG:  "^a001 OK ",
		}
		err = msg.connect(w, r)
	case "pop3":
		msg := startTLSmsg{
			protocol: proto,
			greetMSG: "^\\+OK ",
			authMSG:  "STLS\r\n",
			respMSG:  "^\\+OK ",
		}
		err = msg.connect(w, r)
	case "smtp":
		msg := startTLSmsg{
			protocol: proto,
			greetMSG: "^220 ",
			authMSG:  "STARTTLS\r\n",
			respMSG:  "^220 ",
		}
		err = msg.connect(w, r)
	}

	return
}
