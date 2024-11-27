package winsddlconverter

import "errors"

type stringReader struct {
	s string
	r int
}

func (sr *stringReader) Len() int {
	return len(sr.s) - sr.r
}

func (sr *stringReader) Remaining() string {
	return sr.s[sr.r:]
}

func (sr *stringReader) Consume(n int) {
	sr.r += n
}

func (sr *stringReader) ReadChars(n int) string {
	c := sr.s[sr.r : sr.r+n]
	sr.r += n
	return c
}

func (sr *stringReader) ReadSid() (string, error) {
	head := sr.ReadChars(2)
	if head != "S-" {
		sid, ok := wellKnownSidsReverse[head]
		if !ok {
			return "", errors.New("invalid")
		}
		return sid, nil
	}
	begin := sr.r
	for {
		c := sr.s[sr.r]
		if !(c >= '0' && c <= '9') && c != '-' {
			break
		}
		sr.r++
	}
	return head + sr.s[begin:sr.r], nil
}
