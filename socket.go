/*
MIT License

Copyright (c) 2017 Simon Schmidt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/*
SEEP, short for Socket Extensible Encryption Protocol, is a socket encryption
protocol based on the noise protocol framwork and XDR
(external data representation). This package also comes with an RPC codec,
loosely based on SEEP and an encoding format (XDR and GOB are supported).
*/
package seep

import "io"
import "sync"
import "bytes"
import "github.com/flynn/noise"
import "github.com/davecgh/go-xdr/xdr2"

type Reader struct{
	lck sync.Mutex
	src *xdr.Decoder
	dec *noise.CipherState
	buf bytes.Buffer
}
func (r *Reader) Read(p []byte) (n int, err error){
	r.lck.Lock(); defer r.lck.Unlock()
	if r.buf.Len()==0 {
		buf,_,e := r.src.DecodeOpaque()
		if e!=nil { err = e; return }
		buf,e = r.dec.Decrypt(nil,nil,buf)
		if e!=nil { err = e; return }
		r.buf.Write(buf)
	}
	return r.buf.Read(p)
}
func NewReader(src *xdr.Decoder,dec *noise.CipherState) *Reader {
	return &Reader{src:src,dec:dec}
}

type Writer struct{
	lck sync.Mutex
	dst *xdr.Encoder
	enc *noise.CipherState
}
func (w *Writer) Write(p []byte) (n int, err error) {
	w.lck.Lock(); defer w.lck.Unlock()
	buf := w.enc.Encrypt(nil,nil,p)
	_,e := w.dst.EncodeOpaque(buf)
	if e!=nil { err = e; return }
	n = len(p)
	return
}
func NewWriter(dst *xdr.Encoder,enc *noise.CipherState) *Writer {
	return &Writer{dst:dst,enc:enc}
}

/*
The Connection is a simple object acting as reader and writer, carrying the
minimal information needed to perform the noise protocol handshake. After
the call to the .Init() method, the connection can be written to, so that the
data is being send during the handshake. However, this data is not encrypted
using a private key, so no secrecy for this data is given.

	c := new(seep.Connection)
	c.Init()
	c.Write(someData) // this data is sent during the handshake.
	err := c.Handshake(src,dst,cfg)
	// ... check error
	// use c as Reader and Writer
*/
type Connection struct {
	io.Writer
	io.Reader
	
	outbuf *bytes.Buffer
	inbuf  *bytes.Buffer
}
func (c *Connection) Init() {
	c.outbuf = new(bytes.Buffer)
	c.inbuf = new(bytes.Buffer)
	c.Writer = c.outbuf
	c.Reader = c.inbuf
}
func (c *Connection) Handshake(src *xdr.Decoder, dst *xdr.Encoder,nc noise.Config) error {
	var o,i *noise.CipherState
	state := nc.Initiator
	l := c.outbuf.Len()
	if l>0x1000 {
		nm := len(nc.Pattern.Messages)
		if state { nm++ }
		nm/=2
		l2 := nm*0x1000
		if l2<l { l = (l/nm)+1 } else { l = 0x1000 }
	}
	hs := noise.NewHandshakeState(nc)
	for {
		if state {
			buf := c.outbuf.Next(l)
			buf,o,i = hs.WriteMessage(nil,buf)
			_,e := dst.EncodeOpaque(buf)
			if e!=nil { return e }
			state = false
			if o!=nil { break }
		}
		buf,_,e := src.DecodeOpaque()
		if e!=nil { return e }
		buf,i,o,e = hs.ReadMessage(nil,buf)
		if e!=nil { return e }
		c.inbuf.Write(buf)
		state = true
		if o!=nil { break }
	}
	w := NewWriter(dst,o)
	r := NewReader(src,i)
	r.buf.ReadFrom(c.inbuf)
	c.Writer = w
	c.Reader = r
	c.inbuf = nil
	c.outbuf = nil
	return nil
}

