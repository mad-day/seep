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

package seep

import "io"
import "sync"
import "bytes"
import "github.com/flynn/noise"
import "github.com/davecgh/go-xdr/xdr2"
import "net/rpc"
import "encoding/gob"

type rpcCloser struct {}
func (r rpcCloser) Close() error { return nil }

var rpcCloserInst = &rpcCloser{}

type rpcClientCodec struct{
	io.Closer
	wm sync.Mutex
	src *xdr.Decoder
	dst *xdr.Encoder
	enc,dec *noise.CipherState
	encode func(*rpc.Request, interface{}) ([]byte,error)
	decode func([]byte,*rpc.Response) (error,func(i interface{}) error)
	decode2 func(i interface{}) error
}
func (r *rpcClientCodec) WriteRequest(req *rpc.Request, i interface{}) error {
	r.wm.Lock(); defer r.wm.Unlock()
	buf,err := r.encode(req,i)
	if err!=nil { return err }
	buf = r.enc.Encrypt(nil,nil,buf)
	_,err = r.dst.EncodeOpaque(buf)
	return err
}
func (r *rpcClientCodec) ReadResponseHeader(resp *rpc.Response) error {
	buf,_,err := r.src.DecodeOpaque()
	if err!=nil { return err }
	buf,err = r.dec.Decrypt(nil,nil,buf)
	if err!=nil { return err }
	
	err,dc2 := r.decode(buf,resp)
	if err!=nil { return err }
	r.decode2 = dc2
	return nil
}
func (r *rpcClientCodec) ReadResponseBody(i interface{}) error {
	return r.decode2(i)
}
func (r *rpcClientCodec) handshake(src *xdr.Decoder, dst *xdr.Encoder,nc noise.Config) error {
	state := nc.Initiator
	hs := noise.NewHandshakeState(nc)
	for {
		if state {
			var buf []byte
			buf,r.enc,r.dec = hs.WriteMessage(nil,nil)
			_,e := dst.EncodeOpaque(buf)
			if e!=nil { return e }
			state = false
			if r.enc!=nil { break }
		}
		buf,_,e := src.DecodeOpaque()
		if e!=nil { return e }
		_,r.enc,r.dec,e = hs.ReadMessage(nil,buf)
		if e!=nil { return e }
		state = true
		if r.enc!=nil { break }
	}
	return nil
}


type rpcServerCodec struct{
	io.Closer
	rm sync.Mutex
	src *xdr.Decoder
	dst *xdr.Encoder
	enc,dec *noise.CipherState
	encode func(*rpc.Response, interface{}) ([]byte,error)
	decode func([]byte,*rpc.Request) (error,func(i interface{}) error)
	decode2 func(i interface{}) error
}
func (r *rpcServerCodec) WriteResponse(resp *rpc.Response, i interface{}) error {
	r.rm.Lock(); defer r.rm.Unlock()
	buf,err := r.encode(resp,i)
	if err!=nil { return err }
	buf = r.enc.Encrypt(nil,nil,buf)
	_,err = r.dst.EncodeOpaque(buf)
	return err
}
func (r *rpcServerCodec) ReadRequestHeader(req *rpc.Request) error {
	buf,_,err := r.src.DecodeOpaque()
	if err!=nil { return err }
	buf,err = r.dec.Decrypt(nil,nil,buf)
	if err!=nil { return err }
	
	err,dc2 := r.decode(buf,req)
	if err!=nil { return err }
	r.decode2 = dc2
	return nil
}
func (r *rpcServerCodec) ReadRequestBody(i interface{}) error {
	return r.decode2(i)
}
func (r *rpcServerCodec) handshake(src *xdr.Decoder, dst *xdr.Encoder,nc noise.Config) error {
	state := nc.Initiator
	hs := noise.NewHandshakeState(nc)
	for {
		if state {
			var buf []byte
			buf,r.dec,r.enc = hs.WriteMessage(nil,nil)
			_,e := dst.EncodeOpaque(buf)
			if e!=nil { return e }
			state = false
			if r.enc!=nil { break }
		}
		buf,_,e := src.DecodeOpaque()
		if e!=nil { return e }
		_,r.dec,r.enc,e = hs.ReadMessage(nil,buf)
		if e!=nil { return e }
		state = true
		if r.enc!=nil { break }
	}
	return nil
}

/* ------------------------------------------------------------------------- */

func xdrEncReq(r *rpc.Request, i interface{}) ([]byte,error) {
	dst := new(bytes.Buffer)
	enc := xdr.NewEncoder(dst)
	_,err := enc.Encode(r)
	if err!=nil { return nil,err }
	_,err = enc.Encode(i)
	if err!=nil { return nil,err }
	return dst.Bytes(),nil
}
func xdrDecReq(b []byte,r *rpc.Request) (error,func(i interface{}) error) {
	dec := xdr.NewDecoder(bytes.NewReader(b))
	_,err := dec.Decode(r)
	return err,func(i interface{}) error {
		_,err := dec.Decode(i)
		return err
	}
}

func xdrEncResp(r *rpc.Response, i interface{}) ([]byte,error) {
	dst := new(bytes.Buffer)
	enc := xdr.NewEncoder(dst)
	_,err := enc.Encode(r)
	if err!=nil { return nil,err }
	_,err = enc.Encode(i)
	if err!=nil { return nil,err }
	return dst.Bytes(),nil
}
func xdrDecResp(b []byte,r *rpc.Response) (error,func(i interface{}) error) {
	dec := xdr.NewDecoder(bytes.NewReader(b))
	_,err := dec.Decode(r)
	return err,func(i interface{}) error {
		_,err := dec.Decode(i)
		return err
	}
}

func NewRpcClient(src *xdr.Decoder, dst *xdr.Encoder,nc noise.Config,c io.Closer) (rpc.ClientCodec,error) {
	if c==nil { c = rpcCloserInst }
	r := new(rpcClientCodec)
	r.Closer = c
	r.encode = xdrEncReq
	r.decode = xdrDecResp
	err := r.handshake(src,dst,nc)
	return r,err
}

func NewRpcSource(src *xdr.Decoder, dst *xdr.Encoder,nc noise.Config,c io.Closer) (rpc.ServerCodec,error) {
	if c==nil { c = rpcCloserInst }
	r := new(rpcServerCodec)
	r.Closer = c
	r.encode = xdrEncResp
	r.decode = xdrDecReq
	err := r.handshake(src,dst,nc)
	return r,err
}

/* ------------------------------------------------------------------------- */

func gobEncReq(r *rpc.Request, i interface{}) ([]byte,error) {
	dst := new(bytes.Buffer)
	enc := gob.NewEncoder(dst)
	err := enc.Encode(r)
	if err!=nil { return nil,err }
	err = enc.Encode(i)
	if err!=nil { return nil,err }
	return dst.Bytes(),nil
}
func gobDecReq(b []byte,r *rpc.Request) (error,func(i interface{}) error) {
	dec := gob.NewDecoder(bytes.NewReader(b))
	err := dec.Decode(r)
	return err,func(i interface{}) error {
		return dec.Decode(i)
	}
}

func gobEncResp(r *rpc.Response, i interface{}) ([]byte,error) {
	dst := new(bytes.Buffer)
	enc := gob.NewEncoder(dst)
	err := enc.Encode(r)
	if err!=nil { return nil,err }
	err = enc.Encode(i)
	if err!=nil { return nil,err }
	return dst.Bytes(),nil
}
func gobDecResp(b []byte,r *rpc.Response) (error,func(i interface{}) error) {
	dec := gob.NewDecoder(bytes.NewReader(b))
	err := dec.Decode(r)
	return err,func(i interface{}) error {
		return dec.Decode(i)
	}
}

func NewGobRpcClient(src *xdr.Decoder, dst *xdr.Encoder,nc noise.Config,c io.Closer) (rpc.ClientCodec,error) {
	if c==nil { c = rpcCloserInst }
	r := new(rpcClientCodec)
	r.Closer = c
	r.encode = gobEncReq
	r.decode = gobDecResp
	err := r.handshake(src,dst,nc)
	return r,err
}

func NewGobRpcSource(src *xdr.Decoder, dst *xdr.Encoder,nc noise.Config,c io.Closer) (rpc.ServerCodec,error) {
	if c==nil { c = rpcCloserInst }
	r := new(rpcServerCodec)
	r.Closer = c
	r.encode = gobEncResp
	r.decode = gobDecReq
	err := r.handshake(src,dst,nc)
	return r,err
}

/* ------------------------------------------------------------------------- */

