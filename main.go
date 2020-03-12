package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/elazarl/goproxy"
	"github.com/pubgo/g/xerror"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	url2 "net/url"
	"strconv"
	"strings"
)

var ipReg = `^\d+?\.\d+?\.\d+?\.\d+?$`

// Get a free port.
func Get() (port int, err error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	addr := listener.Addr().String()
	_, portString, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(portString)
}

func main() {
	defer xerror.Assert()

	addr := flag.String("addr", ":8088", "proxy listen address")
	flag.Parse()

	var cert = "rootCA.pem"
	//var cert = goproxy.CA_CERT
	var key = "rootCA-key.pem"
	//var key = goproxy.CA_KEY

	//setCA(cert, key)
	setCA(
		xerror.PanicBytes(ioutil.ReadFile(cert)),
		xerror.PanicBytes(ioutil.ReadFile(key)),
	)

	//FuncHttpsHandler
	proxy := goproxy.NewProxyHttpServer()

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		url := resp.Request.URL.String()
		_in := strings.Contains
		if _in(url, "mp.weixin.qq.com") {
			fmt.Println(url)
			sss, _ := ioutil.ReadAll(resp.Body)

			if _in(url, "/mp/profile_ext") {
				if resp.Request.Method == "GET" {
					fmt.Println(string(sss))
				}
			}

			if _in(url, "/mp/appmsg_comment") {
				if _in(url, "getcomment") {
					fmt.Println(resp.Request.URL.Query().Get("appmsgid"))
					fmt.Println(string(sss))
				}
			}

			if _in(url, "/mp/getappmsgext") {
				_url := xerror.PanicErr(url2.Parse(resp.Request.Header.Get("Referer"))).(*url2.URL)
				fmt.Println(_url.Query().Get("mid"))
				//fmt.Println(string(sss))
			}

			if _in(url, "/s?__biz=") {
				fmt.Println(resp.Request.URL.Query().Get("mid"))
			}

			resp.Body = ioutil.NopCloser(bytes.NewBuffer(sss))
		}

		return resp
	})

	proxy.Verbose = true
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	log.Fatal(http.ListenAndServe(*addr, proxy))
}

func setCA(caCert, caKey []byte) error {
	goproxyCa, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return err
	}
	if goproxyCa.Leaf, err = x509.ParseCertificate(goproxyCa.Certificate[0]); err != nil {
		return err
	}
	goproxy.GoproxyCa = goproxyCa
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	return nil
}

//mkcert localhost 127.0.0.1 ::1
