package antproxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	url2 "net/url"
	"path/filepath"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/pubgo/antproxy/cmds/cnst"
	"github.com/pubgo/g/xerror"
	"github.com/pubgo/xcmd/xcmd"
	"github.com/spf13/viper"
)

// Init init cmd
func Init() *xcmd.Command {
	var cert = cnst.RootName
	var key = cnst.RootKeyName
	var addr = ":4233"

	args := xcmd.Args(func(cmd *xcmd.Command) {
		cmd.Flags().StringVarP(&addr, "addr", "", addr, "proxy listen address")
	})

	return args(&xcmd.Command{
		Use:   "proxy",
		Short: "proxy server",
		RunE: func(cmd *xcmd.Command, args []string) (err error) {
			defer xerror.RespErr(&err)

			ca := xerror.PanicErr(tls.X509KeyPair(
				xerror.PanicBytes(ioutil.ReadFile(filepath.Join(cnst.GetCAROOT(), cert))),
				xerror.PanicBytes(ioutil.ReadFile(filepath.Join(cnst.GetCAROOT(), key)))),
			).(tls.Certificate)

			ca.Leaf = xerror.PanicErr(x509.ParseCertificate(ca.Certificate[0])).(*x509.Certificate)

			goproxy.GoproxyCa = ca
			goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
			goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
			goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
			goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&ca)}

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

			proxy.Verbose = viper.GetBool("debug")
			proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
			return http.ListenAndServe(addr, proxy)
		},
	})
}
