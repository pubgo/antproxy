package wv

import (
	"fmt"
	"github.com/pubgo/g/xerror"
	"github.com/pubgo/xcmd/xcmd"
	"github.com/zserge/webview"
	"net/url"
)

func Init() *xcmd.Command {
	return &xcmd.Command{
		Use:   "wv",
		Short: "simple webview",
		RunE: func(cmd *xcmd.Command, args []string) (err error) {
			defer xerror.RespErr(&err)

			var indexHTML = `
			<!DOCTYPE html>
			<html>
			<head>
			<title>测试 - 幕布</title>
			<meta charset="utf-8"/>
			<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
			<meta name="renderer" content="webkit"/>
			<meta name="author" content="mubu.com"/>
			</head>
			<body style="margin: 50px 20px;color: #333;font-family: SourceSansPro,-apple-system,BlinkMacSystemFont,'PingFang SC',Helvetica,Arial,'Microsoft YaHei',微软雅黑,黑体,Heiti,sans-serif,SimSun,宋体,serif">
						


<div class="export-wrapper"><div style="font-size: 22px; padding: 0 15px 0;"><div style="padding-bottom: 24px">测试</div><div style="background: #e5e6e8; height: 1px; margin-bottom: 20px;"></div></div><ul style="list-style: disc outside;"><li style="line-height: 34px;"><span class="content mubu-node" heading="1" style="line-height: 34px; min-height: 34px; font-size: 24px; padding: 2px 0px; display: inline-block; vertical-align: top;"># sssnj</span></li><li style="line-height: 34px;"><span class="content mubu-node" heading="1" style="line-height: 34px; min-height: 34px; font-size: 24px; padding: 2px 0px; display: inline-block; vertical-align: top;"><span class="bold" style="font-weight: bold;">heade1</span></span><ul class="children" style="list-style: disc outside; padding-bottom: 4px;"><li style="line-height: 30px;"><span class="content mubu-node" heading="2" style="line-height: 30px; min-height: 30px; font-size: 21px; padding: 2px 0px; display: inline-block; vertical-align: top;">heade2</span><ul class="children" style="list-style: disc outside; padding-bottom: 4px;"><li style="line-height: 27px;"><span class="content mubu-node" heading="3" style="line-height: 27px; min-height: 27px; font-size: 19px; padding: 2px 0px; display: inline-block; vertical-align: top;">heade3</span><ul class="children" style="list-style: disc outside; padding-bottom: 4px;"><li style="line-height: 24px;"><span class="content mubu-node" color="#dc2d1e" style="color: rgb(220, 45, 30); line-height: 24px; min-height: 24px; font-size: 16px; padding: 2px 0px; display: inline-block; vertical-align: top;">三生三世</span></li></ul></li></ul></li></ul></li><li style="line-height: 30px;"><span class="content mubu-node" heading="2" style="line-height: 30px; min-height: 30px; font-size: 21px; padding: 2px 0px; display: inline-block; vertical-align: top;"><span class="bold" style="font-weight: bold;">heade2</span></span><ul class="children" style="list-style: disc outside; padding-bottom: 4px;"><li style="line-height: 27px;"><span class="content mubu-node" heading="3" style="line-height: 27px; min-height: 27px; font-size: 19px; padding: 2px 0px; display: inline-block; vertical-align: top;">heade3</span><ul class="children" style="list-style: disc outside; padding-bottom: 4px;"><li style="line-height: 24px;"><span class="content mubu-node" style="line-height: 24px; min-height: 24px; font-size: 16px; padding: 2px 0px; display: inline-block; vertical-align: top;"><span class="bold" style="font-weight: bold;">三生三世</span></span></li></ul></li></ul></li><li style="line-height: 27px;"><span class="content mubu-node" heading="3" style="line-height: 27px; min-height: 27px; font-size: 19px; padding: 2px 0px; display: inline-block; vertical-align: top;"><span class="bold" style="font-weight: bold;">heade3</span></span><ul class="children" style="list-style: disc outside; padding-bottom: 4px;"><li style="line-height: 24px;"><span class="content mubu-node" style="line-height: 24px; min-height: 24px; font-size: 16px; padding: 2px 0px; display: inline-block; vertical-align: top;"><span class="bold underline" style="font-weight: bold; text-decoration: underline;">三生三世</span></span></li></ul></li><li style="line-height: 24px;"><span class="content mubu-node" color="#dc2d1e" style="color: rgb(220, 45, 30); line-height: 24px; min-height: 24px; font-size: 16px; padding: 2px 0px; display: inline-block; vertical-align: top;">三生三世</span><ul class="children" style="list-style: disc outside; padding-bottom: 4px;"><li style="line-height: 24px;"><span class="content mubu-node" color="#dc2d1e" style="color: rgb(220, 45, 30); line-height: 24px; min-height: 24px; font-size: 16px; padding: 2px 0px; display: inline-block; vertical-align: top;">hello</span></li></ul></li><li style="line-height: 30px;"><span class="content mubu-node" color="#333333" heading="2" style="color: rgb(51, 51, 51); line-height: 30px; min-height: 30px; font-size: 21px; padding: 2px 0px; display: inline-block; vertical-align: top;">测试</span><ul class="children" style="list-style: disc outside; padding-bottom: 4px;"><li style="line-height: 30px;"><span class="content mubu-node" color="#3da8f5" heading="2" images="%5B%7B%22id%22%3A%221d916f3267c0b118a-40263%22%2C%22oh%22%3A1004%2C%22ow%22%3A742%2C%22uri%22%3A%22document_image%2F7fabd28a-8c59-4ffe-b9f3-ab2ef4c91549-40263.jpg%22%2C%22w%22%3A87%7D%5D" style="color: rgb(61, 168, 245); line-height: 30px; min-height: 30px; font-size: 21px; padding: 2px 0px; display: inline-block; vertical-align: top;"><span class="bold italic underline" style="font-weight: bold; text-decoration: underline; font-style: italic;">测试图片</span></span><div style="padding: 3px 0"><img src="https://img.mubu.com/document_image/7fabd28a-8c59-4ffe-b9f3-ab2ef4c91549-40263.jpg" style="max-width: 720px; width: 87px;" class="attach-img"></div></li><li style="line-height: 30px;"><span class="content mubu-node" color="#3da8f5" heading="2" style="color: rgb(61, 168, 245); line-height: 30px; min-height: 30px; font-size: 21px; padding: 2px 0px; display: inline-block; vertical-align: top;">是是是</span><ul class="children" style="list-style: disc outside; padding-bottom: 4px;"><li style="line-height: 30px;"><span class="content mubu-node" color="#3da8f5" heading="2" style="color: rgb(61, 168, 245); line-height: 30px; min-height: 30px; font-size: 21px; padding: 2px 0px; display: inline-block; vertical-align: top;">ssss</span></li><li style="line-height: 30px;"><span class="content mubu-node" color="#dc2d1e" heading="2" style="color: rgb(220, 45, 30); line-height: 30px; min-height: 30px; font-size: 21px; padding: 2px 0px; display: inline-block; vertical-align: top;">
<a class="content-link"  href="https://mubu.com/doclcoXBPA2D" style="text-decoration: underline; opacity: 0.6; color: inherit;" >
<span class="bold italic" style="font-weight: bold; font-style: italic;">https://mubu.com/doclcoXBPA2D</span></a></span></li><li style="line-height: 24px;"><span class="content mubu-node" color="#dc2d1e" images="%5B%7B%22id%22%3A%2237d16f3289cb16101%22%2C%22oh%22%3A1004%2C%22ow%22%3A742%2C%22uri%22%3A%22document_image%2F7fabd28a-8c59-4ffe-b9f3-ab2ef4c91549-40263.jpg%22%2C%22w%22%3A87%7D%5D" style="color: rgb(220, 45, 30); line-height: 24px; min-height: 24px; font-size: 16px; padding: 2px 0px; display: inline-block; vertical-align: top;"><a class="content-link" target="_blank" href="https://mubu.com/doclcoXBPA2D" style="text-decoration: underline; opacity: 0.6; color: inherit;"><span class="bold italic" style="font-weight: bold; font-style: italic;">https://mubu.com/doclcoXBPA2D</span></a></span><div style="padding: 3px 0"><img src="https://img.mubu.com/document_image/7fabd28a-8c59-4ffe-b9f3-ab2ef4c91549-40263.jpg" style="max-width: 720px; width: 87px;" class="attach-img"></div></li><li style="line-height: 30px;"><span class="content mubu-node" color="#dc2d1e" heading="2" style="color: rgb(220, 45, 30); line-height: 30px; min-height: 30px; font-size: 21px; padding: 2px 0px; display: inline-block; vertical-align: top;"><span class="italic" style="font-style: italic;">sss</span></span></li></ul></li></ul></li><li style="line-height: 30px;"><span class="content mubu-node" color="#dc2d1e" heading="2" style="color: rgb(220, 45, 30); line-height: 30px; min-height: 30px; font-size: 21px; padding: 2px 0px; display: inline-block; vertical-align: top;"></span></li><li style="line-height: 30px;"><span class="content mubu-node" color="#dc2d1e" heading="2" style="color: rgb(220, 45, 30); line-height: 30px; min-height: 30px; font-size: 21px; padding: 2px 0px; display: inline-block; vertical-align: top;">ok</span></li><li style="line-height: 30px;"><span class="content mubu-node" color="#dc2d1e" heading="2" style="color: rgb(220, 45, 30); line-height: 30px; min-height: 30px; font-size: 21px; padding: 2px 0px; display: inline-block; vertical-align: top;"><a class="content-link" target="_blank" href="https://github.com/alash3al/redix" style="text-decoration: underline; opacity: 0.6; color: inherit;">https://github.com/alash3al/redix</a></span></li><li style="line-height: 27px;"><span class="content mubu-node" color="#dc2d1e" heading="3" style="color: rgb(220, 45, 30); line-height: 27px; min-height: 27px; font-size: 19px; padding: 2px 0px; display: inline-block; vertical-align: top;">标签</span></li></ul></div>
			
			</body>
			</html>
			`

			w := webview.New(webview.Settings{
				Title: "Loaded: Injected via JavaScript",
				URL:   "data:text/html," + url.PathEscape(indexHTML),
				//URL:       "data:image/gif;base64,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",
				Resizable: false,
				ExternalInvokeCallback: func(w webview.WebView, data string) {
					fmt.Println(data)
				},
			})

			defer w.Exit()

			//w.Dispatch(func() {
			//	w.Eval(`document.body.innerHTML = "<h1>Hello, world</h1>";`)
			//})

			w.Run()

			return
		},
	}
}
