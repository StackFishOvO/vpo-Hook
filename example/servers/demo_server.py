#!/usr/bin/env python3
"""vpo-hook 外发蜜罐 demo 服务器（纯标准库，无依赖）。

用法: python3 demo_server.py [port]
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/send":
            msg = parse_qs(p.query).get("msg", ["hello password 123"])[0]
            body = ("sent: " + msg + "\n").encode("utf-8")
        else:
            body = (
                "<h1>vpo-hook 外发蜜罐 demo</h1>"
                "<p>访问 <a href='/send?msg=my+password+123'>/send?msg=my+password+123</a></p>"
            ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)


print(f"listening on http://127.0.0.1:{PORT}", flush=True)
HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
