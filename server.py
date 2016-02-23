#!/usr/bin/evn python
# coding:utf-8

import sys
reload(sys)
sys.setdefaultencoding('utf-8')

import logging
import socket
import os
import hashlib
from urlparse import urlparse
import tornado.web
import tornado.ioloop
import tornado.httpserver
from tornado.gen import coroutine
import tornado.gen
import tornado.httpclient
import tornado.iostream
import tornado.options
from tornado.options import options, define
import tornado.tcpclient
import tornado.httputil

define("port", 22222, type=int)
define("auth", False, type=bool)
define("username", "xjj")
define("password", "1234")

logger = logging.getLogger()


def get_hash(s):
    if not s:
        s = ''
    return hashlib.md5(s)


def get_proxy(url):
    url_parsed = urlparse(url, scheme='http')
    proxy_key = '%s_proxy' % url_parsed.scheme
    return os.environ.get(proxy_key)


def parse_proxy(proxy):
    proxy_parsed = urlparse(proxy, scheme='http')
    return proxy_parsed.hostname, proxy_parsed.port


class ProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST', 'CONNECT']

    def prepare(self):
        """
        auth
        :return:
        """
        if 'Proxy-Authorization' in self.request.headers:
            try:
                auth_info = self.request.headers.get('Proxy-Authorization', '')
                del self.request.headers['Proxy-Authorization']
                mode, base64 = auth_info.split(' ')
                username, password = base64.decode('base64').split(':')
                if username != options.username or password != options.password:
                    raise tornado.web.HTTPError(status_code=403, log_message='Proxy Auth Failed')

            except Exception as e:
                if not isinstance(e, tornado.web.HTTPError):
                    raise e
                raise e

    def compute_etag(self):
        return None  # disable tornado Etag

    #def _log(self):
    #    pass

    @coroutine
    def get(self, *args, **kwargs):
        target_url = self.request.uri
        body = self.request.body if self.request.body else None
        if 'Proxy-Connection' in self.request.headers:
            del self.request.headers['Proxy-Connection']
        proxy = get_proxy(target_url)
        if proxy:
            tornado.httpclient.AsyncHTTPClient.configure('tornado.curl_httpclient.CurlAsyncHTTPClient')
            proxy_host, proxy_port = parse_proxy(proxy)
        else:
            proxy_host, proxy_port = None, None
        request = tornado.httpclient.HTTPRequest(
            target_url,
            method=self.request.method,
            headers=self.request.headers,
            body=body,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            follow_redirects=True,  # 应对302，301
            allow_nonstandard_methods=True,
        )
        try:
            response = yield tornado.httpclient.AsyncHTTPClient().fetch(request, raise_error=False)
        except Exception as e:
            if isinstance(e, tornado.httpclient.HTTPError) and hasattr(e, 'response') and e.response:
                response = e.response
            else:
                response = tornado.httpclient.HTTPResponse(request, 500)
        self.handler_response(response)

    def handler_response(self, response):
        self.set_status(response.code, response.reason)

        self._headers = tornado.httputil.HTTPHeaders()  # 清除tornado默认请求头, 如果不清除的话，就会出现知乎等网站css加载不出来
        for h, v in self.request.headers.get_all():
            if h not in ('Content-Length', 'Transfer-Encoding', 'Content-Encoding', 'Connection'):  # 清除掉这些状态也是必须的，不然会造成301，302，比如content-length不对出错
                self.add_header(h, v)  # some header appear multiple times, eg 'Set-Cookie'
        self.add_header('VIA', 'Tornado-Proxy')

        if response.body:
            self.set_header('Content-Length', len(response.body))
            self.write(response.body)
        self.finish()

    post = get

    @coroutine
    def connect(self, *args, **kwargs):
        host, port = self.request.uri.split(':')

        try:
            remote = yield tornado.gen.with_timeout(tornado.ioloop.IOLoop.current().time()+10,
                                                    tornado.tcpclient.TCPClient().connect(host, int(port)))
        except Exception as e:
            raise e

        client = self.request.connection.detach()
        yield client.write(b'HTTP/1.0 200 Connection established\r\n\r\n')

        remote.set_close_callback(tornado.gen.Callback(remote))
        client.read_until_close(lambda x: x, streaming_callback=lambda x: remote.write(x))
        remote.read_until_close(lambda x: x, streaming_callback=lambda x: client.write(x))

        yield [
            tornado.gen.Task(client.set_close_callback),
            tornado.gen.Task(remote.set_close_callback),
        ]
        self._log()

def server():
    tornado.options.parse_command_line()
    settings = {
        'debug': True,
    }
    handler = [
        (r'.*', ProxyHandler),
    ]
    app = tornado.web.Application(handler, **settings)
    tornado.httpserver.HTTPServer(app).listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    server()
