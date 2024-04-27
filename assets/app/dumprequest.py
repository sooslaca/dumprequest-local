import signal, sys
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, request, abort
import logging, json
from datetime import datetime as dt
from datetime import UTC
from werkzeug.serving import WSGIRequestHandler, _log, BaseWSGIServer

import ssl

#logging.basicConfig(level=logging.INFO)
log = logging.getLogger('werkzeug')
#log.setLevel(logging.ERROR)

class ReverseProxied(object):
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        scheme = environ.get('HTTP_X_FORWARDED_PROTO')
        if scheme:
            environ['wsgi.url_scheme'] = scheme
        return self.app(environ, start_response)

app = Flask(__name__)

#app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
#app.wsgi_app = ReverseProxied(app.wsgi_app)

def prepstr(s, c = "│ "):
    ret = ""
    for l in s.splitlines():
        ret += c + l + "\n"
    return ret

def longestline(s):
    maxlen = 0
    for l in s.splitlines():
      if len(l) > maxlen:
        maxlen = len(l)
    return maxlen

def addborder(s):
    ret = ""
    maxlen = longestline(s)+1
    rowindex=0
    maxrow=len(s.splitlines())-1
    for l in s.splitlines():
        if l[-1] == "─": padding = "─"
        else: padding = " "
        ret += l
        for x in range(len(l), maxlen):
            ret += padding
        if rowindex == 0:
            ret += "┐"
        elif rowindex == maxrow:
            ret += "┘"
        else:
          if padding == "─":
            ret += "┤"
          else:
            ret += "│"
        if rowindex != maxrow:
            ret += "\n"
        rowindex+=1
    return ret

@app.after_request
def after_request(response):
    logline  = ('%s - - [%s] "%s %s %s" %s %s' % (request.remote_addr, dt.now(UTC).replace(tzinfo=None).strftime("%d/%b/%Y %H:%M:%S"), request.method, request.path, request.environ.get('SERVER_PROTOCOL'), response.status_code, response.content_length))
    if request.referrer:
        logline += " " + request.referrer
    print(logbox(request, logline + "\n"))
    return response

def logbox(request, logline=None):
    resp  = "┌" + "─"*70 + "\n"
    resp += "│ " + request.remote_addr + " [" + dt.now(UTC).replace(tzinfo=None).strftime("%d/%b/%Y %H:%M:%S.%f")[:-3] + "] \n"
    resp += "│ " + request.method + " " + request.url + " [" + request.scheme.upper() + "]\n"
    resp += "├" + "─"*70 + "\n"
    resp += "│ --~~~=:> HEADERS <:=~~~--" + "\n"
    resp += prepstr(str(request.headers))
    resp += "├" + "─"*70 + "\n"
    resp += "│ --~~~=:> COOKIES <:=~~~--" + "\n"
    resp += prepstr(str(request.cookies))
    if request.method == 'POST':
        resp += "├" + "─"*70 + "\n"
        resp += "│ --~~=:> POST DATA <:=~~--" + "\n"
#        resp += "│ " + request.data.decode() + "\n"
        resp += "│ " + json.dumps(request.form) + "\n"
    if logline:
        resp += "├" + "─"*70 + "\n"
        resp += "│ --~~~=:>   LOG   <:=~~~--" + "\n"
        resp += "│ " + logline
    resp += "└" + "─"*70
    resp = addborder(resp)
    return resp

@app.route("/404")
def handler404():
    handler()
    abort(404)

@app.route("/", methods = ['GET', 'POST'])
@app.route("/<path:dummy>", methods = ['GET', 'POST'])
def handler(dummy=None):
    return "<pre>"+logbox(request)+"</pre>"

class MyRequestHandler(WSGIRequestHandler):
    # Just like WSGIRequestHandler, except not to log INFO
    def log(self, type, message, *args):
        if type != "info":
          _log(type, '%s - - [%s] %s\n' % (self.address_string(),
                                           self.log_date_time_string(),
                                           message % args))

    def log_request(self, code='-', size='-'):
        self.log('info', '"%s" %s %s', self.requestline, code, size)

def signal_handler(signal, frame):
  print('dumprequest exiting...')
  sys.exit(0)

def verify_request(self, request, client_address):
    data = request.getpeercert(True)
#    print(request)
#    cert = request.getpeercert(True)
#    raw = decoder.decode(cert)[0]
#    print("Serial Number of your certificate is: % " % str(raw[0][1]))
    # todo: do checks & if serial no is ok then return true
#    cert = x509.load_der_x509_certificate(data, default_backend())
#    print(cert)
    return True

if __name__ == "__main__":
#    BaseWSGIServer.verify_request = verify_request

#    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
#    context.verify_mode = ssl.CERT_REQUIRED
#    context.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF

#    context.load_verify_locations(cafile="mtlsca.crt")
#    context.load_cert_chain(certfile="server.crt",
#                            keyfile="server.key",)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
#    app.run(host="0.0.0.0", ssl_context=context, port=443, debug=True, request_handler=MyRequestHandler)
    app.run(host="0.0.0.0", port=80, debug=True, request_handler=MyRequestHandler)

