#!/usr/bin/env python
# -*- coding: utf-8 -*-
##
##  Whabapp - A Web application microframework
##
##  usage: $ python app.py -s localhost 8080
##
import sys
import re
import cgi
import Cookie

# quote HTML metacharacters.
def q(s):
    assert isinstance(s, basestring), s
    return (s.
            replace('&','&amp;').
            replace('>','&gt;').
            replace('<','&lt;').
            replace('"','&#34;').
            replace("'",'&#39;'))

# encode as a URL.
URLENC = re.compile(r'[^a-zA-Z0-9_.-]')
def urlenc(url, codec='utf-8'):
    def f(m):
        return '%%%02X' % ord(m.group(0))
    return URLENC.sub(f, url.encode(codec))

# remove redundant spaces.
RMSP = re.compile(r'\s+', re.U)
def rmsp(s):
    return RMSP.sub(' ', s.strip())

# merge two dictionaries.
def mergedict(d1, d2):
    d1 = d1.copy()
    d1.update(d2)
    return d1

# iterable
def iterable(obj):
    return hasattr(obj, '__iter__')

# closable
def closable(obj):
    return hasattr(obj, 'close')


##  Template
##    $(var) ... encode var as a sanitized html.
##    $[var] ... encode var as an encoded url.
##    $<var> ... dump var as a raw html.
##
class Template(object):

    debug = 0

    def __init__(self, *args, **kwargs):
        if '_copyfrom' in kwargs:
            _copyfrom = kwargs['_copyfrom']
            objs = _copyfrom.objs
            kwargs = mergedict(_copyfrom.kwargs, kwargs)
        else:
            objs = []
            for line in args:
                i0 = 0
                for m in self._VARIABLE.finditer(line):
                    objs.append(line[i0:m.start(0)])
                    x = m.group(1)
                    if x == '$':
                        objs.append(x)
                    else:
                        objs.append(self.Variable(x[0], x[1:-1]))
                    i0 = m.end(0)
                objs.append(line[i0:])
        self.objs = objs
        self.kwargs = kwargs
        return

    def __call__(self, **kwargs):
        return self.__class__(_copyfrom=self, **kwargs)

    def __iter__(self):
        return self.render()

    def __repr__(self):
        return '<Template %r>' % self.objs

    def __str__(self):
        return ''.join(self)

    @classmethod
    def load(klass, lines, **kwargs):
        template = klass(*lines, **kwargs)
        if closable(lines):
            lines.close()
        return template
    
    def render(self, codec='utf-8', **kwargs):
        kwargs = mergedict(self.kwargs, kwargs)
        def render1(value, quote=False):
            if value is None:
                pass
            elif isinstance(value, Template):
                if quote:
                    if 2 <= self.debug:
                        raise ValueError
                    elif self.debug:
                        yield '[ERROR: Template in a quoted context]'
                else:
                    for x in value.render(codec=codec, **kwargs):
                        yield x
            elif isinstance(value, dict):
                if 2 <= self.debug:
                    raise ValueError
                elif self.debug:
                    yield '[ERROR: Dictionary included]'
            elif isinstance(value, basestring):
                if quote:
                    yield q(value)
                else:
                    yield value
            elif callable(value):
                for x in render1(value(**kwargs), quote=quote):
                    yield x
            elif iterable(value):
                for obj1 in value:
                    for x in render1(obj1, quote=quote):
                        yield x
            else:
                if quote:
                    yield q(unicode(value))
                else:
                    if 2 <= self.debug:
                        raise ValueError
                    elif self.debug:
                        yield '[ERROR: Non-string object in a non-quoted context]'
            return
        for obj in self.objs:
            if isinstance(obj, self.Variable):
                k = obj.name
                if k in kwargs:
                    value = kwargs[k]
                elif k in self.kwargs:
                    value = self.kwargs[k]
                else:
                    yield '[notfound:%s]' % k
                    continue
                if obj.type == '(':
                    for x in render1(value, quote=True):
                        yield x
                    continue
                elif obj.type == '[':
                    yield urlenc(value)
                    continue
            else:
                value = obj
            for x in render1(value):
                yield x
        return

    _VARIABLE = re.compile(r'\$(\(\w+\)|\[\w+\]|<\w+>)')
    
    class Variable(object):
        
        def __init__(self, type, name):
            self.type = type
            self.name = name
            return
        
        def __repr__(self):
            if self.type == '(':
                return '$(%s)' % self.name
            elif self.type == '[':
                return '$[%s]' % self.name
            else:
                return '$<%s>' % self.name
    

##  Router
##
class Router(object):
    
    def __init__(self, method, regex, func):
        self.method = method
        self.regex = regex
        self.func = func
        return

    @staticmethod
    def make_wrapper(method, pat):
        regex = re.compile('^'+pat+'$')
        def wrapper(func):
            return Router(method, regex, func)
        return wrapper

def GET(pat): return Router.make_wrapper('GET', pat)
def POST(pat): return Router.make_wrapper('POST', pat)


##  Response
##
class Response(object):

    def __init__(self, status='200 OK', content_type='text/html; charset=utf-8', **kwargs):
        self.status = status
        self.headers = [('Content-Type', content_type)]+kwargs.items()
        return

    def add_header(self, k, v):
        self.headers.append((k, v))
        return

class Redirect(Response):

    def __init__(self, location):
        Response.__init__(self, '302 Found', Location=location)
        return

class NotFound(Response):

    def __init__(self):
        Response.__init__(self, '404 Not Found')
        return

class InternalError(Response):

    def __init__(self):
        Response.__init__(self, '500 Internal Server Error')
        return


##  WebApp
##
class WebApp(object):

    debug = 0
    codec = 'utf-8'
    
    def run(self, environ, start_response):
        method = environ.get('REQUEST_METHOD', 'GET')
        path = environ.get('PATH_INFO', '/')
        fp = environ.get('wsgi.input')
        fields = cgi.FieldStorage(fp=fp, environ=environ)
        result = None
        for attr in dir(self):
            router = getattr(self, attr)
            if not isinstance(router, Router): continue
            if router.method != method: continue
            m = router.regex.match(path)
            if m is None: continue
            cookie = Cookie.SimpleCookie()
            cookie.load(environ.get('HTTP_COOKIE', ''))
            params = m.groupdict().copy()
            params['_path'] = path
            params['_fields'] = fields
            params['_environ'] = environ
            params['_cookie'] = cookie
            code = router.func.func_code
            args = code.co_varnames[:code.co_argcount]
            kwargs = {}
            for k in args[1:]:
                if k in fields:
                    kwargs[k] = fields.getvalue(k)
                elif k in params:
                    kwargs[k] = params[k]
            try:
                result = router.func(self, **kwargs)
            except TypeError:
                if 2 <= self.debug:
                    raise
                elif self.debug:
                    result = [InternalError()]
            break
        if result is None:
            result = self.get_default(path, fields, environ)
        def f(obj):
            try:
                if isinstance(obj, Response):
                    start_response(obj.status, obj.headers)
                elif isinstance(obj, Template):
                    for x in obj.render(codec=self.codec):
                        if isinstance(x, unicode):
                            x = x.encode(self.codec)
                        yield x
                elif iterable(obj):
                    for x in obj:
                        for y in f(x):
                            yield y
                else:
                    if isinstance(obj, unicode):
                        obj = obj.encode(self.codec)
                    yield obj
            except Exception, e:
                print >>sys.stderr, 'ERROR:', e
                obj = InternalError()
                start_response(obj.status, obj.headers)
                return
        return f(result)

    def get_default(self, path, fields, environ):
        return [NotFound(), '<html><body>not found</body></html>']


# run_server
def run_server(host, port, app):
    from wsgiref.simple_server import make_server
    print >>sys.stderr, 'Serving on %r port %d...' % (host, port)
    httpd = make_server(host, port, app.run)
    httpd.serve_forever()

# run_cgi
def run_cgi(app):
    from wsgiref.handlers import CGIHandler
    CGIHandler().run(app.run)

# run_httpcgi: for cgi-httpd
def run_httpcgi(app):
    from wsgiref.handlers import CGIHandler
    class HTTPCGIHandler(CGIHandler):
        def start_response(self, status, headers, exc_info=None):
            protocol = self.environ.get('SERVER_PROTOCOL', 'HTTP/1.0')
            sys.stdout.write('%s %s\r\n' % (protocol, status))
            return CGIHandler.start_response(self, status, headers, exc_info=exc_info)
    HTTPCGIHandler().run(app.run)

# main
def main(app, argv):
    import getopt
    def usage():
        print 'usage: %s [-d] [-s] [host [port]]' % argv[0]
        return 100
    try:
        (opts, args) = getopt.getopt(argv[1:], 'ds')
    except getopt.GetoptError:
        return usage()
    server = False
    debug = 0
    for (k, v) in opts:
        if k == '-d': debug += 1
        elif k == '-s': server = True
    Template.debug = debug
    WebApp.debug = debug
    if server:
        host = ''
        port = 8080
        if args:
            host = args.pop(0)
        if args:
            port = int(args.pop(0))
        run_server(host, port, app)
    else:
        run_httpcgi(app)
    return


##  FileManager
##
import os
import time
import stat
import uuid
import hmac
import hashlib
import config
def sanitize(name):
    pat = re.compile(ur'[\s\\*?|"<>/:]+', re.U)
    name = pat.sub(u'_', name)
    timestamp = time.strftime('t%Y%m%d%H%M%S')
    return timestamp+'_'+name
    
class FileManager(WebApp):
    
    HEADER = u'''<!DOCTYPE HTML>
<html><head>
<style><!--
body { line-height: 1.2; }
table { margin: 1em; border-collapse: collapse; }
td { padding:0.5em; }
th { background:#eee; }
h1 { border-bottom: solid darkblue 4pt; }
.highlight { background:#dfd; }
.error { font-weight: bold; text-color: red; }
.upload { margin: 1em; padding:1em; background:#fdf; border: solid black 2pt; }
--></style>
'''
    FOOTER = u'<hr><address>Yusuke Shinyama</address>\n'
    NOTFOUND = u'<html><body>not found</body></html>\n'
    ERROR = Template(
        u'<title>$(TITLE) - $(folder)/ - エラー</title>\n'
        u'<body><h1>$(folder)/ - エラー</h1>\n'
        u'<div class=error>$(message)</div>\n'
        u'<p> <a href="$(BASEURL)/view/$(folder)/">$(folder)/ に戻る</a>\n',
        TITLE=config.TITLE, BASEURL=config.BASEURL)
    BUFSIZ = 65536

    def _get_ident(self, username):
        path = os.path.join(config.BASEDIR, username)
        path = os.path.join(path, '.ident')
        fp = open(path, 'r')
        ident = fp.read().strip()
        fp.close()
        (s,_,v) = ident.partition(' ')
        return (s,v)

    class NotAuthenticated(Exception): pass
    def _auth(self, cookie, username=None, password=None):
        curtime = int(time.time())
        if username and password:
            try:
                (s,v) = self._get_ident(username)
            except IOError:
                raise self.NotAuthenticated
            h = hashlib.sha1()
            h.update(username+s+password)
            if h.hexdigest() != v:
                raise self.NotAuthenticated
            h = hmac.HMAC(config.KEY, digestmod=hashlib.sha1)
            nonce = uuid.uuid4().hex
            h.update(username+repr(curtime)+nonce)
            path = config.BASEURL+'/'
            session = ':'.join((username, repr(curtime), nonce, h.hexdigest()))
            cookie['session'] = session
            cookie['session']['path'] = path
        else:
            try:
                session = cookie['session']
            except KeyError:
                raise self.NotAuthenticated
            try:
                (username, logintime, nonce, v) = session.value.split(':')
                logintime = int(logintime)
            except ValueError:
                raise self.NotAuthenticated
            if logintime+config.DURATION < curtime:
                raise self.NotAuthenticated
            h = hmac.HMAC(config.KEY, digestmod=hashlib.sha1)
            h.update(username+repr(logintime)+nonce)
            if h.hexdigest() != v:
                raise self.NotAuthenticated
        print >>sys.stderr, 'auth', username
        return username

    @POST(r'/login')
    def login_check(self, _cookie, f='/', username='', password=''):
        try:
            self._auth(_cookie, username, password)
            resp = Redirect(config.BASEURL+f)
            resp.headers.extend( ('Set-Cookie', m.OutputString())
                                 for m in _cookie.values() )
            yield resp
        except self.NotAuthenticated:
            yield Redirect(config.BASEURL+'/login?f='+urlenc(f))
        return

    @POST(r'/logout')
    def logout(self, _cookie, f='/'):
        _cookie['session'] = ''
        resp = Redirect(config.BASEURL+f)
        resp.headers.extend( ('Set-Cookie', m.OutputString())
                             for m in _cookie.values() )
        yield resp
        return
    
    @GET(r'/login')
    def login(self, f='/'):
        yield Response()
        yield self.HEADER
        yield Template(
            u'<title>$(TITLE) - ログイン</title>\n'
            u'<body><h1>$(TITLE) - ログイン</h1>\n'
            u'<hr><form method=POST action="$(BASEURL)/login"><table>\n'
            u'<tr><td>Username:</td><td><input name=username></td></tr>\n'
            u'<tr><td>Password:</td><td><input name=password type=password></td></tr>\n'
            u'</table><input type=hidden name=f value="$(f)">\n'
            u'<input type="submit" value="Login">\n'
            u'<input type="reset" value="Reset">\n'
            u'</form>\n',
            TITLE=config.TITLE, BASEURL=config.BASEURL, f=f)
        yield self.FOOTER
        return

    @GET(r'/')
    def index(self, _cookie):
        try:
            username = self._auth(_cookie)
        except self.NotAuthenticated:
            yield Redirect(config.BASEURL+'/login')
            return
        yield Response()
        yield self.HEADER
        yield Template(
            u'<title>$(TITLE)</title>\n'
            u'<body><h1>$(TITLE)</h1>\n'
            u'<form method=POST action="$(BASEURL)/logout">\n'
            u'<p> ようこそ、$(username)さん。\n'
            u'<input type="submit" value="Logout">\n'
            u'</form>\n',
            TITLE=config.TITLE, BASEURL=config.BASEURL,
            username=username)
        yield u'<hr><table border>\n'
        yield u' <tr><th>ユーザ名</th></tr>\n'
        for name in sorted(os.listdir(config.BASEDIR)):
            if name.startswith('.'): continue
            path = os.path.join(config.BASEDIR, name)
            if not os.path.isdir(path): continue
            folder = name
            c = ''
            if folder == username:
                c = 'highlight'
            yield Template(
                u' <tr><td class=$(c)>'
                u'<a href="$(BASEURL)/view/$(folder)/">$(folder)</a>'
                u'</td></tr>\n',
                BASEURL=config.BASEURL, c=c, folder=folder)
        yield u'</table>\n'
        yield self.FOOTER
        return
    
    @GET(r'/view/(?P<folder>[^/]+)/')
    def view_folder(self, _path, _cookie, folder):
        try:
            username = self._auth(_cookie)
        except self.NotAuthenticated:
            yield Redirect(config.BASEURL+'/login?f='+urlenc(_path))
            return
        if folder.startswith('.'):
            yield NotFound()
            yield self.NOTFOUND
            yield self.FOOTER
            return
        yield Response()
        yield self.HEADER
        yield Template(
            u'<title>$(TITLE) - $(folder)/</title>\n'
            u'<body><h1>$(folder)/</h1>\n'
            u'<p> <a href="$(BASEURL)/">ひとつ上に戻る</a>\n',
            TITLE=config.TITLE,
            BASEURL=config.BASEURL,
            folder=folder)
        if username == folder:
            yield Template(
                u'<form method=POST enctype="multipart/form-data"'
                u' action="$(BASEURL)/upload/$(folder)/"><div class=upload>\n'
                u'<strong>自分のファイルをアップロードする:</strong>\n'
                u'<input type="file" name="item" value="">\n'
                u'<input type="submit" value="Upload">\n'
                u'<input type="reset" value="Reset">\n'
                u'</div></form>',
                BASEURL=config.BASEURL,
                folder=folder)
        yield u'<hr><table border>\n'
        yield u' <tr><th>ファイル名</th><th>更新日時</th><th>サイズ</th></tr>\n'
        dirpath = os.path.join(config.BASEDIR, folder)
        files = []
        for name in sorted(os.listdir(dirpath)):
            if name.startswith('.'): continue
            path = os.path.join(dirpath, name)
            if not os.path.isfile(path): continue
            try:
                sv = os.stat(path)
                mtime = sv[stat.ST_MTIME]
                size = sv[stat.ST_SIZE]
                files.append((mtime, name, size, path))
            except OSError:
                continue
        files.sort(reverse=True)
        if files:
            for (mtime, name, size, path) in files:
                mtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))
                yield Template(
                    u' <tr><td>'
                    u'<a href="$(BASEURL)/view/$(folder)/$(name)">$(name)</a></td>'
                    u'<td><code>$(mtime)</code></td>'
                    u'<td align=right>$(size) bytes</td></tr>\n',
                    BASEURL=config.BASEURL,
                    folder=folder, name=name,
                    mtime=mtime, size=size)
        else:
            yield u' <tr><td colspan="3">ファイルなし</td></tr>\n'
        yield u'</table>\n'
        yield self.FOOTER
        return

    @GET(r'/view/(?P<folder>[^/]+)/(?P<name>[^/]+)')
    def view_file(self, _path, _cookie, folder, name):
        try:
            username = self._auth(_cookie)
        except self.NotAuthenticated:
            yield Redirect(config.BASEURL+'/login?f='+urlenc(_path))
            return
        if (folder.startswith('.') or
            name.startswith('.')):
            yield NotFound()
            yield self.NOTFOUND
            yield self.FOOTER
            return
        path = os.path.join(config.BASEDIR, folder)
        path = os.path.join(path, name)
        if not os.path.isfile(path):
            yield NotFound()
            yield self.NOTFOUND
            yield self.FOOTER
            return
        try:
            fp = open(path, 'rb')
        except IOError:
            yield self.NOTFOUND
            yield self.FOOTER
            return
        yield Response(content_type='text/plain')
        size = config.MAXSIZE
        while 0 < size:
            data = fp.read(min(size, self.BUFSIZ))
            if not data: break
            size -= len(data)
            yield data
        fp.close()
        return

    @POST(r'/upload/(?P<folder>[^/]+)/')
    def upload_file(self, _path, _cookie, _fields, folder):
        try:
            username = self._auth(_cookie)
        except self.NotAuthenticated:
            yield Redirect(config.BASEURL+'/login?f='+urlenc(_path))
            return
        item = _fields['item']
        if not (item is not None and item.file and item.filename):
            yield Response()
            yield self.HEADER
            yield self.ERROR(
                folder=folder,
                message=u'ファイルが選択されていません。')
            yield self.FOOTER
            return
        infp = item.file
        name = sanitize(item.filename)
        if (username != folder or
            folder.startswith('.') or
            name.startswith('.')):
            yield NotFound()
            yield self.NOTFOUND
            yield self.FOOTER
            return
        print >>sys.stderr, 'upload', (folder, name)
        path = os.path.join(config.BASEDIR, folder)
        path = os.path.join(path, name)
        try:
            outfp = open(path, 'wb')
        except IOError, e:
            yield Response()
            yield self.HEADER
            yield self.ERROR(
                folder=folder,
                message=u'ファイル処理上のエラーが発生しました。')
            yield self.FOOTER
            return
        size = config.MAXSIZE
        while 0 < size:
            data = infp.read(min(size, self.BUFSIZ))
            if not data: break
            size -= len(data)
            outfp.write(data)
        outfp.close()
        if size == 0:
            yield Response()
            yield self.HEADER
            yield self.ERROR(
                folder=folder,
                message=u'ファイルの大きさが制限を超えています。')
            yield self.FOOTER
            return
        yield Response()
        yield self.HEADER
        yield Template(
            u'<title>$(TITLE) - $(folder)/ - アップロード成功</title>\n'
            u'<body><h1>$(folder)/ - アップロード成功</h1>\n'
            u'<p> <code>$(name)</code> という名前でアップロードしました。\n'
            u'<p> <a href="$(BASEURL)/view/$(folder)/">$(folder)/ に戻る</a>\n',
            TITLE=config.TITLE, BASEURL=config.BASEURL,
            name=name, folder=folder)
        yield self.FOOTER
        return

if __name__ == '__main__': sys.exit(main(FileManager(), sys.argv))
