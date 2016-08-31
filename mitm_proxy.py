# -*- coding: utf-8 -*-
#!/usr/bin/env python
import logging
#Import for proxy
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from urlparse import urlparse, urlunparse, ParseResult
from SocketServer import ThreadingMixIn
from httplib import HTTPResponse
from tempfile import gettempdir
from os import path, listdir
from socket import socket
from re import compile
# import for check params
import json
import argparse
import re
# import for SSL runtimes
import ssl
from functools import wraps
from OpenSSL.crypto import (X509Extension, X509, dump_privatekey, dump_certificate, load_certificate, load_privatekey, PKey, TYPE_RSA, X509Req)
from OpenSSL.SSL import FILETYPE_PEM
#import for check response and request
from bs4 import BeautifulSoup
import StringIO
import gzip
import urllib

__author__ = 'Sanukode based in jod of Nadeem Douba'
__copyright__ = 'MitmProxy'
__credits__ = ['LVS']

__license__ = 'GPL'
__version__ = '0.1'
__email__ = 'fernando.mateluna@gmail.com'
__maintainer__ = 'Fernando Mateluna'
__status__ = 'CTO'

__all__ = [
    'CertificateAuthority',
    'ManagerProxyMITM',
    'RequestInterceptorPlugin',
    'ResponseInterceptorPlugin',
    'MitmProxy',
    'AsyncMitmProxy',
    'InvalidInterceptorPluginException'
]

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s', filename='{}/info.log'.format("."), filemode='w')

sources = {}
sources['Script'] = 'js,vb,css'
sources['HTML'] = 'htm,html,jsp,jsf,xhtml,php,do,xml'

pen_tester = {}
#Obtencion de codigo
pen_tester['get'] = []
#Cambio en valores post
pen_tester['post'] = []
#Enviar N solicitudes
pen_tester['ddos'] = []
#Reemplazar recursos remotos por locales
pen_tester['xss'] = []
#Guardar historico de valres
pen_tester['val'] = []
#Crear formularios
pen_tester['frm'] = []
#cambia codigo HTML en regex
pen_tester['chg'] = []

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ManagerProxyMITM(BaseHTTPRequestHandler):

    # Manager de proxy para MITM
    JSON = "application/json"
    FORM = "application/x-www-form-urlencoded"

    r = compile(r'http://[^/]+(/?.*)(?i)')

    def __init__(self, request, client_address, server):
        self.is_connect = False
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def _connect_to_host(self):
        # Obtiene puerto y host
        if self.is_connect:
            self.hostname, self.port = self.path.split(':')
        else:
            u = urlparse(self.path)
            if u.scheme != 'http':
                raise UnsupportedSchemeException('Unknown scheme %s' % repr(u.scheme))
            self.hostname = u.hostname
            self.port = u.port or 80
            self.path = urlunparse(
                ParseResult(
                    scheme='',
                    netloc='',
                    params=u.params,
                    path=u.path or '/',
                    query=u.query,
                    fragment=u.fragment
                )
            )

        # conecion al destino
        self._proxy_sock = socket()
        self._proxy_sock.settimeout(48000)
        self._proxy_sock.connect((self.hostname, int(self.port)))

        # Si requiere SSL conectar a wrap_socket
        if self.is_connect:
            self._proxy_sock = ssl.wrap_socket(self._proxy_sock)

    def _transition_to_ssl(self):
        self.request = ssl.wrap_socket(self.request, server_side=True, certfile=self.server.ca[self.path.split(':')[0]], ssl_version=ssl.PROTOCOL_SSLv23)

    def do_CONNECT(self):
        self.is_connect = True
        try:
            # Inicia conexion
            self._connect_to_host()

            # Si la conexion se realiza retorna desde el proxy un estado 200
            self.send_response(200, 'Connection established')
            self.end_headers()
            # Probar esto, retornar con detalle
            # self.request.sendall('%s 200 Connection established\r\n\r\n' % self.request_version)
            self._transition_to_ssl()
        except Exception, e:
            # print "Error in url : {}{}".format(self.hostname, self.path)
            # si la conexion tiene problemas retorna 500
            self.send_error(500, str(e))
            return

        # Reiniciar!!
        self.setup()
        self.ssl_host = 'https://%s' % self.path
        self.handle_one_request()

    def do_COMMAND(self):
        # Es un tunel SSL ?
        if not self.is_connect:
            try:
                # Conecta al host!
                self._connect_to_host()
            except Exception, e:
                # print "Error in url : {}{}".format(self.hostname, self.path)
                self.send_error(500, str(e))
                return

        # Formatear respuesta REQUEST
        req = '%s %s %s\r\n' % (self.command, self.path, self.request_version)
        # Agregar HEADER a Respuesta
        req += '%s\r\n' % self.headers
        # Concatenar mensaje y cuerto si existe en la respuesta
        if 'Content-Length' in self.headers:
            req += self.rfile.read(int(self.headers['Content-Length']))

        # Enviar todo al MEN IN THE MIDDLE!!
        self._proxy_sock.sendall(self.mitm_request(req))
        # parsear la resuesta a objeto HTTPRESPONSE
        http_response = HTTPResponse(self._proxy_sock)
        http_response.begin()
        content = http_response.read()

        # Eliminar del header 'Transfer-Encoding'
        del http_response.msg['Transfer-Encoding']

        if 'content-encoding' in http_response.msg.keys():
            if http_response.msg['Content-Encoding'] == 'gzip':
                compress_data = StringIO.StringIO(content)
                gzipper = gzip.GzipFile(fileobj=compress_data)
                del http_response.msg['Content-Encoding']
                content = gzipper.read()


        # Reenviar mensaje obtenido por proxy
        response = '%s %s %s\r\n' % (self.request_version, http_response.status, http_response.reason)
        response += '%s\r\n' % http_response.msg
        response += content

        # y ahora a cerrar la conexion remota quien nos dio info para enviar al cliente
        http_response.close()
        self._proxy_sock.close()

        # transmitir respuesta al MITM
        self.request.sendall(self.mitm_response(response))

    def mitm_request(self, data):
        data = self.do_tampering(data)
        times = 1
        for p in self.server._req_plugins:
            for tampering_value in  pen_tester['ddos']:
                if tampering_value['url'] in self.path:
                    times = tampering_value['times']
            for x in range(0, times):
                data = p(self.server, self).do_request(data)
        if times>1:
            logging.debug("Post {} times ".format(times))
        return data

    # MITM PRINCIPAL METODO!!
    def mitm_response(self, data):
        logging.debug("check : {}{}".format(self.hostname, self.path))
        #change values from any form or input type
        for post_data in pen_tester['frm']:
            if self.hostname in post_data['url'] and post_data['done'] == False:
                print("url = {} , host = {}".format(post_data['url'],self.hostname))
                self.post_data(post_data['url'], post_data['values'], post_data['download_path'])
                post_data['done'] = True
        #Save values fromo any input like value
        for value in pen_tester['val']:
            self.download_values(value['name'],value['file'],data)
        #download a content from url
        for download in pen_tester['get']:
            if download['url'] in self.path or download['url'] == "#":
                logging.debug("download {} ".format(self.path))
                self.wget(self.path,download, data)
        #change response from server fot any data
        for xss_value in pen_tester['xss']:
            if xss_value['url'] in self.path and xss_value['content']:
                logging.debug("CAMBIO!!!! {} to {}".format(xss_value['url'], self.path))
                # Inicia el cambio de recursos!!
                if 'HTTP/1.1 304 Not Modified' in data:
                    data = data.replace('HTTP/1.1 304 Not Modified','HTTP/1.1 200 OK')
                    data += "{}".format(xss_value['content'])
                else:
                    # Tomar todo el Data y reemplezar la ultima linea
                    new_data = ""
                    index = 0
                    for values in data.split('\n'):
                        index += 1
                        new_data += values + "\n"
                        if len(values.strip()) == 0:
                            break
                    logging.debug("!XSS attack in {} from {}".format(self.path, xss_value['src']))
                    #new_content_length = len(xss_value['content'])
                    data = new_data + xss_value['content']
                    #POC :
                    data = re.sub(r'Content-Length: (\d+)(?!.*\d)',"Content-Length: {}".format(len(xss_value['content'])), data)
                data = data.replace("HTTP/1.1 400 Bad Request","HTTP/1.1 200 OK")
                data = data.replace("HTTP/1.1 500 Internal Server Error","HTTP/1.1 200 OK")
                logging.debug("NEW RESPONSE : \n{}".format(data))
        data = data.replace("HTTP/1.1 401 Unauthorized","HTTP/1.1 200 OK")
        content_types = re.search(r'Content-Type: ([^&>]+)d', data)
        if content_types:
            content_type = content_types.group(0).split('\n')[0]
            if (r'text/xml' in content_type) or (r'text/html' in content_type):
                logging.debug("pen this {} : {}".format(self.path, content_type))
                #data = self.add_mitm_html_kode(data)
        for p in self.server._res_plugins:
            data = p(self.server, self).do_response(data)
        for giniu in pen_tester['chg']:
            if giniu['replace'].startswith( 'http' ):
                data = re.sub(giniu['find'], giniu['replace'], data)
            if giniu['replace'].startswith('path'):
                new_source = ""
                if giniu['local_source']:
                    new_source = giniu['local_source']
                else:
                    new_source = self.read_source_from_file(giniu['replace'])
                    giniu['local_source'] = new_source
                data = re.sub(giniu['find'], new_source, data)
            else:
                new_source = giniu['replace']
                data = re.sub(giniu['find'], new_source, data)
        return data

    def read_source_from_file(self, local_path):
        source = open(local_path.split(':')[1], 'r')
        return source.read()

    def post_data(self, url, inputs, local_path):
        #TODO: WTF is this shit!!
        # values = inputs.split('&')
        # values = inputs.split('&')
        data={'gcm_ID':'79511','estado':'2'}
        print ("url : {}, values = {}".format(url, inputs))
        """
        req = requests.post(url, data)
        """
        params = urllib.urlencode(data)
        f = urllib.urlopen(url, params)
        content = f.read()
        with open(local_path, 'wb') as download_file:
            download_file.write(content)

    def download_values(self, name, file_name, data):
        read_html = False
        index = 0
        html = ""
        for values in data.split('\n'):
            index += 1
            if read_html:
                html += values + "\n"
            if len(values.strip()) == 0:
                read_html = True
        pen_html = BeautifulSoup(html.decode('utf-8', 'ignore'), "lxml")
        # input_text = pen_html.findAll('input', {'type': 'text'})
        # input_hidden = pen_html.findAll('input', {'type': 'hidden'})
        # inputs = input_text.extend(input_hidden)
        inputs = pen_html.findAll('input', {'type': 'hidden'})
        for elem in inputs:
            if elem['name'] and name == elem['name']:
                print("Text  {}/{} >> {} = {}".format(self.hostname, self.path, elem['name'], elem['value']))
                f1 = open(file_name, 'a')
                f1.write("{}\n".format(elem['value']))


    def add_mitm_html_kode(self, data):
        header = ""
        index = 0
        html = ""
        read_html = False
        for values in data.split('\n'):
            index += 1
            if read_html:
                html += values + "\n"
            else:
                header += values + "\n"
            if len(values.strip()) == 0:
                read_html = True
        pen_html = BeautifulSoup(html.decode('utf-8', 'ignore'))
        body_tag = pen_html
        hr = pen_html.new_tag("hr")
        if body_tag.body:
            body_tag.body.append(hr)
        html_hack = body_tag.prettify('utf-8')
        logging.debug(u"!HEADER> \n {}".format(header))
        logging.debug("!HTML \n %s" %html)
        logging.debug("!HACK \n %s" %html_hack)
        header = re.sub(r'Content-Length: (\d+)(?!.*\d)', "Content-Length: {}".format(len(html_hack)), header)
        return header + html_hack

    def wget(self,url ,download, content):
        import uuid
        import urlparse, os
        local = download['local_path']
        pathX = urlparse.urlparse(url).path
        ext = os.path.splitext(pathX)[1]
        if ext.lower() not in [".png",".jpg",".gif",".jpeg"]:
            print "Create {}".format(url)
            fileName = "{}{}".format(uuid.uuid4(),ext)
            fileUrl = open("{}\{}".format(local ,fileName),"wb")
            fileUrl.write(url)
            fileUrl.write("\n")
            fileUrl.write(content)
            fileUrl.close()
            pass

    def is_json(self, myjson):
      try:
        json.loads(myjson)
      except ValueError:
        return False
      return True

    def do_tampering(self, data):
        eof_data_index = len(data.split('\n'))-1
        last_line = data.split('\n')[eof_data_index]
        content_Length = len(last_line)
        if len(last_line) == 0:
            return data
        else:
            content_type = re.search(r'Content-Type: ([^&>]+)d', data).group(0)
            logging.debug("! content_type = {}".format(content_type))
            # Diferenciar si los parametros vienen en formato POST o JSON
            if self.JSON in content_type:
                json_param = json.loads(last_line)
                new_json_param = {}
                new_json_params = "{"
                for json_key, param_value in json_param.iteritems():
                    do_tampering = False
                    logging.debug("- {} = [{}]".format(json_key , param_value))
                    for tampering_value in  pen_tester['post']:
                        if tampering_value['url'] != "#":
                            if tampering_value['url'] in self.path:
                                do_tampering = True
                        else:
                            do_tampering = True
                        if do_tampering:
                            logging.debug("! {} = [{}] in {}{}".format(json_key , tampering_value['new'], self.hostname, self.path))
                            if json_key == tampering_value['name'] and (param_value == tampering_value['old'] or tampering_value['old'] == '*'):
                                param_value = tampering_value['new']
                                logging.debug("! {} = [{}] in {}".format(json_key , tampering_value['new'], self.path))
                                break
                    new_json_param[json_key] = param_value
                    if self.is_json(param_value):
                        new_json_params +="'{}':{},".format(json_key,param_value)
                    else:
                        new_json_params +="'{}':'{}',".format(json_key,param_value)
                new_json_params = ("{}{}".format(new_json_params[:-1],"}")).replace("'",'"')
                content_Length = len(new_json_params)
                data = data.replace(last_line,new_json_params)
            if self.FORM in content_type:
                for value in last_line.split('&'):
                    do_tampering = False
                    if '=' in value:
                        name = value.split('=')[0]
                        value = value.split('=')[1]
                        logging.debug("- {} = [{}]".format(name , value))
                        for tampering_value in pen_tester['post']:
                            if tampering_value['url'] != "#":
                                if tampering_value['url'] in self.path:
                                    do_tampering = True
                            else:
                                do_tampering = True
                            if do_tampering:
                                if name == tampering_value['name'] and (value == tampering_value['old'] or tampering_value['old'] == '*'):
                                    logging.debug("! {} = [{}] in {}{}".format(name , tampering_value['new'], self.hostname, self.path))
                                    new_value = ("{}".format(tampering_value['new']))
                                    data = data.replace("{}={}".format(name, value), "{}={}".format(name, new_value))
                                    break
                last_line = data.split('\n')[eof_data_index]
                content_Length = len(last_line)
            data = re.sub(r'Content-Length: (\d+)(?!.*\d)', "Content-Length: {}".format(content_Length), data)
            # logging.debug("{}".format(data))
        return data

    def __getattr__(self, item):
        if item.startswith('do_'):
            return self.do_COMMAND

    def show_type_tag(self, html, input_type):
        b_object = BeautifulSoup(html,"lxml")
        for ext in sources['HTML'].split(","):
            if ext == self.path[-len(ext):]:
                i = 0
                for hidden_tag in b_object.find_all('input', type=input_type):
                    if i==0:
                        logging.debug("!:{} >> URL : {} ,Titulo : {}".format(input_type, self.path, b_object.title))
                        i += 1
                    tag_value = hidden_tag.get('value')
                    if hidden_tag.get('id'):
                        logging.debug("- {} = {}".format(hidden_tag.get('id'), tag_value))
                    if hidden_tag.get('name'):
                        logging.debug("- {} = {}".format(hidden_tag.get('name'), tag_value))
        return html

class CertificateAuthority(object):

    def __init__(self, ca_file='bciTest.pem', cache_dir=gettempdir()):
        self.ca_file = ca_file
        self.cache_dir = cache_dir
        self._serial = self._get_serial()
        if not path.exists(ca_file):
            self._generate_ca()
        else:
            self._read_ca(ca_file)
        print "Certificate Ready"

    def _get_serial(self):
        s = 1
        print "Loading files for SSL config."
        for c in filter(lambda x: x.startswith('.pymp_'), listdir(self.cache_dir)):
            print "{} ..OK".format(path.sep.join([self.cache_dir, c]))
            c = load_certificate(FILETYPE_PEM, open(path.sep.join([self.cache_dir, c])).read())
            sc = c.get_serial_number()
            if sc > s:
                s = sc
            del c
        return s

    def _generate_ca(self):
        # Crea KEY de tipo RSA
        self.key = PKey()
        self.key.generate_key(TYPE_RSA, 2048)
        # Crea Certificado X509
        self.cert = X509()
        self.cert.set_version(3)
        # Le puse 10000 no se por que
        self.cert.set_serial_number(1)
        self.cert.get_subject().CN = 'ca.proxymitm.com'
        self.cert.gmtime_adj_notBefore(0)
        #Tiempo de duracion del certificado
        self.cert.gmtime_adj_notAfter(315360000)
        self.cert.set_issuer(self.cert.get_subject())
        self.cert.set_pubkey(self.key)
        #Atributos del ceriticado
        self.cert.add_extensions([
            X509Extension("basicConstraints", True, "CA:TRUE, pathlen:0"),
            X509Extension("keyUsage", True, "keyCertSign, cRLSign"),
            X509Extension("subjectKeyIdentifier", False, "hash", subject=self.cert),
            ])
        self.cert.sign(self.key, "sha256")

        with open(self.ca_file, 'wb+') as f:
            f.write(dump_privatekey(FILETYPE_PEM, self.key))
            f.write(dump_certificate(FILETYPE_PEM, self.cert))

    def _read_ca(self, file):
        self.cert = load_certificate(FILETYPE_PEM, open(file).read())
        self.key = load_privatekey(FILETYPE_PEM, open(file).read())

    def __getitem__(self, cn):
        cnp = path.sep.join([self.cache_dir, '.pymp_%s.pem' % cn])
        if not path.exists(cnp):
            # Crea Key
            key = PKey()
            key.generate_key(TYPE_RSA, 2048)

            # Crea CSR
            # revisar : http://stackoverflow.com/questions/24043226/generating-a-csr-with-python-crypto
            req = X509Req()
            req.get_subject().CN = cn
            req.set_pubkey(key)
            req.sign(key, 'sha1')

            # Firmar CSR
            cert = X509()
            cert.set_subject(req.get_subject())
            cert.set_serial_number(self.serial)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(31536000)
            cert.set_issuer(self.cert.get_subject())
            cert.set_pubkey(req.get_pubkey())
            cert.sign(self.key, 'sha1')

            with open(cnp, 'wb+') as f:
                f.write(dump_privatekey(FILETYPE_PEM, key))
                f.write(dump_certificate(FILETYPE_PEM, cert))

        return cnp

    @property
    def serial(self):
        self._serial += 1
        return self._serial


class UnsupportedSchemeException(Exception):
    pass


class InterceptorPlugin(object):

    def __init__(self, server, msg):
        # Servidor
        self.server = server
        # Mensaje
        self.message = msg


class RequestInterceptorPlugin(InterceptorPlugin):

    def do_request(self, data):
        # logging.debug("do_request")
        return data


class ResponseInterceptorPlugin(InterceptorPlugin):

    def do_response(self, data):
        # Reenvio la data
        return data


class InvalidInterceptorPluginException(Exception):
    # no se que hacer
    pass


class MitmProxy(HTTPServer):

    def __init__(self, server_address=('', 9000), RequestHandlerClass=ManagerProxyMITM, bind_and_activate=True, ca_file='bciTest.pem'):
        HTTPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        print "Create certificate {}".format(ca_file)
        self.ca = CertificateAuthority(ca_file)
        self._res_plugins = []
        self._req_plugins = []

    def register_interceptor(self, interceptor_class):
        if not issubclass(interceptor_class, InterceptorPlugin):
            raise InvalidInterceptorPluginException('Expected type InterceptorPlugin got %s instead' % type(interceptor_class))
        if issubclass(interceptor_class, RequestInterceptorPlugin):
            self._req_plugins.append(interceptor_class)
        if issubclass(interceptor_class, ResponseInterceptorPlugin):
            self._res_plugins.append(interceptor_class)


def sslwrap( func):
    """
    client / server	SSLv2	SSLv3	SSLv23	TLSv1
    SSLv2	yes	no	yes	no
    SSLv3	no	yes	yes	no
    SSLv23	yes	no	yes	no
    TLSv1	no	no	yes	yes
    """
    # Agrega un nuevo metodo a una funcion ya creada!!
    @wraps(func)
    def bar(*args, **kw):
        kw['ssl_version'] = ssl.PROTOCOL_SSLv23
        return func(*args, **kw)
    return bar


class AsyncMitmProxy(ThreadingMixIn, MitmProxy):
    ssl.wrap_socket = sslwrap(ssl.wrap_socket)
    pass


class DebugInterceptor(RequestInterceptorPlugin, ResponseInterceptorPlugin):

        def do_request(self, data):
            # logging.debug('>> %s' % repr(data))
            # logging.debug("{}".format(data))
            return data

        def do_response(self, data):
            # logging.debug('<< %s' % repr(data))
            return data

def xss_value(src_local_path):
    source = ""
    logging.debug("get local resources >> {}".format(src_local_path))
    try:
        new_src_file = open(src_local_path, "r")
        for lxl in new_src_file:
            source += lxl
    except:
        logging.error(("Error al intentar leer archivo {}".format(src_local_path)))
        return
    return source

def set_tampering(ft_path):
    try:
        new_src_file = open(ft_path, "r")
    except:
        print(("Error al intentar leer archivo {}".format(ft_path)))
        return
    for line_source in new_src_file:
        (method, tampering_conf, url) = line_source.replace("\r\n","").split(";")
        param = {}
        method_ok = False

        param['url'] = url.split('=')[1]

        if method == 'frm':
            param['download_path'] = tampering_conf.split('#')[0]
            param['values'] = tampering_conf.split('#')[1]
            param['done'] = False
            param['url'] = tampering_conf.split('#')[2]
            method_ok = True

        if method in ('post'):
            name = tampering_conf.split('=')[0]
            param['name'] = name
            values = tampering_conf.split('=')[1]
            param['old'] = values.split('!')[0]
            param['new'] = values.split('!')[1]
            method_ok = True
        if method == 'ddos':
            param['times'] = int(tampering_conf)
            method_ok = True
        if method == 'xss':
            param['src'] = tampering_conf
            param['content'] = xss_value(tampering_conf)
            method_ok = True
        if method == 'get':
            param['local_path'] = tampering_conf
            method_ok = True
        if method == 'val':
            param['name'] = tampering_conf
            param['file'] = param['url']
            method_ok = True
        if method == 'chg':
            print tampering_conf
            param['find'] = tampering_conf.split('?')[0]
            param['replace'] = tampering_conf.split('?')[1]
            param['local_source'] = ""
            method_ok = True
        if method_ok:
            pen_tester[method].append(param)
    # logging.debug("Paramtros = {}".format(pen_tester))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Proxy tempering.")
    parser.add_argument('-t', help="Archivo con configuracion tampering", default=None)
    parser.add_argument('-port', help="Puerto del proxy", default=9000)
    parser.add_argument('-hostname', help="Host a evaluar", default='')
    parser.add_argument('-cert', help="archivo de certificacion", default='')
    args = parser.parse_args()
    file_tampering = args.t
    port = args.port
    hostname = args.hostname

    if file_tampering:
        tampering = set_tampering(file_tampering)

    logging.debug("Iniciando Proxy")
    proxy = None
    if not args.cert:
        proxy = AsyncMitmProxy()
    else:
        proxy = AsyncMitmProxy(ca_file=args.cert)
    proxy.register_interceptor(DebugInterceptor)
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        proxy.server_close()