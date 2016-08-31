# -*- coding: utf-8 -*-
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
# import for SSL runtimes
import ssl
from functools import wraps
from OpenSSL.crypto import (X509Extension, X509, dump_privatekey, dump_certificate, load_certificate, load_privatekey, PKey, TYPE_RSA, X509Req)
from OpenSSL.SSL import FILETYPE_PEM
#import for check response and request
from bs4 import BeautifulSoup
import StringIO
import gzip


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
            # kw = {}
            # kw['ssl_version'] = ssl.PROTOCOL_TLSv1
            # self._proxy_sock = ssl.wrap_socket(self._proxy_sock, **kw)
            # self._proxy_sock = ssl.wrap_socket(self._proxy_sock, server_side=True, certfile=self.server.ca[self.path.split(':')[0]])
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
        logging.debug("get : {}{}".format(self.hostname, self.path))
        self.request.sendall(self.mitm_response(response))

    def mitm_request(self, data):
        # if "bci" in self.path:
        # logging.debug("[!] \n<REQUEST>\n{}\n</REQUEST>\n".format(data))
        data = self.do_tampering(data)
        # logging.debug("Pre do_request")
        times = 1
        for p in self.server._req_plugins:
            for tampering_value in  pen_tester['ddos']:
                if tampering_value['url'] in self.path:
                    times = tampering_value['times']
            for x in range(0, times):
                data = p(self.server, self).do_request(data)
        if times>1:
            logging.debug("Post {} times ".format(times))
        # logging.debug("Post do_request")
        return data

    def mitm_response(self, data):
        for download in pen_tester['get']:
            if download['url'] in self.path:
                logging.debug("Download {} : \n{}".format(self.path, data))
                self.wget(download['local_path'], data)
        for xss_value in  pen_tester['xss']:
            if xss_value['url'] in self.path and xss_value['content']:
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
                    data = data.replace(r"^Content-Length: [~0-9]$","Content-Length: {}".format(len(xss_value['content'])))
                    # TEST LOGIN : data = xss_value['content']
                    pass
                data = data.replace("HTTP/1.1 400 Bad Request","HTTP/1.1 200 OK")
                data = data.replace("HTTP/1.1 500 Internal Server Error","HTTP/1.1 200 OK")
                logging.debug("NEW RESPONSE : \n{}".format(data))
        for p in self.server._res_plugins:
            data = p(self.server, self).do_response(data)
        return data

    def wget(self, local_path, content):
        pass

    def do_tampering(self, data):
        eof_data_index = len(data.split('\n'))-1
        last_line = data.split('\n')[eof_data_index]
        content_Length = len(last_line)
        if len(last_line) == 0:
            return data
        else:
            content_type = data.split('\n')[6]
            content_len_data = "Content-Length: {}".format(content_Length)
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
                            logging.debug("!:params >> URL : {}{} >> {}".format(self.hostname, self.path, content_type))
                            # logging.debug("- [{}] = [{}]".format(json_key , tampering_value['name']))
                            # logging.debug("- [{}] = [{}]".format(param_value , tampering_value['old']))
                            if json_key == tampering_value['name'] and (param_value == tampering_value['old'] or tampering_value['old'] == '*'):
                                param_value = tampering_value['new']
                                logging.debug("! {} = [{}] in {}".format(json_key , tampering_value['new'], self.path))
                                break
                    new_json_param[json_key] = param_value
                    new_json_params +="'{}':'{}',".format(json_key,param_value)
                # new_json_params = '{"pwCliente":"lf271275", "canal":"102","idAplicacion":"cl.bci.bancamovil.personas","rutCliente":"12657328","dvCliente":"6","srvInicial":"","plataforma":"X-BOX360","version":"Inedita"}'
                new_json_params = ("{}{}".format(new_json_params[:-1],"}")).replace("'",'"')

                # logging.debug("original   JSON1 param : {} ".format(last_line))
                # logging.debug("modificada JSON1 param : {} ".format(new_json_params))
                # logging.debug("JSON2 param : {} ".format(new_json_param))
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
                                logging.debug("!:params >> URL : {}{} >> {}".format(self.hostname, self.path, content_type))
                                if name == tampering_value['name'] and (value == tampering_value['old'] or tampering_value['old'] == '*'):
                                    logging.debug("! {} = [{}]".format(name , tampering_value['new']))
                                    new_value = ("{}".format(tampering_value['new']))
                                    data = data.replace("{}={}".format(name, value), "{}={}".format(name, new_value))
                                    break
                last_line = data.split('\n')[eof_data_index]
                content_Length = len(last_line)
            new_content_len_data = "Content-Length: {}".format(content_Length)
            data = data.replace(content_len_data, new_content_len_data)
            logging.debug("{}".format(data))
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
                        #change_tag_value = ("{}".format(hidden_tag)).replace(tag_value, 'XD')
                        #html = html.replace("{}".format(hidden_tag), change_tag_value)
        return html