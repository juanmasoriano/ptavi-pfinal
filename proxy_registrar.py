#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Clase para un servidor de eco en UDP simple
"""

import sys
import socketserver
import socket
import time
import json
import hashlib
import random
from xml.sax import make_parser
from xml.sax.handler import ContentHandler


def log(evento):
    evento = (" ".join(evento.split()))
    Tiempo = time.strftime('%Y%m%d%H%M%S', time.gmtime(time.time()))
    log_line = Tiempo + ' ' + evento + '\n'
    with open(LOG_PATH, 'a') as log_file:
        log_file.write(log_line)


class XMLHandler(ContentHandler):

    def __init__(self):
        self.config = []
        attrs_server = ['name', 'ip', 'puerto']
        attrs_database = ['path', 'passwdpath']
        attrs_log = ['path']
        self.dicc_etiquetas = {'server': attrs_server,
                                'database': attrs_database,
                                'log': attrs_log}

    def startElement(self, name, attrs):
        if name in self.dicc_etiquetas:
            dicc = {}
            for attr in self.dicc_etiquetas[name]:
                dicc[attr] = attrs.get(attr, "")

            self.config.append([name, dicc])

    def get_tags(self):
        return self.config


class SIPRegisterHandler(socketserver.DatagramRequestHandler):
    """
    Echo server class
    """

    dic = {}
    destino = ['']
    nonce = []

    def reenvio(self, metodo, ip_invited_user, port_invited_user,
                                line_str):
        """
        Proceso para la comunicación del proxy con el uaserver y los reenvios
        al uaclient.
        """
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        my_socket.connect((ip_invited_user, port_invited_user))
        log('Starting socket...')


        new_line_str = line_str.split('SIP/2.0\r\n')
        line_str = (new_line_str[0] + 'SIP/2.0\r\n' +
                    new_line_str[1])
        my_socket.send(bytes(line_str, 'utf-8')+b'\r\n\r\n')
        log(('Sent to ' + ip_invited_user + ':' +
                str(port_invited_user) + ' ' + line_str))

        if metodo in ['INVITE', 'BYE']:
            data = my_socket.recv(1024)
            received_line = data.decode('utf-8')
            log(('Received from ' + ip_invited_user + ':' +
                    str(port_invited_user) + ' ' + received_line))

            if 'Content-Type' not in received_line:
                LINE = (received_line.split('\r\n\r\n')[0] + '\r\n\r\n')
            else:
                partes = received_line.split('\r\n\r\n')
                LINE = (partes[0] + '\r\n\r\n' +
                        partes[1] + '\r\n\r\n' +
                        partes[2].split('Content')[0] +
                        '\r\n' + 'Content' +
                        partes[2].split('Content')[1] + '\r\n\r\n' +
                        partes[3] + '\r\n\r\n')

            self.wfile.write(bytes(LINE, 'utf-8'))
            log(('Sent to ' + self.client_address[0] + ':' +
                    str(self.client_address[1]) + ' ' + received_line))

        my_socket.close()
        log('Finishing socket.')

    def handle(self):
        """
        Manejador de peticiones de cliente. Solo hace algo si recibe
        peticiones tipo REGISTER
        """
        valid_request = False
        valid_method = False
        valid_user = False
        metodos_proxy = ['REGISTER', 'INVITE', 'ACK', 'BYE']
        line_str = self.rfile.read().decode('utf-8')
        list_linecontent = line_str.split()
        metodo = list_linecontent[0]
        log(('Received from ' + self.client_address[0] + ':' +
                str(self.client_address[1]) + ' ' + line_str))

        try:
            fich_json = open(PATH_Register, 'r')
            self.dic = json.load(fich_json)
        except:
            pass

        if len(list_linecontent)>= 3:
            valid_request = True
        else:
            self.wfile.write(b'SIP/2.0 400 Bad Request\r\n\r\n')
            log(('Sent to ' + self.client_address[0] + ':' +
                    str(self.client_address[1]) + ' ' +
                    'SIP/2.0 400 Bad Request\r\n\r\n'))
        if metodo in metodos_proxy:
            valid_method = True
        else:
            self.wfile.write(b'SIP/2.0 405 Method Not Allowed\r\n\r\n')
            log(('Sent to ' + self.client_address[0] + ':' +
                    str(self.client_address[1]) + ' ' +
                    'SIP/2.0 405 Method Not Allowed\r\n\r\n'))

        if valid_method and valid_request:
            if metodo == 'REGISTER':
                self.nonce.append(str(random.randint(0,
                                            99999999999999999999999999999999)))
                user = list_linecontent[1].split(':')[1]
                for elem in allowed_users:
                    if elem['user'] == user:
                        valid_user = True
                        passwd = elem['password']
                        ip_ua = self.client_address[0]
                        port_ua = list_linecontent[1].split(':')[-1]

                if ('Digest' in list_linecontent) and (valid_user is True):
                    hash_received = line_str.split('"')[1]
                    authenticate = hashlib.md5()
                    authenticate.update(bytes(passwd, 'utf-8'))
                    authenticate.update(bytes(self.nonce[0], 'utf-8'))
                    authenticate.digest
                    if hash_received == authenticate.hexdigest():
                        self.dic[user] = [{'ip': ip_ua},
                                            {'port': port_ua},
                                            {'register_date': time.time()},
                                            {'expire_time': list_linecontent[4]}]
                        print(self.dic)
                        self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")
                        log(('Sent to ' + self.client_address[0] +
                                str(self.client_address[1]) + ' ' +
                                'SIP/2.0 200 OK\r\n\r\n'))
                        self.nonce.clear()

                    else:
                        print('Client password is not correct')
                        self.wfile.write(b'SIP/2.0 401 Unauthorized\r\n\r\n')
                        log(('Sent to ' + self.client_address[0] + ':' +
                                str(self.client_address[1]) + ' ' +
                                'SIP/2.0 401 Unauthorized\r\n\r\n'))

                elif ('Digest' not in list_linecontent) and (valid_user is
                                                                        False):
                    self.wfile.write(bytes("SIP/2.0 401 Unauthorized\r\n" +
                                            'WWW Authenticate: Digest nonce="' +
                                            self.nonce[0] +
                                            '"\r\n\r\n', 'utf-8'))
                    log(('Sent to ' + self.client_address[0] + ':' +
                            str(self.client_address[1]) + ' ' +
                            "SIP/2.0 401 Unauthorized\r\n" +
                            'WWW Authenticate: Digest nonce ="' +
                            self.nonce[0] + '"\r\n\r\n'))
                else:
                    self.wfile.write(bytes("SIP/2.0 401 Unauthorized\r\n" +
                                            'WWW Authenticate: Digest nonce="' +
                                            self.nonce[0] +
                                            '"\r\n\r\n', 'utf-8'))
                    log(('Sent to ' + self.client_address[0] + ':' +
                            str(self.client_address[1]) + ' ' +
                            "SIP/2.0 401 Unauthorized\r\n" +
                            'WWW Authenticate: Digest nonce ="' +
                            self.nonce[0] + '"\r\n\r\n'))

            elif metodo == 'INVITE':
                invited_user = list_linecontent[1].split(':')[1]
                registered_invited_user = False
                sdp = line_str.split('\r\n\r\n')[1]
                o_user_name = sdp.split('\r\n')[1].split('=')[1].split(' ')[0]
                registered_o_user = False
                for usuario in self.dic:
                    if invited_user == usuario:
                        registered_invited_user = True
                        ip_invited_user = self.dic[invited_user][0]['ip']
                        port_invited_user = self.dic[invited_user][1]['port']
                        port_invited_user = int(port_invited_user)
                        self.destino[0] = invited_user

                    if o_user_name == usuario:
                        registered_o_user = True

                if registered_invited_user and registered_o_user:
                    self.reenvio(metodo, ip_invited_user,
                                    port_invited_user, line_str)

                elif not registered_o_user:
                    self.wfile.write(b'SIP/2.0 401 Unauthorized\r\n\r\n')
                    log(('Sent to ' + self.client_address[0] + ':' +
                            str(self.client_address[1]) + ' ' +
                            'SIP/2.0 401 Unauthorized\r\n\r\n'))
                elif not registered_invited_user:
                    self.wfile.write(b'SIP/2.0 404 User Not Found\r\n\r\n')
                    log(('Sent to ' + self.client_address[0] + ':' +
                            str(self.client_address[1]) + ' ' +
                            'SIP/2.0 404 User Not Found\r\n\r\n'))

            elif metodo == 'ACK':
                invited_user = self.destino[0]
                ip_invited_user = self.dic[invited_user][0]['ip']
                port_invited_user = int(self.dic[invited_user][1]['port'])

                self.reenvio(metodo, ip_invited_user,
                                            port_invited_user, line_str)

            elif metodo == 'BYE':
                registered_invited_user = False
                invited_user = list_linecontent[1].split(':')[1]
                for usuario in self.dic:
                    if invited_user == usuario:
                        registered_invited_user = True
                        ip_invited_user = self.dic[invited_user][0]['ip']
                        port_invited_user = int(self.dic[invited_user][1]['port'])
                if registered_invited_user:
                    self.reenvio(metodo, ip_invited_user,
                                    port_invited_user, line_str)
                elif not registered_invited_user:
                    self.wfile.write(b'SIP/2.0 404 User Not Found\r\n\r\n')
                    log(('Sent to ' + self.client_address[0] + ':' +
                            str(self.client_address[1]) + ' ' +
                            'SIP/2.0 404 User Not Found\r\n\r\n'))

            else:
                self.wfile.write(b'SIP/2.0 404 User Not Found\r\n\r\n')
                log(('Sent to ' + self.client_address[0] + ':' +
                        str(self.client_address[1]) + ' ' +
                        'SIP/2.0 404 User Not Found\r\n\r\n'))

        expired_users = []
        for usuario in self.dic:
            time_now = time.time()
            user_expires = (self.dic[usuario][2]['register_date'] +
                            float(self.dic[usuario][3]['expire_time']))
            if time_now  >= user_expires:
                expired_users.append(usuario)

        for  usuario in expired_users:
            del self.dic[usuario]



        fich_json = open(PATH_Register, 'w')
        codigo_json = json.dumps(self.dic)
        fich_json.write(codigo_json)
        fich_json.close()

if __name__ == "__main__":
    try:
        CONFIG = sys.argv[1]
    except:
        sys.exit('Usage: python proxy_registrar.py config')

    parser = make_parser()
    cHandler = XMLHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open(CONFIG))

    LOG_PATH = cHandler.config[2][1]['path']
    log('Starting...')

    if cHandler.config[0][1]['ip'] != '':
        IP_PROXY = cHandler.config[0][1]['ip']
    else:
        IP_PROXY = '127.0.0.1'

    PORT_PROXY = int(cHandler.config[0][1]['puerto'])
    NAME_PROXY = cHandler.config[0][1]['name']
    PATH_Register = cHandler.config[1][1]['path']
    PATH_Passwords = cHandler.config[1][1]['passwdpath']

    allowed_users = []
    passwd_file = open(PATH_Passwords, 'r')
    for line in passwd_file.readlines():
        u = line.split(' ')[1]
        p = line.split(' ')[3][0:-1]
        d = {'user': u, 'password': p}
        allowed_users.append(d)

    serv = socketserver.UDPServer((IP_PROXY,PORT_PROXY), SIPRegisterHandler)
    print('Server ' + NAME_PROXY + ' listening at port ' + str(PORT_PROXY) +
            '...')

    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print("Server finished")
        log('Finishing.')
