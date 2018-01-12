#!/usr/bin/python3
# -*- coding: utf-8 -*-
import sys
import socket
import hashlib
import os
import time
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

def log(evento):
    evento = (" ").join(evento.split())
    Tiempo = time.strftime('%Y%m%d%H%M%S', time.gmtime(time.time()))
    log_line = Tiempo + ' ' + evento + '\n'
    with open(LOG_PATH, 'a') as log_file:
        log_file.write(log_line)

class XMLHandler(ContentHandler):

    def __init__(self):
        self.config = []

        attrs_account = ['username', 'passwd']
        attrs_uaserver = ['ip', 'puerto']
        attrs_rtpaudio = ['puerto']
        attrs_regproxy = ['ip', 'puerto']
        attrs_log = ['path']
        attrs_audio = ['path']
        self.dicc_etiquetas = {'account': attrs_account,
                               'uaserver': attrs_uaserver,
                               'rtpaudio': attrs_rtpaudio,
                               'regproxy': attrs_regproxy,
                               'log': attrs_log,
                               'audio': attrs_audio}

    def startElement(self, name, attrs):
        if name in self.dicc_etiquetas:
            dicc = {}
            for attr in self.dicc_etiquetas[name]:
                dicc[attr] = attrs.get(attr, "")
            self.config.append([name, dicc])
        return self.config


if __name__ == "__main__":

    metodos_client = ['REGISTER' , 'INVITE' , 'BYE']

    try:
        CONFIG = sys.argv[1]
        METODO = sys.argv[2].upper()
        if METODO not in metodos_client:
            sys.exit('Unknown methods')
        OPTION = sys.argv[3]

    except:
        sys.exit('Usage: python uaclient.py config method option')

    parser = make_parser()
    cHandler = XMLHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open(CONFIG))

    LOG_PATH = cHandler.config[4][1]['path']
    log('Starting Client...')


    IP_PROXY = cHandler.config[3][1]['ip']
    PORT_PROXY = int(cHandler.config[3][1]['puerto'])
    USER_NAME = cHandler.config[0][1]['username']
    PASSWD = cHandler.config[0][1]['passwd']
    PORT_UASERVER = int(cHandler.config[1][1]['puerto'])
    PORT_RTP = int(cHandler.config[2][1]['puerto'])
    if cHandler.config[1][1]['ip'] == '':
        IP_UASERVER = '127.0.0.1'
    else:
        IP_UASERVER = cHandler.config[1][1]['ip']
    fichero_audio = cHandler.config[5][1]['path']
    if not os.path.isfile(fichero_audio):
        sys.exit('File Error: ' + fichero_audio + ' does not exist')
        log('File Error: ' + fichero_audio + 'does not exist')

    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        my_socket.connect((IP_PROXY, PORT_PROXY))

        if METODO == 'REGISTER':
            LINE = (METODO + ' sip:' + USER_NAME + ':' + str(PORT_UASERVER) +
                    ' SIP/2.0\r\nExpires: ' + OPTION)
            my_socket.send(bytes(LINE, 'utf-8') + b'\r\n\r\n')
            log('Sent to ' + IP_PROXY + ':' + str(PORT_PROXY) + ' ' + LINE)
        elif METODO == 'INVITE':
            BODY = ('v=0\r\no=' + USER_NAME + ' ' + IP_UASERVER +
                    '\r\ns=misesion\r\nt=0\r\nm=audio ' + str(PORT_RTP)+ ' RTP')
            LINE = (METODO + ' sip:' + OPTION +
                    ' SIP/2.0\r\nConten-type: application/sdp\r\n\r\n' + BODY)
            my_socket.send(bytes(LINE, 'utf-8') + b'\r\n\r\n')
            log('Sent to ' + IP_PROXY + ':' + str(PORT_PROXY) + ' ' + LINE)
        elif METODO == 'BYE':
            LINE = (METODO + ' sip:' + str(OPTION) + ' SIP/2.0')
            my_socket.send(bytes(LINE, 'utf-8') + b'\r\n\r\n')
            log('Sent to ' + IP_PROXY + ':' + str(PORT_PROXY) + ' ' + LINE)

        data = my_socket.recv(1024)
        received_line = data.decode('utf-8')
        print('Received -- ', received_line)
        log('Received from ' + IP_PROXY + ':' + str(PORT_PROXY) +
                ' ' + received_line)

        if (METODO == 'REGISTER') and ('SIP/2.0 401 Unauthorized' in received_line):
            nonce = received_line.split('"')[1]
            authenticate = hashlib.md5()
            authenticate.update(bytes(PASSWD, 'utf-8'))
            authenticate.update(bytes(nonce, 'utf-8'))
            authenticate.digest
            LINE = (METODO + ' sip:' + USER_NAME + ':' + str(PORT_UASERVER) +
                    ' SIP/2.0\r\nExpires: ' + OPTION + '\r\n' +
                    'Authorization: Digest response="' +
                    authenticate.hexdigest() + '"')
            my_socket.send(bytes(LINE, 'utf-8') + b'\r\n\r\n')
            log(('Sent to ' + IP_PROXY + ':' + str(PORT_PROXY) + ' '
                    + LINE))

            data = my_socket.recv(1024)
            received_line = data.decode('utf-8')
            print('Received -- ', received_line)
            log('Received from ' + IP_PROXY + ':' + str(PORT_PROXY) +
                        ' ' + received_line)

        elif (METODO == 'INVITE') and 'OK' in received_line:
            METODO = 'ACK'
            LINE = (METODO + ' sip:' + OPTION + ' SIP/2.0')
            my_socket.send(bytes(LINE, 'utf-8') + b'\r\n\r\n')
            log('Sent to ' + IP_PROXY + ':' + str(PORT_PROXY) +
                    ' ' + LINE)

            print('Listening rtp in: ' + IP_UASERVER + ':' + str(PORT_RTP))
            os.system('./mp32rtp -i ' + IP_UASERVER + ' -p '
                        + str(PORT_RTP) + ' < ' + fichero_audio)

            print('Starting rtp transmission...')
            sdp_received = received_line.split('\r\n\r\n')[-2]
            ip_server = sdp_received.split('\r\n')[1].split(' ')[1]
            p_rtp_server = sdp_received.split('\r\n')[4].split(' ')[1]
            os.system('./mp32rtp -i ' + ip_server + ' -p ' +
                        p_rtp_server + ' < ' + fichero_audio)
            print('RTP transmission finished')
            log('Sent to ' + ip_server + ':' + str(p_rtp_server) +
                    ' ' + fichero_audio + ' via RTP protocol')

        my_socket.close()
        print("Client finished")
        log('Client finished')

    except ConnectionRefusedError:
        print('Error: No server listening at ' + IP_PROXY + ' port ' +
                str(PORT_PROXY))
        log('Error: No server listening at ' + IP_PROXY + ' port ' +
            str(PORT_PROXY))
