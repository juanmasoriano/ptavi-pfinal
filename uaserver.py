#!usr/bin/python3
# -*- coding: utf-8 -*-
import socketserver
import sys
import os
import time
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from uaclient import XMLHandler


def log(evento):
    evento = (" ").join(evento.split())
    Tiempo = time.strftime('%Y%m%d%H%M%S' , time.gmtime(time.time()))
    log_line = Tiempo + ' ' + evento + '\n'
    with open(LOG_PATH, 'a') as log_file:
        log_file.write(log_line)


class EchoHandler(socketserver.DatagramRequestHandler):

    p_rtp_client = ['']
    ip_client = ['']

    def handle(self):
        valid_request = False
        valid_method = False
        server_methods = ['INVITE' , 'ACK' , 'BYE']
        line_str = self.rfile.read().decode('utf-8')
        list_linecontent = line_str.split()
        method = list_linecontent[0]
        log(('Received from ' + self.client_address[0] + ':' +
                str(self.client_address[1]) + ':' + line_str))
        print('Recibido del proxy: \n' + line_str)

        if len(list_linecontent) >= 3 and method in server_methods:
            valid_request = True
            valid_method = True
        elif len(list_linecontent) < 3:
            self.wfile.write(b'SIP/2.0 400 Bad Request\r\n\r\n')
            log(('Sent to ' + self.client_address[0] + ':' +
                    str(self.client_address[1]) + ' ' +
                    'SIP/2.0 400 Bad Request\r\n\r\n'))
        elif method not in server_methods:
            self.wfile.write(b'SIP/2.0 405 Method Not Allowed\r\n\r\n')
            log(('Sent to ' + self.client_address[0] + ':' +
                    str(self.client_address[1]) + ' ' +
                    'SIP/2.0 405 Method Not Allowed\r\n\r\n'))

        if valid_method and valid_request:
            if method == 'INVITE':
                sdp_received = line_str.split('\r\n\r\n')[1]
                sdp_to_send = ('v=0\r\no=' + USER_NAME + ' ' + IP_UASERVER +
                                '\r\ns=misesion\r\nt=0\r\nm=audio ' +
                                str(PORT_RTP) + ' RTP')
                self.ip_client[0] = sdp_received.split('\r\n')[1].split(' ')[1]
                self.p_rtp_client[0] = sdp_received.split('\r\n')[4]
                self.p_rtp_client[0] = self.p_rtp_client[0].split(' ')[1]
                self.wfile.write(bytes('SIP/2.0 100 Trying\r\n\r\n'
                                        'SIP/2.0 180 Ringing\r\n\r\n'
                                        'SIP/2.0 200 OK\r\n'
                                        'Content-Type: application/sdp\r\n\r\n'
                                        + sdp_to_send + '\r\n\r\n' , 'utf-8'))
                log(('Sent to ' + self.client_address[0] + ':' +
                        str(self.client_address[1]) + ' ' +
                        'SIP/2.0 100 Trying\r\n\r\n'
                        'SIP/2.0 180 Ringing\r\n\r\n'
                        'SIP/2.0 200 OK\r\n'
                        'Content-Type: application/sdp\r\n\r\n'
                        + sdp_to_send + '\r\n\r\n'))
            elif method == 'ACK':
                print('ACK received. Starting rtp transmission...')
                os.system('./mp32rtp -i ' + self.ip_client[0] + ' -p ' +
                            self.p_rtp_client[0] + ' < ' + fichero_audio)
                print('Rtp transmission finished')
                log(('Sent to ' + self.ip_client[0] + ':' +
                        self.p_rtp_client[0] + ' ' + fichero_audio +
                        ' via RTP protocol'))

                print('Listening rtp in: ' + IP_UASERVER + ':' + str(PORT_RTP))
                os.system('./mp32rtp -i ' + IP_UASERVER + ' -p '
                            + str(PORT_RTP) + ' < ' + fichero_audio)

            elif method == 'BYE':
                self.wfile.write(b'SIP/2.0 200 OK\r\n\r\n')
                log(('Sent to ' + self.client_address[0] + ':' +
                        str(self.client_address[1]) + ' ' +
                        'SIP/2.0 200 OK\r\n\r\n'))


if __name__ == "__main__":
    try:
        CONFIG = sys.argv[1]
    except:
        sys.exit('Usage: python uaserver.py config')

    cHandler = XMLHandler()
    parser = make_parser()
    parser.setContentHandler(cHandler)
    parser.parse(open(CONFIG))

    LOG_PATH = cHandler.config[4][1]['path']
    log('Starting Server...')

    IP_PROXY = cHandler.config[3][1]['ip']
    PORT_PROXY = int(cHandler.config[3][1]['puerto'])
    USER_NAME = cHandler.config[0][1]['username']
    IP_UASERVER = cHandler.config[1][1]['ip']
    PORT_UASERVER = int(cHandler.config[1][1]['puerto'])
    PORT_RTP = int(cHandler.config[2][1]['puerto'])

    fichero_audio = cHandler.config[5][1]['path']
    if not os.path.isfile(fichero_audio):
        sys.exit('File Error: ' + fichero_audio + ' does not exist')
        log(('File: Error' + fichero_audio + ' does not exist.'))

    print("Listening...")

    serv = socketserver.UDPServer((IP_UASERVER, PORT_UASERVER), EchoHandler)

    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print('Server finished')
