#!/usr/bin/env python2.7
import socket
from struct import pack
from sys import argv
from json import dumps, loads


# Encryption and Decryption of TP-Link Smart Home Protocol
# XOR Autokey Cipher with starting key = 171
def encrypt_prev_1_0_10(string):
    key = 171
    result = "\0\0\0\0"
    for i in string:
        a = key ^ ord(i)
        key = a
        result += chr(a)
    return result


def encrypt_post_1_0_10(string):
    key = 171
    result = "\0\0\0"+chr(len(string))
    for i in string:
        a = key ^ ord(i)
        key = a
        result += chr(a)
    return result


def encrypt_official(string):
    key = 171
    result = pack('>I', len(string))
    for i in string:
        a = key ^ ord(i)
        key = a
        result += chr(a)
    return result


methods = [encrypt_official, encrypt_prev_1_0_10, encrypt_post_1_0_10]
current_method = 0


def decrypt(string):
    key = 171
    result = ""
    for i in string:
        a = key ^ ord(i)
        key = ord(i)
        result += chr(a)
    return result


def str_hook(obj):
    return {k.encode('utf-8') if isinstance(k, unicode) else k:
            v.encode('utf-8') if isinstance(v, unicode) else v
            for k, v in obj}


def send_command(command, ip, port=9999):
    """
        command: dictionary of command json
    """
    global current_method
    try:
        sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_tcp.connect((ip, port))
        sock_tcp.send(methods[current_method](dumps(command).encode('utf-8')))
        data = sock_tcp.recv(2048)
        sock_tcp.close()
        # return dumps(loads(decrypt(data[4:]), object_pairs_hook=str_hook))
        if len(data) == 0:
            if current_method < len(methods):
                current_method += 1
                return send_command(command, ip)
            else:
                return {}
        response = loads(decrypt(data[4:]), object_pairs_hook=str_hook)
        return {
            "power": response["emeter"]["get_realtime"]["power"] if current_method != 1 else response["emeter"]["get_realtime"]["power_mw"]/1000,
            "relay_state": response["system"]["get_sysinfo"]["relay_state"],
            "power_err_code": response["emeter"]["get_realtime"]["err_code"],
            "relay_state_err_code": response["system"]["get_sysinfo"]["err_code"]
        }

    except socket.error:
        return {}


if __name__ == "__main__":
    command = {"emeter": {"get_realtime": {}}, "system": {"get_sysinfo": {}}}
    print dumps(send_command(command, argv[1]))
