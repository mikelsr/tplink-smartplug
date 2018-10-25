#!/usr/bin/env python3
import socket
from struct import pack
from sys import argv
from json import dumps, loads


# Encryption and Decryption of TP-Link Smart Home Protocol
# XOR Autokey Cipher with starting key = 171
def encrypt_prev_1_0_10(string):
    key = 171
    result = b'\0\0\0\0'
    for i in string:
        a = key ^ i
        key = a
        result += a
    return result


def encrypt_post_1_0_10(string):
    key = 171
    result = b'\0\0\0'+bytes(len(string))
    for i in string:
        a = key ^ i
        key = a
        result += bytes([a])
    return result


def encrypt_official(string):
    key = 171
    result = pack('>I', len(string))
    for i in string:
        a = key ^ i
        key = a
        result += bytes([a])
    return result


methods = [encrypt_official, encrypt_prev_1_0_10, encrypt_post_1_0_10]
current_method = 0


def decrypt(string):
    key = 171
    result = b''
    for i in string:
        a = key ^ i
        key = i
        result += bytes([a])
    return result


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
        if len(data) == 0:
            if current_method < len(methods):
                current_method += 1
                return send_command(command, ip)
            else:
                return {}
        response = loads(decrypt(data[4:]))
        power_key = "power" if "power" in response["emeter"]["get_realtime"].keys() else "power_mw"
        power = response["emeter"]["get_realtime"][power_key]
        if power_key == "power_mw":
            power = power/1000.0
        return {
            "power": power,
            "relay_state": response["system"]["get_sysinfo"]["relay_state"],
            "power_err_code": response["emeter"]["get_realtime"]["err_code"],
            "relay_state_err_code": response["system"]["get_sysinfo"]["err_code"]
        }

    except socket.error:
        return {}


if __name__ == "__main__":
    command = {"emeter": {"get_realtime": {}}, "system": {"get_sysinfo": {}}}
    print(dumps(send_command(command, argv[1])))
