#!/usr/bin/env python3
#
# TP-Link Wi-Fi Smart Plug Protocol Client
# For use with TP-Link HS-100 or HS-110
#
# by Lubomir Stroetmann
# Copyright 2016 softScheck GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
import argparse
import socket
from json import dumps, loads
from struct import pack

version = 0.1


# Check if IP is valid
def validIP(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
    except socket.error:
        parser.error("Invalid IP Address.")
    return ip


# Predefined Smart Plug Commands
# For a full list of command_list, consult tplink_commands.txt
command_list = {"info": '{"system": {"get_sysinfo": {}}}',
                "on": '{"system": {"set_relay_state": {"state": 1}}}',
                "off": '{"system": {"set_relay_state": {"state": 0}}}',
                "cloudinfo": '{"cnCloud": {"get_info": {}}}',
                "wlanscan": '{"netif": {"get_scaninfo": {"refresh": 0}}}',
                "time": '{"time": {"get_time": {}}}',
                "schedule": '{"schedule": {"get_rules": {}}}',
                "countdown": '{"count_down": {"get_rules": {}}}',
                "antitheft": '{"anti_theft": {"get_rules": {}}}',
                "reboot": '{"system": {"reboot": {"delay": 1}}}',
                "reset": '{"system": {"reset": {"delay": 1}}}'
                }


# Encryption and Decryption of TP-Link Smart Home Protocol
# XOR Autokey Cipher with starting key = 171
def encrypt_prev_1_0_10(string):
    key = 171
    result = b'\0\0\0\0'
    for i in string:
        a = key ^ i
        key = a
        result += bytes([a])
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


methods = {
    "1": encrypt_official,
    "2": encrypt_post_1_0_10,
    "3": encrypt_prev_1_0_10
}


def decrypt(string):
    key = 171
    result = b''
    for i in string:
        a = key ^ i
        key = i
        result += bytes([a])
    return result


# Parse commandline arguments
parser = argparse.ArgumentParser(description="TP-Link Wi-Fi Smart Plug Client v" + str(version))
parser.add_argument("-t", "--target", metavar="<ip>", required=True, help="Target IP Address", type=validIP)
parser.add_argument("-m", "--method", metavar="<method>", required=False, help="encryption method to be used", choices=["1", "2", "3"])
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-c", "--command", metavar="<command>", help="Preset command to send. Choices are: "+", ".join(command_list), choices=command_list)
group.add_argument("-j", "--json", metavar="<JSON string>", help="Full JSON string of command to send")
args = parser.parse_args()

# Set target IP, port and command to send
ip = args.target
method = args.method

port = 9999
if args.command is None:
    cmd = args.json
else:
    cmd = command_list[args.command]

if args.method is not None:
    methods = {method: methods[method]}

if type(cmd) is str:
    cmd = loads(cmd)

err = None
for encrypt in methods.values():
    # Send command and receive reply
    try:
        sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_tcp.connect((ip, port))
        sock_tcp.send(encrypt(dumps(cmd).encode('utf-8')))
        data = sock_tcp.recv(2048)
        sock_tcp.close()
        if len(data) == 0:
            err = "Received no data"
            continue
        print("Sent:     ", cmd)
        print("Received: ", decrypt(data[4:]).decode("utf-8"))
        exit(0)
    except socket.error as serr:
        err = serr

print("Error: %s" % err)
