#!/usr/bin/env python2.7
import socket
from sys import argv
from json import dumps, loads
from pprint import pprint

# Predefined Smart Plug Commands
# For a full list of commands, consult tplink_commands.txt
command_list = {'info'     : '{"system":{"get_sysinfo":{}}}',
			'on'       : '{"system":{"set_relay_state":{"state":1}}}',
			'off'      : '{"system":{"set_relay_state":{"state":0}}}',
			'cloudinfo': '{"cnCloud":{"get_info":{}}}',
			'wlanscan' : '{"netif":{"get_scaninfo":{"refresh":0}}}',
			'time'     : '{"time":{"get_time":{}}}',
			'schedule' : '{"schedule":{"get_rules":{}}}',
			'countdown': '{"count_down":{"get_rules":{}}}',
			'antitheft': '{"anti_theft":{"get_rules":{}}}',
			'reboot'   : '{"system":{"reboot":{"delay":1}}}',
			'reset'    : '{"system":{"reset":{"delay":1}}}'
}

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


methods = [encrypt_prev_1_0_10, encrypt_post_1_0_10]
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
    return {k.encode('utf-8') if isinstance(k,unicode) else k :
            v.encode('utf-8') if isinstance(v, unicode) else v
            for k,v in obj}


def send_command(command, ip, port=9999):
	"""
		command: dictionary of command json
	"""
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
			"power": response["emeter"]["get_realtime"]["power"],
			"relay_state": response["system"]["get_sysinfo"]["relay_state"],
			"power_err_code": response["emeter"]["get_realtime"]["err_code"],
			"relay_state_err_code": response["system"]["get_sysinfo"]["err_code"]
		}

	except socket.error:
		return {}


if __name__ == "__main__":
	command = {"emeter": {"get_realtime": {}}, "system": {"get_sysinfo": {}}}
	print(dumps(send_command(command, argv[1])))
