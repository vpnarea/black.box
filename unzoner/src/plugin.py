#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sqlite3
import requests
import json

from inspect import stack
from datetime import datetime, time

from http.client import (
	NO_CONTENT,
	UNAUTHORIZED,
	BAD_REQUEST,
	NOT_FOUND,
	OK,
	FORBIDDEN,
	INTERNAL_SERVER_ERROR,
	CREATED,
	CONFLICT
)

# hack: lazy-loading doesn't work with Nuitka compiled code
#from passlib.hash import phpass, pbkdf2_sha256
from passlib.handlers import phpass, pbkdf2

from utils import (
	get_ip_address,
	get_hostname,
	get_default_iface,
	get_container_name,
	get_container_id
)

from common import retry, get_md5
from config import *

import vpn


# VPNArea (Colibri) specific environment
VPNAREA_API_HOST = os.getenv('VPNAREA_API_HOST', 'https://api.vpnarea.com')
VPNAREA_API_VERSION = os.getenv('VPNAREA_API_VERSION', '1.0')
VPNAREA_API_SECRET = os.getenv('VPNAREA_API_SECRET', None)
COLIBRI_MAX_CONNS = int(os.getenv('COLIBRI_MAX_CONNS', 7))
COLIBRI_CONNS_LOG = bool(int(os.getenv('COLIBRI_CONNS_LOG', True)))
COLIBRI_CONNS_TRACKING = bool(int(os.getenv('COLIBRI_CONNS_TRACKING', True)))

					 
# Colibri auth (VPNArea)
def auth_user(uid, pwd):
	if uid and pwd: return validate_user_api(username=uid, passwd=pwd)

	return False


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def log_user_conns():
	md5_users = [get_md5(user) for user in vpn.get_clients()]
	if DEBUG: print('md5_users={}'.format(md5_users))
	payload = {
		'key': 'u:{}{}'.format(get_container_id(), get_container_name()),
		'value': {
			'users': md5_users,
			'count': len(md5_users)
		}
	}
	if DEBUG: print('payload={}'.format(payload))
	headers = {
		'X-Auth-Token': VPNAREA_API_SECRET,
		'Content-Type': 'application/json'
	}
	res = requests.put(
		'{}/api/v{}/connections'.format(
			VPNAREA_API_HOST,
			VPNAREA_API_VERSION
		),
		headers=headers,
		verify=REQUESTS_VERIFY,
		data=json.dumps(payload),
		timeout=CONN_TIMEOUT
	)
	if DEBUG: print('{}: {}'.format(stack()[0][3], res))
	if res.status_code not in [OK, NO_CONTENT]:
		raise AssertionError((res.status_code, res.content))


# Colibri connect (VPNArea)
@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def client_connect(username=None):
	print("plugin='{}' user='{}' conns_tracking='{}' auth_type='{}'".format(
		DNS_SUB_DOMAIN,
		username,
		COLIBRI_CONNS_TRACKING
	))

	if not COLIBRI_CONNS_TRACKING: return True

	# update user and server connections (assume both protos are up)
	try:
		log_plugin_server(status=[True, True])
	except:
		pass

	return True


# Colibri disconnect (VPNArea)
@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def client_disconnect(username=None):
	print("plugin='{}' user='{}' conns_tracking='{}' auth_type='{}'".format(
		DNS_SUB_DOMAIN,
		username,
		COLIBRI_CONNS_TRACKING
	))

	if not COLIBRI_CONNS_TRACKING: return True

	# update user and server connections (assume both protos are up)
	try:
		log_plugin_server(status=[True, True])
	except:
		pass

	return True


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_user_conns(username=None):
	conns = 0

	headers = {
		'X-Auth-Token': VPNAREA_API_SECRET
	}
	res = requests.get(
		'{}/api/v{}/connections/username/{}'.format(
			VPNAREA_API_HOST,
			VPNAREA_API_VERSION,
			username
		),
		headers=headers,
		verify=REQUESTS_VERIFY,
		timeout=CONN_TIMEOUT
	)

	if DEBUG: print('{}: status_code={}'.format(
		stack()[0][3],
		res.status_code
	))
	if res.status_code in [OK]:
		try:
			conns = int(res.content)
		except:
			pass

	return int(conns)


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def validate_user_api(username=None, passwd=None):
	headers = {
		'X-Auth-Token': VPNAREA_API_SECRET
	}
	res = requests.get(
		'{}/api/v{}/authenticate/username/{}/password/{}'.format(
			VPNAREA_API_HOST,
			VPNAREA_API_VERSION,
			username,
			passwd
		),
		headers=headers,
		verify=REQUESTS_VERIFY,
		timeout=CONN_TIMEOUT
	)

	if DEBUG: print('{}: status_code={}'.format(
		stack()[0][3],
		res.status_code
	))
	if res.status_code in [OK, NO_CONTENT]:
		log_user_conns()
		return True
	return False


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def log_plugin_server(status=[False, False]):
	if COLIBRI_CONNS_LOG:
		try:
			conns = vpn.get_server_conns(status=status)
			ip = get_ip_address(os.getenv('EXT_IFACE', get_default_iface()))
			hostname = get_hostname()
		except:
			return

		headers = {
			'X-Auth-Token': VPNAREA_API_SECRET
		}
		res = requests.put(
			'{}/api/v{}/connections/hostname/{}/ip/{}/conns/{}'.format(
				VPNAREA_API_HOST,
				VPNAREA_API_VERSION,
				hostname,
				ip,
				conns
			),
			headers=headers,
			verify=REQUESTS_VERIFY,
			timeout=CONN_TIMEOUT
		)
		if DEBUG: print('{}: {}'.format(stack()[0][3], res))
		if res.status_code not in [OK, NO_CONTENT]:
			raise AssertionError((res.status_code, res.content))

		# update user connections
		log_user_conns()
	else:
		print('{}: server_conns_tracking={}'.format(
			stack()[0][3],
			COLIBRI_CONNS_LOG
		))
