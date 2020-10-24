#!/usr/bin/python3
import requests
import base64
import os
import subprocess
import urllib.parse
import getpass

def login(username, password, appKey):
    url = 'https://v2-api.cyberghostvpn.com/v2/my/account/jwt'
    payload = {'userName': username, 'password': password}
    header = {'x-app-key': appKey}
    r = requests.post(url, json=payload, headers=header)
    jwt = r.json()['jwt']
    return jwt

def getDevice(jwtToken, appKey):
    url = 'https://v2-api.cyberghostvpn.com/v2/my/devices'
    header = {'x-app-key': appKey, 'Authorization': 'Bearer ' + jwtToken}
    r = requests.get(url, headers=header)
    token = r.json()[0]['token']
    tokenSecret = r.json()[0]['tokenSecret']
    authToken = token + ':' + tokenSecret
    return authToken

def encodeAuthToken(authToken):
    s = authToken
    s_bytes = s.encode('ascii')
    base64_bytes = base64.b64encode(s_bytes)
    base64AuthToken = base64_bytes.decode('ascii')
    return base64AuthToken

def getServer(jwtToken, appKey):
    country = input('Type a country abbreviation (e.g. NL): ')
    url = 'https://v2-api.cyberghostvpn.com/v2/my/servers/filters/74?filter_protocol=wireguard&filter_country=' + country
    header = {'x-app-key': appKey, 'Authorization': 'Bearer ' + jwtToken}
    r = requests.get(url, headers=header)
    server = r.json()[0]['name']
    return server.lower()

def genKeys():
    genKey = subprocess.run(['wg', 'genkey'], stdout=subprocess.PIPE)
    pubKey = subprocess.run(['wg', 'pubkey'], stdout=subprocess.PIPE, input=genKey.stdout)
    privateKey = genKey.stdout.decode('ascii').rstrip('\n')
    publicKey = pubKey.stdout.decode('ascii').rstrip('\n')
    return [privateKey, publicKey]

def getWireGuardConfig(server, base64AuthToken, publicKey):
    url = 'https://' + server + '.cg-dialup.net:1337/addKey?pubkey=' + urllib.parse.quote_plus(publicKey)
    header = {'Authorization': 'Basic ' + base64AuthToken}
    r = requests.get(url, headers=header, verify=False)
    address = r.json()['peer_ip']
    dns = r.json()['dns_servers'][0]
    peerPublicKey = r.json()['server_key']
    return [address, dns, peerPublicKey]

def printConfig(address, dns, privateKey, peerPublicKey, server):
    print('************\n************\nValues below can be used to create a WireGuard tunnel\n')
    print('[Interface]')
    print('Address = ' + address)
    print('DNS = ' + dns)
    print('PrivateKey = ' + privateKey + '\n')
    print('[Peer]')
    print('PublicKey = ' + peerPublicKey)
    print('AllowedIPs = 0.0.0.0/0')
    print('Endpoint = ' + server + '.cg-dialup.net:1337')

if __name__ == '__main__':
    appKey = input('x-app-key: ')
    username = input('Username: ')
    password = getpass.getpass()
    jwtToken = login(username, password, appKey)
    authToken = getDevice(jwtToken, appKey)
    base64AuthToken = encodeAuthToken(authToken)
    server = getServer(jwtToken, appKey)
    privateKey, publicKey = genKeys()
    address, dns, peerPublicKey = getWireGuardConfig(server, base64AuthToken, publicKey)
    printConfig(address, dns, privateKey, peerPublicKey, server)
