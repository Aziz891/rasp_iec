from flask import Flask, jsonify
from flask.globals import request
from flask_cors import CORS, cross_origin
import subprocess
import argparse
from scapy.all import *



def arp_scan(ip):
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

    ans, unans = srp(request, timeout=5, retry=1, iface="eth0")
    result = []

    for sent, received in ans:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc})

    return result
app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

@app.route('/5')
@cross_origin()
def arp_scan():
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.2.1/24")

    ans, unans = srp(request, timeout=5, retry=1, iface="eth0")
    result = []

    for sent, received in ans:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc})

    result = jsonify(result)
    return result   

@app.route('/1')
@cross_origin()
def hello_world():
    ip = request.args.get('ip')
    print(ip)
    cmd = ["./client_example2", ip]
    p = subprocess.Popen(cmd, stdout = subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE)
    out,err = p.communicate()
    return out

@app.route('/3')
@cross_origin()
def hello_world3():
    cmd = ["./sel_set"]
    p = subprocess.Popen(cmd, stdout = subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE)
    out,err = p.communicate()
    return out
@app.route('/2')
@cross_origin()
def hello_world2():
    cmd = ["./client_example1"]
    p = subprocess.Popen(cmd, stdout = subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE)
    out,err = p.communicate()
    return out

@app.route('/4')
@cross_origin()
def hello_world4():
    cmd = ["./sel_curr"]
    p = subprocess.Popen(cmd, stdout = subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE)
    out,err = p.communicate()
    return out