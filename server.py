from unittest import result
from flask import Flask, jsonify
from flask.globals import request
from flask_cors import CORS, cross_origin
import subprocess, re
import argparse
from scapy.all import *
from psutil import net_if_addrs
import io



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

@app.route('/6')
@cross_origin()
def get_comms():

    ip = request.args.get('ip')
    cmd = ["./file-tool -h {}  subdir COMTRADE".format(ip)]
    p = subprocess.Popen(cmd, stdout = subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE, shell=True)
    out,err = p.communicate()
    y =  out.decode('ascii').split("\n")
    list_comms = [i.split()[0] for i in y if re.match('^\S*CFG', i)]
    result = []
    for i in list_comms: 
        cmd = ["./file-tool -h {} get '{}'".format(ip,i)]
        p = subprocess.Popen(cmd, stdout = subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE, shell=True)
        out,err = p.communicate()
        result.append({"name": i,"date" : out.decode('ascii').split('\r\n')[-4]})

    return jsonify(result)

@app.route('/7')
@cross_origin()
def download_comms():

    f = io.BytesIO()
    ip = request.args.get('ip')
    name = request.args.get('name')
    cmd = ["./file-tool -h {}  get 'COMTRADE\{}'".format(ip, name)]
    p = subprocess.Popen(cmd, stdout = subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE, shell=True)
    out,err = p.communicate()
    f.write(out)
    result = f.getvalue()
    f.close()



    
   

    return (result)
    


    return result
def get_name(ip):
    cmd = ["./client_example3", ip]
    p = subprocess.Popen(cmd, stdout = subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE)
    out,err = p.communicate()
    out = out.decode('utf-8').strip()
    print(out[:2])
    if out[:2] == 'LD':
        return out[2:]
    else:
        return "Unknown"
@app.route('/5')
@cross_origin()
def arp_scan():
    ip="172.16.1.1"

    if net_if_addrs().get("eth0"):
    	ip = net_if_addrs().get("eth0")[0].address
    

    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=f"{ip}/22")

    ans, unans = srp(request, timeout=5, retry=1, iface="eth0")
    result = []

    for sent, received in ans:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc, 'NAME': get_name(received.psrc)})

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

