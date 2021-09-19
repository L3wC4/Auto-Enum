import sys
import os
import traceback
import subprocess as sub
import re
from googlesearch import search

ip_addr = ''
Dir = ''
portDir = ''
http_dicti = {}
http_port_dicti = {}
port_dicti = {}


def getIP():
    global ip_addr
    ip_addr = str(input('[?] Please enter the DOMAIN or IP you would like to enumerate\n (Fuzzing Sub-domains will not work with an IP): '))
 
    

def mkdir():
    global Dir
    Dir = f"{os.getenv('HOME')}/Documents/" + ip_addr
    os.makedirs(Dir, mode=0o700, exist_ok=True)
    

#output from rustscan is messy and could be cleaned up, but it works.
def PortScan():
    global portDir
    portDir = Dir +'/portscan.txt'
    print('[+] Starting portscan.\n[+] The results can be found here: ' + portDir )
    cmd = "rustscan", "-a", ip_addr, "--", "-sV", "-sC", "-A", "-Pn"
    f = open(portDir, "w")
    p = sub.Popen(cmd, stdout=f, text=True)
    p.wait()
    Greped(portDir)

def Greped(portDir):
    f = open(portDir, 'r')
    count_lines = 0
    global http_dicti
    http_dicti = {}
    for line in f:
        if 'tcp' in line:
            if 'http' in line:
                count_lines = count_lines + 1
                Get_line(count_lines, line)
    count = 0
    for l in http_dicti:
        count = count + 1
        part = http_dicti[l].partition('/')
        http_port_dicti["port" + str(count)] = part[0]



#creates dictionary entry for lines in Greped function 
def Get_line(count_lines, line):
    http_dicti["port" + str(count_lines)] = line

def dir_fuzz():
    print('[+] Starting directory bruteforce!')
    count = 0
    for e in http_dicti:
        if http_dicti[e][0:3] == '80/':
            count = count + 1
            url = 'http://' + ip_addr + '/FUZZ'
            ffuf_dir = Dir + '/Directories' + '_' + str(count) + '.html'
            cmd = "ffuf", "-w", "./directory-list-2.3-medium.txt", "-u", url, "-recursion", "-o", ffuf_dir, "-of", "html", "-e", ".php,.txt"
            p = sub.Popen(cmd, stdout=sub.DEVNULL)
        elif http_dicti[e][0:4] == '443/':
            count = count + 1
            url = 'https://' + ip_addr + '/FUZZ'
            ffuf_dir = Dir + '/Directories' + '_' + str(count) + '.html'
            cmd = "ffuf", "-w", "./directory-list-2.3-medium.txt", "-u", url, "-recursion", "-o", ffuf_dir, "-of", "html", "-e", ".php,.txt"
            p = sub.Popen(cmd, stdout=sub.DEVNULL)
        elif 'tls' in http_dicti[e]:
            part = http_dicti[e].partition('/')
            port = part[0]
            count = count + 1
            url = 'https://' + ip_addr + ':' + port + '/FUZZ'
            ffuf_dir = Dir + '/Directories' + '_' + str(count) + '.html'
            cmd = "ffuf", "-w", "./directory-list-2.3-medium.txt", "-u", url, "-recursion", "-o", ffuf_dir, "-of", "html", "-e", ".php,.txt"
            p = sub.Popen(cmd, stdout=sub.DEVNULL)
        elif 'ssl' in http_dicti[e]:
            part = http_dicti[e].partition('/')
            port = part[0]
            count = count + 1
            url = 'https://' + ip_addr + ':' + port + '/FUZZ'
            ffuf_dir = Dir + '/Directories' + '_' + str(count) + '.html'
            cmd = "ffuf", "-w", "./directory-list-2.3-medium.txt", "-u", url, "-recursion", "-o", ffuf_dir, "-of", "html", "-e", ".php,.txt"
            p = sub.Popen(cmd, stdout=sub.DEVNULL)
        else:
            part = http_dicti[e].partition('/')
            port = part[0]
            count = count + 1
            url = 'http://' + ip_addr + ':' + port + '/FUZZ'
            ffuf_dir = Dir + '/Directories' + '_' + str(count) + '.html'
            cmd = "ffuf", "-w", "./directory-list-2.3-medium.txt", "-u", url, "-recursion", "-o", ffuf_dir, "-of", "html", "-e", ".php,.txt"
            p = sub.Popen(cmd, stdout=sub.DEVNULL)

def Sub_dom_fuzz():
    print('[+] Starting sub-domain bruteforce!')
    print('[+] Auto filtering is enabled to minimize false positives!')
    #test options of adding /etc/host entry. Sudo/password will be needed.
    if re.match("^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$", ip_addr):
        return
    else:
        count = 0 
        domain = 'Host:FUZZ.' + ip_addr 
        for e in http_dicti:
            if http_dicti[e][0:3] == '80/':
                count = count + 1
                url = 'http://' + ip_addr 
                Sub_Domain = Dir + '/Sub_Domains' + '_' + str(count) + '.html'
                cmd = "ffuf", "-w", "./subdomains.txt", "-u", url, "-H", domain, "-ac", "-o", Sub_Domain, "-of", "html"                
                p = sub.Popen(cmd, stdout=sub.DEVNULL)
            elif http_dicti[e][0:4] == '443/':
                count = count + 1
                url = 'https://' + ip_addr 
                Sub_Domain = Dir + '/Sub_Domains' + '_' + str(count) + '.html'
                cmd = "ffuf", "-w", "./subdomains.txt", "-u", url, "-H", domain, "-ac", "-o", Sub_Domain, "-of", "html"                
                p = sub.Popen(cmd, stdout=sub.DEVNULL)
            elif 'tls' in http_dicti[e]:
                part = http_dicti[e].partition('/')
                port = part[0]
                count = count + 1
                url = 'https://' + ip_addr + ':' + port 
                Sub_Domain = Dir + '/Sub_Domains' + '_' + str(count) + '.html'
                cmd = "ffuf", "-w", "./subdomains.txt", "-u", url, "-H", domain, "-ac", "-o", Sub_Domain, "-of", "html"                
                p = sub.Popen(cmd, stdout=sub.DEVNULL)
            elif 'ssl' in http_dicti[e]:
                part = http_dicti[e].partition('/')
                port = part[0]
                count = count + 1
                url = 'https://' + ip_addr + ':' + port 
                Sub_Domain = Dir + '/Sub_Domains' + '_' + str(count) + '.html'
                cmd = "ffuf", "-w", "./subdomains.txt", "-u", url, "-H", domain, "-ac", "-o", Sub_Domain, "-of", "html"               
                p = sub.Popen(cmd, stdout=sub.DEVNULL)
            else:
                part = http_dicti[e].partition('/')
                port = part[0]
                count = count + 1
                url = 'http://' + ip_addr + ':' + port + '/FUZZ'
                Sub_Domain = Dir + '/Sub_Domains' + '_' + str(count) + '.html'
                cmd = "ffuf", "-w", "./subdomains.txt", "-u", url, "-H", domain, "-ac", "-o", Sub_Domain, "-of", "html"
                p = sub.Popen(cmd, stdout=sub.DEVNULL)

def google_search():
    vulnDir = Dir + '/Exploits.txt'
    f = open(portDir, 'r')
    f2 = open(vulnDir, 'w')   
    for line in f:
        if 'syn-ack' in line:
            port = line.partition('/')
            port = port[0]
            part = line.partition('syn-ack')
            part2 = part[2]
            part2 = part2.partition('(')
            part3 = part2[0]
            query = part3 + 'exploits'
            f2.write(f'[+] Possible exploits for port {port}.\n')
            for j in search(query, num_results=3, lang="en"):
                f2.write(j + '\n')


def cve_search():
    cve = CVESearch()
    cveDir = Dir + '/CVEs.txt'
    f = open(portDir, 'r')
    f2 = open(vulnDir, 'w')   
    for line in f:
        if 'syn-ack' in line:
            port = line.partition('/')
            port = port[0]
            part = line.partition('syn-ack')
            part2 = part[2]
            part2 = part2.partition('(')
            part3 = part2[0]
            query = part3 
            f2.write(f'[+] CVEs for port {port}.\n')
            results = cve.browse(query)
            print(results)
            f2.write(results)



print('[+] Lets start enumerating!!!')
getIP()
mkdir()
PortScan()
dir_fuzz()
Sub_dom_fuzz()
google_search()



