# Bobby Chapa
# 6/22/2021

import dpkt
import socket
import pygeoip
import argparse

# open Geo Lite City database
gi = pygeoip.GeoIP('GeoLiteCity.dat')

def main():
    parser = argparse.ArgumentParser(description='-p <pcap file>')
    parser.add_argument('-p', dest='pcapFile', type=str, help='specify pcap filename')

    args = parser.parse_args()

    if args.pcapFile == None:
        print(parser.usage)

        exit(0)

    pcapFile = args.pcapFile

    f = open(pcapFile,'rb')
    pcap = dpkt.pcap.Reader(f)

    printPcap(pcap)
    
    f.close()

    return

# process each packet in the pcap
# called from main()
def printPcap(pcap):
    for (ts, buf) in pcap:
        try:
            #extract ip addresses
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            # convert to IP address string format
            src = inet_to_str(ip.src)
            dst = inet_to_str(ip.dst)
            
            print('[+] Src: ' + src + ' --> Dst: ' + dst)
            print()
            print('[+] Src: ' + retGeoStr(src)+ ' --> Dst: ' + retGeoStr(dst))
            print()
            
        except:
            pass    

    return

# auxillary functions----------------------------//

# find geographical address of city
# called from printPcap()
def retGeoStr(ip):
    try:
        # look up IP by name
        rec = gi.record_by_name(ip)
        address = gi.record_by_addr(ip)

        # decode the geographical address for city
        city = rec['city']
        country = rec['country_code3']
        
        if city != '':
            geoLoc = city + ', ' + country
        else:
            geoLoc = country
            
        return geoLoc
    
    except Exception as e:
        return 'Unregistered'

# find ipv
# called from printPcap()
def inet_to_str(inet):
    # first try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


if __name__ == '__main__':
    main()
