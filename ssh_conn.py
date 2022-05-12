from scapy.all import *
from collections import Counter

pkt_per_sec = 0

def timer_func():
    pkt_per_sec = 0 
    sleep(1)
    if pkt_per_sec > 20:
        print("[+] Fuzzing detected")#its a alot of pkt that was sent and probably fuzzing
        exit(0)

def filter_packets(pkt):
    #checks if the packet is an SSH packet
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if pkt[TCP].dport == 22:
            str_p = ""
		    #ubuntu debian redhat centos fedora windows Windows Server UNIX OS 
			#check the src send frequency if too high then drop the packet
            str_p = str(pkt[Raw].show())
            words = ["ssh", "Ssh", "SSH", "sha2", "sha1", "sha256", "sha512", "md5", "md4", "md5-sha1", "md4-sha1", "rsa", "dsa", "ecdsa", "ed25519", "aes", "OpenSSH", "PuTTY", "sshdod", "SSH-2.0", "diffie-hellman" ,"~$","$", "./" ,"ubuntu" ,"debian" ,"redhat" ,"centos" ,"fedora" ,"windows" ,"Windows" ,"Server" ,"UNIX" ,"OS" ]
            for word in words:
                if word in str_p:
                    print("[+] Fuzzing detected") #reason why is that if there is one thoose keyes then probbley no incryption happend and someone just send words to us
                    exit(0)
            runner = 0 
            while(runner < len(str_p)-7):
                temp_str = str_p[runner:runner+7]
                count = Counter(temp_str)
                for key in count:
                    if count[key] > 5:
                        print("[+] Fuzzing detected")
                        exit(0)

            #read auth.log and check for errors
            with open("/var/log/auth.log", "r") as f:
                #check for errors in auto.log file in the last 5 lines
                for line in f.readlines()[-5:]:
                    if "error" in line.lower():
                        print("[+] Fuzzing detected")
                        exit(0)

            print("[-] Fuzzing not detected")

pkt = sniff(filter="port 22", prn=filter_packets)