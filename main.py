import nmap

def full_scan():
    ip = input("Host to scan: ") #ip
    nm = nmap.PortScanner()
    nm.scan(ip, '1', '-v') #first we'll check if the host is up or not

    if (nm[ip].state() == 'down'):
        print("Host seems down")
        exit()

    else:
        print("\n ***Scanning open ports***")
        ports = []
        #default is set to scan all ports 1-65535, you can change it if you want
        nm.scan(ip, '1-65535', arguments='--open -T5 -n') #the higher the -T argument, the noisier and the faster it will be (from 0 to 5).

        for host in nm.all_hosts():            
            print('----------------------------------------------------')
            print(f'Host : {ip}')

            for proto in nm[host].all_protocols():
                print('----------------------------------------------------')
                print('Protocol : %s' % proto)
                lport = nm[host][proto].keys()

                for port in lport:
                    ports.append(port)
                    print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

        print("\n Applying some scripts and generating logs, please wait...")
        open_ports = ','.join([str(port) for port in ports])
        nm.scan(ip, open_ports, arguments='-sC -sV -oN target')
        nm.scan(ip, open_ports, arguments=' --script vulscan/vulscan --script-args vulscandb=cve.csv -sV -oN target_cve')
        print("\n Done! Two logs have been generated.")

if __name__ == "__main__":
    full_scan()
    

                