from port_scanner import PortScanner
from bruteforcer import Bruteforcer
from report import Report
import pprint
import configparser

if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read("config.ini")
    ps = PortScanner(config["Port Scanner"], config["Check active services"])
    #ps.scan()
    hosts_data = ps.parsing()
    #b = Bruteforcer(hosts_data, config["Bruteforce"])
    #b.scan()
    #pprint.pprint(hosts_data)
    r = Report(hosts_data, config["Report"])
    r.new_report()
    #r.save_hosts_data()
