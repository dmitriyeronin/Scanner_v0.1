from port_scanner import PortScanner
from bruteforcer import Bruteforcer
from report import Report
import configparser
import pprint

if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read("config.ini")
    ps = PortScanner(config["Port Scanner"], config["Check active services"])
    ps.scan()
    hosts_data = ps.parsing()
    b = Bruteforcer(hosts_data, config["Bruteforce"])
    b.scan()
    r = Report(hosts_data, config["Report"])
    pprint.pprint(hosts_data)
    r.new_report()
    r.save_hosts_data()
