from port_scanner import PortScanner
from bruteforcer import Bruteforcer
from report import Report
import pprint

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.


def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    scanner = PortScanner()
    #scanner.scan("192.168.1.100")
    hosts_data = scanner.parsing()
    #b = Bruteforcer(hosts_data)
    #b.scan()
    #pprint.pprint(hosts_data)
    r = Report(hosts_data)
    r.new_report()
    #r.save_hosts_data()
    #r.compere()
