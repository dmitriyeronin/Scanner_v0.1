import pprint
from xml.etree import ElementTree
import subprocess


class PortScanner:
    def __init__(self):
        self.path = "nmap"
        # TODO: Full path

        # self.scan_result = {}
        #self.output_file = "/home/kali/nmap_output.xml"
        self.output_file = "nmap_output.xml"

        try:
            subprocess.Popen(
                [self.path, "-V"],
                bufsize=10000,
                stdout=subprocess.PIPE,
                close_fds=True,
            )

        except OSError:
            '''
            raise PortScannerError(
                f"Nmap was not found in path. Try to edit configuration file."
            )
            '''
            print("Nmap was not found in path. Try to edit configuration file.")

    def scan(self, hosts):
        # ports = ""
        output = ["-oX", self.output_file, "--open"]
        service_detection = "-sV"
        os_detection = "-O"
        script = "--script=vulners"

        cmd = ["sudo", self.path, hosts] + output + [os_detection, service_detection, script]

        p = subprocess.run(
            cmd,
            bufsize=100000,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # print(p)

        # TODO: Check errors (returncode = 0) and timeout

        return p

    def parsing(self):
        file = self.output_file
        tree = ElementTree.parse(file)
        hosts_data = []

        for host in tree.findall("host"):

            host_data = {
                "host_address": {
                    "address": "",
                    "type": ""
                },
                "host_names": [],
                "open_ports": [],
                "os": [],
                "uptime": {
                    "seconds": "",
                    "last_boot": ""
                },
                "max_score": 0,
                "vuln_level": ""
            }

            host_data["host_address"]["address"] = host.find("address").get("addr")
            host_data["host_address"]["type"] = host.find("address").get("addrtype")

            for hostname in host.findall("hostnames/hostname"):

                host_name = {"name": hostname.get("name"), "type": hostname.get("type")}

                host_data["host_names"].append(host_name)

            ports = host.find("ports")
            for port in ports.findall("port"):
                if port.find("state").get("state") == "open":

                    open_port = {"port_id": int(port.get("portid")), "protocol": port.get("protocol"), "service": "",
                                 "product": "", "version": "", "cpe": "", "vulns": [], "vuln_level": "", "score": 0}

                    service = port.find("service")
                    open_port["service"] = service.get("name")
                    open_port["product"] = service.get("product")
                    open_port["version"] = service.get("version")
                    for cpe in service.findall("cpe"):
                        open_port["cpe"] = cpe.text

                    for script in port.findall("script"):
                        if script.get("id") == "vulners":
                            vuln = {"module": "vulners", "results": []}
                            cve_id = ""
                            cvss = 0
                            # cve = {"cve_id": "", "cvss": "", "notes": []}
                            for note in script.findall("table/table"):
                                flag = 1
                                cve_note = {"id": "", "type": "", "is_exploit": ""}
                                for elem in note.findall("elem"):
                                    if elem.get("key") == "cvss":
                                        cvss = float(elem.text)
                                        if cvss > open_port["score"]:
                                            open_port["score"] = cvss
                                    if elem.get("key") == "is_exploit":
                                        if elem.text == "true":
                                            cve_note["is_exploit"] = "EXPLOIT"
                                    if elem.get("key") == "id":
                                        cve_note["id"] = elem.text
                                        i = cve_note["id"].find("CVE-")
                                        if i == -1:
                                            cve_id = cve_note["id"]
                                        else:
                                            j = cve_note["id"].find("/", i)
                                            if j == -1:
                                                cve_id = cve_note["id"][i:]
                                            else:
                                                cve_id = cve_note["id"][i:j]
                                    if elem.get("key") == "type":
                                        cve_note["type"] = elem.text
                                if not vuln["results"]:
                                    vuln["results"].append({"cve_id": cve_id, "cvss": cvss, "notes": []})
                                for result_note in vuln["results"]:
                                    if result_note["cve_id"] == cve_id:
                                        flag = 0
                                        result_note["notes"].append(cve_note)
                                        break
                                if flag:
                                    vuln["results"].append({"cve_id": cve_id, "cvss": cvss, "notes": [cve_note]})
                            pprint.pprint(vuln)
                            open_port["vulns"].append(vuln)
                    host_data["open_ports"].append(open_port)

            operating_systems = host.find("os")
            for os_match in operating_systems.findall("osmatch"):

                os = {"name": os_match.get("name"), "name_accuracy": int(os_match.get("accuracy")), "type": "",
                      "vendor": "", "family": "", "gen": "", "class_accuracy": None, "cpe": ""}

                os_class = os_match.find("osclass")
                os["type"] = os_class.get("type")
                os["vendor"] = os_class.get("vendor")
                os["family"] = os_class.get("osfamily")
                os["gen"] = os_class.get("osgen")
                os["class_accuracy"] = int(os_class.get("accuracy"))
                for cpe in os_class.findall("cpe"):
                    os["cpe"] = cpe.text
                host_data["os"].append(os)

            uptime = host.find("uptime")
            host_data["uptime"]["seconds"] = uptime.get("seconds")
            host_data["uptime"]["last_boot"] = uptime.get("lastboot")

            hosts_data.append(host_data)

        return hosts_data
