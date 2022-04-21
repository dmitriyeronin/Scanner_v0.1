from xml.etree import ElementTree
import subprocess
import functions as func


class PortScanner:
    def __init__(self, ps_config, ch_config):
        self.path = "nmap"  # TODO: Full path
        self.output_file = "nmap_output.xml"
        self.ps_config = ps_config
        self.ch_config = ch_config
        self.check_services = eval(ch_config["Check"])

        try:
            subprocess.Popen(
                [self.path, "-V"],
                bufsize=10000,
                stdout=subprocess.PIPE,
                close_fds=True,
            )
        except OSError:
            raise PortScannerError("Nmap was not found in path. Try to edit configuration file.")

    def scan(self):
        hosts = self.ps_config["hosts"]
        output = ["-oX", self.output_file, "--open"]
        service_detection = "-sV"
        os_detection = "-O"
        script = ""
        if eval(self.ps_config["Vulners"]):
            if script:
                script += "vulners"
            else:
                script += "--script=vulners"

        cmd = ["sudo", self.path, hosts] + output + [os_detection, service_detection, script]
        try:
            subprocess.run(
                cmd,
                bufsize=100000,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except OSError:
            raise PortScannerError("Failed to start port scan.")

    def parsing(self):
        file = self.output_file
        try:
            tree = ElementTree.parse(file)
        except FileNotFoundError:
            raise PortScannerError("Failed to open output file.")

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
                    "seconds": 0,
                    "last_boot": ""
                },
                "score": 0
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
                                 "product": "", "version": "", "cpe": "", "vulns": [], "score": 0}

                    service = port.find("service")
                    open_port["service"] = service.get("name")

                    if eval(self.ch_config["Check"]):
                        CheckService(self.ch_config).check(open_port["vulns"], open_port["service"])

                    if service.get("product"): open_port["product"] = service.get("product")
                    if service.get("version"): open_port["version"] = service.get("version")
                    for cpe in service.findall("cpe"):
                        open_port["cpe"] = cpe.text

                    for script in port.findall("script"):
                        if script.get("id") == "vulners":
                            Vulners.parsing(script, open_port)

                    host_data["open_ports"].append(open_port)
                    if open_port["score"] > host_data["score"]:
                        host_data["score"] = open_port["score"]

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
            host_data["uptime"]["seconds"] = int(uptime.get("seconds"))
            host_data["uptime"]["last_boot"] = uptime.get("lastboot")

            hosts_data.append(host_data)
        return hosts_data


class PortScannerError(Exception):
    pass


class CheckService:
    def __init__(self, ch_config):
        try:
            self.allowed_services = ch_config["Allowed"]
        except KeyError:
            self.allowed_services = ""

        try:
            self.denied_services = ch_config["Denied"]
        except KeyError:
            self.denied_services = ""

    def check(self, vulns, service):
        if service in self.denied_services:
            vuln = {"module": "check_service", "results": f"{service} denied in configuration file"}
            vulns.append(vuln)
        else:
            if self.allowed_services and service not in self.allowed_services:
                vuln = {"module": "check_service",
                        "results": f"{service} is not in allowed services in configuration file"}
                vulns.append(vuln)

    @staticmethod
    def add_to_report(vuln):
        # Add check results
        # Warning_|_Service_denied_in_configuration_file_|___
        html_data = f'''
        <tr>
            <td class="line" rowspan="2" colspan="2">Warning</td>
            <td class="line" colspan="3"></td>
            <td class="line"></td>
        </tr>
        <tr>
            <td colspan="3">{vuln["results"]}</td>
            <td></td>
        </tr>
        '''
        return html_data


class Vulners:
    @staticmethod
    def parsing(script, open_port):
        vuln = {"module": "vulners", "results": []}
        cve_id = ""
        cvss = 0
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
        open_port["vulns"].append(vuln)

    @staticmethod
    def add_to_report(vuln, ls_port):
        ls_results = []
        if ls_port:
            for ls_vulns in ls_port["vulns"]:
                if ls_vulns["module"] == "vulners":
                    ls_results = ls_vulns["results"]
        # Add vulners header
        # Vulners_|_Name_|_Database_:_ID_:_IsExploit_|_CVSS
        html_data = f'''
        <tr>
            <td valign="top" colspan="2" rowspan="{len(vuln["results"]) + 1}" class="line_1">Vulners</td>
            <td class="line_1">Name</td>
            <td class="line_1" colspan="2">Database : ID : IsExploit</td>
            <td class="line_1">CVSS</td>
        </tr>
        '''
        for result_note in vuln["results"]:
            cmp = ""
            if ls_results:
                for ls_result_note in ls_results:
                    if result_note["cve_id"] == ls_result_note["cve_id"]:
                        cmp = "(Not fixed since previous scan)"
            # Add vulners data
            # ___|_CVE-0000-0000_|_metasploit_:_MSF:ILITIES/CVE..._:_EXPLOIT_|_10.0
            # Add cve id
            lv = func.level(result_note["cvss"]) + "_"
            html_data += f'''
            <tr>
                <td>{result_note["cve_id"]} {cmp}</td>
                <td class="left" colspan="2">
            '''
            for cve_note in result_note["notes"]:
                # Add cve notes
                html_data += f'''
                <a href="https://vulners.com/{cve_note["type"]}/{cve_note["id"]}">
                    {cve_note["type"]} : {cve_note["id"]} : {cve_note["is_exploit"]}
                <br></a>
                '''
            # Add cvss
            html_data += f'''
                </td>
                <td class="{lv}">{result_note["cvss"]}</td>
            </tr>
            '''
        return html_data
