import json
from datetime import datetime
from port_scanner import Vulners, CheckService
from bruteforcer import Bruteforcer
import functions as func


class Report:
    def __init__(self, data, config):
        self.output_file = config["HTML report directory"] + "report.html"
        self.css_file = "report_style.css"
        self.hosts_data = data
        self.results_path = config["JSON results directory"]
        self.compere = eval(config["Compere with last result"])

        try:
            with open(self.output_file, 'w'):
                pass
        except PermissionError:
            raise ReportError("Failed to open or create HTML-report file.")
        try:
            with open(self.output_file, 'r'):
                pass
        except (FileNotFoundError, PermissionError):
            raise ReportError("Failed to open CSS file.")

    def save_hosts_data(self):
        date_format = "%d-%m-%Y_%H:%M"
        file = f"scan_{datetime.now().strftime(date_format)}.json"
        try:
            with open(self.results_path + file, 'w') as f:
                json.dump(self.hosts_data, f)
            with open(self.results_path + "last_scan.json", 'w') as f:
                json.dump(self.hosts_data, f)
        except PermissionError:
            raise ReportError("Failed to save JSON results file.")

    def new_report(self):
        with open(self.output_file, 'w') as f:
            if self.compere:
                try:
                    ls_f = open(self.results_path + "last_scan.json", "r")
                    ls_data = json.load(ls_f)
                except FileNotFoundError:
                    self.compere = False
            # CSS, title and header
            try:
                with open(self.css_file, 'r') as css_f:
                    css_style = css_f.read()
            except (FileNotFoundError, PermissionError):
                raise ReportError("CSS file was not found.")

            html_data = f'''
               <!doctype html>
                <html>
                <head>
                    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
                    <style type="text/css">
                        {css_style}
                    </style>
                    <title>Scan Report</title>
                </head>
                <body>
                    <h1>Scan report</h1>
                '''
            for host_data in self.hosts_data:
                host_cmp = ""
                if self.compere:
                    host_cmp = "(new)"
                    for ls_host_data in ls_data:
                        if ls_host_data["host_address"]["address"] == host_data["host_address"]["address"]:
                            host_cmp = ""
                            break

                lv = func.level(host_data["score"])
                # Add hostblock and host address header
                html_data += f'''
                <a name="host_{host_data["host_address"]["address"]}"></a>
                <h2 class={lv}>{host_data["host_address"]["address"]} {host_cmp}</h2>
                <div id="hostblock_{host_data["host_address"]["address"]}">   
                '''
                # Add host names to report
                if host_data["host_names"]:
                    html_data += f'''<h3>Hostnames</h3>'''
                    for hostname in host_data["host_names"]:
                        html_data += f'''
                        <ul><li>{hostname["name"]} ({hostname["type"]})</li></ul>
                        '''
                # Add os data to report
                if host_data["os"]:
                    html_data += f'''
                    <h3>Operating system</h3>
                    '''
                    for os in host_data["os"]:
                        html_data += f'''
                        <ul>
                            <li>Type: {os["type"]}</li>
                            <li>Vendor: {os["vendor"]}</li>
                            <li>Family: {os["family"]}</li>
                            <li>Generation: {os["gen"]}</li>
                            <li>Accuracy: {os["class_accuracy"]}</li>
                            <li>{os["cpe"]}</li>
                        </ul>
                        '''
                # Add uptime data to report
                html_data += f'''
                    <h3>Uptime</h3>
                    <ul>
                            <li>{func.convert_time(host_data["uptime"]["seconds"])}</li>
                            <li>Last boot: {host_data["uptime"]["last_boot"]}</li>
                        </ul>
                   '''
                html_data += f'''
                <table id="porttable_{host_data["host_address"]["address"]}">
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Product</th>
                            <th>Version</th>
                            <th>CPE</th>
                            <th>Score</th>
                        </tr>
                    </thead>
                    <tbody>
                '''
                for port in host_data["open_ports"]:
                    port_cmp = ""
                    ls_port = None
                    if self.compere:
                        port_cmp = "(new)"
                        for ls_port in ls_host_data["open_ports"]:
                            if ls_port["port_id"] == port["port_id"]:
                                ls_port = port
                                port_cmp = ""
                                break
                    lv = func.level(port["score"])
                    html_data += f'''
                    <tr>
                        <td class="{lv}">{port["port_id"]} {port_cmp}</td>
                        <td class="{lv}">{port["service"]}</td>
                        <td class="{lv}">{port["product"]}</td>
                        <td class="{lv}">{port["version"]}</td>
                        <td class="{lv}">{port["cpe"]}</td>
                        <td class="{lv}">{port["score"]}</td>
                    </tr>
                    '''
                    for vuln in port["vulns"]:
                        if vuln["module"] == "check_service":
                            html_data += CheckService.add_to_report(vuln)
                        if vuln["module"] == "vulners":
                            html_data += Vulners.add_to_report(vuln, ls_port)
                        if vuln["module"] == "bruteforcer":
                            html_data += Bruteforcer.add_to_report(vuln, ls_port)
                html_data += f'''
                </tbody>
                </table>
                </div>
                '''
            html_data += f'''
            </body>
            </html>
            '''

            ls_f.close()
            f.write(html_data)


class ReportError(Exception):
    pass
