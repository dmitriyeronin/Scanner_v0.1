import csv
import subprocess


class Bruteforcer:
    def __init__(self, data, config):
        self.config = config
        self.path = "patator"
        self.output_file = "patator_output.csv"
        self.hosts_data = data
        self.pass_list = config["Login list"]
        self.login_list = config["Password list"]

        try:
            subprocess.Popen(
                [self.path, "-V"],
                bufsize=10000,
                stdout=subprocess.DEVNULL,
                close_fds=True
            )
        except OSError:
            raise BruteforcerError(
                "Patator was not found in path. Try to edit configuration file."
            )

        try:
            with open(self.login_list, 'r'):
                pass
            with open(self.pass_list, 'r'):
                pass
        except FileNotFoundError:
            raise BruteforcerError(
                "Login or password lists was not find. Try to edit configuration file."
            )

    def scan(self):
        for host_data in self.hosts_data:
            if host_data["host_address"]["type"] != "ipv4":
                print("--info: Host address type is not ipv4.--")
                break
            host = host_data["host_address"]["address"]

            for port in host_data["open_ports"]:
                try:
                    if port["service"] == "ssh" and eval(self.config["ssh"]):
                        # 0=success; 1=incorrect
                        args = [self.path, "ssh_login", "host=" + host, "user=FILE0", "password=FILE1",
                                "0=" + self.login_list, "1=" + self.pass_list,
                                "-x", "free=user:code=0", "-x", "ignore:code=1", "--allow-ignore-failures",
                                "--csv=" + self.output_file]
                        self.start_bruteforce(args, port)
                    elif port["service"] == "ftp" and eval(self.config["ftp"]):
                        # 230=success; 530=incorrect
                        args = [self.path, "ftp_login", "host=" + host, "user=FILE0", "password=FILE1",
                                "0=" + self.login_list, "1=" + self.pass_list,
                                "-x", "free=user:code=230", "-x", "ignore:code=530",
                                "-x", "ignore:code=503",
                                "--allow-ignore-failures",
                                "--csv=" + self.output_file]
                        self.start_bruteforce(args, port)
                    elif port["service"] == "mysql" and eval(self.config["mysql"]):
                        # 0=success; 1045=denied
                        args = [self.path, "mysql_login", "host=" + host, "user=FILE0", "password=FILE1",
                                "0=" + self.login_list, "1=" + self.pass_list,
                                "-x", "free=user:code=0", "-x", "ignore:code=1045", "--allow-ignore-failures",
                                "--csv=" + self.output_file]
                        self.start_bruteforce(args, port)
                    elif port["service"] == "postgresql" and eval(self.config["postgresql"]):
                        # 0=success; 1=denied
                        args = [self.path, "pgsql_login", "host=" + host, "user=FILE0", "password=FILE1",
                                "0=" + self.login_list, "1=" + self.pass_list,
                                "-x", "free=user:code=0", "-x", "ignore:code=1", "--allow-ignore-failures",
                                "--csv=" + self.output_file]
                        self.start_bruteforce(args, port)
                    elif port["service"] == "oracle" and eval(self.config["oracle"]):
                        args = [self.path, "oracle", "host=" + host, "user=FILE0", "password=FILE1",
                                "0=" + self.login_list, "1=" + self.pass_list,
                                "-x", "free=user:code=0", "-x", "ignore:code=1", "--allow-ignore-failures",
                                "--csv=" + self.output_file]
                        self.start_bruteforce(args, port)
                    elif port["service"] == "telnet" and eval(self.config["telnet"]):
                        args = [self.path, "telnet_login", "host=" + host, "inputs='FILE0\nFILE1'",
                                "0=" + self.login_list, "1=" + self.pass_list,
                                "persistent=0", "prompt_re='Username:|Password:'",
                                "-x", "ignore:egrep=\'Login incorrect\'", "-x", "ignore:code=500",
                                "--allow-ignore-failures",
                                "--csv=" + self.output_file]
                        self.start_bruteforce(args, port)
                except KeyError:
                    pass

    def start_bruteforce(self, cmd, port):
        with open(self.output_file, 'w'):
            pass
        print("STATUS:  Start bruteforce " + port["service"])
        try:
            p = subprocess.run(
                cmd,
                bufsize=100000,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            # print(p)
        except OSError:
            raise BruteforcerError("Failed to start password сracker.")

        vuln = self.parsing()
        if vuln["results"]:
            port["vulns"].append(vuln)
            print("INFO:    Password was founded")

    def parsing(self):
        with open(self.output_file, 'r') as f:
            reader = csv.reader(f)
            vuln = {"module": "bruteforcer", "results": []}
            for row in reader:
                result = {"login:pass": row[5], "mesg": row[7]}
                vuln["results"].append(result)
        return vuln

    @staticmethod
    def add_to_report(vuln, ls_port):
        ls_results = []
        if ls_port:
            for ls_vulns in ls_port["vulns"]:
                if ls_vulns["module"] == "bruteforcer":
                    ls_results = ls_vulns["results"]
        # Add bruteforces header
        # Bruteforcer_|_login:pass_|_Мessage_|___
        html_data = f'''
        <tr>
            <th valign="top" colspan="2" rowspan="{len(vuln["results"]) + 1}">Bruteforcer</th>
            <th>login:pass</th>
            <th colspan="2">Мessage</th>
            <th></th>
        </tr>
        '''

        for result_note in vuln["results"]:
            cmp = ""
            if ls_results:
                for ls_result_note in ls_results:
                    if result_note["login:pass"] == ls_result_note["login:pass"]:
                        cmp = "(Not fixed since previous scan)"
            # Add bruteforces data
            # ___|_root:toor_|_mesg_|___
            html_data += f'''
            <tr>
                <td>{result_note["login:pass"]} {cmp}</td>
                <td colspan="2">{result_note["mesg"]}</td>
                <td></td>
            </tr>
            '''

        return html_data


class BruteforcerError(Exception):
    pass
