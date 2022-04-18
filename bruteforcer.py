import csv
import subprocess


class Bruteforcer:
    def __init__(self, data):
        self.path = "patator"
        self.output_file = "patator_output.csv"
        self.hosts_data = data

        try:
            subprocess.Popen(
                [self.path, "-V"],
                bufsize=10000,
                stdout=subprocess.DEVNULL,
                close_fds=True
            )

        except OSError:
            '''
            raise BruteforcerError(
                f"Nmap was not found in path. Try to edit configuration file."
            )
            '''
            print("Patator was not found in path. Try to edit configuration file.")

    def scan(self):
        pass_list = "Scanner/common_passwords.txt"

        for host_data in self.hosts_data:
            if host_data["host_address"]["type"] != "ipv4":
                print("--info: Host address type is not ipv4.--")
                break
            host = host_data["host_address"]["address"]

            for port in host_data["open_ports"]:
                if port["service"] == "ssh":
                    # 0=success; 1=incorrect
                    args = [self.path, "ssh_login", "host=" + host, "user=FILE0", "password=FILE1",
                            "0=" + pass_list, "1=" + pass_list,
                            "-x", "free=user:code=0", "-x", "ignore:code=1", "--allow-ignore-failures",
                            "--csv=" + self.output_file]
                    self.bruteforce(args, port)

                elif port["service"] == "ftp":
                    # 230=success; 530=incorrect
                    args = [self.path, "ftp_login", "host=" + host, "user=FILE0", "password=FILE1",
                            "0=" + pass_list, "1=" + pass_list,
                            "-x", "free=user:code=230", "-x", "ignore:code=530", "--allow-ignore-failures",
                            "--csv=" + self.output_file]
                    self.bruteforce(args, port)

                elif port["service"] == "mysql":
                    # 0=success; 1045=denied
                    args = [self.path, "mysql_login", "host=" + host, "user=FILE0", "password=FILE1",
                            "0=" + pass_list, "1=" + pass_list,
                            "-x", "free=user:code=0", "-x", "ignore:code=1045", "--allow-ignore-failures",
                            "--csv=" + self.output_file]
                    self.bruteforce(args, port)

                elif port["service"] == "postgresql":
                    # 0=success; 1=denied
                    args = [self.path, "pgsql_login", "host=" + host, "user=FILE0", "password=FILE1",
                            "0=" + pass_list, "1=" + pass_list,
                            "-x", "free=user:code=0", "-x", "ignore:code=1", "--allow-ignore-failures",
                            "--csv=" + self.output_file]
                    self.bruteforce(args, port)

                elif port["service"] == "oracle":
                    # 
                    args = [self.path, "oracle", "host=" + host, "user=FILE0", "password=FILE1",
                            "0=" + pass_list, "1=" + pass_list,
                            "-x", "free=user:code=0", "-x", "ignore:code=1", "--allow-ignore-failures",
                            "--csv=" + self.output_file]
                    self.bruteforce(args, port)

                elif port["service"] == "telnet":
                    args = [self.path, "telnet_login", "host=" + host, "inputs='FILE0\nFILE1'",
                            "0=" + pass_list, "1=" + pass_list,
                            "persistent=0", "prompt_re='Username:|Password:'",
                            "-x", "ignore:egrep='Login incorrect'", "-x", "ignore:code=500", "--allow-ignore-failures",
                            "--csv=" + self.output_file]
                    self.bruteforce(args, port)

    def bruteforce(self, cmd, port):
        with open(self.output_file, 'w'):
            pass
        print("--Start bruteforce " + port["service"] + "--")
        p = subprocess.run(
            cmd,
            bufsize=100000,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        vuln = self.parsing()
        if vuln["results"]:
            port["vulns"].append(vuln)
            print("--Password was founded--")

    def parsing(self):
        with open(self.output_file) as file:
            reader = csv.reader(file)
            vuln = {"module": "bruteforcer", "results": []}
            for row in reader:
                result = {"login:pass": row[5], "mesg": row[7]}
                vuln["results"].append(result)
            print("::", vuln)
            print()
        return vuln
