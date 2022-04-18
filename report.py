import pprint

class Report:
    def __init__(self, data):
        self.output_file = "report.html"
        self.hosts_data = data

    def new_report(self):
        with open(self.output_file, 'w') as f:
            html_data = '''
               <!doctype html>
                <html>
                <head>
                    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
                    <style type="text/css">
                        
                        /* stylesheet screen */
                        @media screen
                        {
                          body {
                            font-family: Verdana, Helvetica, sans-serif;
                            margin: 0px;
                            background-color: #FFFFFF;
                            color: #000000;
                            text-align: center;
                          }
                          #container {
                            text-align:left;
                            margin: 10px auto;
                            width: 90%;
                          }
                          h1 {
                            font-family: Verdana, Helvetica, sans-serif;
                            font-weight:bold;
                            font-size: 14pt;
                            color: #FFFFFF;
                            background-color:#2A0D45;
                            margin:10px 0px 0px 0px;
                            padding:5px 4px 5px 4px;
                            width: 100%;
                            border:1px solid black;
                            text-align: left;
                          }
                          h2 {
                            font-family: Verdana, Helvetica, sans-serif;
                            font-weight:bold;
                            font-size: 11pt;
                            color: #000000;
                            margin:30px 0px 0px 0px;
                            padding:4px;
                            width: 100%;
                            background-color:#F0F8FF;
                            text-align: left;
                          }
                          h3 {
                            font-family: Verdana, Helvetica, sans-serif;
                            font-weight:bold;
                            font-size: 10pt;
                            color:#000000;
                            background-color: #FFFFFF;
                            width: 75%;
                            text-align: left;
                          }
                          p {
                            font-family: Verdana, Helvetica, sans-serif;
                            font-size: 8pt;
                            color:#000000;
                            background-color: #FFFFFF;
                            width: 75%;
                            text-align: left;
                          }
                          p i {
                            font-family: Verdana, Helvetica, sans-serif;
                            font-size: 8pt;
                            color:#000000;
                            background-color: #CCCCCC;
                          }
                          ul {
                            font-family: Verdana, Helvetica, sans-serif;
                            font-size: 8pt;
                            color:#000000;
                            background-color: #FFFFFF;
                            width: 75%;
                            text-align: left;
                          }
                          a {
                            font-family: Verdana, Helvetica, sans-serif;
                            text-decoration: none;
                            font-size: 8pt;
                            color:#000000;
                            font-weight:bold;
                            background-color: #FFFFFF;
                            color: #000000;
                          }
                          li a {
                            font-family: Verdana, Helvetica, sans-serif;
                            text-decoration: none;
                            font-size: 10pt;
                            color:#000000;
                            font-weight:bold;
                            background-color: #FFFFFF;
                            color: #000000;
                          }
                          a:hover {
                            text-decoration: underline;
                          }
                          
                          table {
                            width: 90%;
                            border:0px;
                            color: #000000;
                            background-color: #ffffff;
                            margin:10px;
                          }
                          
                          thead {
                            background-color: #555;
                            color: #FFFFFF;
                            font-size: 12pt;
                            font-weight:bold;
                          }
                          
                          tbody tr:nth-child(odd) {
                              background-color: #fff;
                              font-size: 8pt;
                            }

                          tbody tr:nth-child(even) {
                              background-color: #eee;
                              font-size: 8pt;
                            }
                          
                          }
                          
                          #menu li {
                            display         : inline;
                            margin          : 0;
                            /*margin-right    : 10px;*/
                            padding         : 0;
                            list-style-type : none;
                          }
                          #menubox {
                            position: fixed;
                            bottom: 0px;
                            right: 0px;
                            width: 120px;
                          }
                          /* This section handle's IE's refusal to honor the fixed CSS attribute */
                          * html div#menubox {
                            position: absolute;
                            top:expression(eval(
                              document.compatMode && document.compatMode=='CSS1Compat') ?
                              documentElement.scrollTop+(documentElement.clientHeight-this.clientHeight)
                              : document.body.scrollTop +(document.body.clientHeight-this.clientHeight));
                          }
                          /* This fixes the jerky effect when scrolling in IE*/
                          * html,* html body {
                            background: #fff url(nosuchfile) fixed;
                          }
                          .no {
                            color:#000000;
                            background-color: #b2ec5d;
                            font-size: 12pt;
                            font-weight:bold;
                          }
                          .low {
                            color: #000000;
                            background-color:#ffff66;
                            font-size: 12pt;
                            font-weight:bold;
                          }
                          .mid {
                            color:#000000;
                            background-color: #ff8c00;
                            font-size: 12pt;
                            font-weight:bold;
                          }
                          .high {
                            color:#000000;
                            background-color: #ff4500;
                            font-size: 12pt;
                            font-weight:bold;
                          }
                          .no_ {
                            color:#00d600;

                            font-weight:bold;
                            font-size: 12pt;
                          }
                          .low_ {
                            color: #eed202;

                            font-weight:bold;
                            font-size: 12pt;
                          }
                          .mid_ {
                            color:#ff8c00;

                            font-weight:bold;
                            font-size: 12pt;
                          }
                          .high_ {
                            color:#ff0000;
                            
                            font-weight:bold;
                            font-size: 12pt;
                        }
                          .line {
                            background-color: #555;
                            color: #FFFFFF;
                            font-size: 12pt;
                            font-weight:bold;
                          }
                          .line_1 {
                            background-color: #555;
                            color: #FFFFFF;
                            font-size: 12pt;
                            font-weight:bold;
                          }
                          .left {
                            text-align:left;
                            padding    : 10px;
                          }
                    </style>
                    <title>Scan Report</title>
                </head>
                <body>
                    <h1>Scan report</h1>
                '''
            for host_data in self.hosts_data:
                html_data += f'''
                <a name="host_{host_data["host_address"]["address"]}"></a>
                <h2 class={host_data["vuln_level"]}>{host_data["host_address"]["address"]}</h2>
                <div id="hostblock_{host_data["host_address"]["address"]}">   
                '''
                if host_data["host_names"]:
                    html_data += f'''<h3>Hostnames</h3>'''
                    for hostname in host_data["host_names"]:
                        html_data += f'''
                        <ul><li>{hostname["name"]} ({hostname["type"]})</li></ul>
                        '''
                if host_data["os"]:
                    html_data += f'''
                    <h3>Operation system</h3>
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

                html_data += f'''
                    <h3>Uptime</h3>
                    <ul>
                            <li>{host_data["uptime"]["seconds"]} seconds</li>
                            <li>Last boot: {host_data["uptime"]["last_boot"]}</li>
                        </ul>
                   '''
                html_data += f'''
                <table id="porttable_{host_data["host_address"]["address"]}">
                    <thead>
                        <tr class="head">
                            <td>Port</td>
                            <td>Service</td>
                            <td>Product</td>
                            <td>Version</td>
                            <td>CPE</td>
                            <td>Score</td>
                        </tr>
                    </thead>
                    <tbody>
                '''
                for port in host_data["open_ports"]:
                    if port["score"] == 0:
                        level = "no"
                    if port["score"] > 0 and port["score"] < 3:
                        level = "low"
                    if port["score"] > 3 and port["score"] < 7:
                        level = "mid"
                    if port["score"] > 7:
                        level = "high"
                    html_data += f'''
                    <tr>
                        <td class="{level}">{port["port_id"]}</td>
                        <td class="{level}">{port["service"]}</td>
                        <td class="{level}">{port["product"]}</td>
                        <td class="{level}">{port["version"]}</td>
                        <td class="{level}">{port["cpe"]}</td>
                        <td class="{level}">{port["score"]}</td>
                    </tr>
                    '''
                    for vuln in port["vulns"]:
                        if vuln["module"] == "vulners":
                            html_data += f'''
                            <tr>
                                <td valign="top" colspan="2" rowspan="{len(vuln["results"])+1}" class="line_1">Vulners</td>
                                <td class="line_1">Name</td>
                                <td class="line_1" colspan="2">Database : ID : IsExploit</td>
                                <td class="line_1">CVSS</td>
                            </tr>
                            '''
                            for result_note in vuln["results"]:
                                if result_note["cvss"] > 0 and result_note["cvss"] < 3:
                                    level = "low_"
                                if result_note["cvss"] > 3 and result_note["cvss"] < 7:
                                    level = "mid_"
                                if result_note["cvss"] > 7:
                                    level = "high_"
                                """if group is not "Other":
                                    ref = "href=https://cve.report/" + group
                                else:
                                    ref = ""
                                print("group:", group, "    len:", len(vuln["results"][group]))
                                print()
                                pprint.pprint(vuln["results"][group], depth=1)"""
                                html_data += f'''
                                <tr>
                                    
                                    <td>{result_note["cve_id"]}</td>
                                    <td class="left" colspan="2">
                                '''
                                for cve_note in result_note["notes"]:
                                    html_data += f'''
                                        <a href="https://vulners.com/{cve_note["type"]}/{cve_note["id"]}">{cve_note["type"]} : {cve_note["id"]} : {cve_note["is_exploit"]}<br></a>
                                    '''
                                html_data += f'''
                                    </td>
                                    <td class="{level}">{result_note["cvss"]}</td>
                                </tr>
                                '''
                        if vuln["module"] == "bruteforcer":
                            html_data += f'''
                            <tr>
                                <td valign="top" colspan="2" rowspan="{len(vuln["results"])+1}" class="line_1">Bruteforcer</td>
                                <td class="line_1">"login:pass"</td>
                                <td class="line_1">Мessage</td>
                                <td class="line_1"></td>
                            </tr>
                            '''
                            for result_note in vuln["results"]:
                                html_data += f'''
                                <tr>
                                    <td>{result_note["login:pass"]}</td>
                                    <td>{result_note["mesg"]}</td>
                                    <td></td>
                                </tr>
                                '''

            f.write(html_data)



