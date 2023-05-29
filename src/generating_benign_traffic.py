import os

from datetime import datetime
from time import sleep
from random import choice, randint

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.node import Controller
from mininet.link import TCLink
from mininet.log import setLogLevel

from lib.Topology import ApplicationTopology
from lib.application_parameters import controller as controller_params, switches as switches_params, hosts as hosts_params, config as config_params
from lib.helpers import draw_horizontal_line, retrieve_ip_address_from_cidr_ip, retrieve_host_number_from_cidr_ip

def run_benign_traffic():
    hosts = list()
    app_topology = ApplicationTopology(controller_params, switches_params, hosts_params, config_params)
    controller = RemoteController("C0", ip="127.0.0.1")
    net = Mininet(topo=app_topology, controller=controller, link=TCLink)
    # net = Mininet(app_topology, controller=Controller)

    net.start()

    # print(dir(app_topology))

    for host_name in app_topology.params["hosts"]["names"]:
        hosts.append(net.get(host_name))

    # print("\n\n")
    # print("Host Count is {}".format(len(hosts)))
    # print("\n\n")

    base_host_index = 0

    host_1 = hosts[base_host_index]
    host_1_ip = retrieve_ip_address_from_cidr_ip(host_1.params["ip"])
    host_1_mac = host_1.params["mac"]
    host_1_name = host_1.name

    print("\n\n")
    print(draw_horizontal_line())
    print("\nGENERATING BENIGN TRAFFIC ...")

    host_1.cmd("cd /home/mininet/webserver")
    host_1.cmd("python -m SimpleHTTPServer 80 &")
    host_1.cmd("iperf -s -p 5050 &")
    host_1.cmd("iperf -s -u -p 5051 &")

    scapy_dir = "scapy/"
    scripts_dir = "scripts"
    base_dir = os.getcwd()
    scapy_directory_path = os.path.join(base_dir, scapy_dir)
    scripts_directory_path = os.path.join(base_dir, scripts_dir)

    host_251 = net.get("H251")
    host_251_ip = retrieve_ip_address_from_cidr_ip(host_251.params["ip"])
    host_251_mac = host_251.params["mac"]
    host_251_name = host_251.name
    host_251.cmd("cd {}; ./mqtt_proxy_m2m.sh &".format(scapy_directory_path))
    host_251.cmd("cd {}; ./mqtt_proxy_as_broker.sh &".format(scapy_directory_path))

    for host in hosts:
        host.cmd("cd /home/mininet/Downloads")

    for i in range(100):
        print("\n")
        print(draw_horizontal_line())
        print("# of Iteration {} ...".format((i+1)))
        print(draw_horizontal_line())
        print("\n")

        for j in range(100):
            source_host = choice(hosts)
            source_host_name = source_host.name
            destination_host = app_topology.select_ip_address()
            dest_ip_address = retrieve_ip_address_from_cidr_ip(destination_host)
            dst_host_name = "{}{}".format(app_topology.default_host_initial, retrieve_host_number_from_cidr_ip(destination_host).split(".")[-1])

            if source_host.params["device_type"] == "iot":
                print("Generating MQTT Subscribe traffic between {} and {}".format(source_host_name, host_251_name))
                source_host.cmd("{}/start_mqtt_subscriber.sh {} &".format(scripts_directory_path, host_251_ip))
                print("Generating MQTT Publish traffic between {} and {}".format(source_host_name, host_251_name))
                source_host.cmd("{}/start_mqtt_publisher.sh {} &".format(scripts_directory_path, host_251_ip))
                # source_host.cmd("{}/start_mqtt_subscriber.sh {} &".format(scripts_directory_path, host_1_ip))
                # source_host.cmd("{}/start_mqtt_subscriber.sh {} &".format(scripts_directory_path, host_1_ip))
                print("\n\n")
            else:
                print("Generating ICMP traffic between {} and {}".format(source_host_name, dst_host_name))
                source_host.cmd("ping {} -c 100 &".format(dest_ip_address))
                print("Generating TCP traffic between {} and {}".format(source_host_name, host_1_name))
                source_host.cmd("iperf -c {}".format(host_1_ip))
                print("Generating UDP traffic between {} and {}".format(source_host_name, host_1_name))
                source_host.cmd("iperf -u -c {}".format(host_1_ip))
                print("{} is downloading index.html from {}".format(source_host_name, host_1_name))
                source_host.cmd("wget http://{}/index.html".format(host_1_ip))
                print("{} is downloading test.zip from {}".format(source_host_name, host_1_name))
                source_host.cmd("wget http://{}/test.zip".format(host_1_ip))
                print("\n\n")

        host.cmd("rm -f *.* /home/mininet/Downloads")

    print(draw_horizontal_line())
    net.stop()

if __name__ == '__main__':
    start_time = datetime.now()
    setLogLevel("info")
    run_benign_traffic()
    stop_time = datetime.now()

    print("\n\n")
    print("Time taken to generate Benign Traffic generation is {}".format(stop_time - start_time))
    print("\n\n")