import sys

sys.path.append("../lib")

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.node import Controller
from mininet.util import dumpNetConnections
from mininet.log import setLogLevel

from lib.Topology import ApplicationTopology
from lib.application_parameters import controller as controller_params, switches as switches_params, hosts as hosts_params, config as config_params
from lib.helpers import retrieve_ip_address_from_cidr_ip

def test_network_topology():

    hosts = list()

    app_topology = ApplicationTopology(controller_params, switches_params, hosts_params, config_params)
    controller = RemoteController("C0", ip="127.0.0.1")
    net = Mininet(topo=app_topology, controller=controller, link=TCLink)
    # net = Mininet(app_topology, controller=Controller)

    net.start()

    for host_name in app_topology.params["hosts"]["names"]:
        hosts.append(net.get(host_name))

    target_host_index = len(hosts) -1

    web_server = hosts[target_host_index]
    web_server_ip = retrieve_ip_address_from_cidr_ip(web_server.params["ip"])
    web_server_mac = web_server.params["mac"]
    web_server_name = web_server.name

    web_server.cmd("cd /home/mininet/webserver")
    web_server.cmd("python -m SimpleHTTPServer 80 &")


    print("""

        Configured Web Server Net Info:
        ===============================
        Host Name    :  {}
        MAC Address  :  {}
        IP Address   :  {}

        
    """.format(web_server_ip, web_server_mac, web_server_name))

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel("info")
    test_network_topology()