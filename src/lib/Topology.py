from random import choice, randint

from mininet.topo import Topo
from mininet.node import OVSKernelSwitch

def generate_mac_address(digit):
    if digit >= 1 and digit < 10:
        return "00:00:00:00:00:0{}".format(digit)
    elif digit >= 10 and digit < 100:
        return "00:00:00:00:00:{}".format(digit)
    elif digit >= 100 and digit <= 251:
        stringified_digit = str(digit)
        return "00:00:00:00:0{}:{}{}".format(stringified_digit[0], stringified_digit[1], stringified_digit[2])
    else:
        raise ValueError("The range of allow number is between 1 and 251")
    

class ApplicationTopology(Topo):

    switch_details = None
    host_details = None
    ip_collections = None

    default_switch_initial = "S"
    default_host_initial = "H"

    default_controller = {
        "name": "app_controller",
        "type": "default",
        "ip": "127.0.0.1",
        "protocol": "tcp",
        "port": 6633
    }

    default_switches = {
        "count" : 1,
        "names": ["Switch-1"],
        "abbrv": "S",
    }

    default_hosts = {
        "count" : 2,
        "names": ["Host-1", "Host-2"],
        "abbrv": "H",
    }

    default_config = {

    }

    params = {
        "controller": None,
        "switches": None,
        "hosts": None,
        "config": None
    }
    
    def __init__(self, controller, switches, hosts, config, **opts):
        Topo.__init__(self, **opts)
        
        self.switch_intances = list()
        self.host_intances = list()
        self.ip_collections = list()
        self.iot_cameras = list()
        self.iot_watches = list()


        if (isinstance(controller, dict) and "name" in list(controller.keys())):
            self.params["controller"] = controller
        else:
            self.params["controller"] = None

        if (isinstance(switches, dict) and "count" in list(switches.keys())):   
            self.params["switches"] = switches
        else:
            self.params["switches"] = None

        if (isinstance(hosts, dict) and "count" in list(hosts.keys())):
            self.params["hosts"] = hosts
        else:
            self.params["hosts"] = None
        
        if isinstance(config, dict):
            self.params["config"] = config
        else:
            self.params["config"] = self.default_config

        self.configuration_nodes()


    def configuration_nodes(self):
        if not self.can_configure_hosts_switches():
            raise Exception("Hosts and Switches configuration parameters are not defined accurately!!!")
        
        switch_counter = self.params["switches"]["count"]
        host_counter = self.params["hosts"]["count"]
        num_of_hosts_per_switch = host_counter if switch_counter == 1 else int(host_counter / (switch_counter-1))
        num_of_hosts_for_last_switch = host_counter if switch_counter == 1 else int(host_counter % (switch_counter-1))

        for i in range(switch_counter):
            switch_name = self.get_switch_name(i)
            switch_node = self.addSwitch(switch_name, cls=OVSKernelSwitch, protocol="OpenFlow13")
            self.switch_intances.append(switch_node)
            base_host_counter = i * num_of_hosts_for_last_switch if switch_counter == 1 else i * num_of_hosts_per_switch

            if i == (switch_counter - 1):
                for k in range(num_of_hosts_for_last_switch):
                    host_index = k + base_host_counter
                    host_name = self.get_host_name(host_index)
                    host_ip = "10.0.0.{}/24".format((host_index + 1))
                    host_mac = generate_mac_address((host_index + 1))
                    self.ip_collections.append(host_ip)
                    host_node = self.addHost(host_name, cpu=1/20, mac=host_mac, ip=host_ip, device_type="regular", generic_name="")
                    self.host_intances.append(host_node)

                    # Connect host to switch
                    self.addLink(host_node, switch_node)
            else:
                for j in range(num_of_hosts_per_switch):
                    if ((i == 1) and (j == 2 or j == 3)) or ((i == 3) and (j == 4)) or ((i == 4) and (j == 1 or j == 3)):
                        host_index = j + base_host_counter

                        if ((i == 1) and (j == 2 or j == 3)):
                            device_name, generic_name = self.get_iot_host_name_for_switch_one(j)

                        if ((i == 3) and (j == 4)):
                            device_name, generic_name = self.get_iot_host_name_for_switch_three(j)

                        if ((i == 4) and (j == 1 or j == 3)):
                            device_name, generic_name = self.get_iot_host_name_for_switch_four(j)

                        host_ip = "10.0.0.{}/24".format((host_index + 1))
                        host_mac = generate_mac_address((host_index + 1))
                        self.ip_collections.append(host_ip)
                        host_node = self.addHost(device_name, cpu=1/20, mac=host_mac, ip=host_ip, device_type="iot", generic_name=generic_name)
                        self.host_intances.append(host_node)
                    else:
                        host_index = j + base_host_counter
                        host_name = self.get_host_name(host_index)
                        host_ip = "10.0.0.{}/24".format((host_index + 1))
                        host_mac = generate_mac_address((host_index + 1))
                        self.ip_collections.append(host_ip)
                        host_node = self.addHost(host_name, cpu=1/20, mac=host_mac, ip=host_ip, device_type="regular", generic_name="")
                        self.host_intances.append(host_node)

                    # Connect host to switch
                    self.addLink(host_node, switch_node)

        
        # Connect host to switch
        self.addLink(host_node, self.switch_intances[len(self.switch_intances)-1])

        
        if len(self.switch_intances) > 1:
            for i in range(1, len(self.switch_intances)):
                self.addLink(self.switch_intances[i-1], self.switch_intances[i])



        
    def can_configure_hosts_switches(self):
        valid_switch_params = False
        valid_host_params = False

        if (isinstance(self.params["switches"], dict) and "count" in list(self.params["switches"].keys())):   
            valid_switch_params = True
        else:
            valid_switch_params = False

        if (isinstance(self.params["hosts"], dict) and "count" in list(self.params["hosts"].keys())):   
            valid_host_params = True
        else:
            valid_host_params = False

        return True if valid_switch_params and valid_host_params else False
    
    
    def get_switch_name(self, switch_index):
        names = self.params["switches"]["names"] if len(self.params["switches"]["names"]) > 0 else list()
        name = None
        if switch_index < len(names):
            name = self.params["switches"]["names"][switch_index]
        else:
            name = "{}{}".format(self.default_switch_initial, (switch_index + 1))
            self.params["switches"]["names"].append(name)
        return name
    
    def get_iot_host_name_for_switch_one(self, device_index):
        device_name = generic_name = ""

        if device_index == 2:
            device_name, generic_name = self.create_camera_object()
        elif device_index == 3:
            device_name, generic_name = self.create_watch_object()

        return device_name, generic_name

    def get_iot_host_name_for_switch_three(self, device_index):
        device_name = generic_name = ""
        
        device_name, generic_name = self.create_camera_object()

        return device_name, generic_name

    def get_iot_host_name_for_switch_four(self, device_index):
        device_name = generic_name = ""

        if device_index == 1:
            device_name, generic_name = self.create_camera_object()
        elif device_index == 3:
            device_name, generic_name = self.create_watch_object()

        return device_name, generic_name
    
    def create_camera_object(self):
        camera_count = len(self.iot_cameras)
        camera_name = "C{}".format(camera_count + 1)
        self.iot_cameras.append(camera_name)
        self.params["hosts"]["names"].append(camera_name)
        return camera_name, "Camera"

    def create_watch_object(self):
        watch_count = len(self.iot_watches)
        watch_name = "W{}".format(watch_count + 1)
        self.iot_watches.append(watch_name)
        self.params["hosts"]["names"].append(watch_name)
        return watch_name, "Watch"

    

    def get_host_name(self, host_index):
        names = self.params["hosts"]["names"] if len(self.params["hosts"]["names"]) > 0 else list()
        name = None
        if host_index < len(names):
            name = self.params["hosts"]["names"][host_index]
        else:
            name = "{}{}".format(self.default_host_initial, (host_index + 1))
            self.params["hosts"]["names"].append(name)
        return name
    


    def select_ip_address(self):
        return choice(self.ip_collections)
