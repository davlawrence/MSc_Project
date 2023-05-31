# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from datetime import datetime

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import addrconv
from ryu.lib.packet import in_proto, ipv4, icmp, tcp, udp, ipv6, mqtt, mqtt2multicast
import struct, socket
import networkx as nx

class SimpleSwitch13(app_manager.RyuApp):
    # OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.packet_inst = 0
        self.last_timestamp = None
        self.interval = 10  # time interval in seconds
        self.main_port_stats = {}  # dictionary to store port statistics

        # Multicast
        self.mac_addr = '00:00:00:00:00:01'
        self.ip_addr  = '10.0.0.1'
        self.idle_timeout = 3600
        self.topicToMulticast = {}
        self.noTopic = {}
        self.multicastTransmittersForTopic = {}
        self.multicastReceiversForTopic = {}
        self.firstMulticastIPAddress = '225.255.255.0'

        self.MULTICAST_ROUTING = False

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    idle_timeout=idle, hard_timeout=hard,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle, hard_timeout=hard,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt_mqtt2multicast = None

        self.packet_inst += 1

        if self.last_timestamp == None:
            self.last_timestamp = ev.timestamp

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        
        ip = pkt.get_protocol(ipv4.ipv4)

        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            # check IP protocol and create a match for IP
            if ip:
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto
                    
                if protocol == in_proto.IPPROTO_ICMP:
                    # target_protocol = pkt.get_protocol(icmp.icmp)
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=srcip,
                        ipv4_dst=dstip,
                        eth_src=src,
                        eth_dst=dst,
                        ip_proto=protocol,
                        in_port=in_port
                    )
                elif protocol == in_proto.IPPROTO_TCP:
                    # t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=srcip,
                        ipv4_dst=dstip,
                        eth_dst=dst,
                        eth_src=src,
                        ip_proto=protocol,
                        in_port=in_port
                    )
                elif protocol == in_proto.IPPROTO_UDP:
                    # u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=srcip,
                        ipv4_dst=dstip,
                        eth_dst=dst,
                        eth_src=src,
                        ip_proto=protocol,
                        in_port=in_port
                    )
            else:
                match = parser.OFPMatch(eth_type=eth.ethertype, eth_src=src, eth_dst=dst)

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle=20, hard=100)
                return
            else:
                self.add_flow(datapath, 1, match, actions, idle=20, hard=100)

        else:
            pass

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


    ###################################################################################
    ### MQTT to MULTICAST related functions
    ###################################################################################
    def _handle_mqtt2multicast(self, datapath, in_port, data, pkt_ethernet, pkt_ipv4, pkt_udp, pkt_mqtt2multicast):

        now = datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')
        self.logger.info("### %s > MQTT2MULTICAST message received! MQTT2MULTICAST packet type: %d", now, pkt_mqtt2multicast.mqtt2multicastPacketType)

        if pkt_mqtt2multicast.mqtt2multicastPacketType == mqtt2multicast.MQTT2MULTICAST_REQUEST:
            # REQUEST received

            # Check if the topic was already included (so it has a corresponding multicast IP address) or it is new (so it requires a new multicast IP address)
            # multicastIPAddress is a string representing the IP address, e.g. '225.0.0.0'
            topic = pkt_mqtt2multicast.mqtt2multicastTopic
            flags = pkt_mqtt2multicast.mqtt2multicastFlags

            if topic.decode() in self.topicToMulticast:
                # Topic already exists
                multicastIPAddress = self.topicToMulticast[topic.decode()]
                self.logger.info("### %s > MQTT2MULTICAST - multicast IP address already assigned to existing topic ('%s'): %s", now, topic.decode(), multicastIPAddress)

            else:
                # New topic
                numberOfTopics = len(self.topicToMulticast)

                multicastIPAddress = self._get_nth_multicast_ip_address(numberOfTopics) # The first multicast IP address has index=0
                self.logger.info("### %s > MQTT2MULTICAST - multicast IP address assigned to new topic ('%s'): %s", now, topic.decode(), multicastIPAddress)
                self.topicToMulticast[topic.decode()] = multicastIPAddress
                self.noTopic[topic.decode()] = numberOfTopics + 1 # Start from 1

            if flags == 0:
                # The sender is going to publish to this multicast IP address
                self.logger.info("### %s > MQTT2MULTICAST - %s will publish to the multicast IP address %s", now, pkt_ipv4.src, multicastIPAddress)
                if topic.decode() in self.multicastTransmittersForTopic:
                    multicastTransmittersForThisTopic = self.multicastTransmittersForTopic[topic.decode()]
                    multicastTransmittersForThisTopic.append(pkt_ipv4.src)
                else:
                    self.multicastTransmittersForTopic[topic.decode()] = [pkt_ipv4.src]
                self.logger.info("### %s > MQTT2MULTICAST - multicast transmitters for topic %s: %s", now, topic.decode(), self.multicastTransmittersForTopic[topic.decode()])

                if self.MULTICAST_ROUTING:
                    self.updateMulticastRoutingTree(topic)

            elif flags == 1:
                # The sender subscribes to this multicast IP address
                self.logger.info("### %s > MQTT2MULTICAST - subscribe %s to the multicast IP address %s", now, pkt_ipv4.src, multicastIPAddress)
                if topic.decode() in self.multicastReceiversForTopic:
                    multicastReceiversForThisTopic = self.multicastReceiversForTopic[topic.decode()]
                    multicastReceiversForThisTopic.append(pkt_ipv4.src)
                else:
                    self.multicastReceiversForTopic[topic.decode()] = [pkt_ipv4.src]
                self.logger.info("### %s > MQTT2MULTICAST - multicast receivers for topic %s: %s", now, topic.decode(), self.multicastReceiversForTopic[topic.decode()])

                if self.MULTICAST_ROUTING:
                    self.updateMulticastRoutingTree(topic)

            elif flags == 2:
                # The sender unsubscribes to this multicast IP address
                self.logger.info("### %s > MQTT2MULTICAST - unsubscribe %s from the multicast IP address %s (topic: %s)", now, pkt_ipv4.src, multicastIPAddress, topic.decode())
                #for topic in self.multicastReceiversForTopic.copy():
                multicastReceiversForThisTopic = self.multicastReceiverForsTopic[topic.decode()]
                multicastReceiversForThisTopic = [x for x in multicastReceiversForThisTopic if not(x == pkt_ipv4.src)] # Removing based on the content of the first element. 
                                                                                                                       # Maybe list comprehension is not the best for performance, but it works...
                self.multicastReceiversForTopic[topic.decode()] = multicastReceiversForThisTopic                       # Required since subscribersList is now a different object
                # If this key has no content, remove it from the dictionary
                if not self.multicastReceiversForTopic[topic.decode()]:
                    del self.multicastReceiversForTopic[topic.decode()]
                    self.logger.info("### %s > MQTT2MULTICAST - no multicast receivers for topic %s", now, topic.decode())
                else:
                    self.logger.info("### %s > MQTT2MULTICAST - multicast receivers for topic %s: %s", now, topic.decode(), self.multicastReceiverForsTopic[topic.decode()])

                if self.MULTICAST_ROUTING:
                    self.updateMulticastRoutingTree(topic)

            # Create a new packet MQTT2MULTICAST REPLY to be sent
            if flags == 0 or flags == 1:
                pkt = packet.Packet()

                    # Add Ethernet header
                pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                                   dst=pkt_ethernet.src,
                                                   src=self.mac_addr))

                    # Add IP header
                pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                           src=self.ip_addr,
                                           proto=pkt_ipv4.proto))

                    # Add UDP header
                pkt.add_protocol(udp.udp(src_port=pkt_udp.dst_port, 
                                         dst_port=pkt_udp.src_port))

                    # Add MQTT2MULTICAST application packet
                pkt.add_protocol(mqtt2multicast.mqtt2multicast(mqtt2multicastPacketType=2,
                                                               mqtt2multicastTransactionID=pkt_mqtt2multicast.mqtt2multicastTransactionID,
                                                               mqtt2multicastFlags=0,
                                                               mqtt2multicastTopicSize=None,
                                                               mqtt2multicastTopic=None,
                                                               mqtt2multicastIPAddress=addrconv.ipv4.text_to_bin(multicastIPAddress)))

                # Send packet
                now = datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')
                self.logger.info("### %s > MQTT2MULTICAST REPLY sent (%s) to %s", now, pkt, pkt_ipv4.src)

                self._send_packet(datapath, in_port, pkt)

            return

    def _send_packet(self, datapath, port, pkt):
        # Send packet
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)

    def _get_nth_multicast_ip_address(self, n):
        # n starts at 0, i.e. the first multicast IP address would be self._get_nth_multicast_ip_address(0)
        (forthByte, thirdByte, secondByte, firstByte) = struct.unpack('BBBB', socket.inet_aton(self.firstMulticastIPAddress))
        #self.logger.info("### multicastIPAddress: %s.%s.%s.%s", forthByte, thirdByte, secondByte, firstByte)

        auxFirstByte = firstByte + n
        auxSecondByte = secondByte + int(auxFirstByte / 256)
        auxThirdByte = thirdByte + int(auxSecondByte / 256)
        auxForthByte = forthByte + int(auxThirdByte / 256)
        auxFirstByte = auxFirstByte % 256
        auxSecondByte = auxSecondByte % 256
        auxThirdByte = auxThirdByte % 256

        # TO BE DONE: We should check if we have too many topics converted to multicast IP addresses.
        # Anyway, if we employ 225.0.0.0-231.0.0.1 (reserved according to https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml), this gives as more than 117 million of topics!
        multicastIPAddress = str(auxForthByte) + '.' + str(auxThirdByte) + '.' + str(auxSecondByte) + '.' + str(auxFirstByte)

        return multicastIPAddress

    ###################################################################################
    ### MULTICAST related functions
    ###################################################################################
    def updateMulticastRoutingTree (self, topic):
        now = datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')

        # Get information for this topic / multicast IP address
        multicastIPAddress = None
        multicastTransmittersForThisTopic = None
        multicastReceiversForThisTopic = None

        if topic.decode() in self.topicToMulticast:
            multicastIPAddress = self.topicToMulticast[topic.decode()]
        if topic.decode() in self.multicastTransmittersForTopic:
            multicastTransmittersForThisTopic = self.multicastTransmittersForTopic[topic.decode()]
        if topic.decode() in self.multicastReceiversForTopic:
            multicastReceiversForThisTopic = self.multicastReceiversForTopic[topic.decode()]

        # If there are transmitters and receivers, let us update the multicast routing tree (using shortest paths from sources=transmitters to destinations=receivers)
        if (multicastIPAddress and multicastTransmittersForThisTopic and multicastReceiversForThisTopic):
            self.logger.info("### %s > MQTT2MULTICAST - update multicast routing tree", now)
            self.logger.info("##### Multicast IP address: %s", multicastIPAddress)
            self.logger.info("##### Multicast transmitters: %s", multicastTransmittersForThisTopic)
            self.logger.info("##### Multicast receivers: %s", multicastReceiversForThisTopic)

            # Get shortest paths (from transmitters to receivers)
            shortestPathsList = []
            for transmitter in multicastTransmittersForThisTopic:
                for receiver in multicastReceiversForThisTopic:
                    transmitterMac = None
                    receiverMac = None

                    if transmitter in self.arpCache: 
                        transmitterMac = self.arpCache[transmitter]
                    if receiver in self.arpCache:
                        receiverMac = self.arpCache[receiver]

                    if transmitterMac and receiverMac:
                        shortestPath = nx.shortest_path(self.net, transmitterMac, receiverMac)
                        self.logger.info("####### Multicast path (IP address: %s) between %s and %s: %s", multicastIPAddress, transmitter, receiver, shortestPath)
                        shortestPathsList.append(shortestPath)
            self.logger.info("######### All multicast paths (IP address: %s): %s", multicastIPAddress, shortestPathsList)

            # Update group tables for multicasting this specific IP address associated to this specific topic
            noTopic = self.noTopic[topic.decode()] # noTopic will be used as groupTableID

                # portsForEachSwitch is a dictionary of dictionaries. Each dictionary element represents the links to be included per switch, which are also stored in a dictionary.
                # This way we avoid repeated links (dictionaries do not allow repeated elements).
            portsForEachSwitch = {}
            for path in shortestPathsList:
                for on_path_switch in range(1, len(path)-1):
                    current_switch = path[on_path_switch]
                    portsForEachSwitch[current_switch] = {}

                # Fill portsForEachSwitch. Add all the ports in each switch that will forward a multicast packet for this packet.
            for path in shortestPathsList:
                for on_path_switch in range(1, len(path)-1):
                    current_switch = path[on_path_switch]
                    next_switch = path[on_path_switch+1]
                    next_port = self.net[current_switch][next_switch]['port']
                    portsForEachSwitch[current_switch][next_port] = 1

            for switch in portsForEachSwitch:
                # Make a list of ports in each switch, so we can create/update the corresponding group table in the switch.
                portList = []
                for port in portsForEachSwitch[switch]:
                    self.logger.info("### Multicast tree for IP address %s (groupTableID %d), add switch %s port %s", multicastIPAddress, noTopic, switch, port)
                    portList.append(port)

                # Create/update a group table entry and add a flow table entry pointing to that group table entry
                groupTableID = noTopic
                self.logger.info("### Multicast tree for IP address %s (groupTableID %d), switch %s with ports %s", multicastIPAddress, noTopic, switch, portList)

                datapath = self.switchMap[switch]
                parser = datapath.ofproto_parser
                priority = 100
                match = parser.OFPMatch(eth_type=0x800, ipv4_dst=multicastIPAddress)
                self.send_group_mod(datapath, portList, groupTableID)
                actions = [parser.OFPActionGroup(group_id=groupTableID)]
                self.add_flow(datapath, priority, match, actions, None, self.idle_timeout)

        else:
            self.logger.info("### %s > MQTT2MULTICAST - multicast routing tree not updated, some information missing!!!")
            if multicastIPAddress:
                self.logger.info("##### Multicast IP address: %s", multicastIPAddress)
            else:
                self.logger.info("##### No multicast IP address!!!")
            if multicastTransmittersForThisTopic:
                self.logger.info("##### Multicast transmitters: %s", multicastTransmittersForThisTopic)
            else:
                self.logger.info("##### No multicast transmitters!!!")
            if multicastReceiversForThisTopic:
                self.logger.info("##### Multicast receivers: %s", multicastReceiversForThisTopic)
            else:
                self.logger.info("##### No multicast receivers!!!")         
