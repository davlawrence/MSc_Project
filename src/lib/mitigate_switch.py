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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import in_proto, ipv4, icmp, tcp, udp, ipv6, arp

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.should_mitigate = False
        self.flow_ref = 0
        self.mac_to_port = {}
        self.arp_ip_to_port = {}
        self.packet_inst = 0
        self.last_timestamp = None
        self.interval = 10  # time interval in seconds
        self.main_port_stats = {}  # dictionary to store port statistics

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        flow_ref = self.generate_flow_ref()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, flow_ref)

    def add_flow(self, datapath, priority, match, actions, flow_ref, buffer_id=None, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    idle_timeout=idle, hard_timeout=hard,
                                    priority=priority, match=match,
                                    instructions=inst, cookie=flow_ref)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle, hard_timeout=hard,
                                    match=match, instructions=inst, 
                                    cookie=flow_ref)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

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
        self.arp_ip_to_port.setdefault(dpid, {})
        self.arp_ip_to_port[dpid].setdefault(in_port, [])

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # if ARP request, log the IP and MAC address from that port
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)

            if arp_pkt.opcode == arp.ARP_REPLY or arp_pkt.opcode == arp.ARP_REQUEST:
                if not arp_pkt.src_ip in self.arp_ip_to_port[dpid][in_port]:
                    self.arp_ip_to_port[dpid][in_port].append(arp_pkt.src_ip)

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

                if self.should_mitigate:
                    if not (srcip in self.arp_ip_to_port[dpid][in_port]):
                        self.mitigate_attack(datapath, in_port)
                        return
                
            else:
                match = parser.OFPMatch(eth_type=eth.ethertype, eth_src=src, eth_dst=dst)


            flow_ref = self.generate_flow_ref()
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, flow_ref, msg.buffer_id, idle=20, hard=100)
                return
            else:
                self.add_flow(datapath, 1, match, actions, flow_ref, idle=20, hard=100)
        else:
            pass

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
            
    def mitigate_attack(self, datapath, in_port):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port)
        actions = []
        flow_ref = self.generate_flow_ref()
        self.add_flow(datapath, 100, match, actions, flow_ref, hard=120)
        self.should_mitigate = False


    def generate_flow_ref(self):
        self.flow_ref += 1
        return self.flow_ref