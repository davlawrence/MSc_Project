import os
from io import StringIO
from datetime import datetime
from operator import attrgetter

import joblib

import pandas as pd
import numpy as np
import csv
from sklearn.preprocessing import StandardScaler

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import in_proto
from ryu.lib.packet import ether_types
from ryu.lib.packet import mqtt

from lib.mitigate_switch import SimpleSwitch13
from lib.helpers import draw_horizontal_line, create_directory, clear_file, write_to_existing_file, create_directory, write_to_new_file
from lib.application_parameters import report_filename, delay, data_directory, bytes_filename, packets_filename, src_ip_filename, dst_ip_filename, netflow_filename, live_filename, agg_live_filename


def compute_dataset_parameters(packets_file_path, bytes_file_path, srcip_file_path, dstip_file_path, netflow_path):
    ssip = sdfp = sdfb = sfe =rfip = 0

    # Standard deviation of packets (SDFP)
    # SDFP = sqrt((1/n) * sum((packets_i - mean_packets,2) ** 2))
    # packets_i = number of packets of flow ith in T period
    # mean_packets: mean of total packets of all flows in T period

    try:
        if not (os.stat(packets_file_path).st_size == 0):
            packets_csv = np.genfromtxt(packets_file_path, delimiter=",")
            dt_packets = packets_csv[:,0]
            sdfp = np.std(dt_packets) 
    except:
        pass 

    # Standard deviation of bytes (SDFB)
    # SDFB = sqrt((1/n) * sum((bytes_i - mean_bytes,2) ** 2))
    # bytes_i: number of total bytes of flow ith in T period
    # mean_bytes: mean of total bytes of all flows in T period
    
    try:
        if not (os.stat(bytes_file_path).st_size == 0):
            bytes_csv = np.genfromtxt(bytes_file_path, delimiter=",")
            dt_bytes = bytes_csv[:,0]
            sdfb = np.std(dt_bytes)
    except:
        pass

    # Number of source IPs
    # Speed of source IP (SSIP), number of source IPs per unit of time
    # SSIP = Number of different IP sources / T period
    
    try:
        n_ip = np.prod(dt_bytes.shape)      # Get number of different source IPs
        ssip = n_ip // delay # Get number of IPs for every second by multiple interval - 3s
    except:
        pass

    # Number of Flow entries
    # Speed of Flow entries (SFE), number of flow entries to the switch per unit of time
    # SFE = Number of flow entries / T period
    
    try:
        sfe = n_ip // delay
    except:
        pass

    # Number of interactive flow entries
    # Ratio of Pair-Flow Entries (RFIP)
    # RFIP = Interactive flow entries / total number of flows in T period
    fileone = None
    filetwo = None

    with open(srcip_file_path, 'r') as t1, open(dstip_file_path, 'r') as t2:
        fileone = t1.readlines()
        filetwo = t2.readlines()

    # Check if the src_ip exists in the dst_ip,
    # which indicates that source IP has two-way interaction with the destination IP. 
    # If not, append that one-way interaction IP into interactive flow file (intflow.csv)
    with open(netflow_path,'w') as f:
        for line in fileone:
            if line not in filetwo:
                f.write(line)

    # Count number of 
    with open(netflow_path) as f:
        reader = csv.reader(f, delimiter=",")
        dt = list(reader)
        row_count_nonint = len(dt)# Count number of 

    
    try:
        rfip = abs(float(n_ip - row_count_nonint) / n_ip)
    except:
        pass

    return ssip, sdfp, sdfb, sfe, rfip


class MonitorNetwork(SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(MonitorNetwork, self).__init__(*args, **kwargs)
        self.save_model_directory = "build"
        self.trained_model = None
        self.agg_trained_model = None
        self.load_trained_model()
        self.load_agg_trained_model()

        self.data_record_head = "timestamp,switch,src_ip,dst_ip,packet_count,byte_count,duration_sec,duration_nsec,total_dur,flows,packet_inst,packet_per_flow,byte_per_flow,pktrate,pair_flow,protocol,port_no,tx_bytes,rx_bytes,tx_kbps,rx_kbps,total_kbps"
        self.agg_data_record_head = "ssip,sdfp,sdfb,sfe,rfip"

        create_directory(data_directory)

        self.live_file_path = os.path.join(data_directory, live_filename)
        write_to_new_file(self.live_file_path, self.data_record_head)

        self.agg_live_file_path = os.path.join(data_directory, agg_live_filename)
        write_to_new_file(self.live_file_path, self.agg_live_file_path)

        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        self.flow_stats = []
        self.port_stats = []
        self.possible_victims = []

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):

        body = ev.msg.body
        dpid = ev.msg.datapath.id

        #
        # Aggregate Params
        #
        bytes_file_path = os.path.join(data_directory, bytes_filename)
        packets_file_path = os.path.join(data_directory, packets_filename)
        srcip_file_path = os.path.join(data_directory, src_ip_filename)
        dstip_file_path = os.path.join(data_directory, dst_ip_filename)
        netflow_path = os.path.join(data_directory, netflow_filename)

        clear_file(bytes_file_path, "")
        clear_file(packets_file_path, "")
        clear_file(srcip_file_path, "")
        clear_file(dstip_file_path, "")

        write_to_new_file(self.live_file_path, self.data_record_head)
        write_to_new_file(self.agg_live_file_path, self.agg_data_record_head)

        agg_flow_count = len(body)

        agg_flow_iter_counter = -1

        self.possible_victims = []

        # 
        # Dataset Creation Params
        #

        current_datetime = datetime.now()
        timestamp = int(current_datetime.timestamp())

        stats = {}
        dst= []
        src=[]
        packet_count=[]
        byte_count=[]

        pktrate = 0
        packet_inst = 0

        if self.last_timestamp is None:
            self.last_timestamp = ev.timestamp
        else:
            time_interval = ev.timestamp - self.last_timestamp
            packet_inst = self.packet_inst
            pktrate = self.packet_inst / time_interval
            self.last_timestamp = ev.timestamp
            self.packet_inst = 0

        flow_dict = {}
        pair_flow_count = 0

        

        for stat in sorted(
            [flow for flow in body if (flow.priority == 1)], key=lambda flow: (flow.match["eth_type"])
        ):
            agg_flow_iter_counter += 1

            if stat.match["eth_type"] == ether_types.ETH_TYPE_IP:
                dst_ip = stat.match['ipv4_dst']
                src_ip = stat.match['ipv4_src']
                pkt_cnt = stat.packet_count
                byte_cnt = stat.byte_count

                # 
                # Aggregate Data Code
                #
                write_to_existing_file(packets_file_path, "{},".format(str(pkt_cnt)))
                write_to_existing_file(bytes_file_path, "{},".format(str(byte_cnt)))
                write_to_existing_file(srcip_file_path, "{},".format(str(src_ip)))
                write_to_existing_file(dstip_file_path, "{},".format(str(dst_ip)))

                # 
                # Dataset Creation Code
                #
                if src_ip and dst_ip:
                    flow_key = (src_ip, dst_ip)
                    if flow_key in flow_dict:
                        flow_dict[flow_key] += 1
                    else:
                        flow_dict[flow_key] = 1

                dst.append(dst_ip)
                src.append(src_ip)

                packet_count.append(pkt_cnt) 
                byte_count.append(byte_cnt)

                key = (ev.msg.datapath.id, stat.match['in_port'],
                   src_ip, dst_ip,
                   stat.match['ip_proto'], stat.instructions[0].actions[0].port)

                if key not in stats:
                    stats[key] = []
                    stats[key].append(stat)


            if agg_flow_iter_counter == (agg_flow_count-2):
                try:
                    ssip, sdfp, sdfb, sfe, rfip = compute_dataset_parameters(packets_file_path, bytes_file_path, srcip_file_path, dstip_file_path, netflow_path)

                    agg_data_record = self.stringify_aggregated_data_record(ssip, sdfp, sdfb, sfe, rfip)
                    write_to_existing_file(self.agg_live_file_path, agg_data_record)
                    pv = "H{}".format(dst_ip.split(".")[-1])
                    self.possible_victims.append(pv)
                except:
                    pass


        df = pd.DataFrame(list(zip(dst, src, packet_count, byte_count)), columns=["src", "dst", "packet_count", "byte_count"])
        unique_ips = set(df["src"]).union(set(df["dst"]))
        flow_count = len(unique_ips)
        total_pkt_count = df['packet_count'].sum()
        total_byte_count = df['byte_count'].sum()

        for key, value in flow_dict.items():
            if value > 0:
                pair_flow_count += 1

        for key in stats.keys():
            src_ip = dst_ip = ""
            switch = packet_count = byte_count = duration_sec = duration_nsec = protocol = port_no = 0

            for stat in stats[key]:
                switch = stat.match['in_port']
                src_ip = stat.match['ipv4_src']
                dst_ip = stat.match['ipv4_dst']
                packet_count = stat.packet_count
                byte_count = stat.byte_count
                duration_sec = stat.duration_sec
                duration_nsec = stat.duration_nsec
                protocol = stat.match["ip_proto"]
                port_no = stat.instructions[0].actions[0].port
            
            data_record = {
                "dpid": dpid,
                "timestamp": timestamp,
                "switch": switch,
                "src_ip": src_ip, 
                "dst_ip": dst_ip,
                "packet_count": packet_count,
                "byte_count": byte_count,
                "duration_sec": duration_sec,
                "duration_nsec": duration_nsec,
                "total_dur": self.process_total_duration(duration_sec, duration_nsec),
                "flows": flow_count,
                "packet_inst": packet_inst,
                "packet_per_flow": total_pkt_count/packet_count if packet_count != 0 else 0,
                "byte_per_flow": total_byte_count/byte_count if byte_count != 0 else 0,
                "packet_rate": pktrate,
                "pair_flow": pair_flow_count,
                "protocol": protocol,
                "port_no": port_no,
                "tx_bytes": None,
                "rx_bytes": None,
                "tx_kbps": None,
                "rx_kbps": None,
                "total_kbps": None
            }

            self.flow_stats.append(data_record)
            
            

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):

        body = ev.msg.body
        port_stats = []
        dpid = ev.msg.datapath.id

        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            rx_bytes = stat.rx_bytes
            tx_bytes = stat.tx_bytes
            rx_kbps = 0
            tx_kbps = 0

            self.main_port_stats.setdefault(dpid, {})

            # calculate the reception rate in kbps
            if port_no in self.main_port_stats[dpid]:
                # get the previous statistics
                prev_rx_bytes = self.main_port_stats[dpid][port_no]['rx_bytes']
                prev_tx_bytes = self.main_port_stats[dpid][port_no]['tx_bytes']
                prev_timestamp = self.main_port_stats[dpid][port_no]['timestamp']
                
                
                # calculate the rate in kbps
                delta_rx_bytes = rx_bytes - prev_rx_bytes
                delta_tx_bytes = tx_bytes - prev_tx_bytes
                delta_time = ev.timestamp - prev_timestamp
                rx_kbps = int(delta_rx_bytes * 8 / delta_time / 1000)
                tx_kbps = int(delta_tx_bytes * 8 / delta_time / 1000)
                
                # store the current statistics
                self.main_port_stats[dpid][port_no]['rx_bytes'] = rx_bytes
                self.main_port_stats[dpid][port_no]['tx_bytes'] = tx_bytes
                self.main_port_stats[dpid][port_no]['timestamp'] = ev.timestamp
                

                if not rx_kbps:
                    rx_kbps = 0
                
                if not tx_kbps:
                    tx_kbps = 0
            else:
                # initialize the statistics for the port
                self.main_port_stats[dpid][port_no] = {'rx_bytes': rx_bytes, 'tx_bytes': tx_bytes, 'timestamp': ev.timestamp}

            stat_item = {
                "dpid": dpid,
                "port_no": stat.port_no,
                "tx_bytes": stat.tx_bytes,
                "rx_bytes": stat.rx_bytes,
                "tx_kbps": tx_kbps,
                "rx_kbps": rx_kbps,
                "total_kbps": rx_kbps + tx_kbps,
                "rx_packets": stat.rx_packets,
                "tx_packets": stat.tx_packets,
                "rx_errors": stat.rx_errors,
                "tx_errors": stat.tx_errors
            }

            port_stats.append(stat_item)


        if len(self.flow_stats) > 0 and len(port_stats) > 0:
            for flow in self.flow_stats:
                for port in port_stats:
                    if flow["dpid"] == port["dpid"] and flow["port_no"] == port["port_no"]:
                        flow["tx_bytes"] = port["tx_bytes"]
                        flow["rx_bytes"] = port["rx_bytes"]
                        flow["tx_kbps"] =  port["tx_kbps"]
                        flow["rx_kbps"] =  port["rx_kbps"]
                        flow["total_kbps"] = port["total_kbps"]

        write_to_new_file(self.live_file_path, self.data_record_head)

        for flow in self.flow_stats: 
            timestamp, switch, src_ip, dst_ip, packet_count, byte_count, duration_sec, duration_nsec, total_dur, flows, packet_inst, packet_per_flow, byte_per_flow, packet_rate, pair_flow, protocol, port_no, tx_bytes, rx_bytes, tx_kbps, rx_kbps, total_kbps = self.validate_flow_record(flow)
            data_record = self.stringify_data_record(timestamp, switch, src_ip, dst_ip, packet_count, byte_count, duration_sec, duration_nsec, total_dur, flows, packet_inst, packet_per_flow, byte_per_flow, packet_rate, pair_flow, protocol, port_no, tx_bytes, rx_bytes, tx_kbps, rx_kbps, total_kbps)
            write_to_existing_file(self.live_file_path, data_record)

        if self.can_make_prediction():
            X = self.get_preprocessed_dataframe_for_analysis(self.live_file_path)
            agg_X = self.get_preprocessed_agg_dataframe_for_analysis(self.agg_live_file_path)

            preds = self.trained_model.predict(X)

            agg_preds = np.array([])
            if not (agg_X.size == 0):
                agg_preds = self.agg_trained_model.predict(agg_X)
           

            if len(agg_preds) > 0:
                self.make_prediction(agg_preds[0], None, self.possible_victims[len(self.possible_victims) - 1])     
            else: 
                self.show_notification("Legitimate network activity detected ...")


        self.flow_stats = []
        port_stats = []

    def can_make_prediction(self):
        with open(self.live_file_path, "r") as file:
            for count, line in enumerate(file):
                pass
        return True if (count+1) > 1 else False

    def validate_flow_record(self, flow):
        if None in flow.values():
            self.replacer(flow)

        return flow["timestamp"], flow["switch"], flow["src_ip"], flow["dst_ip"], flow["packet_count"], flow["byte_count"], flow["duration_sec"], flow["duration_nsec"], flow["total_dur"], flow["flows"], flow["packet_inst"], flow["packet_per_flow"], flow["byte_per_flow"], flow["packet_rate"], flow["pair_flow"], flow["protocol"], flow["port_no"], flow["tx_bytes"], flow["rx_bytes"], flow["tx_kbps"], flow["rx_kbps"], flow["total_kbps"]

    def replacer(self, data):
        for k, v in data.items():
            if isinstance(v, dict):
                self.replacer(v)

            elif v is None:
                data[k] = 0


    def process_total_duration(self, duration_sec, duration_nsec):
        return "{}{}".format(duration_sec, duration_nsec)
                
    
    def stringify_data_record(self, timestamp, switch, src_ip, dst_ip, packet_count, byte_count, duration_sec, duration_nsec, total_dur, flows, packet_inst, packet_per_flow, byte_per_flow, pktrate, pair_flow, protocol, port_no, tx_bytes, rx_bytes, tx_kbps, rx_kbps, total_kbps):
        return "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}".format(
            timestamp, switch, src_ip, dst_ip, packet_count, byte_count, duration_sec, duration_nsec, total_dur, flows, packet_inst, packet_per_flow, byte_per_flow, pktrate, pair_flow, protocol, port_no, tx_bytes, rx_bytes, tx_kbps, rx_kbps, total_kbps
        )

    def stringify_aggregated_data_record(self, ssip, sdfp, sdfb, sfe, rfip):
        return "{},{},{},{},{}".format(ssip, sdfp, sdfb, sfe, rfip)


    def get_model_directory(self, model_name):
        model_dir = os.path.join(os.getcwd(), self.save_model_directory)
        return os.path.join(model_dir, model_name)

    
    def load_trained_model(self, target_model=None):
        svm_directory = "svm"
        rfc_directory = "rfc"
        lrc_directory = "lrc"
        knn_directory = "knn"
        ffnn_directory = "ffnn"
        saved_model_path = None

        if target_model == svm_directory:
            save_dir = self.get_model_directory(svm_directory)
            saved_model_path = os.path.join(save_dir, "model")
        elif target_model == rfc_directory:
            save_dir = self.get_model_directory(rfc_directory)
            saved_model_path = os.path.join(save_dir, "model")
        elif target_model == knn_directory:
            save_dir = self.get_model_directory(knn_directory)
            saved_model_path = os.path.join(save_dir, "model")
        elif target_model == lrc_directory:
            save_dir = self.get_model_directory(lrc_directory)
            saved_model_path = os.path.join(save_dir, "model")
        else:
            save_dir = self.get_model_directory(svm_directory)
            saved_model_path = os.path.join(save_dir, "model")

        if saved_model_path == None or (not os.path.exists(saved_model_path)):
            raise ValueError("Fatal Error: Network Monitoring subsystem failed to start because trained ML module DOES NOT exist. Please build a model and start this module again")
        else:
            with open(saved_model_path, 'rb') as file:
                    self.trained_model = joblib.load(file)

    def load_agg_trained_model(self, target_model=None):
        agg_directory = "agg_model"
        save_dir = self.get_model_directory(agg_directory)
        saved_model_path = os.path.join(save_dir, "model")

        if saved_model_path == None or (not os.path.exists(saved_model_path)):
            raise ValueError("Fatal Error: Network Monitoring subsystem failed to start because trained ML module DOES NOT exist. Please build a model and start this module again")
        else:
            with open(saved_model_path, 'rb') as file:
                    self.agg_trained_model = joblib.load(file)

    def get_preprocessed_dataframe_for_analysis(self, live_file_path):
        df = pd.read_csv(live_file_path)

        # Remove String Variables
        columns = []
        for column in df.columns:
            if df[column].dtype != "O":
                columns.append(column)
        df = df[columns]

        X = df.to_numpy()

        return X
    
    def get_preprocessed_agg_dataframe_for_analysis(self, agg_live_file_path):
        X = np.array([])
        try:
            df = pd.read_csv(agg_live_file_path)

            X = df.to_numpy()
        except:
            pass

        return X
    
    def show_notification(self, notification, victim=None, mitigate=""):
        affected_device = "\n" if victim == None else "\n\t\tTarget Device: {}\n".format(victim)
        mitigate_notif = "" if mitigate == "" else "\n\n\t\t{}\n".format(mitigate)
        self.logger.info(draw_horizontal_line())
        self.logger.info('\n\t\t{}{}{}'.format(notification, affected_device, mitigate_notif))
        self.logger.info(draw_horizontal_line())

    def make_prediction(self, agg_pred, r_pred, victim):
        pred = 0
        if r_pred:
            if agg_pred == 1 and r_pred == 1:
                pred = 1
            elif agg_pred == 1:
                pred = 1

        else:
            if agg_pred == 1:
                pred = 1

        if pred == 0:
            self.show_notification("Legitimate network activity detected ...")
        else:
            self.should_mitigate = True
            self.show_notification("DDoS attack activity detected ...", victim, "Attack traffic mitigated.")  
