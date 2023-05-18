import os

# Data files configure
legitmate_data_filename = "legitimate.csv"
attacks_data_filename = "attacks.csv"

agg_legitmate_data_filename = "agg_legitimate.csv"
agg_attacks_data_filename = "agg_attacks.csv"

bytes_filename = "bytes.csv"
packets_filename = "packets.csv"
src_ip_filename = "ipsrc.csv"
dst_ip_filename = "ipdst.csv"
netflow_filename = "netflow.csv"
live_filename = "live.csv"
report_filename = "report.csv"
agg_live_filename = "agg_live.csv"

delay = 3


# Data directory
base_dir = os.getcwd()
dir_name = "data/"
data_directory = os.path.join(base_dir, dir_name)


number_of_switches = 6
number_of_hosts_per_switch = 5

controller = {
    "name": "app_controller"
}

switches = {
    "count" : number_of_switches,
    "names": [],
    "abbrv": "S",
}

hosts = {
    "count" : ((number_of_switches - 1) * number_of_hosts_per_switch) + 1,
    "names": [],
    "abbrv": "H",
}

config = {

}