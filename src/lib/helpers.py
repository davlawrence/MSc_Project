import os
import pathlib

def get_terminal_width():
    return os.get_terminal_size().columns

def draw_horizontal_line():
    line = ""
    for i in range(get_terminal_width()):
        line += "="
    return line

def retrieve_ip_address_from_cidr_ip(cidr_ip):
    return cidr_ip.split("/")[0]

def retrieve_host_number_from_cidr_ip(cidr_ip):
    ip = retrieve_ip_address_from_cidr_ip(cidr_ip)
    return ip.split(".")[3]

def create_directory(dir_name, dir_path=None):
    if not dir_path:
        dir_path = os.getcwd()

    if os.path.isdir(dir_path) and (not os.path.exists(dir_name)):
        pathlib.Path(dir_name).mkdir(parents=True, exist_ok=True)

def write_to_new_file(file_path, data):
    with open(file_path, "w") as file:
        file.write(data + "\n")
        file.close()

def clear_file(file_path, data):
    with open(file_path, "w") as file:
        file.write(data)
        file.close()

def write_to_existing_file(file_path, data):
    with open(file_path, "a") as file:
        file.write(data + "\n")
        file.close()




        
