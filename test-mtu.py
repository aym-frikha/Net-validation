#! /usr/bin/env python

# standard modules
import logging
import os
import sys
import time
import ipaddress
from scapy.all import *
import maas_utils as maas

# ostinato modules
# (user scripts using the installed package should prepend ostinato. i.e
#  ostinato.core and ostinato.protocols)
from core import ost_pb, DroneProxy
from protocols.mac_pb2 import mac
from protocols.ip4_pb2 import ip4, Ip4
from protocols.textproto_pb2 import TextProtocol, textProtocol

# setup logging
log = logging.getLogger(__name__)
logging.basicConfig(level=logging.ERROR)

# Subnet to test
IP_ADD = u'192.168.120.50'
MASK = u'24'
FIRST_PAYLOAD = 'MAAS'


def connect_drone(drone):
    # connect to drone
    drone.connect()

def get_interface_by_name(drone, name):
    port_id_list = drone.getPortIdList()
    # retrieve port config list
    port_config_list = drone.getPortConfig(port_id_list)
    for port in port_config_list.port:
        if port.name == name:
            return port.port_id.id

def add_stream(drone, tx_port):
    # add a stream
    stream_id = ost_pb.StreamIdList()
    stream_id.port_id.CopyFrom(tx_port.port_id[0])
    stream_id.stream_id.add().id = 1
    drone.addStream(stream_id)
    return stream_id

def configure_stream(stream_id, stream_cfg, num_packets, frame_len):
    # configure the stream
    s = stream_cfg.stream.add()
    s.stream_id.id = stream_id.stream_id[0].id
    s.core.is_enabled = True
    s.core.frame_len = frame_len
    s.control.num_packets = num_packets
    return s

def configure_traffic_protocols(stream_config, mac_src, mac_dst, ip_src, ip_dst, payload):
    # setup stream protocols as mac:eth2:ip4:udp:payload
    p = stream_config.protocol.add()
    p.protocol_id.id = ost_pb.Protocol.kMacFieldNumber
    p.Extensions[mac].dst_mac = mac_dst
    p.Extensions[mac].src_mac = mac_src

    p = stream_config.protocol.add()
    p.protocol_id.id = ost_pb.Protocol.kEth2FieldNumber

    p = stream_config.protocol.add()
    p.protocol_id.id = ost_pb.Protocol.kIp4FieldNumber
    ip = p.Extensions[ip4]
    ip.src_ip = ip_src
    ip.dst_ip = ip_dst

    stream_config.protocol.add().protocol_id.id = ost_pb.Protocol.kTcpFieldNumber
    p = stream_config.protocol.add()
    p.protocol_id.id = ost_pb.Protocol.kTextProtocolFieldNumber
    pload = p.Extensions[textProtocol]
    pload.text = FIRST_PAYLOAD + '--' + payload
    pload.eol = TextProtocol.kCr

def convert_ip_to_hex(ip):
    a = str(ip).split('.')
    return int('0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, a)), 16)
def get_broadcast_ip(ip, mask):
    net = ipaddress.IPv4Network(ip + '/' + mask, False)
    return convert_ip_to_hex(net.broadcast_address)

def get_machine_list(machines):
    return [machine['hostname'] for machine in machines]

def get_mgmt_ip_addresses_and_tests(machines):
    machine_map = {}
    for machine in machines:
        if machine['power_state'] == "on":
             machine_map[machine['hostname']] = {}
             # machine_map[machine['hostname']]['mgmt_ip'] = machine['boot_interface']['links'][0]['ip_address']
             machine_map[machine['hostname']]['drone'] = DroneProxy(machine['boot_interface']['links'][0]['ip_address'])
             connect_drone(machine_map[machine['hostname']]['drone'])
             machine_map[machine['hostname']]['interfaces'] = []
             for interface in machine['interface_set']:
                interface_config = {
                    'name': interface['name'],
                    'mtu': interface['effective_mtu'],
                    'cidr': interface['links'][0]['subnet']['cidr'],
                    'drone_port': ost_pb.PortIdList()
                }

                interface_config['drone_port'].port_id.add().id = \
                    get_interface_by_name(machine_map[machine['hostname']]['drone'], interface['name'])
                machine_map[machine['hostname']]['interfaces'].append(interface_config)
    return machine_map

cidr = sys.argv[1]

try:

    machines = maas.maas_get("machines/")
    environment = get_mgmt_ip_addresses_and_tests(machines)
    print("#######################################################\n")
    print("#####  Start MTU Test For Subnet: " + cidr + " ####\n")
    print("#######################################################\n")
    # SETUP the Test
    for machine in environment.keys():
        drone_gen = environment[machine]['drone']
        for interface in environment[machine]['interfaces']:
            if interface['cidr'] == cidr:

                drone_int = interface['drone_port']
                stream = add_stream(drone_gen, drone_int)
                time.sleep(1)
                interface['stream_id_list'] = stream
                stream_cfg = ost_pb.StreamConfigList()
                stream_cfg.port_id.CopyFrom(drone_int.port_id[0])
                s_conf = configure_stream(stream, stream_cfg, 3, int(interface['mtu']))
                configure_traffic_protocols(s_conf,
                                            0x0205FFFFFFFF,
                                            0xFFFFFFFFFFFF,
                                            convert_ip_to_hex(IP_ADD),
                                            get_broadcast_ip(IP_ADD, MASK), machine + '--' + interface['name'])
                drone_gen.modifyStream(stream_cfg)

    # RUN the Test
    for sender in environment.keys():
        print("Sender is " + sender)
        for receiver in environment.keys():
            if sender == receiver:
                continue
            #Listen to the traffic
            for interface in environment[receiver]['interfaces']:
                if interface['cidr'] == cidr:
                    environment[receiver]['drone'].startCapture(interface['drone_port'])

        #Send Traffic
        for interface in environment[sender]['interfaces']:
            if interface['cidr'] == cidr:
                environment[sender]['drone'].startTransmit(interface['drone_port'])
                time.sleep(3)
                environment[sender]['drone'].stopTransmit(interface['drone_port'])

        #Stop Capture
        for receiver in environment.keys():
            if sender == receiver:
                continue
            #Analyse Capture
            result = False
            for interface in environment[receiver]['interfaces']:
                if interface['cidr'] == cidr:
                    environment[receiver]['drone'].stopCapture(interface['drone_port'])
                    buff = environment[receiver]['drone'].getCaptureBuffer(interface['drone_port'].port_id[0])
                    pcap_file_name = receiver + '_' + interface['name'] + '.pcap'
                    environment[receiver]['drone'].saveCaptureBuffer(buff, pcap_file_name)

                    to_analyze = rdpcap(pcap_file_name)
                    sessions = to_analyze.sessions()
                    for session in sessions:
                        for packet in sessions[session]:
                            try:
                                if str(packet[IP].src) == IP_ADD:
                                    if str(packet[TCP].payload).startswith(FIRST_PAYLOAD):
                                        result = True
                            except:
                                pass
                    os.remove(pcap_file_name)
            if result:
                print("Connection is OK between " + sender + " and " + receiver)
            else:
                print("Connection is NOT OK between " + sender + " and " + receiver)

        print("\n")

    for machine in environment.keys():
        drone_gen = environment[machine]['drone']
        for interface in environment[machine]['interfaces']:
            if interface['cidr'] == cidr:
                environment[machine]['drone'].deleteStream(interface['stream_id_list'])

except Exception as ex:
    log.exception(ex)
    sys.exit(1)