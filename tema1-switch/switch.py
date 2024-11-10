#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

LISTENING_STATE = "listening"
BLOCKING_STATE = "blocking"

def is_unicast_mac(mac_addr):
    # A MAC address is unicast if the least significant bit of the most significant byte is 0
    return int(mac_addr.split(":")[0], 16) % 2 == 0

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def create_bpdu(root_bridge_id, own_bridge_id, root_path_cost):
    src_mac = get_switch_mac()
    dst_mac = bytes.fromhex('0180C2000000')
    bpdu_format = '!6s6sQQQ'                         #root bridge id, sender bridge id, root path cost
    bpdu = struct.pack(bpdu_format, dst_mac, src_mac, own_bridge_id, own_bridge_id, root_path_cost)
    return bpdu

def send_bdpu_every_sec(own_bridge_id, root_bridge_id, root_path_cost, port_states, vlan_table, interfaces):
    while True:
        # TODO Send BDPU every second if necessary
        if own_bridge_id == root_bridge_id:
            bpdu_frame = create_bpdu(root_bridge_id, own_bridge_id, root_path_cost)
            for i in interfaces:
                i_name = get_interface_name(i)
                i_type = get_interface_type(i_name, vlan_table)
                if i_type == 'trunk':
                    send_to_link(i, len(bpdu_frame), bpdu_frame)
                    
        time.sleep(1)

def parse_bpdu_frame(data):
    bpdu_format = '!6s6sQQQ'
    dst_mac, src_mac, root_bridge_id, sender_bridge_id, root_path_cost = struct.unpack(bpdu_format, data[:38])
    return root_bridge_id, sender_bridge_id, root_path_cost

def process_bdpu(interface, data, port_states, interfaces, root_bridge_id, root_path_cost, own_bridge_id, root_port, vlan_table):
    sender_root_bridge_id, sender_bridge_id, sender_root_path_cost = parse_bpdu_frame(data)
    we_were_root = own_bridge_id == root_bridge_id
    # If the sender's root bridge ID is lower than the current root bridge ID, then it becomes our new root bridge
    if sender_root_bridge_id < root_bridge_id:
        root_bridge_id = sender_root_bridge_id
        # Set the root path cost to the sender's root path cost plus the cost from the sender to us
        root_path_cost = sender_root_path_cost + 10
        root_port = interface

        # If we were the root bridge, we need to update the port states
        if we_were_root:
            for i in interfaces:
                i_name = get_interface_name(i)
                i_type = get_interface_type(i_name, vlan_table)
                if i_type == 'trunk' and i != root_port:
                    port_states[i] = BLOCKING_STATE
        # if root_port was blocking, set it to listening
        if port_states[root_port] == BLOCKING_STATE:
            port_states[root_port] = LISTENING_STATE

        bpdu_frame = create_bpdu(root_bridge_id, own_bridge_id, root_path_cost)
        for i in interfaces:
            i_name = get_interface_name(i)
            i_type = get_interface_type(i_name, vlan_table)
            # if i_type == 'trunk' and i != interface and port_states.get(i, LISTENING_STATE) == LISTENING_STATE:
            if i_type == 'trunk' and i != interface and port_states[i] == LISTENING_STATE:
                send_to_link(i, len(bpdu_frame), bpdu_frame)
    
    elif sender_root_bridge_id == root_bridge_id:
        if interface == root_port and sender_root_path_cost + 10 < root_path_cost:
            # if the sender's root path cost is lower than ours, update the root path cost
            root_path_cost = sender_root_path_cost + 10
        elif interface != root_port:
            if sender_root_path_cost > root_path_cost:
                # if the sender's root path cost is higher than ours, then it means that his path is through us
                port_states[interface] = LISTENING_STATE
    
    elif sender_bridge_id == own_bridge_id:
        # if the sender is us, then we have a loop
        port_states[interface] = BLOCKING_STATE
    # if we are the root bridge, set all the ports to listening
    if own_bridge_id == root_bridge_id:
        for i in interfaces:
            port_states[i] = LISTENING_STATE

        
    return port_states, root_bridge_id, root_path_cost, root_port
            
    
def send_frame(interface, data, length, vlan_id, source_interface_name, source_interface_type, vlan_table):
    # Send the frame to the specified interface
    dest_interface_name = get_interface_name(interface)
    dest_interface_type = get_interface_type(dest_interface_name, vlan_table)
    # If both interfaces are trunk, forward the frame
    if source_interface_type == 'trunk' and dest_interface_type == 'trunk':
        send_to_link(interface, length, data)
    elif source_interface_type == 'access' and dest_interface_type == 'access':
        # If the interfaces are access and have the same VLAN ID, forward the frame
        if vlan_id == vlan_table[dest_interface_name]:
            send_to_link(interface, length, data)
        # If the interfaces are access and have different VLAN IDs, drop the frame
        else:
            return
    # If the source interface is access and the destination interface is trunk, add a VLAN tag to the frame
    elif source_interface_type == 'access' and dest_interface_type == 'trunk':
        # If the VLAN ID of the frame matches the VLAN ID of the source interface, add a VLAN tag
        tagged_frame_data = add_vlan_tag(data, vlan_id)
        length += 4
        send_to_link(interface, length, tagged_frame_data)
    # If the source interface is trunk and the destination interface is access, remove the VLAN tag from the frame
    elif source_interface_type == 'trunk' and dest_interface_type == 'access':
        # If the VLAN ID of the frame matches the VLAN ID of the destination interface, remove the VLAN tag
        if(vlan_id == vlan_table[dest_interface_name]):
            untagged_frame_data = remove_vlan_tag(data)
            length -= 4
            send_to_link(interface, length, untagged_frame_data)
        else:
            # Drop the frame if the VLAN IDs do not match
            return
    
def get_interface_type(interface_name, vlan_table):
    if vlan_table[interface_name] == 'T':
        return 'trunk'
    return 'access'

def get_switch_config(switch_id, vlan_table):
    fin = open(f'./configs/switch{switch_id}.cfg', 'r')
    file_lines = fin.read().splitlines()
    fin.close()
    # Read the switch priority from the config file
    switch_priority = int(file_lines[0])
    # Delete the switch priority line from the list
    file_lines.pop(0)
    # Read the interfaces and their vlan ids from the config file
    for line in file_lines:
        interface, vlan_id = line.split()
        if(vlan_id != 'T'):
            vlan_id = int(vlan_id)
        # Add the interface and its vlan id to the vlan table
        vlan_table[interface] = vlan_id
    
    return switch_priority, vlan_table
    
def add_vlan_tag(data, vlan_id):
    # Add a VLAN tag to the frame
    return data[0:12] + create_vlan_tag(vlan_id) + data[12:]

def remove_vlan_tag(data):
    # Remove the VLAN tag from the frame
    return data[0:12] + data[16:]


def main():
    mac_table = {}
    vlan_table = {}
    port_states = {}
    root_port = None
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    switch_priority, vlan_table = get_switch_config(switch_id, vlan_table)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))
    # initialize the port states
    for i in interfaces:
        i_name = get_interface_name(i)
        if get_interface_type(i_name, vlan_table) == 'trunk':
            port_states[i] = BLOCKING_STATE
        else:
            port_states[i] = LISTENING_STATE
    
    own_bridge_id = switch_priority
    root_bridge_id = own_bridge_id
    root_path_cost = 0

    # if the switch is the root bridge, set all the ports to listening
    if root_bridge_id == own_bridge_id:
        for i in interfaces:
            port_states[i] = LISTENING_STATE

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec, args=(own_bridge_id, root_bridge_id, root_path_cost, port_states, vlan_table, interfaces))
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')
        print("Received frame of size {} on interface {}".format(length, interface), flush=True)


        # Get the interface name from the interface number
        interface_name = get_interface_name(interface)
        # Get the interface type (access or trunk) from the VLAN table
        interface_type = get_interface_type(interface_name, vlan_table)
        # If the frame is a BPDU, process it
        if dest_mac == "01:80:c2:00:00:00":
            port_states, root_bridge_id, root_path_cost, root_port = process_bdpu(interface, data, port_states, interfaces, root_bridge_id, root_path_cost, own_bridge_id, root_port, vlan_table)
            continue
        
        # If the interface is in blocking state, do not process the frame
        if port_states.get(interface, LISTENING_STATE) == BLOCKING_STATE:
            continue

        # If the frame was received from an access interface, assign the VLAN ID from the VLAN table
        if interface_type == 'access' and vlan_id == -1:
            vlan_id = vlan_table[interface_name]


        # Add the source MAC to the MAC table
        mac_table[src_mac] = interface

        # Forward the frame to the destination MAC if it is unicast
        if is_unicast_mac(dest_mac):
            # If the destination MAC is in the MAC table, forward the frame to the corresponding interface
            if dest_mac in mac_table:
                if port_states.get(mac_table[dest_mac], LISTENING_STATE) == LISTENING_STATE:
                    send_frame(mac_table[dest_mac], data, length, vlan_id, interface_name, interface_type, vlan_table)
            # If the destination MAC is not in the MAC table, broadcast the frame to all interfaces except the one it was received on
            else:
                for i in interfaces:
                    if i != interface and port_states.get(i, LISTENING_STATE) == LISTENING_STATE:
                        send_frame(i, data, length, vlan_id, interface_name, interface_type, vlan_table)
        # Broadcast the frame to all interfaces except the one it was received on
        else:
            for i in interfaces:
                if i != interface and port_states.get(i, LISTENING_STATE) == LISTENING_STATE:
                    send_frame(i, data, length, vlan_id, interface_name, interface_type, vlan_table)

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()