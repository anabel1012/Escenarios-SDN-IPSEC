from multiprocessing import Queue
from ncclient import manager
from ncclient.transport.session import *
from flask import Flask, request, Response
from werkzeug.serving import run_simple
import simplejson as json
from datetime import datetime
from threading import Thread, Lock
from enum import Enum
import traceback
import time
import string
import random
# Global variables

app = Flask(__name__)

hosts = {}  # Hosts inside the network
registration_process = {}  # Currently active registration processes.
ipsec_associations = {}  # IPSec associations established
active_rekeys = []  # SPIs of SAs that are in an active rekey process
rpc_ids = {}  # Dictionary msg_id <---> spi for troubleshooting
active_rekey_information = {}   # Information generated for the renovation of a SA. -
                                # Dictionary spi_in_old --> information_rekey
workers = []  # Threads to execute tasks

spinumber = 257
rulenumber = 1

mutex_register = Lock()  # Lock to control registration process
mutex = Lock()  # Lock to control that if two notifications arrive sadb_expire (soft type) of the same SA in the same
                # instant of time, only the rekey process is executed once.

mutex_update_spinumber = Lock()
mutex_update_rulenumber = Lock()
mutex_rpc = Lock()
mutex_hosts = Lock()
mutex_ipsec_associations = Lock()
mutex_active_rekeys = Lock()
mutex_rpc_ids = Lock()
mutex_active_rekeys_information = Lock()
mutex_registration_process = Lock()

#files = ["./xml/0_h2h_transport_esp_enc_auth_hX.xml", "./xml/1_h2h_add_sad_in_hX.xml", "./xml/2_h2h_add_sad_out_hX.xml",
 #        "./xml/3_h2h_del_sad_in_out_hX.xml"]    # Templates used by the controller to send the IPsec configuration
                                            # to the nodes
files = ["./xml/g2g/0_g2g_tunnel_esp_enc_auth_gwX.xml", "./xml/g2g/1_g2g_tunnel_add_sad_in_gX.xml", "./xml/g2g/2_g2g_tunnel_add_sad_out_gX.xml", "./xml/g2g/3_g2g_tunnel_del_sad_in_out_hX.xml"]

#files = ["./xml/g2g/0_g2g_tunnel_linux_fg_2.xml", "./xml/g2g/1_g2g_tunnel_linux_fg_add_sad.xml", "./xml/g2g/", "./xml/g2g/"]

# Constants

SADB_STATE_DYING = 'Dying'
time_out = 60


# Enum
class StateRekey(Enum):
    INBOUD = 1
    OUTBOUND = 2
    DELETE = 3

# Global
#global key, vector, old_key, old_vector


def init_controller():
    log = open("./controller.log", "a")
    log.write("The controller is running (" + str(datetime.now()) + ")\n")
    log.close()
    run_simple(hostname='0.0.0.0', port=5000, threaded=True, application=app)


# Endpoint for the registration
@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        content = request.get_json()
        ip_control = content['control_network_ip']
        ip_internal = content['internal_network_ip']
	ip_data = content['data_network_ip']
        print("Pet rx " + ip_control + " " + ip_data)
        log_writeln("Peticion recibida ----> IP Control: " + ip_control + " IP internal " + ip_internal + " IP Data: " + ip_data + "\n")
        return sign_up(ip_control, ip_internal, ip_data)


def sign_up(ip_control, ip_internal, ip_data):
    log_writeln("Registro recibido ----> IP Control: " + ip_control + " IP internal " + ip_internal + " IP Data: " + ip_data + "\n")
    if not ip_control or not ip_data:
        response = json.dumps({'Error': 'cliente no encontrado'})
        response = Response(response=response, status=400, mimetype='application/json')
        return response

    if ip_control not in hosts.keys():
        try:
            m = manager.connect(host=ip_control, port=830, username="root", password="root",
                                hostkey_verify=False)
            m._session.add_listener(Listener())
            m.create_subscription()
            m.async_mode = True
        except Exception as e:
            log_writeln(str(e))
            log_writeln(traceback.format_exc())
            return 'ERROR'
        result = create_associations(ip_control, ip_internal, ip_data, m)
        if result:
            log_writeln("Registro completado: nodo ip_control " + ip_control + " ip_internal " + ip_internal + " ip_data " + ip_data + "\n")
            return 'OK'
        else:
            log_writeln("Registro no completado: nodo ip_control " + ip_control + " ip_internal " + ip_internal + " ip_data " + ip_data + "\n")
            m.close_session()
            return 'ERROR'
    else:
        log_writeln("Nodo ya registrado " + "\n")
        return 'OK'


def create_associations(ip_control, ip_internal, ip_data, manager):
    config1 = config2 = True
    mutex_register.acquire()
    if hosts:
        for ip_control_remote in hosts:
            message_id1 = message_id2 = None
            log_writeln("Creando asociaciones de seguridad IPsec para " + ip_data + " -> " +
                        hosts[ip_control_remote].ip_data + "\n")

            mutex_update_spinumber.acquire()
            spi_in = get_spi_number()  # Security Parameter Index
            spi_out = increment_spi_number()  # Security Parameter Index + 1
            increment_spi_number()  # Update global SPI Generator
            mutex_update_spinumber.release()

            mutex_update_rulenumber.acquire()
            rule_in = get_rule_number()  # Rule number
            rule_out = increment_rule_number()  # Rule number + 1
            rule_fwd = increment_rule_number()  # Rule number + 1
            increment_rule_number()  # Update Rule Number
            mutex_update_rulenumber.release()

            try:
                config_local_node = create_initial_config(rule_in, rule_out, rule_fwd, ip_data,
                                                          hosts[ip_control_remote].ip_data, ip_internal, hosts[ip_control_remote].ip_internal, spi_in, spi_out, enc_key, vector, int_key)
                rpc = manager.edit_config(target='running', config=config_local_node, test_option='test-then-set')
                message_id1 = rpc.id
                add_registration_process(message_id1, False)
            except Exception as e:
                config1 = False
                log_writeln(str(e))
                log_writeln(traceback.format_exc())

            try:
                config_remote_node = create_initial_config(rule_in, rule_out, rule_fwd,
                                                           hosts[ip_control_remote].ip_data, ip_data, hosts[ip_control_remote].ip_internal, ip_internal,  spi_out, spi_in, enc_key, vector, int_key)
                m = hosts[ip_control_remote].manager
                rpc = m.edit_config(target='running', config=config_remote_node, test_option='test-then-set')
                message_id2 = rpc.id
                add_registration_process(message_id2, False)
            except Exception as e:
                config2 = False
                log_writeln(str(e))
                log_writeln(traceback.format_exc())

            reg = check_registration_process(message_id1, message_id2)

            if config1 and config2 and reg:  # and reg
                # Create a ipsec association for local node (Local ---> Remote)
                add_ipsec_association(Ipsa(ip_control, ip_data, ip_internal, ip_control_remote, hosts[ip_control_remote].ip_data,
                                           hosts[ip_control_remote].ip_internal, spi_in, spi_out))
                # Create a ipsec association for local node (Remote ---> Local)
                add_ipsec_association(Ipsa(ip_control_remote, hosts[ip_control_remote].ip_data, hosts[ip_control_remote].ip_internal, ip_control,
                                           ip_data, ip_internal, spi_out, spi_in))

            else:
                mutex_register.release()
                return False
        add_host(ip_control, ip_data, ip_internal, manager)
        mutex_register.release()
        return True
    else:
        add_host(ip_control, ip_data, ip_internal, manager)
        mutex_register.release()
        return True


# It is checked if the confirmations of the configurations applied in the nodes are received, in case of not receiving
# these in the established time the process of registry will fail.
def check_registration_process(message_id1, message_id2):
    initial = time.time()
    limit = initial + time_out

    while initial <= limit:
        if (message_id1 in registration_process.keys()) and (message_id2 in registration_process.keys()):
            received1 = registration_process.get(message_id1)
            received2 = registration_process.get(message_id2)

            if received1 and received2:
                delete_registration_process(message_id1)
                delete_registration_process(message_id2)
                return True

            time.sleep(0.2)
            initial = time.time()

    return False


def add_registration_process(message_id, received):
    mutex_registration_process.acquire()
    registration_process.update({message_id: received})
    mutex_registration_process.release()


def delete_registration_process(message_id):
    mutex_registration_process.acquire()
    registration_process.pop(message_id)
    mutex_registration_process.release()


def add_host(ip_control, ip_data, ip_internal, manager):
    mutex_hosts.acquire()
    host = Host(ip_data, ip_internal, manager)
    hosts.update({ip_control: host})
    mutex_hosts.release()


def add_ipsec_association(ipsa):
    mutex_ipsec_associations.acquire()
    ipsec_associations.update({ipsa.spi_in: ipsa})
    mutex_ipsec_associations.release()


def delete_ipsec_association(spi_in):
    mutex_ipsec_associations.acquire()
    ipsec_associations.pop(spi_in)
    mutex_ipsec_associations.release()


def add_active_rekeys(spi, spi2):
    mutex_active_rekeys.acquire()
    active_rekeys.append(spi)
    active_rekeys.append(spi2)
    mutex_active_rekeys.release()


def delete_active_rekeys(spi1, spi2):
    mutex_active_rekeys.acquire()
    active_rekeys.remove(spi1)
    active_rekeys.remove(spi2)
    mutex_active_rekeys.release()


def add_rpc_ids(spi_in_old, message_id1, message_id2):
    mutex_rpc_ids.acquire()
    rpc_ids.update({message_id1: spi_in_old})
    rpc_ids.update({message_id2: spi_in_old})
    mutex_rpc_ids.release()


def delete_rpc_id(msg_id):
    mutex_rpc_ids.acquire()
    rpc_ids.pop(msg_id)
    mutex_rpc_ids.release()


def add_active_rekeys_information(spi_in_old, information_rekey):
    mutex_active_rekeys_information.acquire()
    active_rekey_information.update({spi_in_old: information_rekey})
    mutex_active_rekeys_information.release()


def delete_active_rekeys_information(spi_in_old):
    mutex_active_rekeys_information.acquire()
    active_rekey_information.pop(spi_in_old)
    mutex_active_rekeys_information.release()


def get_spi_number():
    global spinumber
    return spinumber


def increment_spi_number():
    global spinumber
    spinumber += 1
    return spinumber


def get_rule_number():
    global rulenumber
    return rulenumber


def increment_rule_number():
    global rulenumber
    rulenumber += 1
    return rulenumber


def log_writeln(cadena):
    log = open("./controller.log", "a")
    log.write(cadena + "\n")
    log.close()


def log_time(cadena):
    log = open("/time.txt", "a")
    log.write(cadena + "\n")
    log.close()

#Generate a random string of letters and digits
def create_random_keys(stringLength=8):
    #lettersAndDigits= string.digits + "ABCDEF"
    global enc_key, vector, int_key
    for i in range(3):
        lettersAndDigits= string.digits + "abcdef"
        random_string = ''.join(random.choice(lettersAndDigits) for i in range(stringLength))
    # Convert to data type: yang:hex-string
        if i == 0:
            t = iter(random_string)
            enc_key = ''.join(a+b for a,b in zip(t, t))
            #enc_key = ':'.join(a+b for a,b in zip(t, t))
            #print("enc_key " + enc_key)
        if i == 1:
            t = iter(random_string)
            vector = ''.join(a+b for a,b in zip(t, t))
            #vector = ':'.join(a+b for a,b in zip(t, t))
            #print("vector " + vector)
        if i == 2:
            t = iter(random_string)
            #int_key = ':'.join(a+b for a,b in zip(t, t))
            int_key = ''.join(a+b for a,b in zip(t, t))
            #print("int_key " + int_key)


    #return cadena

# Initial configuration (SPD and SAD) sent in the registration process to create SAs between two nodes.
def create_initial_config(rule_in, rule_out, rule_fwd, local_address, remote_address, local_internal, remote_internal, spi_in, spi_out, enc_key, vector, int_key):
    snippet = etree.tostring(etree.parse(files[0]), pretty_print=True)
    snippet = snippet.replace("RULE_IN", str(rule_in))
    snippet = snippet.replace("RULE_OUT", str(rule_out))
    snippet = snippet.replace("RULE_FWD", str(rule_fwd))
    snippet = snippet.replace("LOCAL_ADDRESS", local_address)
    snippet = snippet.replace("REMOTE_ADDRESS", remote_address)
    snippet = snippet.replace("SPI_IN", str(spi_in))
    snippet = snippet.replace("SPI_OUT", str(spi_out))

    snippet = snippet.replace("LOCAL_INTERNAL", local_internal)
    snippet = snippet.replace("REMOTE_INTERNAL", remote_internal)

    snippet = snippet.replace("ENC_KEY", enc_key)
    snippet = snippet.replace("VECTOR", vector)
    snippet = snippet.replace("INT_KEY", int_key)

    return snippet


# Configuration inbound - Rekey - Phase 1
def create_inbound_config(spi_in, local_address, remote_address, local_internal, remote_internal, enc_key, vector, int_key):
    snippet = etree.tostring(etree.parse(files[1]), pretty_print=True)
    snippet = snippet.replace("LOCAL_ADDRESS", local_address)
    snippet = snippet.replace("REMOTE_ADDRESS", remote_address)
    snippet = snippet.replace("SPI_IN", str(spi_in))

    snippet = snippet.replace("LOCAL_INTERNAL", local_internal)
    snippet = snippet.replace("REMOTE_INTERNAL", remote_internal)

    snippet = snippet.replace("ENC_KEY", enc_key)
    snippet = snippet.replace("VECTOR", vector)
    snippet = snippet.replace("INT_KEY", int_key)
    return snippet


# Configuration outbound - Rekey - Phase 2
def create_outbound_config(spi_out, local_address, remote_address, local_internal, remote_internal, enc_key, vector, int_key):
    snippet = etree.tostring(etree.parse(files[2]), pretty_print=True)
    snippet = snippet.replace("LOCAL_ADDRESS", local_address)
    snippet = snippet.replace("REMOTE_ADDRESS", remote_address)
    snippet = snippet.replace("SPI_OUT", str(spi_out))

    snippet = snippet.replace("LOCAL_INTERNAL", local_internal)
    snippet = snippet.replace("REMOTE_INTERNAL", remote_internal)
    
    snippet = snippet.replace("ENC_KEY", enc_key)
    snippet = snippet.replace("VECTOR", vector)
    snippet = snippet.replace("INT_KEY", int_key)
    return snippet


# Configuration delete - Rekey - Phase 3
def delete_config(local_address, remote_address, local_internal, remote_internal, spi_in, spi_out, old_enc_key, old_vector, old_int_key):
    snippet = etree.tostring(etree.parse(files[3]), pretty_print=True)
    snippet = snippet.replace("LOCAL_ADDRESS", local_address)
    snippet = snippet.replace("REMOTE_ADDRESS", remote_address)
    snippet = snippet.replace("SPI_IN", str(spi_in))
    snippet = snippet.replace("SPI_OUT", str(spi_out))

    snippet = snippet.replace("LOCAL_INTERNAL", local_internal)
    snippet = snippet.replace("REMOTE_INTERNAL", remote_internal)

    snippet = snippet.replace("ENC_KEY", old_enc_key)
    snippet = snippet.replace("VECTOR", old_vector)
    snippet = snippet.replace("INT_KEY", old_int_key)
    return snippet


# Procedure that analyze a sadb_expire notification, if this is a soft type then the rekey process for the SA identified
# with the SPI containing the notification is started.
def analyze_notification(notification):
    sadb_notification = notification.find("{http://example.net/ietf-ipsec}sadb_expire")
    if sadb_notification is not None:

        state = notification.find("{http://example.net/ietf-ipsec}sadb_expire").find(
            "{http://example.net/ietf-ipsec}state").text

        if state is not None and state == SADB_STATE_DYING:

            spi_received = notification.find("{http://example.net/ietf-ipsec}sadb_expire").find(
                "{http://example.net/ietf-ipsec}spi").text  # GET the SPI from the notification

            if spi_received is not None:
                spi_received = int(spi_received)
                log_writeln("spi_received = " + str(spi_received) + "\n")

                mutex.acquire()

                if spi_received not in active_rekeys:

                    if spi_received in ipsec_associations.keys():  # Check if the ipsa is active or not
                        ipsec_association = ipsec_associations.get(spi_received)

                        spi_in = spi_received
                        spi_out = ipsec_association.spi_out

                        add_active_rekeys(spi_in, spi_out)
                        log_writeln("Rekey : spi_in = " + str(spi_in) + " spi_out = " + str(spi_out) + "\n")
                        log_writeln("Set inboud task spi_in_old = " + str(spi_in) + "\n")
                        pool.add_task(inbound_rekey, ipsec_association)
                    else:
                        log_writeln("Rekey done for spi -> " + str(spi_received) + "\n")
                else:
                    log_writeln("Active rekey for spi -> " + str(spi_received) + "\n")

                mutex.release()


# Procedure to analyze RPC-Replys for the control of confirmations of Netconf operations
def analyze_rpc_reply(rpc_reply):
    rpc_reply = etree.fromstring(rpc_reply)
    msg_id = rpc_reply.attrib['message-id']

    if msg_id is not None:
        if msg_id in registration_process.keys():
            add_registration_process(msg_id, True)

        elif msg_id in rpc_ids.keys():
            spi_in_old = rpc_ids.get(msg_id)
            active_rekey = active_rekey_information.get(spi_in_old)

            if msg_id == active_rekey.msg_id1:
                active_rekey.receive_id1 = True
                add_active_rekeys_information(spi_in_old, active_rekey)  # Update variable
                delete_rpc_id(msg_id)
            else:
                active_rekey.receive_id2 = True
                add_active_rekeys_information(spi_in_old, active_rekey)  # Update variable
                delete_rpc_id(msg_id)

            active_rekey = active_rekey_information.get(spi_in_old)

            if active_rekey.receive_id1 and active_rekey.receive_id2:
                active_rekey.msg_id1 = None
                active_rekey.msg_id2 = None
                active_rekey.receive_id1 = False
                active_rekey.receive_id2 = False
                add_active_rekeys_information(spi_in_old, active_rekey)  # Update variable
                ipsa = ipsec_associations.get(spi_in_old)

                if active_rekey.state == StateRekey.INBOUD:
                    log_writeln("Set outbound task spi_old = " + str(spi_in_old) + "\n")
                    pool.add_task(outbound_rekey, ipsa)
                elif active_rekey.state == StateRekey.OUTBOUND:
                    log_writeln("Set delete task spi_old = " + str(spi_in_old) + "\n")
                    pool.add_task(delete_rekey, ipsa)
                elif active_rekey.state == StateRekey.DELETE:
                    log_writeln("Set update task spi_old = " + str(spi_in_old) + "\n")
                    pool.add_task(update_structures, ipsa)



# Procedure inbound - Rekey - Phase 1
def inbound_rekey(ipsa):
    mutex_update_spinumber.acquire()
    new_spi_in = get_spi_number()
    new_spi_out = increment_spi_number()
    increment_spi_number()
    mutex_update_spinumber.release()

    log_writeln("Rekey : spi_in_old = " + str(ipsa.spi_in) + " spi_out_old = " + str(ipsa.spi_out) + "spi_in_new = " +
                str(new_spi_in) + " spi_out_new = " + str(new_spi_out) + "\n")

    global old_enc_key, old_vector, old_int_key
    old_enc_key = enc_key
    old_vector = vector
    old_int_key = int_key
    create_random_keys()

    config_local_node = create_inbound_config(new_spi_in, ipsa.ip_local_data, ipsa.ip_remote_data, ipsa.ip_local_internal, ipsa.ip_remote_internal, enc_key, vector, int_key)
    m = hosts[ipsa.ip_local_control].manager
    rpc = m.edit_config(target='running', config=config_local_node, test_option='test-then-set')
    message_id1 = rpc.id

    config_remote_node = create_inbound_config(new_spi_out, ipsa.ip_remote_data, ipsa.ip_local_data, ipsa.ip_remote_internal, ipsa.ip_local_internal, enc_key, vector, int_key)
    m = hosts[ipsa.ip_remote_control].manager
    rpc = m.edit_config(target='running', config=config_remote_node, test_option='test-then-set')
    message_id2 = rpc.id

    log_writeln("IDs Inbound: spi_in_old = " + str(ipsa.spi_in) + " spi_out_old = " + str(ipsa.spi_out) +
                "Inbound ID 1 = " + message_id1 + " Inbound ID 2 = " + message_id2 + "\n")

    add_rpc_ids(ipsa.spi_in, message_id1, message_id2)

    add_active_rekeys_information(ipsa.spi_in, InformationRekey(new_spi_in, new_spi_out, message_id1, message_id2,
                                                                False, False, StateRekey.INBOUD))
    log_writeln("Rekey : spi_in_old = " + str(ipsa.spi_in) + " spi_out_old = " + str(ipsa.spi_out) + "spi_in_new = " +
                str(new_spi_in) + " spi_out_new = " + str(new_spi_out) + " ------> Inbound is sent" + "\n")


# Procedure outbound - Rekey - Phase 2
def outbound_rekey(ipsa):
    info_rekey = active_rekey_information.get(ipsa.spi_in)

    config_local_node = create_outbound_config(info_rekey.spi_out_new, ipsa.ip_local_data, ipsa.ip_remote_data, ipsa.ip_local_internal, ipsa.ip_remote_internal, enc_key, vector, int_key)
    m = hosts[ipsa.ip_local_control].manager
    rpc = m.edit_config(target='running', config=config_local_node, test_option='test-then-set')
    message_id1 = rpc.id

    config_remote_node = create_outbound_config(info_rekey.spi_in_new, ipsa.ip_remote_data, ipsa.ip_local_data, ipsa.ip_remote_internal, ipsa.ip_local_internal, enc_key, vector, int_key)
    m = hosts[ipsa.ip_remote_control].manager
    rpc = m.edit_config(target='running', config=config_remote_node, test_option='test-then-set')
    message_id2 = rpc.id

    log_writeln("IDs Outbound: spi_in_old = " + str(ipsa.spi_in) + " spi_out_old = " + str(ipsa.spi_out) +
                "Outbound ID 1 = " + message_id1 + " Outbound ID 2 = " + message_id2 + "\n")

    add_rpc_ids(ipsa.spi_in, message_id1, message_id2)
    info_rekey.msg_id1 = message_id1
    info_rekey.msg_id2 = message_id2
    info_rekey.receive_id1 = False
    info_rekey.receive_id2 = False
    info_rekey.state = StateRekey.OUTBOUND

    add_active_rekeys_information(ipsa.spi_in, info_rekey)

    log_writeln("Rekey : spi_in_old = " + str(ipsa.spi_in) + " spi_out_old = " + str(ipsa.spi_out) +
                "spi_in_new = " + str(info_rekey.spi_in_new) + " spi_out_new = " + str(info_rekey.spi_out_new)
                + " -----> Outbound is sent" + "\n")


# Procedure delete - Rekey - Phase 3
def delete_rekey(ipsa):
    info_rekey = active_rekey_information.get(ipsa.spi_in)

    config_local_node = delete_config(ipsa.ip_local_data,ipsa.ip_remote_data, ipsa.ip_local_internal, ipsa.ip_remote_internal, ipsa.spi_in, ipsa.spi_out, old_enc_key, old_vector, old_int_key)
    m = hosts[ipsa.ip_local_control].manager
    rpc = m.edit_config(target='running', config=config_local_node, test_option='test-then-set')
    message_id1 = rpc.id

    config_remote_node = delete_config(ipsa.ip_remote_data, ipsa.ip_local_data, ipsa.ip_remote_internal, ipsa.ip_local_internal, ipsa.spi_out, ipsa.spi_in, old_enc_key, old_vector, old_int_key)
    m = hosts[ipsa.ip_remote_control].manager
    rpc = m.edit_config(target='running', config=config_remote_node, test_option='test-then-set')
    message_id2 = rpc.id
    log_writeln("IDS Delete: spi_in_old = " + str(ipsa.spi_in) + " spi_out_old = ""Inbound ID 1 = " + message_id1 +
                " Inbound ID 2 = " + message_id2 + "\n")

    add_rpc_ids(ipsa.spi_in, message_id1, message_id2)
    info_rekey.msg_id1 = message_id1
    info_rekey.msg_id2 = message_id2
    info_rekey.receive_id1 = False
    info_rekey.receive_id2 = False
    info_rekey.state = StateRekey.DELETE

    add_active_rekeys_information(ipsa.spi_in, info_rekey)
    log_writeln("Rekey : spi_in_old = " + str(ipsa.spi_in) + " spi_out_old = " + str(ipsa.spi_out) +
                "spi_in_new = " + str(info_rekey.spi_in_new) + " spi_out_new = " + str(info_rekey.spi_out_new)
                + " -----> Delete is sent" + "\n")


# Procedure for deleting and updating SAs Information  - Rekey - Phase 4
def update_structures(ipsa):
    info_rekey = active_rekey_information.get(ipsa.spi_in)

    ipsa_new_1 = Ipsa(ipsa.ip_local_control, ipsa.ip_local_data, ipsa.ip_local_internal, ipsa.ip_remote_control, ipsa.ip_remote_data, ipsa.ip_remote_internal,
                      info_rekey.spi_in_new, info_rekey.spi_out_new)

    ipsa_new_2 = Ipsa(ipsa.ip_remote_control, ipsa.ip_remote_data, ipsa.ip_remote_internal, ipsa.ip_local_control, ipsa.ip_local_data, ipsa.ip_local_internal,
                      info_rekey.spi_out_new, info_rekey.spi_in_new)

    add_ipsec_association(ipsa_new_1)
    add_ipsec_association(ipsa_new_2)

    delete_ipsec_association(ipsa.spi_in)
    delete_ipsec_association(ipsa.spi_out)

    delete_active_rekeys(ipsa.spi_in, ipsa.spi_out)

    delete_active_rekeys_information(ipsa.spi_in)
    log_writeln("Rekey : spi_in_old = " + str(ipsa.spi_in) + " spi_out_old = " + str(ipsa.spi_out) +
                "spi_in_new = " + str(info_rekey.spi_in_new) + " spi_out_new = " + str(info_rekey.spi_out_new)
                + " -----> Structures Updated" + "\n")


class Host:
    def __init__(self, ip_data, ip_internal, manager):
        self.ip_data = ip_data
	self.ip_internal = ip_internal
        self.manager = manager


class Ipsa:
    def __init__(self, ip_local_control, ip_local_data, ip_local_internal, ip_remote_control, ip_remote_data, ip_remote_internal, spi_in, spi_out):
        self.ip_local_control = ip_local_control
        self.ip_local_data = ip_local_data
        self.ip_remote_control = ip_remote_control
        self.ip_remote_data = ip_remote_data
	self.ip_local_internal = ip_local_internal
        self.ip_remote_internal = ip_remote_internal
        self.spi_in = spi_in
        self.spi_out = spi_out


class Listener(SessionListener):
    def errback(self, ex):
        pass

    def callback(self, root, raw):
        tag, _ = root

        if tag == qualify('notification', NETCONF_NOTIFICATION_NS):  # check if it is a Netconf notification
            log_writeln("Notification -> " + raw + "\n")
            root = etree.fromstring(raw)
            pool.add_task(analyze_notification, root)
        else:  # RCP Notification
            rpc_reply = raw
            pool.add_task(analyze_rpc_reply, rpc_reply)


class InformationRekey:
    def __init__(self, spi_in_new, spi_out_new, msg_id1, msg_id2, receive_id1, receive_id2, state):
        self.spi_in_new = spi_in_new
        self.spi_out_new = spi_out_new
        self.msg_id1 = msg_id1
        self.msg_id2 = msg_id2
        self.receive_id1 = receive_id1
        self.receive_id2 = receive_id2
        self.state = state


class Worker(Thread):
    # Thread executing tasks from a given tasks queue

    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args = self.tasks.get()
            try:
                func(args[0])
            except Exception as e:
                # An exception happened in this thread
                log_writeln(str(e))
                log_writeln(traceback.format_exc())
            finally:
                # Mark this task as done, whether an exception happened or not
                self.tasks.task_done()


class ThreadPool:
    # Pool of threads consuming tasks from a queue

    def __init__(self, num_threads):
        self.tasks = Queue()
        for _ in range(num_threads):
            workers.append(Worker(self.tasks))

    def add_task(self, func, *args):
        # Add a task to the queue
        self.tasks.put((func, args))


if __name__ == '__main__':
    print("Starting the controller...")
    pool = ThreadPool(20) #15
    create_random_keys()
    init_controller()
