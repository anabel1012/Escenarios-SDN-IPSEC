from ncclient import manager
from ncclient.transport.session import *
from xml.dom.minidom import parse, parseString
from lxml import etree
from xml.etree import ElementTree
import xml.etree.ElementTree as ET
from schema import Schema, And, Or, Use, SchemaError, Optional
from jinja2 import Environment, FileSystemLoader
import os
from myconfig import *
from time import sleep


def analyze_notification(notification):
    message = notification.notification_xml

    delete = message.find("delete")
    create = message.find("create")

    if delete > 1:
      return "delete"
    elif (create > 1):
      return "create"
    else:
      return ""

def get_enc_key():
    stream = os.popen('sudo ip xfrm state')

    output = stream.readlines()
    line_split = output[3].split()

    return line_split[2]

def get_variables(results, first_time):
    b = parseString(results).toxml() #.toprettyxml()

    root = ET.fromstring(b)

    if first_time == True:
      gw_row = 12
      enc_row = 10
      gw_col1 = 1
      gw_col2 = 0
    else:
      gw_row = 11
      enc_row = 9
      gw_col1 = 0
      gw_col2 = 1
    
    remote_spi = hex(int(root[1][0][1][0][0].text))
    print("remote_spi " + remote_spi)

    local_spi = hex(int(root[1][0][1][1][0].text))
    print("local_spi " + local_spi)

    tunnel_name = "IPSEC_VPN" + str(local_spi)
    print(tunnel_name)

    remote_gw = root[1][0][1][0][gw_row][gw_col1].text #if fg 12, not 11
    print("remote_gw " + str(remote_gw))

    local_gw = root[1][0][1][0][gw_row][gw_col2].text #if fg 12, not 11
    print("local_gw " + str(local_gw))

    enc_alg = root[1][0][1][0][enc_row][0][0].text #if fg 9, not 10
    print("enc_alg " + enc_alg)

    #enc_key = root[1][0][1][0][enc_row][0][1].text #if fg 9, not 10

    enc_key = get_enc_key()
    #print("enc_key " + enc_key)

    if enc_alg == "3des":
        enc_key = enc_key[2:18] + '-' + enc_key[18:34] + '-' + enc_key[34:]
        #print("enc_key " + enc_key)

    remote_internal = "192.168.201.0/24"
    print("remote_internal " + remote_internal)

    return remote_spi, local_spi, tunnel_name, remote_gw, local_gw, enc_alg, enc_key, remote_internal


def test():
    print("Waiting por connection...")
    with manager.connect(host="192.168.159.34", port=830, username="osm",
                         password="osm4u", hostkey_verify=False,
                         device_params={'name': 'default'},
                         allow_agent=False, look_for_keys=False) as m:

      m.create_subscription()
      print("Connected to netopeer server")
      global old_tunnel_name, old_enc_key, old_remote_spi, old_local_spi
      global tunnel_name, enc_key, remote_spi, local_spi, remote_internal, local_gw, remote_gw, enc_alg
      enc_key = ""
      tunnel_name = ""
      remote_spi = ""
      local_spi = ""
      first_time = True
      #results = m.get_config('running').data_xml
      while True:
        try:
          n = m.take_notification()
          print("Notification received")
          notification = analyze_notification(n)
          if notification == "create":
            #if notification == "delete":
             # print("notification delete")
          
            #if notification == "create":
            results = m.get_config('running').data_xml
            #print(results)
            print("Generating xml...")

            old_enc_key = enc_key
            old_tunnel_name = tunnel_name
            old_remote_spi = remote_spi
            old_local_spi = local_spi

            (remote_spi, local_spi, tunnel_name, remote_gw, local_gw, enc_alg, enc_key, remote_internal) = get_variables(results, first_time)
            #print("old_enc_key " + old_enc_key + "enc_key:" + enc_key)
            #print("old_tunnel_name " + old_tunnel_name + "tunnel_name:" + tunnel_name)
            #print("old_local_spi " + old_local_spi + "local_spi:" + local_spi)
            #print("old_remote_spi " + old_remote_spi + "remote_spi" + remote_spi)
            generate_ansible_create()
            first_time = False

          if first_time == False and notification == "delete":
            results = m.get_config('running').data_xml
            #print(results)
            print("Generating xml...")

            old_enc_key = enc_key
            old_tunnel_name = tunnel_name
            old_remote_spi = remote_spi
            old_local_spi = local_spi

            (remote_spi, local_spi, tunnel_name, remote_gw, local_gw, enc_alg, enc_key, remote_internal) = get_variables(results, first_time)
            #print("old_enc_key " + old_enc_key + "enc_key:" + enc_key)
            #print("old_tunnel_name " + old_tunnel_name + "tunnel_name:" + tunnel_name)
            #print("old_local_spi " + old_local_spi + "local_spi:" + local_spi)
            #print("old_remote_spi " + old_remote_spi + "remote_spi" + remote_spi)
            #generate_ansible_create()
            generate_ansible_delete()
        except KeyboardInterrupt:
          # An exception happened in this thread
          sys.exit(0)



def generate_ansible_create():
    print("Generating ansible yaml for create...")
    file=open("fortinet_ansible.yaml", "w+")
    env = Environment(loader = FileSystemLoader('/home/osm/i2nsf_server/converter/'), trim_blocks=True, lstrip_blocks=True)
    template = env.get_template('allinone.yaml')
    file.write(template.render(host=host, username=user, password=password, vdom="root",local_gw=local_gw, remote_gw=remote_gw, local_spi=local_spi, remote_spi=remote_spi, enc_alg=enc_alg, enc_key=enc_key, remote_internal=remote_internal, tunnel_name=tunnel_name ))
    file.close()

    os.system('sudo ansible-playbook -v fortinet_ansible.yaml')

def generate_ansible_delete():
    print("Generating ansible yaml for create...")
    file=open("delete_fortinet_ansible.yaml", "w+")
    env = Environment(loader = FileSystemLoader('/home/osm/i2nsf_server/converter/'), trim_blocks=True, lstrip_blocks=True)
    template = env.get_template('delete_allinone.yaml')
    file.write(template.render(host=host, username=user, password=password, vdom="root",local_gw=local_gw, remote_gw=remote_gw, local_spi=old_local_spi, remote_spi=old_remote_spi, enc_alg=enc_alg, enc_key=old_enc_key, remote_internal=remote_internal, tunnel_name=old_tunnel_name ))
    file.close()

    os.system('sudo ansible-playbook -v delete_fortinet_ansible.yaml')


if __name__ == '__main__':
    if converter == True:
        print("Starting the converter...")
        for x in range(0, 40): # try 40 times
            try:
           # msg.send() put your logic here
                test()
            except Exception as str_error:
                pass

            if str_error:
                sleep(1) # wait for 1 second before trying to fetch the data again
            else:
                break

    else:
        print("No converter")

