# Overview

## I2NSF
A Network Security Function (NSF) is a function used to ensure integrity, confidentiality, or availability of network communications, to detect unwanted network activity, or to block or at least mitigate the effects of unwanted activity.

The goal of **I2NSF** is to define a set of software interfaces and data models for controlling and monitoring aspects of physical and virtual NSFs, enabling clients to specify rulesets. 

Standard interfaces for monitoring and controlling the behavior of NSFs are essential building blocks for providers of security service to automate the use of different NSFs from multiple vendors. 
______________

## Software-Defined Networking (SDN)-based IPsec Flow Protection

The project focuses on the NSF Facing Interface by providing models for configuration and state data required to allow the Security Controller to configure the IPsec databases.

There are two main well-known scenarios in IPsec: (i) gateway-togateway and (ii) host-to-host. The SDN-based service described in this project allows the distribution and monitoring of IPsec information from a Security Controller to one or several flow-based Network Security Function (NSF). The NSFs implement IPsec to protect data traffic between network resources.

Two cases are considered, depending on whether the NSF ships an IKEv2 implementation or not: IKE case and IKE-less case. We are going to be focused in the last one, **IKE-less case**.

On this case, the NSF only implements the IPsec databases (no IKE implementation). The Security Controller will provide the required parameters to create valid entries in the SPD and the SAD into the NSF. Therefore, the NSF will have only support for IPsec while automated key management functionality is moved to the Security Controller.

IETF Working Draft at [https://tools.ietf.org/html/draft-ietf-i2nsf-sdn-ipsec-flow-protection].
______________

## Components:

- **SDN Controller**. It is based on ncclient, a Python library that facilitates client-side scripting and application development around the NETCONF protocol. It can be found at i2nsf_controller repository [https://pdihub.hi.inet/cne/i2nsf_controller] .

- **Server**. This NETCONF/YANG module is based on Netopeer2. This repository is focused on this server component.
	- **Converter**. A Netconf to Ansible converter has been developed under the server module. It makes possible the IPSEC tunnel establishment between linux and others vendors like Fortinet.

# Requirements
- Python 2.7+
	- Ansible. 
	- Ncclient.
- Supervisor
- Netopeer2
- Libyang
- Libnetconf2
- Sysrepo
- Strongswan
- Cfgipsec2


A .raw image can be found in Openstack, so that it is not necessary to install the required software. Just launch an instance!

Image files to use:
- Controller: i2nsf-controller
- Server: i2nsf-server

## Server module - Supervisor

Server module has been developed to working for both h2h and g2g scenarios.

The main difference between them is that i2nsf converter has only been developed for g2g scenario, so if you want to use it, you need to specify it in the config file: converter=True/False.

On the server module, you need to start different services: 

- ietf-ipsec
- ipsec 
- netopeer2-server
- netopeer-config.sh bash script to register the server on the controller.
- converter python script if it is needed.

**Supervisor** is used to monitor and control all this processes related to the server. Basic commands of supervisor that you might need later on for checking the status supervisor or restarting the service.


Checking the status of supervisor

`$ sudo systemctl status supervisor`

Starting supervisor

`$ sudo systemctl start supervisor`

Stopping and restarting supervisor

`$ sudo systemctl stop supervisor`

`$ sudo systemctl restart supervisor`

To get supervisor to execute all those programs or scripts, we can configure it in the /etc/supervisor/conf.d/ directory.

Therefore, you have to copy/move the file **supervisor.conf**   found at this repository to /etc/supervisor/conf.d/.

## Scenarios 

If converter is needed, you need to configure *myconfig.py* file. You have to mark converter as True. Also, you have to indicate the IP of the vendor machine and its user and password.

Before running any scenario, remember to delete previous policies:

`./remove_policies.sh
`

As mentioned, two different scenarios are considered:

- **Host-to-host (h2h)**. N Host SA with ESP in transport mode. 
- **Gateway-to-gateway (g2g).** Gw-2-Gw SA with ESP in tunnel mode.

### 1. host-to-host

N Host SA with ESP in transport mode: Set up a NxN host to host scenario dynamically managed by a python-based controller.

![Example: h2h scenario](https://pdihub.hi.inet/cne/i2nsf_server/blob/master/images/h2h.jpg)
> Example: h2h scenario
#### Controller

For this scenario, you need 'controller.py' file from i2nsf_controller repository []. 
- Starting the controller: python controller.py
- To check logs: sudo tail -f times.log

#### Server

Once you have run the controller, you have to start supervisor: 

    sudo systemctl start supervisor

To verify the state of the tunnel, you can see SPD and SAD models:

    sudo ip xfrm state
    sudo ip xfrm policy

Finally, you can make a ping to the another server and capture the traffic to check if the packets are encapsulated with ESP protocol:

    sudo tcpdump -i eth1 esp


### 2. gateway-to-gateway

Gw-2-Gw SA with ESP in tunnel mode (case 2- no IKE). Set up a NxN gateway to gateway scenario  dynamically managed by a python-based controller.

![Example: g2g scenario](https://pdihub.hi.inet/cne/i2nsf_server/blob/master/images/g2g.jpg)
> Example: g2g scenario

*Note: Hosts must have as default route the gateway ip.

#### Controller

For this scenario, you need 'tunnel_controller.py' file from i2nsf_controller repository.
- Starting the controller: python tunnel_controller.py
- To check logs: sudo tail -f times.log

#### Server

Once you have run the controller, you have to start supervisor.

    sudo systemctl start supervisor

To verify the state of the tunnel, you can see SPD and SAD models:

    sudo ip xfrm state
    sudo ip xfrm policy

Finally, you can make a ping from one host to another and capture the traffic on a gateway to check if the packets are encapsulated with ESP protocol:

    sudo tcpdump -i eth1 esp
    
#### Converter

For using the converter:

1. Run converter.py (found at converter folder)
2. Start supervisor on server

![Example: g2g scenario with converter](https://pdihub.hi.inet/cne/i2nsf_server/blob/master/images/g2g_converter.jpg)
> Example: g2g scenario with converter


