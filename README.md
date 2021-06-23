# Escenarios-SDN-IPSEC

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
