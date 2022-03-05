# Infrastructure Security in an AMS Cluster

### Basic Components

A typical AMS cluster comprises 7 VMs:
- 1 Haproxy VM
- 3 Kafka/Zookeeper/AMS VMs
- 3 MongoDB VMs(secondary, primary, arbiter)

### Public Access
The Haproxy instance supports the https protocol with all of its clients/frontends and binds
to a public IP.It uses the round-robin algorithm to distribute requests to the various
ams backends.The communication with the respective AMS also happens over https to their public IPs.

### Private Access
Despite the fact that all the VMs hold public IPs,all the fore mentioned VMs share the same
private network and as a result zookeeper, kafka and mongo,
all bind on ports that belong to the network interface that represents the private IP
for both intra communication(kafka -> kafka, zookeeper -> zookeeper, mongo -> mongo)
and outer communication(service -> service).Service to service communication does not
use TLS.

### Firewall
We have two available zones, one for public access and one for private access.We bind each zone to
the respective network interface.We then create a service for each of the installed services we have
and assign the service to the appropriate zone alongside with its port(s).The fore mentioned set up
is configured using firewall-cmd on centos platforms

