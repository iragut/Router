# Router
This project simulate a router in a virtual enviroment using mininet
The following protocols whas implemented:

 - Dynamical ARP
 - IPv4
 - ICMP

### 1. IPv4 :
This protocols simple check if the checksume is good, ttl has not been expired,
and find in the routing table best route , and check in the cache for the **MAC**, if dont exist send a **ARP** request.

 -- The search for the best route, whas implemented with **32 bits Trie**
 -- If ttl is expired or the best route whas not found, the router send a **ICMP**
### 2. Dynamical ARP :
This protocol find the **MAC** adresses for the host if the router don't have it.

### 3. ICMP:
The protocol what send back the packet if ttl expired, the route don't exist or the packet whas for router.

