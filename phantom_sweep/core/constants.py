"""
Common constants used across the application
"""

# Port lists

with open("phantom_sweep/core/top_1000_ports_tcp.txt", "r") as f:
    TOP_1000_PORTS_SERVICES_TCP = f.read().splitlines()

TOP_1000_PORTS_TCP      = [int(port.split(":")[1])  for port in TOP_1000_PORTS_SERVICES_TCP]
TOP_1000_SERVICES_TCP   = [port.split(":")[0]       for port in TOP_1000_PORTS_SERVICES_TCP]

TOP_100_PORTS_TCP = TOP_1000_PORTS_TCP[0:100]
TOP_100_SERVICES_TCP = TOP_1000_SERVICES_TCP[0:100]

with open("phantom_sweep/core/top_1000_ports_udp.txt", "r") as f:
    TOP_1000_PORTS_SERVICES_UDP = f.read().splitlines()

TOP_1000_PORTS_UDP      = [int(port.split(":")[1])  for port in TOP_1000_PORTS_SERVICES_UDP]
TOP_1000_SERVICES_UDP   = [port.split(":")[0]       for port in TOP_1000_PORTS_SERVICES_UDP]

TOP_100_PORTS_UDP = TOP_1000_PORTS_UDP[0:100]
TOP_100_SERVICES_UDP = TOP_1000_SERVICES_UDP[0:100]

# # Top 100 most common ports for fast scanning
# TOP_100_PORTS = [
#     7, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
#     1723, 3306, 3268, 3269, 3389, 5900, 8080, 8443, 1025, 1026, 1027, 1028, 1029, 1030,
#     113, 199, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873,
#     902, 1080, 1099, 123, 137, 138, 161, 162, 177, 1720, 2000, 2049, 2121,
#     2717, 3000, 3128, 3478, 3702, 49152, 49153, 49154, 49155, 49156, 49157,
#     500, 5060, 5222, 5223, 5228, 5357, 5432, 5631, 5666, 6000, 6001, 6646,
#     7070, 8000, 8008, 8009, 8081, 8888, 9100, 9999, 10000, 32768, 49158,
#     49159, 49160, 49161, 49162, 49163
# ]

# TOP_1000_PORTS = TOP_100_PORTS + [
#     # Additional common ports to reach ~1000
#     20, 26, 42, 69, 88, 106, 109, 115, 118, 119, 1433, 1434, 1521, 1720, 1863,
#     2001, 2002, 2222, 2375, 2376, 3001, 3307, 3388, 4000, 4001, 4100, 4500,
#     5000, 5001, 5433, 5500, 5601, 6379, 7001, 7002, 8001, 8002, 8082, 8083,
#     8444, 8889, 9000, 9001, 9200, 9300, 11211, 27017, 27018, 28015, 50000
# ] + list(range(49164, 49200))  # Additional dynamic ports
