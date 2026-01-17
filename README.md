# C-Shark — The Command-Line Packet Predator

C-Shark is a multithreaded packet sniffer built using libpcap.  
It captures, decodes, and displays detailed information about network packets across Ethernet, SLL, IPv4, IPv6, TCP, UDP, and ARP layers.  

It also supports session inspection, allowing you to review previously captured packets after a sniffing session.

---

## Features

- Captures packets live from network interfaces using libpcap
- Supports Ctrl+C to stop capturing and return to menu
- Supports Ctrl+D (via a monitoring thread) to gracefully exit
- Layered decoding:
  - L2: Ethernet & SLL
  - L3: IPv4, IPv6, ARP
  - L4: TCP, UDP
  - L7: App-level protocol hints (HTTP, HTTPS, DNS)
- Provides packet summaries and full hex dumps
- Stores captures in memory for post-capture inspection
- Thread-safe session handling with pthread

---

## Project Structure

| File | Description |
|------|--------------|
| cshark_p1.c | Main program (menu, device listing, packet capture loop) |
| cshark_p2.c / .h | Layer 3–4 decoders (IP, TCP, UDP, ARP, etc.) |
| cshark_p3.c / .h | Filtered capture support using BPF filters |
| cshark_p4.c / .h | Session storage and packet inspection logic |
| helper.c / .h | Top-level protocol dispatcher (Ethernet/SLL/IP autodetection) |
| Makefile | Build script for cshark executable |

---

## Build Instructions

### For Linux

Ensure you have the libpcap development package installed:

```bash
sudo apt install libpcap-dev
```

Then simply build the project using:

```bash
make
```

This will produce an executable named cshark.

Running C-Shark

Run the program with superuser privileges to access network interfaces:

```bash
sudo ./cshark
```

| Action       | Key    | Description                                              |
| ------------ | ------ | -------------------------------------------------------- |
| Stop Capture | Ctrl+C | Stops packet capture and returns to main menu            |
| Exit Program | Ctrl+D | Gracefully exits the program (detected via stdin thread) |

## Usage Flow

### 1. Select an Interface
The tool lists all available network interfaces detected by **libpcap**.

### 2. Choose an Operation
You can select one of the following options:
- **Start Sniffing (all packets)**
- **Start Sniffing (with filters)**
- **Inspect last capture session**
- **Exit**

### 3. Capture Packets
Each packet is decoded and displayed layer-by-layer.  
Captured packets are stored in memory for later inspection.

### 4. Inspect Stored Packets
View stored packet summaries and perform detailed **hex + ASCII** dumps for analysis.


## Technical Notes

- Uses **POSIX threads (pthread)** to monitor standard input for **Ctrl+D** concurrently with the `pcap_loop`.
- `pcap_breakloop()` ensures clean termination of capture sessions.
- Thread synchronization is handled with **pthread_mutex_t** in the session storage layer (`p4`).
- Supports fallback decoding for **raw IP** and **Linux cooked (SLL)** datalinks.

---

## Dependencies

- **libpcap**  
- **pthread**  
- **Standard C libraries** (`stdio`, `stdlib`, `string.h`, etc.)

## Authors & Credits

- **Developer:** Asritha Singam  
