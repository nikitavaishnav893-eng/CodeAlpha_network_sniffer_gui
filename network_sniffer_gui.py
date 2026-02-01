import threading
from tkinter import *
from scapy.all import sniff, IP, TCP, UDP, ICMP

sniffing = False

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "OTHER"

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        output = f"Source: {src_ip}  -->  Destination: {dst_ip}  |  Protocol: {protocol}\n"
        text_area.insert(END, output)
        text_area.see(END)

def start_sniffing():
    global sniffing
    sniffing = True
    status_label.config(text="Status: Sniffing...", fg="green")
    threading.Thread(target=sniff_packets, daemon=True).start()

def sniff_packets():
    sniff(prn=packet_callback, stop_filter=lambda x: not sniffing)

def stop_sniffing():
    global sniffing
    sniffing = False
    status_label.config(text="Status: Stopped", fg="red")

root = Tk()
root.title("Basic Network Sniffer - Internship Project")
root.geometry("900x500")

Label(root, text="Basic Network Sniffer (GUI)", font=("Arial", 16, "bold")).pack(pady=10)
status_label = Label(root, text="Status: Stopped", fg="red", font=("Arial", 12))
status_label.pack()

frame = Frame(root)
frame.pack(pady=10)

Button(frame, text="Start Sniffing", bg="green", fg="white", width=15, command=start_sniffing).grid(row=0, column=0, padx=10)
Button(frame, text="Stop Sniffing", bg="red", fg="white", width=15, command=stop_sniffing).grid(row=0, column=1, padx=10)

text_area = Text(root, height=20, width=110)
text_area.pack(pady=10)

root.mainloop()
