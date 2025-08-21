# -Chronos---A-Time-Dilation-C2-Channel-Using-Network-Timing-Covert-Channels
Chronos is a proof-of-concept covert command-and-control (C2) framework that uses ICMP echo packets with timing-based encoding for stealthy communication between an attacker (controller) and a victim (implant).



> ⚠️ **Disclaimer:** This project is developed strictly for **educational and research purposes** in covert channels and network security.  
Do not use on systems you do not own or have explicit permission to test.

---

## ✨ Features
- 🔐 **AES-128-CBC Encryption** – Secures command & response traffic<br>
- ⏱ **Timing Channel Encoding** – Short delay (`0`), Long delay (`1`)<br>
- 📡 **Bidirectional Communication** – Commands + Victim output exfiltration<br>
- 🖥 **Remote Command Execution** – Implant executes attacker-sent commands<br>
- 🎭 **Stealth Design** – Uses ICMP echo requests, no payload modification<br>
- ⚙️ **Cross-Platform Compatible** – Tested with Linux controller & Windows implant<br>

---

## 🛠 Components<br>
- **`controller.py`** → Attacker-side C2 controller <br> 
- **`implant.py`** → Victim-side implant (executes received commands)  

---

## 🚀 How It Works<br>
1. **Controller** encrypts a command and encodes it into ICMP packet timings.  <br>
2. **Implant** listens, decodes timings, decrypts the command, and executes it.<br>  
3. **Implant** encrypts the command output and sends it back using ICMP timings.<br>  
4. **Controller** decodes and displays the victim’s response.  

---

 📦 Installation & Usage <br>

 1️⃣ Clone the repository:
git clone https://github.com/Adijadhav898/-Chronos---A-Time-Dilation-C2-Channel-Using-Network-Timing-Covert-Channels.git





2️⃣ Dependencies <br>

Install required Python packages: <br>
pip install scapy pycryptodome






3️⃣ Setup <br>
Update IP addresses in controller.py and implant.py <br>
VICTIM_IP → Victim machine IP <br>
ATTACKER_IP → Attacker machine IP <br>
Run with root/admin privileges (ICMP sniffing requires it).






4️⃣ Running<br>
On Victim machine (implant): <br>
python implant.py <br>
On Attacker machine (controller): <br>
python controller.py <br>
Enter commands at the chronos> prompt. <br>
Example:chronos> whoami






📂 Project Structure <br>
ChronosEcho/ <br>
├── controller.py   # Controller (attacker side) <br>
├── implant.py      # Implant (victim side) <br>
└── README.md       # Project documentation <br>




📚 Research Focus <br>

This project demonstrates: <br>
Covert timing channels <br>
Encrypted C2 communications <br>
ICMP-based evasion techniques <br>
Practical adversary simulation for Red Team/Blue Team exercises<br>





⚠️ Legal Notice <br>

Using this tool against networks, systems, or devices without prior consent is illegal. <br>
The author takes no responsibility for misuse. Use only in controlled, authorized environments. <br>




Developed by [Aditya Jadhav]
