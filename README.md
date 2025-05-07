# 🔍 ELK Stack for User Activity Monitoring

This project sets up an **ELK Stack (Elasticsearch, Logstash, Kibana)** using Docker to monitor and analyze Windows user activity logs via **Winlogbeat**. It is designed for IT administrators, SOC teams, or security professionals to centralize and visualize Windows event logs in real time.

---

## 📆 Stack Overview

| Component        | Purpose                                                            |
| ---------------- | -------------------------------------------------------------------|
| 🔍 Elasticsearch | Stores and indexes event logs.                                     |
| 🔊 Logstash      | Processes incoming logs from Winlogbeat.                           |
| 🔺 Kibana        | Visualizes log data with dashboards.                               |
| 🔧 Winlogbeat    | Collects logs from Windows machines and sends them to Logstash.    |

---

## 📁 Project Setup

** In Linux Machine **

```bash
ELK-Stack/
├── docker-compose.yml
└── logstash
    ├── config
    │   ├── jvm.options
    │   ├── logstash.yml
    │   └── pipelines.yml
    └── pipeline
        └── logstash.conf		
```

** In Windows Machine **

```powershell
Winlogbeat.yml (in windows)
```

---

## 🛠️ Architecture
```
┌─────────────────┐     ┌─────────────────────────────────────────┐
│                 │     │                                         │
│  Windows Client │     │           Linux Server (Docker)         │
│  ┌───────────┐  │     │  ┌─────────┐  ┌────────┐  ┌────────┐    │
│  │           │  │     │  │         │  │        │  │        │    │
│  │ Winlogbeat├─────────► │Logstash ├─►│Elastic ├─►│ Kibana │    │
│  │           │  │     │  │         │  │search  │  │        │    │
│  └───────────┘  │     │  └─────────┘  └────────┘  └────────┘    │
│                 │     │                                         │
└─────────────────┘     └─────────────────────────────────────────┘
```
---

## ✨ Features

* ✅ Centralized log monitoring for multiple Windows systems
* ✅ Indexed logs by category (security, sysmon, powershell, etc.)
* ✅ Real-time dashboards and visualizations in Kibana
* ✅ Fine-tuned Winlogbeat configuration for enhanced observability
* ✅ Scalable and modular Docker deployment

---

## ⚙️ Getting Started

### 1. 🔽 Clone the Repository

```bash
git clone https://github.com/Kernel-Freak/ELK-Stack-for-User-Activity-Monitoring.git
cd /ELK-Stack-for-User-Activity-Monitoring/ELK-Stack
```

### 2. ▶️ Launch the ELK Stack

```bash
docker-compose up -d
```

This will start:

* **Elasticsearch**: [http://localhost:9200](http://localhost:9200)
* **Logstash**: Listens on port `5044`
* **Kibana**: [http://localhost:5601](http://localhost:5601)

---

## 🔊 Install & Configure Sysmon (For advanced logging)

### What is Sysmon?

[Sysmon (System Monitor)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) is a Windows system service and device driver that logs system activity to the Windows event log. It provides detailed information about process creations, network connections, and file time changes.

### 1. Download Sysmon

* [Download Sysmon from Microsoft](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

### 2. Use a Trusted Sysmon Configuration

Use [Olaf Hartong's Sysmon Modular Configuration](https://github.com/olafhartong/sysmon-modular) for advanced coverage:

```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml -OutFile sysmonconfig.xml
```

> 💡 Tip: You can customize this config or use the merged `sysmonconfig.xml` from the repo.

### 3. Install Sysmon with Configuration

```powershell
sysmon64.exe -accepteula -i sysmonconfig.xml
```

### 4. Verify Installation

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Format-Table -Wrap
```

### 5. Configure Winlogbeat to Forward Sysmon Logs

Add the Sysmon log channel in your Winlogbeat config:

```yaml
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
    tags: ["sysmon"]
```

---

## 🔧 Configure Winlogbeat on Windows

	1. Download [Winlogbeat](https://www.elastic.co/beats/winlogbeat) on the Windows machine you want to monitor.

	2. Extract the package:
	   * Extract the zip file to `C:\Program Files\Winlogbeat`
	
	3. Replace the configuration:
	   * Save the enhanced configuration I provided as `C:\Program Files\Winlogbeat\winlogbeat.yml` 
	   
	   > 💡 Tip: Change the ip address as per you Configuration
	   
	4. Install Winlogbeat as a service:

       * Open PowerShell as Administrator
       * Navigate to the Winlogbeat directory  

		```powershell
		cd 'C:\Program Files\Winlogbeat'
		```
		
		* Run the installation script:
		```powershell
		# Only needed the first time
		PowerShell.exe -ExecutionPolicy UnRestricted -File .\install-service-winlogbeat.ps1
		```
		
	5. Test the configuration:
	    
	   ```powershell
	   .\winlogbeat.exe test config -c .\winlogbeat.yml
	   ```
	   
	6. Test the output connections:
	
	   ```powershell
	   .\winlogbeat.exe test output -c .\winlogbeat.yml
	   ```
	   
	7. Start the Winlogbeat service:
	
	   ```powershell
	   Start-Service winlogbeat
	   ```
	   
	8. Check the service status:
	   
	   ```powershell
	   Get-Service winlogbeat
	   ```
	   
### Example Configuration Highlights

```yaml
winlogbeat.event_logs:
  - name: Security
    event_id: 4624,4625,4688,4697,...
    fields:
      index: "win_security"
    tags: ["security"]

output.logstash:
  hosts: ["192.168.10.33:5044"] 	(Change the ip address as per you Configuration)

setup.kibana:
  host: "192.168.10.33:5601"

logging.level: debug
```

---

## 🔍 Access Kibana

Go to [http://localhost:5601](http://localhost:5601) to start exploring:

* **Discover** tab for raw logs
* **Visualizations** for dashboards
* **Alerts** and rules for threat monitoring

---

## 📋 Configuration Overview

### docker-compose.yml

* Elasticsearch, Logstash, and Kibana using version `8.12.0`
* Uses `volumes` for persistent data
* Exposes standard ports: 9200 (ES), 5044 (Logstash), 5601 (Kibana)

### logstash/config/logstash.yml

```yaml
http.host: "0.0.0.0"
queue.type: memory
pipeline.batch.size: 125
pipeline.batch.delay: 5
```

### logstash/config/pipelines.yml

```yaml
- pipeline.id: main
  path.config: "/usr/share/logstash/pipeline/logstash.conf"
```

### Winlogbeat (Agent)

Includes:

* Security events: logon/logoff, account use, privilege escalation
* Sysmon: detailed process, file, network events
* PowerShell: execution and script block logging
* Forwarded events

Set up to send logs to `192.168.10.33:5044` (Logstash), dashboards to Kibana.

---

## 🔒 Security Notes

* This stack is meant for **internal or testing environments**.
* For production:

  * Enable Elasticsearch/Kibana authentication
  * Use TLS for Logstash input
  * Lock down firewall rules
  * Use role-based access control

---

## 📄 Useful Commands

1. Check container logs
```bash
docker-compose logs -f logstash
```

2. Restart the ELK stack
```bash
docker-compose down && docker-compose up -d
```

3 View Winlogbeat logs (Windows)
```powershell
Get-Content "C:\Program Files\Winlogbeat\logs\winlogbeat.log" -Tail 50 -Wait
```

---

## 📊 Sample Dashboards to Build

* **User Login Timeline**
* **Failed Login Heatmap**
* **PowerShell Command Execution**
* **New Account Creation Alerts**
* **Process Tree from Sysmon**

---

## 📖 References

* [Elastic Winlogbeat Docs](https://www.elastic.co/guide/en/beats/winlogbeat/current/index.html)
* [Sysmon Event IDs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
* [Windows Security Event IDs](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-audit)

---

## 🤝 Contributing

Want to make this tool even better? PRs and suggestions are welcome!

1. Fork the repo
2. Create a feature branch
3. Submit a pull request

---

## 📝 License

This project is licensed under the [MIT License](LICENSE).

---

## 👤 Contact / Author Info

- **Samrat Mandal**  
- 📧 samratmandal423@gmail.com  
- 🌐 [GitHub](https://github.com/Kernel-Freak) | [LinkedIn](https://www.linkedin.com/in/samrat7/)

For additional questions or further discussion, please feel free to contact the author.