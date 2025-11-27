# Pleroma Sentinel Dashboard - Interview Guide

## 🎯 System Overview

**Pleroma** is a threat detection and network security monitoring platform that combines:
- **Network Scanning** - Automated port/service/vulnerability discovery
- **Machine Learning** - CVE → CWE → CAPEC pattern prediction
- **Petri Net Modeling** - Visual representation of network processes and threats
- **Threat Detection** - Real-time analysis and risk scoring

**Core Principle**: **Detection Only** - We identify threats, classify them, and score risks. No automated defense actions or fixability predictions.

---

## 📊 Petri Nets: What They Are & How They Work

### What is a Petri Net?

A **Petri Net** is a mathematical modeling tool that represents:
- **Places** (circles) - States or conditions (e.g., "Service Running", "Port Open")
- **Transitions** (rectangles) - Events or actions (e.g., "Connection Established", "Data Transfer")
- **Tokens** - Markers that flow through the net, representing activity/state
- **Edges** - Connections showing how tokens move between places and transitions

### In Our System

Petri nets model your **network infrastructure** and **processes**:

```
Example:
[Port 80 Open] → [HTTP Service] → [Web Server Active]
     (Place)      (Transition)        (Place)
```

**Nodes** represent:
- Network services (web servers, databases, APIs)
- System components (firewalls, load balancers)
- Process states (authentication, data processing)

**Tokens** represent:
- Active connections
- Running processes
- Current state of the system

---

## 🔍 Network Scanning → Petri Net Integration

### Step 1: Network Scan

**What happens:**
1. User configures scan (target IP/range, ports, scan type)
2. System runs `nmap` to discover:
   - Hosts (IP addresses, hostnames)
   - Open ports (22, 80, 443, etc.)
   - Services (SSH, HTTP, HTTPS, MySQL, etc.)
   - Service versions
   - Operating systems
   - **Vulnerabilities** (CVEs discovered)

**Input:**
```json
{
  "target": "192.168.1.0/24",
  "ports": "22,80,443,3306",
  "vulnScan": true,
  "scanType": "comprehensive"
}
```

**Output:**
```json
{
  "hosts": [
    {
      "ip": "192.168.1.100",
      "hostname": "web-server",
      "os": "Linux 5.4",
      "services": [
        {
          "port": 80,
          "protocol": "tcp",
          "service": "http",
          "version": "nginx 1.18.0"
        }
      ],
      "vulnerabilities": [
        {
          "cve": "CVE-2024-1234",
          "severity": 7.5,
          "description": "Remote code execution in nginx"
        }
      ]
    }
  ]
}
```

### Step 2: Data Import

**What gets stored:**
- **Network Events** (`network_events` table)
  - Host information
  - Services discovered
  - Scan timestamp
  
- **CVE Records** (`cve_records` table)
  - CVE ID (e.g., CVE-2024-1234)
  - Description
  - Severity (CVSS score)
  - Affected component (hostname/service)

### Step 3: ML Threat Prediction

**What happens:**
1. For each discovered CVE, the system:
   - Extracts the CVE description
   - Sends it to the ML model API
   - Receives predictions:
     - **Predicted CWE** (e.g., CWE-79: XSS)
     - **Predicted CAPEC** (e.g., CAPEC-63: XSS via HTML tags)

**Example:**
```
CVE-2024-1234 Description: "Cross-site scripting vulnerability..."
    ↓
ML Model Prediction:
    ↓
CWE: CWE-79 (Cross-site Scripting)
CAPEC: CAPEC-63, CAPEC-209
```

### Step 4: Threat Detection

**What happens:**
1. System analyzes scan results
2. Classifies threats:
   - **Critical** (CVSS ≥ 9.0 or risk ≥ 80)
   - **High** (CVSS ≥ 7.0 or risk ≥ 60)
   - **Medium** (CVSS ≥ 5.0 or risk ≥ 40)
   - **Low** (everything else)
3. Calculates risk scores (0-100)
4. Groups threats by host

**Output:**
```json
{
  "threats": [
    {
      "host": "web-server",
      "ip": "192.168.1.100",
      "threatLevel": "high",
      "riskScore": 75,
      "threats": [
        {
          "type": "vulnerability",
          "severity": 7.5,
          "description": "Remote code execution",
          "cve": "CVE-2024-1234"
        }
      ]
    }
  ]
}
```

### Step 5: Petri Net Generation

**What happens:**
1. System can auto-generate Petri nets from:
   - **Process definitions** (BPMN/JSON workflows)
   - **Network topology** (discovered services)
   
2. Each **node** in the Petri net represents:
   - A network service (e.g., "Web Server", "Database")
   - A process step (e.g., "Authentication", "Data Processing")
   
3. **Tokens** represent:
   - Active connections
   - Running processes
   - Current state

**Example Petri Net Structure:**
```json
{
  "nodes": [
    {
      "id": "web-server",
      "type": "place",
      "data": {
        "label": "Web Server",
        "tokens": 5  // 5 active connections
      },
      "position": { "x": 100, "y": 100 }
    },
    {
      "id": "db-connection",
      "type": "transition",
      "data": {
        "label": "Database Connection"
      },
      "position": { "x": 300, "y": 100 }
    }
  ],
  "edges": [
    {
      "id": "e1",
      "source": "web-server",
      "target": "db-connection"
    }
  ]
}
```

### Step 6: Node Risk Computation

**What happens:**
1. System matches CVEs to Petri net nodes based on:
   - **Component names** (node label matches CVE component)
   - **Description keywords** (CVE description mentions node)
   - **CWE patterns** (node relates to CWE)

2. Calculates **risk scores** for each node:
   - Base: CVSS score × 10 (0-100 scale)
   - Bonus: +5 per additional CVE
   - Token-based: If no CVEs but tokens present, base risk = tokens × 5

3. Links related CVEs and CAPEC patterns to nodes

**Example:**
```
Node: "Web Server" (nginx)
    ↓
Matching CVEs: CVE-2024-1234, CVE-2024-5678
    ↓
Risk Score: 75 (from max CVSS 7.5 × 10)
    ↓
Metadata: {
  "related_cves": ["CVE-2024-1234", "CVE-2024-5678"],
  "related_capecs": ["CAPEC-63"]
}
```

---

## 🔄 Complete Data Flow

```
1. Network Scan
   ↓
2. Discover Hosts/Services/Vulnerabilities
   ↓
3. Import to Database (network_events, cve_records)
   ↓
4. ML Prediction (CVE → CWE/CAPEC)
   ↓
5. Threat Detection (classify & score)
   ↓
6. Petri Net Generation (from processes or topology)
   ↓
7. Node Risk Computation (link CVEs to nodes)
   ↓
8. Display in Dashboard:
   - CVE Cards (with predictions)
   - Petri Net Studio (with risk scores)
   - Threat Detection Page (with classifications)
```

---

## 📥 Expected Inputs for Petri Nets

### From Network Scanning

**Direct Input:**
- **Hosts** → Become Petri net nodes (places)
- **Services** → Become Petri net nodes (places/transitions)
- **Connections** → Become Petri net edges
- **Vulnerabilities** → Link to nodes via risk computation

**Example Mapping:**
```
Scan Result:
  Host: 192.168.1.100
  Services: HTTP (port 80), MySQL (port 3306)
    ↓
Petri Net:
  Node 1: "HTTP Service" (place, tokens = active connections)
  Node 2: "MySQL Service" (place, tokens = active connections)
  Edge: HTTP → MySQL (data flow)
    ↓
Risk Computation:
  CVE-2024-1234 (nginx) → Linked to "HTTP Service" node
  Risk Score: 75
```

### From Process Definitions

**Input Format (JSON):**
```json
{
  "name": "User Authentication Process",
  "definition": {
    "tasks": [
      {
        "id": "start",
        "name": "Start",
        "next": ["validate"]
      },
      {
        "id": "validate",
        "name": "Validate Credentials",
        "next": ["authenticate"]
      },
      {
        "id": "authenticate",
        "name": "Authenticate User",
        "next": ["end"]
      },
      {
        "id": "end",
        "name": "End"
      }
    ]
  }
}
```

**Petri Net Generation:**
- Each `task` → Petri net node
- `next` array → Edges
- `kind: "gateway"` → Transition node
- Default → Place node
- Activity counts → Tokens

**Result:**
```
[Start] → [Validate] → [Authenticate] → [End]
(Place)   (Place)      (Place)        (Place)
```

---

## 🎯 How to Use the System

### 1. Start All Services

```bash
npm start
```

This starts:
- Frontend (port 3000)
- Query API (port 8000)
- Threat Model API (port 8001)

### 2. Network Scanning

**Via UI:**
1. Navigate to **Network Scanner**
2. Enter target (IP/range)
3. Configure ports, scan type, vulnerability scan
4. Click **Run Scan**
5. View results:
   - Hosts discovered
   - Services found
   - Vulnerabilities detected
   - Threats classified

**What You'll See:**
- ✅ Hosts found
- ✅ Services discovered
- ✅ Vulnerabilities detected
- ✅ Threats classified (Critical/High/Medium/Low)
- ✅ ML predictions generated

### 3. View CVE Cards

**After scanning:**
1. Navigate to **CVE Vulnerabilities**
2. See all discovered CVEs
3. Each card shows:
   - CVE ID
   - CVSS Score
   - Description
   - **Predicted CWE** (from ML model)
   - **Predicted CAPEC** (from ML model)
   - Affected component

**Auto-updates every 30 seconds** after a scan.

### 4. Petri Net Studio

**View/Edit Petri Nets:**
1. Navigate to **Petri Net Studio**
2. Select a net from dropdown
3. See nodes with:
   - **Risk scores** (0-100)
   - **Related CVEs** (linked from scan)
   - **Related CAPEC** patterns
   - Token counts

**Create New Net:**
- Import process definition (JSON)
- Or manually create nodes/edges in UI

### 5. Compute Node Risks

**After scanning and creating Petri nets:**
```bash
cd apps/query
npm run compute:risks
```

This:
- Matches CVEs to Petri net nodes
- Calculates risk scores
- Links related CVEs/CAPEC to nodes

**Result:** Nodes in Petri Net Studio show risk scores and related threats.

---

## 💡 Interview Talking Points

### Architecture

**"How does the system work?"**
- **Three-tier architecture**: Frontend (React), Query API (Elysia/Node), Threat Model API (Python/FastAPI)
- **PostgreSQL** for data persistence
- **ML models** for CVE → CWE/CAPEC prediction
- **Petri nets** for visual threat modeling

### Network Scanning

**"What does network scanning do?"**
- Uses `nmap` to discover hosts, ports, services
- Detects vulnerabilities (CVEs)
- Imports results to database
- Triggers ML predictions automatically
- Classifies and scores threats

### Petri Net Integration

**"How do Petri nets relate to scanning?"**
- **Scan results** → Create/update Petri net nodes (services, hosts)
- **CVEs** → Linked to nodes via risk computation
- **Risk scores** → Displayed on nodes in Petri Net Studio
- **Visual representation** → Shows network topology and threats

### ML Models

**"What do the ML models do?"**
- **Input**: CVE description text
- **Output**: Predicted CWE (weakness type) and CAPEC (attack pattern)
- **Purpose**: Understand attack vectors and weaknesses
- **Integration**: Automatically called for each discovered CVE

### Threat Detection

**"How are threats detected?"**
- **Classification**: Critical/High/Medium/Low based on CVSS and risk
- **Scoring**: 0-100 risk score per host
- **Grouping**: Threats grouped by host/IP
- **Display**: Shown in Network Scanner results and Threat Detection page

### Data Flow

**"Walk me through the data flow."**
1. User scans network
2. System discovers hosts/services/vulnerabilities
3. Data imported to PostgreSQL
4. ML models predict CWE/CAPEC for each CVE
5. Threat detection classifies and scores
6. Petri nets generated/updated from topology
7. Node risks computed (link CVEs to nodes)
8. Dashboard displays everything

---

## 🔧 Technical Details

### Database Schema

**Key Tables:**
- `network_events` - Scan results, host data
- `cve_records` - CVE information, predictions
- `petri_nets` - Petri net structures (nodes, edges)
- `node_risks` - Risk scores, linked CVEs/CAPEC
- `threat_predictions` - ML model outputs

### API Endpoints

**Query API (`/api`):**
- `POST /network-scan/run` - Run network scan
- `GET /cve-records` - List CVEs
- `GET /petri-nets` - List Petri nets
- `GET /node-risks/:netId` - Get node risks
- `POST /import` - Import data (processes, CVEs, events)

**Threat Model API (`/predict`):**
- `POST /predict` - Predict CWE/CAPEC from CVE description
- `POST /predict/batch` - Batch predictions

### Environment Variables

```bash
# Query API
DATABASE_URL=postgresql://user:pass@localhost:5432/sentinel
VITE_QUERY_API=http://localhost:8000/api
VITE_QUERY_TOKEN=your-token

# Threat Model API
VITE_THREAT_MODEL_API=http://localhost:8001/predict
THREAT_MODELS_PATH=../models copy
```

---

## ✅ Key Features

1. **Automated Network Scanning** - Discover hosts, services, vulnerabilities
2. **ML Threat Prediction** - CVE → CWE/CAPEC mapping
3. **Threat Detection** - Classification and risk scoring
4. **Petri Net Modeling** - Visual network/process representation
5. **Node Risk Computation** - Link threats to network components
6. **Real-time Updates** - Auto-refresh CVE cards after scans
7. **Detection-Only Mode** - Identify threats, no automated defense

---

## 🎤 Sample Interview Answers

**Q: "What is a Petri net and why use it?"**
A: "A Petri net is a mathematical model that represents states (places) and events (transitions) in a system. In our platform, we use Petri nets to visually model network infrastructure—each node represents a service or component, tokens represent active connections, and edges show data flow. This helps security teams understand their network topology and see where threats are located."

**Q: "How does network scanning feed into Petri nets?"**
A: "When we scan a network, we discover hosts, services, and vulnerabilities. This data is imported into our database. We then generate or update Petri nets to represent the network topology—each discovered service becomes a node. We compute risk scores for each node by matching discovered CVEs to the nodes, so you can see which services are vulnerable directly on the Petri net visualization."

**Q: "What's the role of machine learning?"**
A: "Our ML models take CVE descriptions and predict the associated CWE (Common Weakness Enumeration) and CAPEC (Common Attack Pattern Enumeration) patterns. This helps security teams understand not just what vulnerabilities exist, but what types of weaknesses they represent and what attack patterns could exploit them. These predictions are automatically generated for every CVE discovered during a network scan."

**Q: "How do you ensure real-time updates?"**
A: "After a network scan completes, the system automatically imports all discovered data, triggers ML predictions, and updates the database. The frontend CVE cards have a 30-second auto-refresh interval, so new threats appear automatically. The Petri Net Studio fetches the latest node risks when you select a net, ensuring you always see current threat information."

---

**This guide covers everything you need to explain the system in an interview!** 🚀

