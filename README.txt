SORM: THE TELECOM INFRASTRUCTURE
Educational Lawful Interception Simulation in Python
=====================================================

OVERVIEW
--------
SORM is a teaching project that simulates how a telecom operator can mirror
network traffic to a lawful interception and monitoring platform. It models
the full chain: telecom core, optical splitter, network tap, passive probe,
deep packet inspection, metadata storage and an analyst terminal.

IMPORTANT NOTICE
----------------
This project is for education and portfolio use only.
  - All data is synthetic. Phone numbers use the fictional prefix +00555.
  - IP addresses come from reserved documentation ranges.
  - The code never opens a network interface and never captures real traffic.
  - Real lawful interception requires legal authorization, strict access
    control, audit logging and independent oversight. This project includes
    simplified teaching versions of access control and auditing, but it is
    not a compliant system and must not be adapted to monitor real people.

FEATURES
--------
  - Traffic generator: SIP signaling, SMS logs, HTTP and HTTPS metadata, IPDR
  - Optical splitter model with a dB power budget and receiver sensitivity
  - Network tap with mirror-port overflow and a live-path integrity check
  - DPI engine: protocol parsing, header extraction, keyword, domain, number
    and IP watchlists, large-record rule and SIP INVITE burst rule
  - SQLite metadata storage with indexed search
  - Role-based login: ADMIN, ANALYST and AUDITOR with least privilege
  - Case reference required for every search and export
  - Tamper-evident audit log of every login, denial, query and change
  - Analyst CLI and a local web dashboard (127.0.0.1 only, login required)
  - Standard library only, no third-party packages

PROJECT STRUCTURE
-----------------
  SORM/
    main.py                 orchestrator and interactive menu
    telecom_generator.py    synthetic telecom traffic
    network_appliances.py   splitter, tap, probe, mirroring fabric
    dpi_engine.py           packet inspection and flagging
    storage_server.py       SQLite storage, role-aware CLI, web dashboard
    access_control.py       login, roles, case references, audit log
    run_windows.bat         one-click Windows launcher
    requirements.txt        empty, standard library only
    config/watchlist.json   detection rules
    data/sample_packets.csv sample dataset of generated packets
    data/sample_ipdr.csv    sample IPDR records
    Project_Report.txt      full project analysis
    README.txt              this file

QUICK START: WINDOWS 10 AND 11
------------------------------
  1. Install Python 3.8 or newer from python.org and tick Add python.exe to PATH
  2. Double-click run_windows.bat
  3. Log in with a demo account (see ACCESS CONTROL AND AUDIT below)
  4. The menu depends on your role. An ADMIN can run a simulation, the terminal
     gives role-specific commands, and the dashboard is at http://127.0.0.1:8080

QUICK START: LINUX AND MACOS
----------------------------
  python3 main.py --demo
  python3 main.py            (interactive menu)

COMMAND LINE OPTIONS
--------------------
  --packets N        number of packets to simulate (default 500)
  --seed N           random seed for repeatable runs (default 42)
  --tap-percent P    optical power share for the monitor leg (default 10.0)
  --db PATH          SQLite database file
  --watchlist PATH   watchlist JSON file
  --user NAME        log in as this user (the password is always prompted)
  --reset            clear the database first
  --demo             run once as the SYSTEM account, print results, exit
  --cli              open the terminal after login
  --dashboard        start the web dashboard
  --port N           dashboard port (default 8080)

DATA FLOW DIAGRAM: LEVEL 0 (CONTEXT)
------------------------------------

  +---------------+   live traffic   +----------------------+   alerts and    +---------------+
  |               | ---------------> |                      |   query results |               |
  | TELECOM CORE  |                  |  SORM SIMULATION     | --------------> |    ANALYST    |
  | (synthetic)   | <--------------- |  SYSTEM              |                 |    TERMINAL   |
  |               |  traffic keeps   |                      | <-------------- |               |
  +---------------+  flowing intact  +----------------------+  search request +---------------+

DATA FLOW DIAGRAM: LEVEL 1
--------------------------

  +-------------------------------------------+
  | TELECOM CORE                              |
  | SIP, SMS, HTTP, HTTPS and IPDR sources    |
  +-------------------------------------------+
        |                                  |
        | D1: live traffic                 | D1: live traffic continues
        v                                  v    to its destination, unchanged
  +-------------------------------------------+
  | 1.0 NETWORK TAPS                          |
  |   1.1 Optical splitter  (90 / 10 power)   |
  |   1.2 Network tap       (mirror port)     |
  |   1.3 Passive probe     (collector)       |
  +-------------------------------------------+
        |
        | D2: mirrored copies only
        v
  +-------------------------------------------+
  | 2.0 DPI ENGINE                            |
  |   2.1 Protocol parser                     |
  |   2.2 Metadata extractor                  |
  |   2.3 Rule matcher and severity scoring   |
  +-------------------------------------------+
        |
        | D3: inspection results (metadata and flags)
        v
  +-------------------------------------------+
  | 3.0 METADATA STORAGE SERVERS              |
  |   3.1 SQLite writer                       |
  |   3.2 Indexed search service              |
  |   Data store: metadata table              |
  +-------------------------------------------+
        ^
        |  D4: authorized, case-referenced queries
        |                                  |
        |                                  v
  +-------------------------------------------+
  | 4.0 ACCESS CONTROL                        |
  |   4.1 Login and lockout                   |
  |   4.2 Role permission check               |
  |   4.3 Case reference check                |
  +-------------------------------------------+
        |  D5: every attempt, allowed or denied
        v
  +-------------------------------------------+
  | Data store: AUDIT LOG (append-only,       |
  | hash-chained)  <---- read by AUDITOR      |
  +-------------------------------------------+
                                   |
                                   | D6: matching records
                                   v
  +-------------------------------------------+
  | 5.0 ANALYST TERMINAL                      |
  |   Command line and local web dashboard    |
  +-------------------------------------------+

ACCESS CONTROL AND AUDIT
------------------------
Demo accounts are created on first run. These passwords are public, so change
them with the passwd command if you keep the database.

  USERNAME    PASSWORD            ROLE      CAN DO
  admin       Admin-Demo-2026     ADMIN     manage users, run simulation, clear metadata
  analyst1    Analyst-Demo-2026   ANALYST   search and export, with a case reference
  auditor1    Auditor-Demo-2026   AUDITOR   read and verify the audit log

Rules:
  - Separation of duties: no role can do everything. The admin cannot read
    records, the analyst cannot read the audit log, the auditor cannot read records
  - Searches and exports need a case reference such as CASE-2026-001
  - Passwords are stored as salted PBKDF2 hashes; five failed logins lock the account
  - The audit log is append-only and hash-chained; the auditor command verify
    detects edits or removed entries
  - The --demo flag runs as SYSTEM for automation and is itself logged

SAMPLE SESSIONS
---------------
  Analyst (python main.py --user analyst1 --cli):
    sorm:analyst1> case CASE-2026-001
    sorm:analyst1> alerts
    sorm:analyst1> number +005550001003
    sorm:analyst1> search protocol=SMS min_severity=30 limit=10
    sorm:analyst1> export sms_alerts.csv

  Auditor (python main.py --user auditor1 --cli):
    sorm:auditor1> audit limit=20 user=analyst1
    sorm:auditor1> verify

  Admin (python main.py --user admin --cli):
    sorm:admin> users
    sorm:admin> adduser analyst2 ANALYST
    sorm:admin> unlock analyst2

EXTENDING THE PROJECT
---------------------
  - Add a new protocol: add a generator method, a parser in dpi_engine.py
    and a row in the parsers table inside inspect()
  - Add detection rules by editing config/watchlist.json
  - Try --tap-percent 0.1 to see optical power starvation lose mirrored copies

LIMITATIONS
-----------
  - Packets are Python objects, not real frames
  - Single machine, single thread, no encryption at rest
  - Demo passwords are public, case references are format-checked only and no
    real warrant system exists
  - The audit log shares the database file with the data, so a person with file
    access can still delete the whole file; real systems ship logs to separate,
    write-once storage

DISCLAIMER
----------
Provided for learning purposes without warranty. Use responsibly and lawfully.
