# Pulse Network Monitor

Sistema di monitoraggio rete completo basato su Python, SQLite e Nmap per la discovery automatica e l'analisi dei dispositivi di rete.

## Caratteristiche

- 🔍 **Network Discovery**: Scansione automatica della rete con Nmap
- 🖥️ **Device Recognition**: Identificazione automatica dispositivi tramite OUI, porte e servizi
- 💾 **Database SQLite**: Storage persistente di tutti i dati
- ⚡ **Multitasking**: Esecuzione parallela delle scansioni con worker pool
- 📅 **Scheduler**: Scansioni programmate e automatiche
- 🌐 **API REST**: Interfaccia Flask per controllo e consultazione
- 📊 **Export**: Esportazione dati in JSON, CSV, HTML, XML
- 🚨 **Alerting**: Notifiche via webhook, email e Telegram
- ⚙️ **Configurabile**: Configurazione completa tramite YAML

## Requisiti

- Python 3.11+
- Nmap (installato nel sistema)
- Linux, macOS o Windows

### Installazione Nmap

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install nmap
```

**CentOS/RHEL:**
```bash
sudo yum install nmap
```

**macOS:**
```bash
brew install nmap
```

**Windows:**
Scaricare da https://nmap.org/download.html

## Installazione

1. Clonare il repository:
```bash
git clone <repository-url>
cd pulse
```

2. Creare un ambiente virtuale:
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# oppure
venv\Scripts\activate  # Windows
```

3. Installare le dipendenze:
```bash
pip install -r requirements.txt
```

4. Configurare il sistema:
```bash
cp config/config.yaml config/config.local.yaml
# Modificare config/config.local.yaml secondo necessità
```

## Configurazione

Il file `config/config.yaml` contiene tutte le opzioni configurabili:

### Configurazione Scanner
```yaml
scanner:
  default_network: "192.168.1.0/24"
  intervals:
    discovery: 300  # 5 minuti
    quick_scan: 900  # 15 minuti
    deep_scan: 3600  # 1 ora
  workers:
    max_workers: 4
    timeout: 600
```

### Configurazione API
```yaml
api:
  host: "0.0.0.0"
  port: 5000
  debug: false
```

### Configurazione Alert
```yaml
alerts:
  enabled: true
  channels:
    webhook:
      enabled: false
      url: "https://your-webhook-url"

    email:
      enabled: false
      smtp_server: "smtp.gmail.com"
      smtp_port: 587
      smtp_username: "your-email@gmail.com"
      smtp_password: "your-password"
      from_address: "pulse@example.com"
      to_addresses:
        - "admin@example.com"

    telegram:
      enabled: false
      bot_token: "your-bot-token"
      chat_id: "your-chat-id"
```

## Utilizzo

### Avvio del Server

```bash
python main.py
```

Il server API sarà disponibile su `http://localhost:5000`

### Interfaccia Web

Aprire il browser all'indirizzo `http://localhost:5000` per accedere all'interfaccia web minimale.

### API REST

#### Dispositivi

**Ottenere tutti i dispositivi:**
```bash
curl http://localhost:5000/api/devices
```

**Ottenere dettagli dispositivo:**
```bash
curl http://localhost:5000/api/devices/1
```

**Ottenere porte di un dispositivo:**
```bash
curl http://localhost:5000/api/devices/1/ports
```

**Statistiche dispositivi:**
```bash
curl http://localhost:5000/api/devices/statistics
```

#### Scansioni

**Avviare discovery scan:**
```bash
curl -X POST http://localhost:5000/api/scans/discovery \
  -H "Content-Type: application/json" \
  -d '{"network": "192.168.1.0/24"}'
```

**Avviare quick scan:**
```bash
curl -X POST http://localhost:5000/api/scans/quick \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.100"}'
```

**Avviare deep scan:**
```bash
curl -X POST http://localhost:5000/api/scans/deep \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.100"}'
```

**Ottenere risultati scansioni:**
```bash
curl http://localhost:5000/api/scans/results?limit=10
```

#### Task ed Eventi

**Ottenere task:**
```bash
curl http://localhost:5000/api/tasks
```

**Ottenere eventi:**
```bash
curl http://localhost:5000/api/events?limit=50
```

**Ottenere dispositivi sospetti:**
```bash
curl http://localhost:5000/api/suspicious
```

#### Scheduler

**Ottenere job schedulati:**
```bash
curl http://localhost:5000/api/scheduler/jobs
```

**Rimuovere job:**
```bash
curl -X DELETE http://localhost:5000/api/scheduler/jobs/job_id
```

#### Configurazione

**Ottenere configurazione:**
```bash
curl http://localhost:5000/api/config
```

**Health check:**
```bash
curl http://localhost:5000/api/health
```

## Architettura

```
pulse/
├── scanner/          # Scanner engine (Nmap wrapper)
│   ├── engine.py     # Nmap execution
│   └── worker.py     # Worker pool & orchestrator
├── parser/           # Nmap output parser
│   └── nmap_parser.py
├── storage/          # Database layer
│   ├── db.py         # Database operations
│   └── schema.sql    # Database schema
├── scheduler/        # Task scheduler
│   └── scheduler.py
├── services/         # Auxiliary services
│   ├── device_recognition.py  # Device classification
│   ├── oui_updater.py        # OUI database updater
│   ├── export.py             # Data export
│   └── alerts.py             # Alert notifications
├── api/              # Flask API
│   └── app.py        # REST API & web UI
└── utils/            # Utilities
    └── config.py     # Configuration manager
```

## Database Schema

Il sistema utilizza SQLite con le seguenti tabelle principali:

- **devices**: Dispositivi scoperti
- **scan_tasks**: Task di scansione
- **scan_results**: Risultati delle scansioni
- **ports**: Porte aperte per dispositivo
- **services**: Servizi rilevati
- **device_history**: Storico cambiamenti
- **events**: Eventi e alert
- **oui_cache**: Cache OUI per vendor lookup
- **configuration**: Configurazioni runtime

## Sviluppo

### Eseguire i test

```bash
pytest
```

### Eseguire test con coverage

```bash
pytest --cov=pulse --cov-report=html
```

### Linting

```bash
pylint pulse/
```

## Export dei Dati

### Tramite Python

```python
from pulse.services.export import get_export_service

export = get_export_service()

# Esportare dispositivi
export.export_devices(format='json', filename='devices.json')
export.export_devices(format='csv', filename='devices.csv')
export.export_devices(format='html', filename='devices.html')

# Esportare risultati scansioni
export.export_scan_results(format='json', limit=100)

# Esportare eventi
export.export_events(format='csv', limit=500)
```

## Aggiornamento Database OUI

Il database OUI (per il riconoscimento vendor da MAC address) può essere aggiornato:

### Manualmente

```python
from pulse.services.oui_updater import get_oui_updater

updater = get_oui_updater()
success, message = updater.update()
print(message)
```

### Automaticamente

Il sistema verifica e aggiorna automaticamente il database OUI secondo l'intervallo configurato (default: 7 giorni).

## Troubleshooting

### Nmap non trovato
Assicurarsi che Nmap sia installato e nel PATH:
```bash
which nmap  # Linux/macOS
where nmap  # Windows
```

### Permessi insufficienti
Alcune scansioni Nmap (es. OS detection) richiedono privilegi root:
```bash
sudo python main.py
```

### Errori di database
Verificare che la directory `instance/` abbia permessi di scrittura:
```bash
chmod 755 instance/
```

### Worker pool non avvia
Verificare che `max_workers` in configurazione non superi il numero di core:
```bash
python -c "import multiprocessing; print(multiprocessing.cpu_count())"
```

## Sicurezza

- **Non esporre** l'API pubblicamente senza autenticazione
- Configurare firewall appropriati
- Usare HTTPS in produzione
- Proteggere il file di configurazione (contiene credenziali)
- Eseguire con privilegi minimi necessari

## Limitazioni

- Le scansioni richiedono tempo (da secondi a ore per reti grandi)
- OS detection richiede privilegi root
- Alcuni firewall possono bloccare le scansioni Nmap
- SQLite ha limitazioni per concorrenza molto elevata

## Contribuire

Contributi benvenuti! Per favore:

1. Fork del repository
2. Creare un branch per la feature
3. Commit delle modifiche
4. Push al branch
5. Aprire una Pull Request

## Licenza

Questo progetto è distribuito sotto licenza MIT.

## Supporto

Per domande o problemi, aprire una issue su GitHub.

## Autori

Pulse Team

## Ringraziamenti

- Nmap Security Scanner
- Flask Web Framework
- APScheduler
- Tutti i contributori open source
