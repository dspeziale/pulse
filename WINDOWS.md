# Pulse Network Monitor - Guida Windows

Guida completa per l'installazione e l'utilizzo di Pulse Network Monitor su Windows.

## Requisiti

- Windows 10/11 o Windows Server 2016+
- Python 3.11 o superiore
- Nmap per Windows
- Privilegi di amministratore (per alcune funzionalità)

## Installazione Passo-Passo

### 1. Installare Python

1. Scaricare Python da https://www.python.org/downloads/
2. Eseguire l'installer
3. **IMPORTANTE**: Selezionare "Add Python to PATH" durante l'installazione
4. Verificare l'installazione:
```cmd
python --version
```

### 2. Installare Nmap

1. Scaricare Nmap da https://nmap.org/download.html
2. Scaricare il file "Latest stable release self-installer"
3. Eseguire l'installer come Amministratore
4. Durante l'installazione, selezionare tutte le componenti
5. Aggiungere Nmap al PATH:
   - Aprire "Modifica variabili d'ambiente di sistema"
   - Cliccare su "Variabili d'ambiente"
   - In "Variabili di sistema", selezionare "Path" e cliccare "Modifica"
   - Cliccare "Nuovo" e aggiungere: `C:\Program Files (x86)\Nmap`
   - Cliccare OK per salvare

6. Verificare l'installazione (aprire un NUOVO prompt dei comandi):
```cmd
nmap --version
```

### 3. Installare Pulse

1. Aprire il Prompt dei comandi
2. Navigare alla cartella del progetto:
```cmd
cd C:\Users\YourName\pulse
```

3. Creare un ambiente virtuale:
```cmd
python -m venv venv
```

4. Attivare l'ambiente virtuale:
```cmd
venv\Scripts\activate
```

5. Installare le dipendenze:
```cmd
pip install -r requirements.txt
```

## Configurazione

1. Copiare il file di configurazione:
```cmd
copy config\config.yaml config\config.local.yaml
```

2. Modificare `config\config.local.yaml` con un editor di testo (es. Notepad++)

3. Configurare la rete da scansionare:
```yaml
scanner:
  default_network: "192.168.1.0/24"  # Modificare secondo la propria rete
```

## Utilizzo

### Avviare il Server

**Metodo 1: Prompt Normale**
```cmd
cd C:\Users\YourName\pulse
venv\Scripts\activate
python main.py
```

**Metodo 2: Come Amministratore** (raccomandato per OS detection)
1. Cercare "Prompt dei comandi" nel menu Start
2. Cliccare con il tasto destro e selezionare "Esegui come amministratore"
3. Eseguire:
```cmd
cd C:\Users\YourName\pulse
venv\Scripts\activate
python main.py
```

Il server sarà disponibile su http://localhost:5000

### Eseguire Scansioni

**Discovery scan:**
```cmd
python main.py scan discovery 192.168.1.0/24
```

**Scan singolo host:**
```cmd
python main.py scan quick 192.168.1.100
```

**Deep scan (richiede privilegi amministratore):**
```cmd
python main.py scan deep 192.168.1.100
```

## Problemi Comuni su Windows

### 1. "python non è riconosciuto come comando"

**Soluzione:**
- Reinstallare Python e selezionare "Add Python to PATH"
- Oppure aggiungere manualmente Python al PATH:
  - Percorso tipico: `C:\Users\YourName\AppData\Local\Programs\Python\Python311`

### 2. "nmap non è riconosciuto come comando"

**Soluzione:**
- Verificare che Nmap sia installato
- Aggiungere al PATH: `C:\Program Files (x86)\Nmap`
- Riavviare il prompt dei comandi

### 3. Errori di permessi

**Soluzione:**
- Eseguire il prompt dei comandi come Amministratore
- Alcune scansioni (come OS detection con `-O`) richiedono privilegi elevati

### 4. Windows Firewall blocca Nmap

**Soluzione:**
- Aprire "Windows Defender Firewall"
- Cliccare "Consenti app o funzionalità attraverso Windows Defender Firewall"
- Cliccare "Modifica impostazioni"
- Trovare "Nmap" e abilitarlo per reti private e pubbliche

### 5. Antivirus blocca le scansioni

**Soluzione:**
- Aggiungere eccezione per Nmap nell'antivirus
- Aggiungere eccezione per la cartella di Pulse

### 6. Errore "ModuleNotFoundError"

**Soluzione:**
- Assicurarsi che l'ambiente virtuale sia attivato: `venv\Scripts\activate`
- Reinstallare le dipendenze: `pip install -r requirements.txt`

### 7. Database locked

**Soluzione:**
- Chiudere tutte le istanze di Pulse
- Eliminare il file `instance\pulse.sqlite` (perderete i dati!)
- Riavviare Pulse

## Eseguire Pulse come Servizio Windows

### Metodo 1: Task Scheduler

1. Aprire "Utilità di pianificazione" (Task Scheduler)
2. Cliccare "Crea attività"
3. Nome: "Pulse Network Monitor"
4. Selezionare "Esegui con i privilegi più elevati"
5. Tab "Trigger": "All'avvio"
6. Tab "Azioni":
   - Programma: `C:\Users\YourName\pulse\venv\Scripts\python.exe`
   - Argomenti: `main.py`
   - Posizione iniziale: `C:\Users\YourName\pulse`
7. Cliccare OK

### Metodo 2: NSSM (Non-Sucking Service Manager)

1. Scaricare NSSM da https://nssm.cc/download
2. Estrarre ed eseguire come amministratore:
```cmd
nssm install Pulse
```
3. Configurare:
   - Path: `C:\Users\YourName\pulse\venv\Scripts\python.exe`
   - Startup directory: `C:\Users\YourName\pulse`
   - Arguments: `main.py`
4. Cliccare "Install service"
5. Avviare il servizio:
```cmd
nssm start Pulse
```

## Performance su Windows

### Ottimizzazioni

1. **Ridurre il numero di worker** se si hanno problemi di performance:
```yaml
scanner:
  workers:
    max_workers: 2  # Invece di 4
```

2. **Aumentare i timeout** su reti lente:
```yaml
scanner:
  workers:
    timeout: 900  # 15 minuti invece di 10
```

3. **Disabilitare Windows Defender durante le scansioni** (temporaneamente):
   - Questo può migliorare significativamente le performance
   - **ATTENZIONE**: Farlo solo se necessario e riattivare dopo

## Differenze rispetto a Linux

1. **Worker Pool**: Usa ThreadPoolExecutor invece di ProcessPoolExecutor
   - Nessun problema di pickling
   - Stessa performance per operazioni I/O bound come Nmap

2. **Paths**: Usa backslash `\` invece di `/`
   - Pulse gestisce automaticamente le differenze

3. **Privilegi**: "Amministratore" invece di "root"
   - Alcune scansioni richiedono privilegi elevati

4. **Servizi**: Task Scheduler o NSSM invece di systemd

## Test dell'Installazione

Eseguire questo comando per testare l'installazione:

```cmd
python main.py scan discovery 127.0.0.1
```

Dovrebbe completare con successo e mostrare il localhost come dispositivo scoperto.

## Log e Debug

I log si trovano in: `C:\Users\YourName\pulse\logs\pulse.log`

Per abilitare il debug:
```yaml
logging:
  level: DEBUG
```

Oppure da riga di comando:
```cmd
python main.py --debug
```

## Supporto

In caso di problemi:
1. Controllare i log in `logs\pulse.log`
2. Verificare che Nmap funzioni: `nmap -sn 127.0.0.1`
3. Verificare Python: `python --version`
4. Aprire una issue su GitHub con:
   - Versione di Windows
   - Versione di Python
   - Versione di Nmap
   - Log dell'errore

## Risorse Aggiuntive

- Documentazione Nmap Windows: https://nmap.org/book/inst-windows.html
- Python Windows FAQ: https://docs.python.org/3/faq/windows.html
- Pulse GitHub: https://github.com/your-repo/pulse
