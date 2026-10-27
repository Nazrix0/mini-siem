# mini-siem


┌────────────────────────────────────────────────────────┐
 │                   Klient / Generator                   │
 └───────────────────────────┬────────────────────────────┘
                             │ (1. REST HTTP POST - Synchronicznie)
                             ▼
                     ┌───────────────┐
                     │     Nginx     │ (Load Balancer)
                     └───────┬───────┘
                             │
            ┌────────────────┼────────────────┐
            │ (Rozkład ruchu na 3 instancje)  │
            ▼                ▼                ▼
      ┌───────────┐    ┌───────────┐    ┌───────────┐
      │ Collector │    │ Collector │    │ Collector │ (Usługa zbierania - 3 repliki w Pythonie)
      │  (Inst. 1)│    │  (Inst. 2)│    │  (Inst. 3)│
      └─────┬─────┘    └─────┬─────┘    └─────┬─────┘
            │                │                │
            └────────────────┼────────────────┘
                             │ (2. Asynchronicznie: Kolejka komunikatów)
                             ▼
                     ┌───────────────┐
                     │     Redis     │ (Kolejka logów)
                     └───────┬───────┘
                             │
                             ▼ (3. Pobieranie zadań)
                     ┌───────────────┐
                     │   Analyzer    │ (Usługa korelacji / worker w Pythonie)
                     └───────┬───────┘
                             │
                             ▼ (4. Zapis alertów i logów)
                     ┌───────────────┐
                     │     MySQL     │ (Relacyjna baza danych)
                     └───────────────┘

   [ Monitorowanie centralne ]
   ┌────────────┐   zbiera metryki   ┌────────────┐   wizualizacja (wykresy/dashboardy)   ┌───────────┐
   │ Prometheus ├───────────────────►│  Grafana   ├──────────────────────────────────────►│ Użytkownik│
   └────────────┘                    └────────────┘                                       └───────────┘
