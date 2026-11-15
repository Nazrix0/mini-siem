# mini-siem

```text
┌────────────────────────────────────────────────────────┐
│                   Klient / Generator                   │
└───────────────────────────┬────────────────────────────┘
                            │ (1. REST HTTP POST - Synchronicznie)
                            ▼
                     ┌──────────────┐
                     │    Nginx     │ (Load Balancer)
                     └──────┬───────┘
                            │
             ┌──────────────┴─────────────────┐
             │ (Rozkład ruchu na 3 instancje) │
             ▼              ▼              ▼
       ┌───────────┐  ┌───────────┐  ┌───────────┐
       │ Collector │  │ Collector │  │ Collector │ (Usługa zbierania - 3 repliki w Pythonie)
       │ (Inst. 1) │  │ (Inst. 2) │  │ (Inst. 3) │
       └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
             └──────────────┼──────────────┘
                            │
                            │ (2. Asynchronicznie: Kolejka komunikatów)
                            ▼
                     ┌──────────────┐
                     │    Redis     │ (Kolejka logów)
                     └──────┬───────┘
                            │
                            ▼ (3. Pobieranie zadań)
                     ┌──────────────┐
                     │   Analyzer   │ (Usługa korelacji / worker w Pythonie)
                     └──────┬───────┘
                            │
                            ▼ (4. Zapis alertów i logów)
                     ┌──────────────┐
                     │    MySQL     │ (Relacyjna baza danych)
                     └──────────────┘

[ Monitorowanie centralne ]
┌────────────┐   zbiera metryki   ┌─────────┐   wizualizacja (wykresy/dashboardy)   ┌────────────┐
│ Prometheus ├───────────────────►│ Grafana ├──────────────────────────────────────►│ Użytkownik │
└────────────┘                    └─────────┘                                       └────────────┘
```
## 1. Główne usługi
1. **Nginx (Load Balancer – port `8080` HTTP / `8443` HTTPS):** Punkt wejściowy systemu. Przyjmuje zapytania i rozkłada ruch równomiernie (Round-Robin) na 3 instancje usługi Collector.
2. **Collector (Python FastAPI – 3 repliki):** Odbiera logi synchronicznie przez REST API (`POST /api/v1/logs`), waliduje je, wystawia dokumentację Swagger (`/docs`) oraz metryki dla Prometheusa (`/metrics`), a następnie wrzuca logi asynchronicznie na kolejkę Redis. Udostępnia też endpointy odczytu (`GET /api/v1/alerts`, `GET /api/v1/logs`).
3. **Redis (Kolejka komunikatów – port `6379`):** Zapewnia komunikację asynchroniczną między Collectorem a Analyzerem (struktura kolejki FIFO `RPUSH` / `BLPOP`).
4. **Analyzer (Python Worker):** Pobiera logi z kolejki Redis i analizuje je:
   - **Detekcja sygnaturowa (bezstanowa):** Wykrywa ataki `SQL_INJECTION`, `PATH_TRAVERSAL` oraz `XSS_ATTACK` na podstawie zawartości pola `payload`.
   - **Korelacja zdarzeń (stanowa):** Zlicza nieudane logowania (`LOGIN_FAILED`) z tego samego adresu IP – po wykryciu 5 prób generuje alert `BRUTE_FORCE_DETECTED`.
5. **MySQL (Baza danych – port `3306`):** Przechowuje surowe logi (tabela `raw_logs`) oraz wykryte incydenty bezpieczeństwa (tabela `alerts`).
6. **Prometheus (port `9090`) + Grafana (port `3000`):** Centralne zbieranie metryk wydajnościowych oraz wizualizacja alertów bezpieczeństwa i obciążenia na żywo.
7. **Locust (port `8089`):** Webowe narzędzie do generowania sztucznego ruchu i wykonywania pomiarów wydajności (opóźnienia i przepustowość).

## 2. Ważne adresy
| Usługa | Adres URL | Dane logowania / Opis |
| :--- | :--- | :--- |
| **Swagger UI (Dokumentacja API)** | `http://serwer1pk:8080/docs` lub `https://serwer1pk:8443/docs` | Testowanie wysyłania logów i pobierania alertów w przeglądarce |
| **Grafana (Dashboard SIEM)** | `http://serwer1pk:3000` | Login: `admin` / Hasło: `admin` (Gotowy dashboard w zakładce *Dashboards*) |
| **Locust (Pomiary wydajności)** | `http://serwer1pk:8089` | Graficzny panel do testów obciążeniowych (bez użycia terminala) |
| **Prometheus (Metryki)** | `http://serwer1pk:9090` | Sprawdzanie zbieranych metryk (zakładka *Status -> Targets*) |
| **Podgląd Alertów (JSON)** | `http://serwer1pk:8080/api/v1/alerts` | Zwraca ostatnie 50 wykrytych ataków z bazy MySQL |
## 3. Instrukcja wykonywania pomiarów wydajności w Locust (Bez terminala!)

Wymagania projektu: *każdy pomiar powtórzony min. 5 razy po kilku minutach rozgrzania systemu; odczytujemy medianę (50%), 95. i 99. percentyl opóźnień oraz przepustowość (RPS)*.

1. Otwórz w przeglądarce stronę: **`http://serwer1pk:8089`**.
2. Wypełnij pola:
   - **Number of users (peak concurrency):** np. `10`, `50`, `100` (liczba jednoczesnych klientów).
   - **Ramp up (users started/second):** np. `5` (szybkość dołączania klientów).
   - **Host:** `http://nginx:80` (lub `http://localhost:8080`).
3. Kliknij przycisk **Start**.
4. Odczekaj 2–3 minuty na rozgrzanie systemu, a następnie:
   - W zakładce **Statistics** odczytaj wartości z kolumn: **50% (Mediana)**, **95%**, **99%** (opóźnienia w ms) oraz **Current RPS** (przepustowość).
   - W zakładce **Charts** zrób zrzuty ekranu wykresów (RPS oraz Response Times).
   - W zakładce **Download Data** możesz pobrać gotowy raport HTML oraz pliki CSV do sprawozdania.
5. Aby zakończyć pomiar, kliknij czerwony przycisk **Stop** w prawym górnym rogu (i **Reset Stats** przed kolejną próbą).


## 4. Przydatne komendy w terminalu (Dla osób pracujących przez SSH)

Wszystkie komendy wykonujemy w katalogu projektu na serwerze:
1. Ręczne zarządzewnie 
```bash
cd /home/user/actions-runner/_work/mini-siem/mini-siem
```
 - Sprawdzenie statusu kontenerów``` docker compose ps```
 - Włączenie/przebudowanie środowiska ``` docker compose up -d --build ```
 - Wyłączenie środowiska ``` docker compose down ```
 - Pełny reset (wraz z wyczyszczeniem bazy MySQL) ``` docker compose down -v ```
 - Podgląd wykrywanych ataków na żywo  ```  docker compose logs -f analyzer ```
2. Ręczne uruchomienie testów i generatora ruchu

```bash
# Testy jednostkowe:
PYTHONPATH=. .venv/bin/pytest tests/test.py

# Test integracyjny całego przepływu (End-to-End):
PYTHONPATH=. .venv/bin/pytest tests/test_integration.py

# Ciągły symulator ataków (wypisuje w konsoli, która z 3 instancji Collectora obsłużyła log):
.venv/bin/python generator/generate_traffic.py
```
3. Awaria collectora
 ```bash 
#Wyłączenie 
docker stop mini-siem-collector-2
#Włączenie 
docker start mini-siem-collector-2
```

