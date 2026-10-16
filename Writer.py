import requests
import psutil
import os
import time
import csv
import datetime
import uuid

URL_AUTENTICACAO = "http://127.0.0.1:3000/api/autenticacao"

INTERVALO_LEITURA = 1

flags_monitoramento = {}

def autenticarComponentes(componentes):
    global flags_monitoramento

    for comp in componentes:
        flags_monitoramento[comp["tipo"]] = True

def leitura():
    CAMINHO_CSV = HOSTNAMELOCAL + ".csv"
    CAMINHO_PROCESSOS = HOSTNAMELOCAL + "_processos.csv"

    arquivo_novo = (
        not os.path.exists(CAMINHO_CSV)
        or os.path.getsize(CAMINHO_CSV) == 0
    )
    arquivo_processos_novo = (
        not os.path.exists(CAMINHO_PROCESSOS)
        or os.path.getsize(CAMINHO_PROCESSOS) == 0
    )

    with open(CAMINHO_CSV, "a", newline="", encoding="utf-8") as csvfile, \
            open(CAMINHO_PROCESSOS, "a", newline="", encoding="utf-8") as arquivo_processos:
        writer = csv.writer(csvfile)
        writer_processos = csv.writer(arquivo_processos)

        if arquivo_novo:
            writer.writerow([
                "Capture_ID",
                "HostName",
                "Porcentagem_CPU",
                "Freq_CPU",
                "Porcentagem_RAM",
                "Total_RAM",
                "Disponivel_RAM",
                "Porcentagem_Disco",
                "Disponivel_Disco",
                "Swap",
                "Load",
                "Timestamp",
            ])

        if arquivo_processos_novo:
            writer_processos.writerow([
                "Capture_ID",
                "HostName",
                "Timestamp",
                "PID",
                "Nome_Processo",
                "Porcentagem_CPU_Processo",
                "Memoria_Bytes",
                "Memoria_MB",
                "Bytes_Lidos_Acumulados",
                "Bytes_Escritos_Acumulados",
            ])

        while True:
            capture_id = str(uuid.uuid4())

            if flags_monitoramento.get("CPU", False):
                cpu_atual = psutil.cpu_percent(interval=1)
                cpu_frequencia_atual = round((psutil.cpu_freq().current), 2)
            else:
                cpu_atual = 0
                cpu_frequencia_atual = 0

            # RAM
            if flags_monitoramento.get("RAM", False):
                ram_atual = psutil.virtual_memory().percent
                memoria_ram_total = round((psutil.virtual_memory().total), 2)
                memoria_ram_disponivel = round((psutil.virtual_memory().available), 2)
            else:
                ram_atual = 0
                memoria_ram_total = 0
                memoria_ram_disponivel = 0

            # DISCO
            if flags_monitoramento.get("DISCO", False):
                disco_atual = psutil.disk_usage("/").percent
                disco_livre = round((psutil.disk_usage("/").free), 2)
            else:
                disco_atual = 0
                disco_livre = 0

            # SWAP
            if flags_monitoramento.get("SWAP", False):
                swap_atual = psutil.swap_memory().percent
            else:
                swap_atual = 0

            # Cálculo de LOAD
            if flags_monitoramento.get("CPU", False):
                loadAtual = (psutil.getloadavg()[0] / psutil.cpu_count()) * 100
            else:
                loadAtual = 0

            timestamp = datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            linha = [
                capture_id,
                HOSTNAMELOCAL,
                cpu_atual,
                cpu_frequencia_atual,
                ram_atual,
                memoria_ram_total,
                memoria_ram_disponivel,
                disco_atual,
                disco_livre,
                swap_atual,
                round(loadAtual, 2),
                timestamp,
            ]

            writer.writerow(linha)
            csvfile.flush()

            for processo in psutil.process_iter():
                try:
                    pid = processo.pid
                    nome = processo.name()
                    cpu_processo = processo.cpu_percent(interval=None)
                    memoria_processo = processo.memory_info().rss

                    try:
                        io_processo = processo.io_counters()
                        bytes_lidos = io_processo.read_bytes
                        bytes_escritos = io_processo.write_bytes
                    except (
                        AttributeError,
                        NotImplementedError,
                        psutil.AccessDenied,
                    ):
                        bytes_lidos = ""
                        bytes_escritos = ""

                    writer_processos.writerow([
                        capture_id,
                        HOSTNAMELOCAL,
                        timestamp,
                        pid,
                        nome,
                        cpu_processo,
                        memoria_processo,
                        round(memoria_processo / (1024 ** 2), 2),
                        bytes_lidos,
                        bytes_escritos,
                    ])

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ):
                    continue

            arquivo_processos.flush()
            print(linha)
            time.sleep(INTERVALO_LEITURA)


autenticar = True

while autenticar:
    try:
        EMAIL = input("E-mail: ")
        SENHA = input("Senha: ")

        resposta = requests.post(
            URL_AUTENTICACAO,
            json={
                "email": EMAIL,
                "senha": SENHA
            }
        )

        resposta.raise_for_status()

        resultado = resposta.json()
        print(resultado)

        if resultado.get("autenticado"):
            mainframes = resultado["mainframe"]
            print("Em qual servidor será a captura")

            i = 1
            for mf in mainframes:
                print(f"{i} - {mf['hostname']}")
                i += 1

            escolha = int(input("Servidor: "))
            HOSTNAMELOCAL = mainframes[escolha - 1]["hostname"]
        else:
            print("E-mail ou senha inválidas!")
            continue

        resposta = requests.post(
            URL_AUTENTICACAO,
            json={
                "email": EMAIL,
                "senha": SENHA,
                "hostname": HOSTNAMELOCAL
            }
        )

        resposta.raise_for_status()

        resultado = resposta.json()
        componentes = resultado["componentes"]

        autenticarComponentes(componentes)
        leitura()
        autenticar = False

    except requests.exceptions.HTTPError as erro:
        print("Status:", erro.response.status_code)
        print("Resposta da API:", erro.response.text)

    except requests.exceptions.RequestException as erro:
        print("Não foi possível conectar à API:", erro)