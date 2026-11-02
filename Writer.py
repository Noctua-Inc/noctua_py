import requests
import psutil
import os
import time
import csv
import datetime
import uuid
import io, boto3
from dotenv import load_dotenv

load_dotenv()

session = boto3.Session(
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    aws_session_token=os.getenv("AWS_SESSION_TOKEN"),
    region_name="us-east-1",
)
s3_client = session.client("s3")

URL_AUTENTICACAO = "http://127.0.0.1:3000/api/autenticacao"

# INTERVALO_LEITURA = 1

flags_monitoramento = {}

def autenticarComponentes(componentes):
    global flags_monitoramento

    for comp in componentes:
        flags_monitoramento[comp["tipo"]] = True

def leitura():
    contador_registros = 0
    buffer_linhas = []
    buffer_processos = []

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

        def contar_sockets_time_wait():
            contador = 0
            conexoes = psutil.net_connections(kind="inet")

            for conexao in conexoes:
                if conexao.status == "TIME_WAIT":
                    contador += 1

            return contador

        # REDE 
        if flags_monitoramento.get("REDE", False):
            dados_enviados = psutil.net_io_counters().bytes_sent
            dados_recebidos = psutil.net_io_counters().bytes_recv
            pacotes_perdido = psutil.net_io_counters().errin
            sockets_tw = contar_sockets_time_wait()
        else:
            dados_enviados = 0
            dados_recebidos = 0
            pacotes_perdido = 0
            sockets_tw = 0 

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
            dados_enviados,
            dados_recebidos,
            pacotes_perdido,
            sockets_tw, 
            timestamp
        ]

        buffer_linhas.append(linha)

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

                buffer_processos.append([
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

        print(linha)
        # time.sleep(INTERVALO_LEITURA)

        contador_registros += 1

        if contador_registros == 60:
            timestamp_arquivo = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
            CAMINHO_CSV = f"{HOSTNAMELOCAL}_{timestamp_arquivo}.csv"
            CAMINHO_PROCESSOS = f"{HOSTNAMELOCAL}_processos_{timestamp_arquivo}.csv"

            with open(CAMINHO_CSV, "w", newline="", encoding="utf-8") as csvfile, \
                    open(CAMINHO_PROCESSOS, "w", newline="", encoding="utf-8") as arquivo_processos:
                writer = csv.writer(csvfile)
                writer_processos = csv.writer(arquivo_processos)

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
                    "Dados_Enviados",
                    "Dados_Recebidos",
                    "Pacotes_Perdido",
                    "Sockets_Tw", 
                    "Timestamp",
                ])

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

                writer.writerows(buffer_linhas)
                writer_processos.writerows(buffer_processos)

                csvfile.flush()
                arquivo_processos.flush()

            buffer_linhas.clear()
            buffer_processos.clear()
            contador_registros = 0

            s3_client.upload_file(
                CAMINHO_CSV,
                os.getenv("NOME_BUCKET"),
                f"01-bronze/{CAMINHO_CSV}"
            )
            s3_client.upload_file(
                CAMINHO_PROCESSOS,
                os.getenv("NOME_BUCKET"),
                f"01-bronze/{CAMINHO_PROCESSOS}"
            )

            os.remove(CAMINHO_CSV)
            os.remove(CAMINHO_PROCESSOS)

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