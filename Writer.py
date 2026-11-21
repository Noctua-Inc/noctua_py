import requests
import psutil
import os
import csv
import datetime
import uuid
import io, boto3
import socket
import time
from getpass import getpass
from dotenv import load_dotenv

load_dotenv()

session = boto3.Session(
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    aws_session_token=os.getenv("AWS_SESSION_TOKEN"),
    region_name="us-east-1",
)
s3_client = session.client("s3")

URL_AUTENTICACAO = os.getenv("URL_AUTENTICACAO")

flags_monitoramento = {"CPU": True, "RAM": True, "DISCO": True, "SWAP": True, "REDE": True}


def autenticar_maquina():
    resposta = requests.post(
        URL_AUTENTICACAO,
        json={"email": EMAIL, "senha": SENHA, "hostname": HOSTNAMELOCAL},
        timeout=15
    )
    if not resposta.ok:
        raise RuntimeError(resposta.json().get("mensagem", "Não foi possível autorizar a captura."))
    return resposta.json()


def calcular_taxas_disco(anterior, atual, intervalo):
    if anterior is None or atual is None or intervalo <= 0:
        return "", ""

    bytes_lidos = atual.read_bytes - anterior.read_bytes
    bytes_escritos = atual.write_bytes - anterior.write_bytes
    if bytes_lidos < 0 or bytes_escritos < 0:
        return "", ""

    # Os contadores sao acumulados; a dashboard usa a taxa no intervalo em MiB/s.
    return (
        round(bytes_lidos / intervalo / (1024 ** 2), 6),
        round(bytes_escritos / intervalo / (1024 ** 2), 6),
    )


def leitura():
    contador_registros = 0
    buffer_linhas = []
    buffer_processos = []
    cpus_logicas = psutil.cpu_count(logical=True)
    io_disco_anterior = None
    instante_disco_anterior = None
    if flags_monitoramento.get("DISCO", False):
        io_disco_anterior = psutil.disk_io_counters()
        instante_disco_anterior = time.monotonic()

    while True:
        if contador_registros == 0:
            autenticar_maquina()

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
        bytes_lidos_disco = ""
        bytes_escritos_disco = ""
        leitura_disco_mib_s = ""
        escrita_disco_mib_s = ""
        if flags_monitoramento.get("DISCO", False):
            disco_atual = psutil.disk_usage("/").percent
            disco_livre = round((psutil.disk_usage("/").free), 2)
            io_disco_atual = psutil.disk_io_counters()
            instante_disco_atual = time.monotonic()
            qtd_requisicao_escrita = ""
            qtd_requisicao_leitura = ""
            if io_disco_atual is not None:
                qtd_requisicao_escrita = io_disco_atual.write_count
                qtd_requisicao_leitura = io_disco_atual.read_count
                bytes_lidos_disco = io_disco_atual.read_bytes
                bytes_escritos_disco = io_disco_atual.write_bytes
                intervalo = (
                    instante_disco_atual - instante_disco_anterior
                    if instante_disco_anterior is not None else 0
                )
                leitura_disco_mib_s, escrita_disco_mib_s = calcular_taxas_disco(
                    io_disco_anterior, io_disco_atual, intervalo
                )
            io_disco_anterior = io_disco_atual
            instante_disco_anterior = instante_disco_atual
        else:
            disco_atual = 0
            disco_livre = 0
            qtd_requisicao_escrita = 0
            qtd_requisicao_leitura = 0
            io_disco_anterior = None
            instante_disco_anterior = None

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
            qtd_requisicao_escrita,
            qtd_requisicao_leitura,
            swap_atual,
            round(loadAtual, 2),
            dados_enviados,
            dados_recebidos,
            pacotes_perdido,
            sockets_tw, 
            timestamp,
            bytes_lidos_disco,
            bytes_escritos_disco,
            leitura_disco_mib_s,
            escrita_disco_mib_s,
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
                    cpu_atual if flags_monitoramento.get("CPU", False) else "",
                    cpus_logicas,
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
                    "Qtd_Requisicao_Escrita",
                    "Qtd_Requisicao_Leitura",
                    "Swap",
                    "Load",
                    "Dados_Enviados",
                    "Dados_Recebidos",
                    "Pacotes_Perdido",
                    "Sockets_Tw", 
                    "Timestamp",
                    "Bytes_Lidos_Disco_Acumulados",
                    "Bytes_Escritos_Disco_Acumulados",
                    "Leitura_Disco_MiB_s",
                    "Escrita_Disco_MiB_s",
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
                    "Porcentagem_CPU_Global",
                    "CPUs_Logicas",
                ])

                writer.writerows(buffer_linhas)
                writer_processos.writerows(buffer_processos)

                csvfile.flush()
                arquivo_processos.flush()

            buffer_linhas.clear()
            buffer_processos.clear()
            contador_registros = 0

            print(f"Enviando os CSVs do lote para {nome_empresa}/01-bronze/{HOSTNAMELOCAL}/...", flush=True)
            s3_client.upload_file(
                CAMINHO_CSV,
                os.getenv("NOME_BUCKET"),
                f"{nome_empresa}/01-bronze/{HOSTNAMELOCAL}/{CAMINHO_CSV}"
            )
            s3_client.upload_file(
                CAMINHO_PROCESSOS,
                os.getenv("NOME_BUCKET"),
                f"{nome_empresa}/01-bronze/{HOSTNAMELOCAL}/{CAMINHO_PROCESSOS}"
            )
            print("Os dois CSVs chegaram ao S3.", flush=True)

            os.remove(CAMINHO_CSV)
            os.remove(CAMINHO_PROCESSOS)

if __name__ == "__main__":
    if not URL_AUTENTICACAO:
        raise SystemExit("Preencha URL_AUTENTICACAO no .env com o endereço da API do Noctua.")

    HOSTNAMELOCAL = socket.gethostname()
    print("Hostname detectado:", HOSTNAMELOCAL)
    EMAIL = input("E-mail: ")
    SENHA = getpass("Senha: ")

    try:
        resultado = autenticar_maquina()
        HOSTNAMELOCAL = resultado["mainframe"]["hostname"]
        nome_empresa = resultado["empresa"]["razao_social"].lower().replace(" ", "_")

        bucket_existe = False
        bronze_existe = False
        silver_existe = False
        gold_existe = False

        mostrar_prefixos = s3_client.list_objects_v2(
            Bucket=os.getenv("NOME_BUCKET"), Prefix=f'{nome_empresa}/'
        )
        arquivos = mostrar_prefixos.get("Contents", [])
        
        for arquivo in arquivos:
            if nome_empresa in arquivo['Key']:
                bucket_existe = True
                break

        
        for arquivo in arquivos:
            if "bronze" in arquivo['Key']:
                bronze_existe = True
                break

        
        for arquivo in arquivos:
            if "silver" in arquivo['Key']:
                silver_existe = True
                break


        for arquivo in arquivos:
            if "gold" in arquivo['Key']:
                gold_existe = True
                break
            

        if(not bucket_existe):
            prefixo_hierarquico = f'{nome_empresa}/'

            s3_client.put_object(
                Bucket=os.getenv("NOME_BUCKET"), Key=prefixo_hierarquico, Body=io.BytesIO(b'')
            )

        
        if(not bronze_existe):
            prefixo_hierarquico = f'{nome_empresa}/01-bronze/'

            s3_client.put_object(
                Bucket=os.getenv("NOME_BUCKET"), Key=prefixo_hierarquico, Body=io.BytesIO(b'')
            )

        if(not silver_existe):
            prefixo_hierarquico = f'{nome_empresa}/02-silver/'

            s3_client.put_object(
                Bucket=os.getenv("NOME_BUCKET"), Key=prefixo_hierarquico, Body=io.BytesIO(b'')
            )

        if(not gold_existe):
            prefixo_hierarquico = f'{nome_empresa}/03-gold/'

            s3_client.put_object(
                Bucket=os.getenv("NOME_BUCKET"), Key=prefixo_hierarquico, Body=io.BytesIO(b'')
            )

        prefixo_controle = f"{nome_empresa}/04-controle/{HOSTNAMELOCAL}/"
        objetos_controle = s3_client.list_objects_v2(
            Bucket=os.getenv("NOME_BUCKET"), Prefix=prefixo_controle, MaxKeys=1
        )
        
        if not objetos_controle.get("Contents"):
            s3_client.put_object(
                Bucket=os.getenv("NOME_BUCKET"), Key=prefixo_controle, Body=io.BytesIO(b'')
            )

        print("Captura autorizada para:", HOSTNAMELOCAL)
        leitura()
    except (RuntimeError, requests.exceptions.RequestException) as erro:
        print("Captura encerrada:", erro)
    except KeyboardInterrupt:
        print("\nCaptura encerrada pelo usuário.")
