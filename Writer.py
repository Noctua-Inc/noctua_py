import requests
import psutil
import os
import csv
import datetime
import uuid
from hashlib import sha256
import io, boto3
import socket
import time
from getpass import getpass
from urllib.parse import quote_plus, unquote_plus
from dotenv import load_dotenv
from botocore.exceptions import ClientError

load_dotenv()

session = boto3.Session(
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    aws_session_token=os.getenv("AWS_SESSION_TOKEN"),
    region_name="us-east-1",
)
s3_client = session.client("s3")
lambda_client = session.client("lambda")

URL_AUTENTICACAO = os.getenv("URL_AUTENTICACAO")

flags_monitoramento = {"CPU": True, "RAM": True, "DISCO": True, "SWAP": True, "REDE": True}
INTERVALO_AMOSTRA_CPU = 1.0


def autenticar_maquina():
    resposta = requests.post(
        URL_AUTENTICACAO,
        json={"email": EMAIL, "senha": SENHA, "hostname": HOSTNAMELOCAL},
        timeout=15
    )
    if not resposta.ok:
        raise RuntimeError(resposta.json().get("mensagem", "Não foi possível autorizar a captura."))
    return resposta.json()


def eventos_cobertos(gatilho, arn, prefixo, sufixo):
    if gatilho["LambdaFunctionArn"] != arn:
        return ()
    filtros = gatilho.get("Filter", {}).get("Key", {}).get("FilterRules", [])
    valores = {filtro["Name"].lower(): unquote_plus(filtro["Value"]) for filtro in filtros}
    if prefixo.startswith(valores.get("prefix", "")) and sufixo.endswith(valores.get("suffix", "")):
        return gatilho["Events"]
    return ()


def criar_gatilhos_lambda():
    bucket = os.getenv("NOME_BUCKET")
    bronze = os.getenv("NOME_LAMBDA_BRONZE")
    silver = os.getenv("NOME_LAMBDA_SILVER")
    if not all((bucket, bronze, silver)):
        raise RuntimeError("Preencha NOME_BUCKET, NOME_LAMBDA_BRONZE e NOME_LAMBDA_SILVER no .env.")

    configuracao = s3_client.get_bucket_notification_configuration(Bucket=bucket)
    notificacao = {chave: valor for chave, valor in configuracao.items() if chave != "ResponseMetadata"}
    gatilhos = list(notificacao.get("LambdaFunctionConfigurations", []))
    arns = {
        nome: lambda_client.get_function(FunctionName=nome)["Configuration"]["FunctionArn"]
        for nome in dict.fromkeys((bronze, silver))
    }
    eventos_criacao = ("s3:ObjectCreated:Put", "s3:ObjectCreated:Post", "s3:ObjectCreated:Copy",
                       "s3:ObjectCreated:CompleteMultipartUpload")
    pendentes = []
    for camada, arn, regras in (
        ("01-bronze", arns[bronze], (("bronze", ".csv"),)),
        ("02-silver", arns[silver], (("historico", "_historico.csv"), ("processos", "_silver.csv"))),
    ):
        prefixo = f"{nome_empresa}/{camada}/{HOSTNAMELOCAL}/"
        for tipo, sufixo in regras:
            cobertos = {evento for g in gatilhos for evento in eventos_cobertos(g, arn, prefixo, sufixo)}
            faltantes = [evento for evento in eventos_criacao if evento not in cobertos]
            if "s3:ObjectCreated:*" in cobertos or not faltantes:
                continue
            eventos = ["s3:ObjectCreated:*"] if len(faltantes) == len(eventos_criacao) else faltantes
            chave = sha256(f"{arn}|{prefixo}|{sufixo}|{','.join(eventos)}".encode()).hexdigest()[:16]
            pendentes.append({
                "Id": f"noctua-{tipo}-{chave}",
                "LambdaFunctionArn": arn,
                "Events": eventos,
                "Filter": {"Key": {"FilterRules": [
                    {"Name": "prefix", "Value": quote_plus(prefixo, safe="/")},
                    {"Name": "suffix", "Value": sufixo},
                ]}},
            })

    if not pendentes:
        print("Os gatilhos de captura já estão configurados.", flush=True)
        return

    identificador_bucket = sha256(bucket.encode()).hexdigest()[:16]
    for arn in dict.fromkeys(g["LambdaFunctionArn"] for g in pendentes):
        particao = arn.split(":")[1]
        try:
            lambda_client.add_permission(
                FunctionName=arn,
                StatementId=f"noctua-s3-{identificador_bucket}",
                Action="lambda:InvokeFunction",
                Principal="s3.amazonaws.com",
                SourceArn=f"arn:{particao}:s3:::{bucket}",
            )
        except ClientError as erro:
            if erro.response["Error"]["Code"] != "ResourceConflictException":
                raise

    notificacao["LambdaFunctionConfigurations"] = gatilhos + pendentes
    try:
        s3_client.put_bucket_notification_configuration(Bucket=bucket, NotificationConfiguration=notificacao)
    except ClientError as erro:
        detalhe = erro.response["Error"]
        if detalhe["Code"] != "InvalidArgument" or "Unable to validate" not in detalhe.get("Message", ""):
            raise
        destinos = ", ".join(
            f"{regra.get('Id', 'sem ID')} → {regra[campo]}"
            for grupo, campo in (
                ("LambdaFunctionConfigurations", "LambdaFunctionArn"),
                ("TopicConfigurations", "TopicArn"),
                ("QueueConfigurations", "QueueArn"),
            )
            for regra in notificacao.get(grupo, [])
        )
        raise RuntimeError(
            f"O S3 recusou a configuração do bucket {bucket} ao validar seus destinos. "
            f"Verifique existência, região e permissão de cada destino: {destinos}"
        ) from erro

    print(f"{len(pendentes)} gatilho(s) de captura configurado(s).", flush=True)


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


def capturar_snapshot_cpu():
    processos = {}

    for processo in psutil.process_iter(attrs=["pid", "create_time", "cpu_times"]):
        try:
            dados = processo.info
            tempos = dados.get("cpu_times")
            segundos_cpu = None if tempos is None else tempos.user + tempos.system
            chave = (dados["pid"], dados.get("create_time"))
            processos[chave] = {
                "segundos_cpu": segundos_cpu,
                "instante": time.monotonic(),
            }
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            continue

    tempos_cpu_sistema = psutil.cpu_times(percpu=True)
    return tempos_cpu_sistema, processos


def calcular_percentual_cpu_global(antes, depois):
    total_decorrido = 0.0
    ocioso_decorrido = 0.0

    for cpu_antes, cpu_depois in zip(antes, depois):
        campos = [campo for campo in cpu_antes._fields if campo not in {"guest", "guest_nice"}]
        total_decorrido += sum(
            getattr(cpu_depois, campo) - getattr(cpu_antes, campo)
            for campo in campos
        )
        ocioso_decorrido += (
            cpu_depois.idle - cpu_antes.idle
            + getattr(cpu_depois, "iowait", 0.0) - getattr(cpu_antes, "iowait", 0.0)
        )

    if total_decorrido <= 0.0:
        return 0.0

    ocupado = max(0.0, total_decorrido - ocioso_decorrido)
    percentual = (ocupado / total_decorrido) * 100.0
    return max(0.0, min(100.0, round(percentual, 2)))


def calcular_percentuais_cpu_processos(antes, depois):
    percentuais = {}

    for chave, amostra_depois in depois.items():
        amostra_antes = antes.get(chave)
        if (amostra_antes is None or amostra_antes["segundos_cpu"] is None
                or amostra_depois["segundos_cpu"] is None):
            percentuais[chave] = 0.0
            continue

        intervalo = amostra_depois["instante"] - amostra_antes["instante"]
        delta_cpu = amostra_depois["segundos_cpu"] - amostra_antes["segundos_cpu"]
        if intervalo <= 0.0 or delta_cpu < 0.0:
            percentuais[chave] = 0.0
            continue

        percentual = (delta_cpu / intervalo) * 100.0
        percentuais[chave] = max(0.0, min(100.0, round(float(percentual), 2)))

    return percentuais


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
            tempos_cpu_antes, processos_cpu_antes = capturar_snapshot_cpu()
            time.sleep(INTERVALO_AMOSTRA_CPU)
            tempos_cpu_depois, processos_cpu_depois = capturar_snapshot_cpu()

            cpu_atual = calcular_percentual_cpu_global(tempos_cpu_antes, tempos_cpu_depois)
            percentuais_cpu_processos = calcular_percentuais_cpu_processos(
                processos_cpu_antes,
                processos_cpu_depois,
            )
            cpu_frequencia_atual = round((psutil.cpu_freq().current), 2)
        else:
            cpu_atual = 0
            percentuais_cpu_processos = {}
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
                if flags_monitoramento.get("CPU", False):
                    try:
                        chave_cpu = (pid, processo.create_time())
                        cpu_processo = percentuais_cpu_processos.get(chave_cpu, 0.0)
                    except psutil.AccessDenied:
                        cpu_processo = 0.0
                else:
                    cpu_processo = processo.cpu_percent(interval=None)
                cpu_processo = max(0.0, min(100.0, round(float(cpu_processo), 2)))
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

        prefixo_bronze_hostname = f'{nome_empresa}/01-bronze/{HOSTNAMELOCAL}/'
        if prefixo_bronze_hostname not in [arquivo['Key'] for arquivo in arquivos]:
            s3_client.put_object(
                Bucket=os.getenv("NOME_BUCKET"), Key=prefixo_bronze_hostname, Body=io.BytesIO(b'')
            )

        if(not silver_existe):
            prefixo_hierarquico = f'{nome_empresa}/02-silver/'

            s3_client.put_object(
                Bucket=os.getenv("NOME_BUCKET"), Key=prefixo_hierarquico, Body=io.BytesIO(b'')
            )

        prefixo_silver_hostname = f'{nome_empresa}/02-silver/{HOSTNAMELOCAL}/'
        if prefixo_silver_hostname not in [arquivo['Key'] for arquivo in arquivos]:
            s3_client.put_object(
                Bucket=os.getenv("NOME_BUCKET"), Key=prefixo_silver_hostname, Body=io.BytesIO(b'')
            )

        if(not gold_existe):
            prefixo_hierarquico = f'{nome_empresa}/03-gold/'

            s3_client.put_object(
                Bucket=os.getenv("NOME_BUCKET"), Key=prefixo_hierarquico, Body=io.BytesIO(b'')
            )

        prefixo_gold_hostname = f'{nome_empresa}/03-gold/{HOSTNAMELOCAL}/'
        if prefixo_gold_hostname not in [arquivo['Key'] for arquivo in arquivos]:
            s3_client.put_object(
                Bucket=os.getenv("NOME_BUCKET"), Key=prefixo_gold_hostname, Body=io.BytesIO(b'')
            )

        prefixo_controle = f"{nome_empresa}/04-controle/{HOSTNAMELOCAL}/"
        objetos_controle = s3_client.list_objects_v2(
            Bucket=os.getenv("NOME_BUCKET"), Prefix=prefixo_controle, MaxKeys=1
        )
        
        if not objetos_controle.get("Contents"):
            s3_client.put_object(
                Bucket=os.getenv("NOME_BUCKET"), Key=prefixo_controle, Body=io.BytesIO(b'')
            )

        criar_gatilhos_lambda()

        print("Captura autorizada para:", HOSTNAMELOCAL)
        leitura()
    except (RuntimeError, requests.exceptions.RequestException, ClientError) as erro:
        print("Captura encerrada:", erro)
    except KeyboardInterrupt:
        print("\nCaptura encerrada pelo usuário.")
