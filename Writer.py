import requests
import psutil
import os
import time
import csv
import datetime
import socket
 
EMAIL = "isabella.csantos@techsolutions.com.br"
SENHA = "Bella2312@"
HOSTNAMELOCAL = socket.gethostname
URL_AUTENTICACAO = "http://127.0.0.1:3000/api/autenticacao"

CAMINHO_CSV = "dadosBrutos.csv"
INTERVALO_LEITURA = 1 

flags_monitoramento = {}
 
dados = []

def autenticarComponentes(componentes):
    global flags_monitoramento
    

    for comp in componentes:
        flags_monitoramento[comp["tipo"]] = True
        

def leitura():

    arquivo_novo = (
        not os.path.exists(CAMINHO_CSV)) or os.path.getsize(CAMINHO_CSV) == 0


 
    with open(CAMINHO_CSV, 'a', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
 
        if arquivo_novo:
            
            writer.writerow(['HostName', 'CPU', 'RAM', 'Disco', 'Swap', 'Load', 'Timestamp'])

        while True:

            if flags_monitoramento.get("CPU", False):
                cpuAtual = psutil.cpu_percent(interval=1)
            else:
                cpuAtual = 0

            # RAM
            if flags_monitoramento.get("RAM", False):
                ramAtual = psutil.virtual_memory().percent
            else:
                ramAtual = 0

            # DISCO
            if flags_monitoramento.get("DISCO", False):
                discoAtual = psutil.disk_usage("/").percent
            else:
                discoAtual = 0

            # SWAP
            if flags_monitoramento.get("SWAP", False):
                swapAtual = psutil.swap_memory().percent
            else:
                swapAtual = 0

            # Cálculo de LOAD
            if flags_monitoramento.get("LOAD", False):
                loadAtual = (psutil.getloadavg()[0] / psutil.cpu_count()) * 100
            else:
                loadAtual = 0
    
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
 
            linha = [HOSTNAMELOCAL, cpuAtual, ramAtual, discoAtual, swapAtual, round(loadAtual, 2), timestamp]
 
            dados.append(linha)
            print(linha)
 
            writer.writerow(linha)
            csvfile.flush()
 
            time.sleep(INTERVALO_LEITURA)
 

try:

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
    print(resultado)

    if resultado.get("autenticado"):

        print("Autenticação realizada com sucesso!")
        print("Hostname:", resultado["mainframe"]["hostname"])

        componentes = resultado["componentes"]

        autenticarComponentes(componentes)

        leitura()

    else:

        print("Falha na autenticação.")

except requests.exceptions.HTTPError as erro:

    print("Erro na autenticação:", erro)

except requests.exceptions.RequestException as erro:

    print("Não foi possível conectar à API:", erro)