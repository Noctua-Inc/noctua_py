import requests
import psutil
import os
import time
import csv
import datetime
import socket

URL_AUTENTICACAO = "http://127.0.0.1:3000/api/autenticacao"

INTERVALO_LEITURA = 1 

flags_monitoramento = {}
 
dados = []

def autenticarComponentes(componentes):
    global flags_monitoramento
    

    for comp in componentes:
        flags_monitoramento[comp["tipo"]] = True
        

def leitura():
    CAMINHO_CSV = HOSTNAMELOCAL + ".csv"

    arquivo_novo = (
        not os.path.exists(CAMINHO_CSV)) or os.path.getsize(CAMINHO_CSV) == 0


 
    with open(CAMINHO_CSV, 'a', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
 
        if arquivo_novo:
            
            writer.writerow(['HostName', 
                             'Porcentagem_CPU', 
                             'Freq_CPU',
                             'Porcentagem_RAM', 
                             'Total_RAM', 
                             'Disponivel_RAM', 
                             'Porcentagem_Disco',
                             'Disponiel_Disco', 
                             'Swap', 
                             'Load', 
                             'Timestamp'])

        while True:

            if flags_monitoramento.get("CPU", False):
                cpuAtual = psutil.cpu_percent(interval=1)
                cpu_frequencia_atual = round((psutil.cpu_freq().current), 2)
            else:
                cpuAtual = 0
                cpu_frequencia_atual = 0

            # RAM
            if flags_monitoramento.get("RAM", False):
                ramAtual = psutil.virtual_memory().percent
                memoria_ram_total = round((psutil.virtual_memory().total), 2)
                memoria_ram_disponivel = round((psutil.virtual_memory().available), 2)
            else:
                ramAtual = 0
                memoria_ram_total = 0
                memoria_ram_disponivel = 0

            # DISCO
            if flags_monitoramento.get("DISCO", False):
                discoAtual = psutil.disk_usage("/").percent
                disco_livre = round((psutil.disk_usage("/").free), 2)
            else:
                discoAtual = 0
                disco_livre = 0

            # SWAP
            if flags_monitoramento.get("SWAP", False):
                swapAtual = psutil.swap_memory().percent
            else:
                swapAtual = 0

            # Cálculo de LOAD
            if flags_monitoramento.get("CPU", False):
                loadAtual = (psutil.getloadavg()[0] / psutil.cpu_count()) * 100
            else:
                loadAtual = 0
    
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
 
            linha = [HOSTNAMELOCAL, 
                    cpuAtual, 
                    cpu_frequencia_atual, 
                    ramAtual, 
                    memoria_ram_total, 
                    memoria_ram_disponivel, 
                    discoAtual,
                    disco_livre,
                    swapAtual, 
                    round(loadAtual, 2), 
                    timestamp]
 
            dados.append(linha)
            print(linha)
 
            writer.writerow(linha)
            csvfile.flush()
 
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
            mainframes = resultado['mainframe']
            print("Em qual servidor será a captura")
            i = 1
            for mf in mainframes:
                print(f"{i} - {mf["hostname"]}")
                i += 1

            escolha = int(input("Servidor: "))

            HOSTNAMELOCAL = mainframes[escolha - 1]["hostname"]
        else:
            print("E-mail ou senha inválidas!")

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

# try:

#     resposta = requests.post(
#         URL_AUTENTICACAO,
#         json={
#             "email": EMAIL,
#             "senha": SENHA,
#             "hostname": HOSTNAMELOCAL
#         }
#     )
#     resposta.raise_for_status()

#     resultado = resposta.json()
#     print(resultado)

#     if resultado.get("autenticado"):

#         print("Autenticação realizada com sucesso!")
#         print("Hostname:", resultado["mainframe"]["hostname"])

#         componentes = resultado["componentes"]

#         autenticarComponentes(componentes)

#         leitura()

#     else:

#         print("Falha na autenticação.")

# except requests.exceptions.HTTPError as erro:
#     print("Status:", erro.response.status_code)
#     print("Resposta da API:", erro.response.text)

# except requests.exceptions.RequestException as erro:

#     print("Não foi possível conectar à API:", erro)