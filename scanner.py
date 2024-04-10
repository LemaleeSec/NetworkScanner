from scapy.all import *
import argparse
import sys         #Biblioteca para sair do programa se a interface nao for selecionada 

#Os prints estao em ingles pq eu prefiro okay professor, nao isso nao foi copiado de IA

#Funcao para fazer o Scan na interface
def scan_packet(packet):
    if IP in packet:               #SE o Ip estiver no argumento packet 
        src_ip = packet[IP].src    #Define source ip = packet[dicionario do scapy IP]e o .src  acessa o endereco IP do pacote
        dst_ip = packet[IP].dst
        print(f'----------------------------------------------------')

#TCP - navegacao web e etc.
    if TCP in packet:
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport
        print(f'Protocolo: TCP')
        print(f'Source Address: {src_ip} ')    #Chamando a variavel de origem do ip
        print(f'Destination Address: {dst_ip} ') # Chama a variavel de destino do ip
        print(f'Source Port: {tcp_sport}')      #Chama a variavel da origem da porta tcp declarada no if 
        print(f'Destination Port: {tcp_dport}') #Chama a variavel de destino da porta tcp  declarada no if tbm
        if TCP in packet and packet[TCP].flags == 'S': #Envia e Verifica o SYN no protocolo TCP
            print(f'Varredura de porta detectada no {packet[IP].src} para {packet[IP].dst}') 

#UDP - jogos onlines, transmissoes em tempo real e etc. 
    elif UDP in packet:
        udp_sport = packet[UDP].sport
        udp_dport = packet[UDP].dport
        print(f'Protocolo: UDP')
        print(f'Source IP Address: {src_ip} ')
        print(f'Destination IP Address: {dst_ip} ')
        print(f'Source Port: {udp_sport}')
        print(f'Destination Port: {udp_dport}')
#IMCP - Echo request e Echo repy (usado em ping)
    elif ICMP in packet:
        icmp_type = packet[ICMP].type           #Declara a variavel para o protocolo ICMP
        icmp_code = packet[ICMP].code
        print(f'Protocolo: ICMP')
        print(f'Source IP Address: {src_ip} ')
        print(f'Destination IP Address: {dst_ip} ')
        print(f'Source Port: {icmp_type}')
        print(f'Destination Port: {icmp_code}')
#ARP - Mapea o ip e endereco fisico
    elif ARP in packet:
        arp_op = packet[ARP].op
        arp_psrc = packet[ARP].psrc
        arp_pdst = packet[ARP].pdst
        print(f'Protocolo: ARP')
        print(f'Source IP Address: {arp_psrc} ')
        print(f'Destination IP Address: {arp_pdst} ')
        print(f'Operation: {arp_op}')



if __name__ == "__main__":  #Costrutor  usado para executar apenas um bloco de codigo e o que esta apos dele sera executado depois
#Argparse usado para adicionar os argumentos como --help , -i e etc.
    parser = argparse.ArgumentParser(description='Scanear IP') 
    parser.add_argument('-i', '--interface', help='Selecinar Interface de Rede')
    parser.add_argument('-p', '--protocolo', help='Filtrar o Protocolo Especifico')
    arg = parser.parse_args()
#Se o valor do arg.interface -i eth0 for vazio ele nao executa e pede para inserir
    if not arg.interface:
        print("Por favor, especifique uma interface de rede usando o argumento -i/--interface.")
        print("Please specify a network interface using the -i/--interface argument")
        sys.exit(1)
#sniff usado para capturar pacotes de rede no scapy
#prn=scan_packet ele chama  a funcao de volta para cada pacote capturado
#store=0 serve para nao armazenar e nao gastar a memoria do sistema
#iface=arg.interface  usado para capturar apenas a interface selecionada
    sniff(prn=scan_packet, store=0, iface=arg.interface)
