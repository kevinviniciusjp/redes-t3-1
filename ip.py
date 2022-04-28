from grader.iputils import IPPROTO_ICMP
from sys import prefix
from grader.tcputils import addr2str, calc_checksum, fix_checksum, str2addr
import struct
from iputils import *
import ipaddress


class IP:
    def _init_(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = []

  def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            next_hop = self._next_hop(dst_addr)
            ttl -= 1
            if ttl>0:
                datagrama= struct.pack('!BBHHHBBHII',69,dscp|ecn,20,identification,flags|frag_offset,ttl,proto,0,int(ipaddress.ip_address(src_addr)),int(ipaddress.ip_address(dst_addr)))
                aux = calc_checksum(datagrama)    
                datagrama= struct.pack('!BBHHHBBHII',69,dscp|ecn,20,identification,flags|frag_offset,ttl,proto,aux,int(ipaddress.ip_address(src_addr)),int(ipaddress.ip_address(dst_addr)))
                self.enlace.enviar(datagrama, next_hop)
            else:
                nova_next_hop = self._next_hop(src_addr)
                datagrama_fail= struct.pack('!BBHHHBBHII',69,dscp|ecn,48,identification,flags|frag_offset,64,1,0,int(ipaddress.ip_address(self.meu_endereco)),int(ipaddress.ip_address(src_addr)))
                aux = calc_checksum(datagrama_fail)    
                datagrama_fail= struct.pack('!BBHHHBBHII',69,dscp|ecn,48,identification,flags|frag_offset,64,1,aux,int(ipaddress.ip_address(self.meu_endereco)),int(ipaddress.ip_address(src_addr)))
                icmp = struct.pack('!BBHHH', 11, 0, 0, 0, 0)
                aux2 = calc_checksum(icmp + datagrama_fail)
                icmp = struct.pack('!BBHHH', 11, 0, aux2, 0, 0)
                msgFinal = datagrama_fail + icmp + datagrama[:28]
                self.enlace.enviar(msgFinal,nova_next_hop)
                return None

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        contador = 0
        indices = []
        maxprefixlen = 0
        maior = 0
        for i in range(len(self.tabela)):
            if ipaddress.ip_address(dest_addr) in ipaddress.ip_network(self.tabela[i][0]):
                contador += 1
                indices.append(i)
        if contador > 1:
            for j in indices:
                if (ipaddress.ip_network(self.tabela[j][0])).prefixlen > maxprefixlen:
                    maxprefixlen = (ipaddress.ip_network(self.tabela[j][0])).prefixlen
                    maior = j
            return self.tabela[maior][1]
        elif contador == 1:
            return self.tabela[indices[0]][1]
        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]
        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        datagrama = struct.pack('!BBHHHBBHII', 69, 0, 20+len(segmento), self.counter+1, 0, 64, 6, 0, int.from_bytes(str2addr(self.meu_endereco), 'big'), int.from_bytes(str2addr(dest_addr), 'big'))
        headerchecksum = calc_checksum(datagrama)
        datagrama = struct.pack('!BBHHHBBHII', 69, 0, 20+len(segmento), self.counter+1, 0, 64, 6, headerchecksum, int.from_bytes(str2addr(self.meu_endereco), 'big'), int.from_bytes(str2addr(dest_addr), 'big'))
        datagrama = datagrama + segmento
        self.counter = self.counter + 1
        self.enlace.enviar(datagrama, next_hop)
