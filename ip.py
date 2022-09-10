from iputils import *
from random import randint
from ipaddress import ip_network, ip_address
import struct
import logging as logger

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        #self.meu_endereco = None

    def _make_ipv4_header(
        self, src_addr, dest_addr, datagram=None, proto=IPPROTO_TCP, ttl=255, payload=""
    ):
        version = 4 << 4
        ihl = 5
        vihl = version + ihl
        src_addr = str2addr(src_addr)
        dest_addr = str2addr(dest_addr)

        if not datagram:
            dscp = 0 << 6
            ecn = 0
            ident = self._twos_comp(randint(0, 2**16), 16)
            flags = (0 << 15) | (0 << 14) | (0 << 13)
            frag_offset = 0

        else:
            dscp, ecn, ident, flags, frag_offset, _, _, _, _, _ = read_ipv4_header(datagram)

        dscpecn = dscp + ecn
        flags |= frag_offset
        ttl = self._twos_comp(ttl, 8)
        tlen = self._twos_comp(len(payload) + 20, 16)

        header = (
            struct.pack("!bbhhhbbh", vihl, dscpecn, tlen, ident, flags, ttl, proto, 0)
            + src_addr
            + dest_addr
        )
        checksum = self._twos_comp(calc_checksum(header[: 4 * ihl]), 16)
        header = (
            struct.pack("!bbhhhbbh", vihl, dscpecn, tlen, ident, flags, ttl, proto, checksum)
            + src_addr
            + dest_addr
        )
        return header

    def _make_icmp_payload(self, datagram):
        payload = datagram[:28]
        tlen = len(payload) + 8
        header = struct.pack("!bbhi", 11, 0, 0, tlen) + payload
        checksum = self._twos_comp(calc_checksum(header), 16)
        header = struct.pack("!bbhi", 11, 0, checksum, tlen) + payload
        return header

    def __raw_recv(self, datagrama):
        (
            dscp,
            ecn,
            identification,
            flags,
            frag_offset,
            ttl,
            proto,
            src_addr,
            dst_addr,
            payload,
        ) = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                logger.info(f"Callback {src_addr} -> {dst_addr}.")
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            ttl -= 1
            next_hop = self._next_hop(dst_addr)
            logger.debug(f"TTL atualizado para {ttl}.")

            if ttl > 0:
                header = self._make_ipv4_header(src_addr, dst_addr, datagram=datagrama, ttl=ttl)
                datagram = header + payload
            else:
                next_hop = self._next_hop(src_addr)
                payload = self._make_icmp_payload(datagrama)
                header = self._make_ipv4_header(
                    self.meu_endereco,
                    src_addr,
                    datagram=datagrama,
                    payload=payload,
                    proto=IPPROTO_ICMP,
                )
                datagram = header + payload
            logger.info(f"Enviando datagrama para {next_hop}.")
            self.enlace.enviar(datagram, next_hop)

    def _next_hop(self, dest_addr):
        dest_addr = ip_address(dest_addr)

        for cidr, next_hop in self.routing_table:
            if dest_addr in cidr:
                return str(next_hop)
        return None

    def _twos_comp(self, value, bits):
        """compute the 2's complement of int value val"""
        if (value & (1 << (bits - 1))) != 0:  # if sign bit is set e.g., 8bit: 128-255
            value = value - (1 << bits)  # compute negative value
        return value  # return positive value as is

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
        self.routing_table = []
        for cidr, next_hop in tabela:
            self.routing_table.append((ip_network(cidr), ip_address(next_hop)))
        self.routing_table.sort(key=lambda pair: pair[0].prefixlen, reverse=True)

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
        header = self._make_ipv4_header(self.meu_endereco, dest_addr, payload=segmento)
        self.enlace.enviar(header + segmento, next_hop)
