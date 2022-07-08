#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from typing import List, Dict, Set, Sequence, Union
from io import BytesIO
import sys

def mon_adler32(entree : bytes) -> int:
    somme_des_octets = 0
    somme_de_chaque_octet_fois_sa_position_depuis_la_fin = 0
    
    for position, octet in enumerate(entree):
        position_depuis_la_fin = len(entree) - position
        
        somme_des_octets += octet
        somme_de_chaque_octet_fois_sa_position_depuis_la_fin += octet * position_depuis_la_fin
        
    somme_des_octets += 1
    somme_de_chaque_octet_fois_sa_position_depuis_la_fin += len(entree)
    
    somme_de_chaque_octet_fois_sa_position_depuis_la_fin %= 65521
    somme_des_octets %= 65521
        
    return (somme_de_chaque_octet_fois_sa_position_depuis_la_fin << 16) | somme_des_octets

class LecteurDeBits:

    def __init__(self, entree : bytes):
        
        self.octets = BytesIO(entree)
        self.bits_non_lus = 0
        self.taille_bits_non_lus = 0
    
    def lire_bits(self, nombre_bits : int) -> int:

        while self.taille_bits_non_lus < nombre_bits:
            
            prochain_octet = self.octets.read(1)
            
            if not prochain_octet:
                raise EOFError

            self.bits_non_lus |= prochain_octet[0] << self.taille_bits_non_lus
            self.taille_bits_non_lus += 8
    
        masque_bits_lus = (1 << nombre_bits) - 1
        
        bits_lus = self.bits_non_lus & masque_bits_lus
        
        self.bits_non_lus >>= nombre_bits
        self.taille_bits_non_lus -= nombre_bits
        
        return bits_lus

    def lire_octets(self, nombre_octets : int) -> bytes:
        
        self.aligner_bits_sur_octet()
        
        octets_lus = self.octets.read(nombre_octets)
        
        if len(octets_lus) < nombre_octets:
            raise EOFError # Pas assez d'octets, déclencher une erreur, EOF = End of file = Fin de fichier
        
        return octets_lus
    
    def aligner_bits_sur_octet(self):
        
        self.bits_non_lus = 0
        self.taille_bits_non_lus = 0
    
# Notre décodeur de Huffman.

class DecodeurHuffman:

    def __init__(self, valeur_vers_taille_de_code : Dict[int, int], lecteur_de_bits : LecteurDeBits):
                
        self.chaine_de_code_vers_valeur : Dict[str, int] = {}
        
        self.lecteur_de_bits : LecteurDeBits = lecteur_de_bits
        
        derniere_taille_de_code : int = None
        dernier_code : int = None
        
        def tri_valeurs(valeur_et_taille_de_code):
            valeur, taille_de_code = valeur_et_taille_de_code # On prend la tuple...
            return (taille_de_code, valeur) # ... et on la change de sens pour dire qu'on trie par tailles de code d'abord
        
        for valeur, taille_de_code in sorted(valeur_vers_taille_de_code.items(), key = tri_valeurs):
            
            if not taille_de_code:
                continue # Taille de code de 0 ! On passe !
            
            if dernier_code is None:
                code = 0
                
            else:
                if taille_de_code < derniere_taille_de_code:
                    raise Exception
                
                elif taille_de_code > derniere_taille_de_code:
                    code = (dernier_code + 1) << (taille_de_code - derniere_taille_de_code)
                
                else:
                    code = dernier_code + 1
            
            chaine_de_code = format(code, 'b').zfill(taille_de_code)
            self.chaine_de_code_vers_valeur[chaine_de_code] = valeur
            dernier_code = code
            derniere_taille_de_code = taille_de_code
        
        self.mon_arbre : Dict[int, Union[dict, int]] = {}
        
        for chaine_de_code, valeur in self.chaine_de_code_vers_valeur.items():
            noeud_actuel_dans_l_arbre = self.mon_arbre
                
            for chiffre_bit in chaine_de_code[:-1]:
                bit = int(chiffre_bit) # Conversion de chaîne en entier
                
                if bit not in noeud_actuel_dans_l_arbre:
                    
                    noeud_actuel_dans_l_arbre[bit] = {} # Création de dictionnaire
                
                noeud_actuel_dans_l_arbre = noeud_actuel_dans_l_arbre[bit]
            dernier_bit = int(chaine_de_code[-1])
            noeud_actuel_dans_l_arbre[dernier_bit] = valeur
        
    def lire_prochaine_valeur(self) -> int:
            
            noeud_actuel_dans_l_arbre = self.mon_arbre
            
            
            while True:
                prochain_bit : int = self.lecteur_de_bits.lire_bits(1)
    
                noeud_actuel_dans_l_arbre = noeud_actuel_dans_l_arbre[prochain_bit]
                if type(noeud_actuel_dans_l_arbre) == int:
                    return noeud_actuel_dans_l_arbre

def mon_decodeur_zlib(entree : bytes) -> bytes:
     
    lecteur_de_bits = LecteurDeBits(entree)
    
    compression_method = lecteur_de_bits.lire_bits(4)
    compression_info = lecteur_de_bits.lire_bits(4)
    
    fcheck = lecteur_de_bits.lire_bits(5)
    fdict = lecteur_de_bits.lire_bits(1)
    flevel = lecteur_de_bits.lire_bits(2)
    
    
    if fdict:
        dict_id = lecteur_de_bits.lire_bits(32)
    
    assert compression_method == 8 # DEFLATE
    
    assert int.from_bytes(entree[:2], 'big') % 31 == 0
    contenu_decompresse = b''
    
    while True:
        
        blocs_restants_ensuite = lecteur_de_bits.lire_bits(1) != 1
        type_de_bloc = lecteur_de_bits.lire_bits(2)


        if type_de_bloc == 0: # Contenu stocké sans compression
            
            lecteur_de_bits.aligner_bits_sur_octet()
            taille_a_lire = lecteur_de_bits.lire_bits(16)
            assert lecteur_de_bits.lire_bits(16) ^ 0xffff == taille_a_lire
            contenu_decompresse += lecteur_de_bits.lire_octets(taille_a_lire)
        
        elif type_de_bloc in (0b01, 0b10): # Instructions codées en Huffman
            
            if type_de_bloc == 0b01: # Arbre pré-défini - d'après https://tools.ietf.org/html/rfc1951#page-12
                
                valeur_vers_taille_de_code = {}
                for valeur in range(256, 279 + 1):
                    valeur_vers_taille_de_code[valeur] = 7
                for valeur in range(0, 143 + 1):
                    valeur_vers_taille_de_code[valeur] = 8
                for valeur in range(280, 287 + 1):
                    valeur_vers_taille_de_code[valeur] = 8
                for valeur in range(144, 255 + 1):
                    valeur_vers_taille_de_code[valeur] = 9
                
                arbre_des_instructions = DecodeurHuffman(valeur_vers_taille_de_code, lecteur_de_bits)
                
                arbre_des_distances = DecodeurHuffman({position: 5 for position in range(0, 31 + 1)}, lecteur_de_bits)
                
            elif type_de_bloc == 0b10: # Arbre inclus dans le flux DEFLATE (voir https://tools.ietf.org/html/rfc1951#page-13)
                
                taille_arbre_des_instructions = lecteur_de_bits.lire_bits(5) + 257
                taille_arbre_des_distances = lecteur_de_bits.lire_bits(5) + 1
                taille_arbre_des_tailles_de_code = lecteur_de_bits.lire_bits(4) + 4
                valeurs_des_tailles_de_code_dans_l_ordre = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
                tailles_de_valeurs_de_l_arbre_de_tailles : Dict[int] = {}
                for position in range(taille_arbre_des_tailles_de_code):
                    vraie_position = valeurs_des_tailles_de_code_dans_l_ordre[position]
                    
                    tailles_de_valeurs_de_l_arbre_de_tailles[vraie_position] = lecteur_de_bits.lire_bits(3)
                    
                arbre_des_tailles_de_code = DecodeurHuffman(tailles_de_valeurs_de_l_arbre_de_tailles,  lecteur_de_bits)
                
                def obtenir_n_tailles_de_code(nombre_tailles_de_code):
                    
                    tailles_de_code : List[int] = []
                    while len(tailles_de_code) < nombre_tailles_de_code:
                        code_de_taille = arbre_des_tailles_de_code.lire_prochaine_valeur() # Code de taille de code !
                        if code_de_taille < 16:
                            tailles_de_code.append(code_de_taille)
                        elif code_de_taille == 16:
                            tailles_de_code += [tailles_de_code[-1]] * (3 + lecteur_de_bits.lire_bits(2))
                        elif code_de_taille == 17:
                            tailles_de_code += [0] * (3 + lecteur_de_bits.lire_bits(3))
                        elif code_de_taille == 18:
                            tailles_de_code += [0] * (11 + lecteur_de_bits.lire_bits(7))
                    
                    return tailles_de_code
                
                arbre_des_instructions = DecodeurHuffman(
                    dict(enumerate(obtenir_n_tailles_de_code(taille_arbre_des_instructions))),
                    lecteur_de_bits)
                
                arbre_des_distances = DecodeurHuffman(
                    dict(enumerate(obtenir_n_tailles_de_code(taille_arbre_des_distances))),
                    lecteur_de_bits)
                
            
            while True:
                code_instruction = arbre_des_instructions.lire_prochaine_valeur()
                
                if code_instruction == 256: # Fin du bloc
                    break
                
                elif code_instruction < 256:
                    contenu_decompresse += bytes([code_instruction])
                
                else:
                    
                    if code_instruction < 265:
                        taille_repetition = 3 + (code_instruction - 257)
            
                    
                    elif code_instruction < 285:
                        extra_bits = 1 + ((code_instruction - 265) >> 2)         
                        taille_repetition = 3 + ((0b100 | ((code_instruction - 265) & 0b11)) << extra_bits)
                        taille_repetition += lecteur_de_bits.lire_bits(extra_bits)
                    
                    else:
                        raise ValueError("Type de code d'instruction DEFLATE invalide : %d" % code_instruction)

                    code_distance = arbre_des_distances.lire_prochaine_valeur()
                    
                    if code_distance < 4:
                        distance = 1 + code_distance
                    else:
                        extra_bits = 1 + ((code_distance - 4) >> 1)
                        distance = 1 + ((0b10 | ((code_distance - 2) & 1)) << extra_bits)
                        distance += lecteur_de_bits.lire_bits(extra_bits)
                    
                    contenu_a_repeter = contenu_decompresse[
                        -distance:
                        -distance + taille_repetition if (-distance + taille_repetition) < 0 else None
                    ]
                    
                    while contenu_a_repeter and len(contenu_a_repeter) < taille_repetition:
                        contenu_a_repeter *= 2
                    contenu_a_repeter = contenu_a_repeter[:taille_repetition]
                    contenu_decompresse += contenu_a_repeter
                    
                    
        else:
            
            raise ValueError('Type de bloc DEFLATE invalide : « 11 ». Est-ce bien du DEFLATE ?')
                
        if not blocs_restants_ensuite:
            lecteur_de_bits.aligner_bits_sur_octet()
            break
    
    somme_adler32 = int.from_bytes(entree[-4:], 'big')
    assert mon_adler32(contenu_decompresse) == somme_adler32
    return contenu_decompresse


input = "789c734bcc2cd6cd495548cecfcd4d5528ce54c8523fbcb20428a890737801977362914249a94231885f58aa9ea55e5c0a6415004541b25e30a559a5c525a91021302bb12c31af04a401a83757bd28352f393fafa428b598a034e90662ea0000a2914fcd"
#print(mon_decodeur_zlib(bytes.fromhex(input)).decode('utf8'))


contenu_decompresse = b'123456aaaaaabbbbb9\n'
adl = mon_adler32(contenu_decompresse)
print(hex(adl))
input= "a33133333433533936133243659f55e7dc0d"
print(len(input))

"""
entree = bytes.fromhex(input)
lecteur_de_bits = LecteurDeBits(entree)

islastblock = lecteur_de_bits.lire_bits(1)
bloc_type = lecteur_de_bits.lire_bits(2)

if bloc_type == 0b01: 
              
    valeur_vers_taille_de_code = {}
    for valeur in range(256, 279 + 1):
        valeur_vers_taille_de_code[valeur] = 7
    for valeur in range(0, 143 + 1):
        valeur_vers_taille_de_code[valeur] = 8
    for valeur in range(280, 287 + 1):contenu_decompresse

    arbre_des_instructions = DecodeurHuffman(valeur_vers_taille_de_code, lecteur_de_bits)
                
    arbre_des_distances = DecodeurHuffman({position: 5 for position in range(0, 31 + 1)}, lecteur_de_bits)

else:
    sys.exit(0)

while True:
    
    code_instruction = arbre_des_instructions.lire_prochaine_valeur()
    
    print(code_instruction)
    
    if code_instruction == 256: # Fin du bloc
        break
    
    elif code_instruction < 256:
        contenu_decompresse += bytes([code_instruction])
    
    else:
        
        if code_instruction < 265:
            taille_repetition = 3 + (code_instruction - 257)

        
        elif code_instruction < 285:
            extra_bits = 1 + ((code_instruction - 265) >> 2)         
            taille_repetition = 3 + ((0b100 | ((code_instruction - 265) & 0b11)) << extra_bits)
            taille_repetition += lecteur_de_bits.lire_bits(extra_bits)
        
        else:
            raise ValueError("Type de code d'instruction DEFLATE invalide : %d" % code_instruction)

        code_distance = arbre_des_distances.lire_prochaine_valeur()
        print(code_distance)
        
        if code_distance < 4:
            distance = 1 + code_distance
        else:
            extra_bits = 1 + ((code_distance - 4) >> 1)
            distance = 1 + ((0b10 | ((code_distance - 2) & 1)) << extra_bits)
            distance += lecteur_de_bits.lire_bits(extra_bits)
        
        contenu_a_repeter = contenu_decompresse[
            -distance:
            -distance + taille_repetition if (-distance + taille_repetition) < 0 else None
        ]
        
        while contenu_a_repeter and len(contenu_a_repeter) < taille_repetition:
            contenu_a_repeter *= 2
        contenu_a_repeter = contenu_a_repeter[:taille_repetition]
        contenu_decompresse += contenu_a_repeter

        print(contenu_decompresse)


print(contenu_decompresse)"""