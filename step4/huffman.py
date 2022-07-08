#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from itertools import compress
from typing import List, Dict, Set, Sequence, Union
from io import BytesIO
import sys


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
            raise EOFError
        
        return octets_lus

    
    def aligner_bits_sur_octet(self):
        
        self.bits_non_lus = 0
        self.taille_bits_non_lus = 0
    


class DecodeurHuffman:
  
    
    def __init__(self, valeur_vers_taille_de_code : Dict[int, int], lecteur_de_bits : LecteurDeBits):
        
        
        self.chaine_de_code_vers_valeur : Dict[str, int] = {}
        
        self.lecteur_de_bits : LecteurDeBits = lecteur_de_bits
        
        derniere_taille_de_code : int = None
        dernier_code : int = None
        
      
        def tri_valeurs(valeur_et_taille_de_code):
            valeur, taille_de_code = valeur_et_taille_de_code 
            return (taille_de_code, valeur)
        
        for valeur, taille_de_code in sorted(valeur_vers_taille_de_code.items(), key = tri_valeurs):
            
            if not taille_de_code:
                continue 
            
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
            
            try:
                for chiffre_bit in chaine_de_code[:-1]:
                    bit = int(chiffre_bit) 
                    
                    
                    if bit not in noeud_actuel_dans_l_arbre:
                        
                        noeud_actuel_dans_l_arbre[bit] = {} 
                    
                    noeud_actuel_dans_l_arbre = noeud_actuel_dans_l_arbre[bit]
            
            
                dernier_bit = int(chaine_de_code[-1])
                
                noeud_actuel_dans_l_arbre[dernier_bit] = valeur
            except Exception:
                pass
        
    
    def lire_prochaine_valeur(self) -> int:
        
        noeud_actuel_dans_l_arbre = self.mon_arbre
        
        while True:
            prochain_bit : int = self.lecteur_de_bits.lire_bits(1)
            
            noeud_actuel_dans_l_arbre = noeud_actuel_dans_l_arbre[prochain_bit]
            
            
            if type(noeud_actuel_dans_l_arbre) == int:
                
                return noeud_actuel_dans_l_arbre

def mon_decodeur_zlib(entree : bytes) -> bytes:
    
    
    lecteur_de_bits = LecteurDeBits(entree)
      
    contenu_decompresse = b''
    cpt=0
    while True:
        
        blocs_restants_ensuite = lecteur_de_bits.lire_bits(1) != 1
        
        type_de_bloc = lecteur_de_bits.lire_bits(2)
            
        if type_de_bloc in (0b01, 0b10): 
            
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
                
            cpt=0
            while True:
                cpt += 1
                if (cpt % 100000 == 0):
                    print(cpt)
                    g.write(contenu_decompresse)
                if (cpt == 100000):
                    break
                code_instruction = arbre_des_instructions.lire_prochaine_valeur()
                
                if code_instruction == 256: 
                    break
                
                elif code_instruction > 30 and code_instruction <125 :
                    contenu_decompresse += bytes([code_instruction])
                    
                
                else: 
                    
                    if code_instruction < 265:
                        taille_repetition = 3 + (code_instruction - (257))
                   
                    
                    elif code_instruction <= 285:
                        extra_bits = 1 + ((code_instruction - (265)) >> 2)
                        
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
                
        if b"SSTIC" in contenu_decompresse:
            print(contenu_decompresse)
            print("FOUND IT")
            sys.exit(0)
        if not blocs_restants_ensuite:
            
            lecteur_de_bits.aligner_bits_sur_octet()
            
            break
        
    return contenu_decompresse

import binascii

f = open("home_backup.tar.zz","rb")
g = open("out","wb")

def reverse(value):
        res = ""
        for i in range(0,len(value),2):
            res += value[len(value)-i-2:len(value)-i]
        return res


data = f.read()
for i in range(len(data)):
    toTest = data[i:]
    
    try:
        print(i, data[i:i+3])
        ez = mon_decodeur_zlib(toTest)
        print(ez)
    except Exception:
        pass