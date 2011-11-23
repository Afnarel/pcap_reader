struct pseudo_entete
{
  unsigned long ip_source; // Adresse ip source
  unsigned long ip_destination; // Adresse ip destination
  char mbz; // Champs à 0
  char type; // Type de protocole (6->TCP et 17->UDP)
  unsigned short length; // htons( Taille de l'entete Pseudo + Entete TCP ou UDP + Data )
};

unsigned short calcul_du_checksum(bool liberation, unsigned short *data, int taille)
{
  unsigned long checksum=0;
  // ********************************************************
  // Complément à 1 de la somme des complément à 1 sur 16 bits
  // ********************************************************
  while(taille>1)
  {
    if (liberation==TRUE)
      liberation_du_jeton(); // Rend la main à la fenêtre principale
    checksum=checksum+*data++;
    taille=taille-sizeof(unsigned short);
  }

  if(taille)
    checksum=checksum+*(unsigned char*)data;

  checksum=(checksum>>16)+(checksum&0xffff);
  checksum=checksum+(checksum>>16);

  return (unsigned short)(~checksum);
}

unsigned short calcul_du_checksum_udp(bool liberation, unsigned long ip_source_tampon, unsigned long ip_destination_tampon, struct udp udp_tampon, char data_tampon[65535])
{
  struct pseudo_entete pseudo_udp;
  char tampon[65535];
  unsigned short checksum;

  // ********************************************************
  // Initialisation du checksum
  // ********************************************************
  udp_tampon.checksum=0; // Doit être à 0 pour le calcul

  // ********************************************************
  // Le calcul du Checksum UDP (Idem à TCP)
  // ********************************************************
  // Le calcul passe par une pseudo entete UDP + l'entete UDP + les Data
  pseudo_udp.ip_source=ip_source_tampon;
  pseudo_udp.ip_destination=ip_destination_tampon;
  pseudo_udp.mbz=0;
  pseudo_udp.type=IPPROTO_UDP;
  pseudo_udp.length=htons((unsigned short)(sizeof(struct udp)+(unsigned short)strlen(data_tampon)));
  memcpy(tampon,&pseudo_udp,sizeof(pseudo_udp));
  memcpy(tampon+sizeof(pseudo_udp),&udp_tampon,sizeof(struct udp));
  memcpy(tampon+sizeof(pseudo_udp)+sizeof(struct udp),data_tampon,strlen(data_tampon));
  checksum=calcul_du_checksum(liberation,(unsigned short*)tampon,sizeof(pseudo_udp)+sizeof(struct udp)+strlen(data_tampon));

  return(checksum);
}
