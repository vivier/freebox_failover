freebox_failover est un script a faire tourner dans une VM freebox et qui assure un basculement vers le modem 4G Free branché sur le port USB de la freebox.

freebox_failover surveille l'état de la ligne et si la ligne tombe déclare la VM comme la nouvelle passerelle du réseau. Tout le traffic IPv4 et IPv6 sera redirigé vers le modem 4G.

Lorsque l'état de la ligne est restaurée, le script redirige à nouveau le traffic vers elle.

Pour créer la machine virtuelle la méthode la plus simble est d'utiliser le script [freeboxvm](https://github.com/vivier/freeboxvm/) avec la ligne de commande suivante:

```
freeboxvm install -n FreeboxFailover  --vcpus 1 --memory 512 --console --cloud-init --cloud-init-hostname freeboxfailover --cloud-init-userdata cloud-init-user-data.yaml -i fedora40 --disk freeboxfailover.qcow2 --disk-size 2g --usb-ports usb-external-type-a
```


