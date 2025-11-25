freebox_failover est un script a faire tourner dans une VM freebox et qui assure un basculement vers le modem 4G Free branché sur le port USB de la freebox.

freebox_failover surveille l'état de la ligne et si la ligne tombe déclare la VM comme la nouvelle passerelle du réseau. Tout le traffic IPv4 et IPv6 sera redirigé vers le modem 4G.

Lorsque l'état de la ligne est restaurée, le script redirige à nouveau le traffic vers elle.

Pour créer la machine virtuelle la méthode la plus simble est d'utiliser le script [freeboxvm](https://github.com/vivier/freeboxvm/) avec la ligne de commande suivante:

```
freeboxvm install -n FreeboxFailover  --vcpus 1 --memory 512 --console --cloud-init --cloud-init-hostname freeboxfailover --cloud-init-userdata cloud-init-user-data.yaml -i fedora40 --disk freeboxfailover.qcow2 --disk-size 2g --usb-ports usb-external-type-a
```

## Construire l'archive source (.tar.gz)

1. Installer l'outil de build Python (dans un venv de préférence) :
   ```
   python3 -m pip install --upgrade build
   ```
2. Générer l'archive source :
   ```
   python3 -m build --sdist
   ```
   Le fichier `dist/freebox_failover-0.0.1.tar.gz` est créé.

## Construire le RPM

1. Installer les dépendances de build RPM (sur Fedora/RHEL-like) :
   ```
   sudo dnf install -y rpm-build pyproject-rpm-macros python3-devel python3-wheel python3-requests python3-scapy python3-systemd
   ```
   (Si `python3dist(ping3)` n'est pas disponible, empaquetez/installez-le depuis PyPI avant le build.)
2. Construire directement depuis l'archive source :
   ```
   rpmbuild -ta dist/freebox_failover-0.0.1.tar.gz
   ```
   Les artefacts sont générés dans `~/rpmbuild/SRPMS/` et `~/rpmbuild/RPMS/noarch/`.
