freebox_failover est un script à faire tourner dans une VM Freebox et qui assure un basculement vers le modem 4G Free branché sur le port USB de la Freebox.

freebox_failover surveille l'état de la ligne et si la ligne tombe déclare la VM comme la nouvelle passerelle du réseau. Tout le trafic IPv4 et IPv6 sera redirigé vers le modem 4G.

Lorsque l'état de la ligne est restauré, le script redirige à nouveau le trafic vers elle.

Pour créer la machine virtuelle la méthode la plus simple est d'utiliser le script [freeboxvm](https://github.com/vivier/freeboxvm/) avec la ligne de commande suivante:

```
freeboxvm install -n FreeboxFailover  --vcpus 1 --memory 512 --console --cloud-init --cloud-init-hostname freeboxfailover --cloud-init-userdata cloud-init-user-data.yaml -i fedora40 --disk freeboxfailover.qcow2 --disk-size 2g --usb-ports usb-external-type-a
```

## Configurer `freebox_failover.conf`

Le daemon lit `/etc/freebox_failover.conf` par défaut. Le fichier
`freebox_failover.conf` fourni dans ce dépôt sert de modèle:

```
sudo cp freebox_failover.conf /etc/freebox_failover.conf
sudo chmod 600 /etc/freebox_failover.conf
sudo editor /etc/freebox_failover.conf
```

Exemple de configuration:

```ini
[SMS]
user = 12345678
pass = XXXXXXXXXXXXXX

[freebox]
token_file = /etc/freebox_app_token.json
lan_iface = eth0
ip = 192.168.100.254
ipv6ll = fe80::1

[failover]
check = 10
down = 20
up = 30
garp = 3

[ipv6]
# ULA/GUA à annoncer aux clients pendant le failover.
prefix = fd00:1234::/64
# DNS IPv6 optionnels à annoncer, séparés par des espaces. Laisser vide
# pour ne pas annoncer de DNS.
rdnss = 2620:fe::fe 2001:4860:4860::8888
# Durée de vie RA, en secondes, pendant le failover.
router_lifetime = 30
```

Adaptez au minimum les identifiants SMS, `lan_iface`, `ip`, `ipv6ll`, `prefix`
et `rdnss` à votre réseau.

Les valeurs importantes sont:

### `[SMS]`

| Paramètre | Description |
| --- | --- |
| `user` | Identifiant de l'API SMS Free Mobile utilisé pour envoyer les alertes. Il se récupère dans l'espace abonné Free Mobile, dans l'option "Notifications par SMS". |
| `pass` | Clé API SMS Free Mobile. |

### `[freebox]`

| Paramètre | Description |
| --- | --- |
| `token_file` | Chemin du fichier JSON créé par `freebox_failover_register.py`. Le service doit pouvoir le lire; gardez-le sous `/etc` avec des permissions restrictives. |
| `lan_iface` | Interface LAN de la VM, connectée au réseau de la Freebox. Dans les exemples de ce README et dans `cloud-init-user-data.yaml`, cette interface est `eth0`. |
| `ip` | Adresse IPv4 LAN de la Freebox. C'est l'adresse que la VM annonce temporairement par Gratuitous ARP lorsque la ligne tombe. |
| `ipv6ll` | Adresse IPv6 link-local de la Freebox (`fe80::...`). Le daemon essaie de la relire via l'API Freebox et utilise cette valeur comme référence ou repli. Si vous ne la connaissez pas, lancez le daemon en mode debug: elle apparaît dans les logs au démarrage, par exemple dans les lignes `Starting failover monitor` et `Network handler started`. |

### `[failover]`

| Paramètre | Description |
| --- | --- |
| `check` | Intervalle, en secondes, entre deux lectures de l'état de la ligne Freebox. |
| `down` | Durée continue pendant laquelle la ligne doit rester down avant d'activer le failover. |
| `up` | Durée continue pendant laquelle la ligne doit rester up avant de rendre la main à la Freebox. |
| `garp` | Intervalle d'envoi des annonces ARP, Neighbor Advertisements et Router Advertisements pendant le failover. |

### `[ipv6]`

| Paramètre | Description |
| --- | --- |
| `prefix` | Préfixe IPv6 annoncé sur le LAN pendant le failover pour que les clients configurent une adresse SLAAC. Utilisez un préfixe ULA (`fd00::/8`) ou un préfixe global qui vous appartient. |
| `rdnss` | Serveurs DNS IPv6 annoncés dans les Router Advertisements. Laissez vide pour ne pas annoncer de DNS IPv6. |
| `router_lifetime` | Durée, en secondes, pendant laquelle les clients gardent la VM comme routeur IPv6 par défaut après une annonce RA. |

### Enregistrer l'application Freebox

Avant de démarrer le daemon, lancez `freebox_failover_register.py` une fois
pour autoriser l'application auprès de Freebox OS:

```
sudo python3 freebox_failover_register.py -c /etc/freebox_failover.conf
```

Le script utilise l'adresse `[freebox] ip` pour contacter l'API Freebox, puis
demande l'autorisation de l'application `Free Wifi Gateway`. Validez la demande
sur l'écran de la Freebox quand le script affiche
`Veuillez accepter l'application sur la Freebox`.

Une fois l'autorisation accordée, le script écrit le token dans le fichier
indiqué par `[freebox] token_file`, par défaut `/etc/freebox_app_token.json`.
Ce fichier est créé avec des permissions restrictives et doit rester privé. Le
daemon le relit ensuite à chaque démarrage pour ouvrir une session Freebox OS.

Si vous voulez stocker le token ailleurs que dans la configuration, utilisez
l'option `-t`:

```
sudo python3 freebox_failover_register.py \
    -c /etc/freebox_failover.conf \
    -t /etc/freebox_app_token.json
```

Si la Freebox refuse le token ou si l'autorisation a été révoquée, supprimez le
fichier de token puis relancez `freebox_failover_register.py`.

### Options de `freebox_failover.py`

Ces options ne sont pas des paramètres du fichier `.conf`; elles permettent de
choisir le fichier de configuration, de surcharger le chemin du token ou de
changer la destination des logs au lancement du daemon.

| Option | Description |
| --- | --- |
| `-c`, `--config` | Chemin du fichier de configuration. Par défaut: `/etc/freebox_failover.conf`. |
| `-t`, `--token-file` | Chemin du fichier token Freebox. Cette option remplace `[freebox] token_file` si elle est fournie. |
| `-l`, `--log-output` | Destination des logs: `stdout`, `stderr` ou `journald`. Par défaut: `stdout`. |

## Configurer la VM comme passerelle de secours

Si la VM est créée avec l'option `--cloud-init-userdata cloud-init-user-data.yaml` de la commande ci-dessus, la configuration sysctl, nftables et IPv6 décrite ici est déjà installée par `cloud-init-user-data.yaml`. Les commandes suivantes documentent ce que fait le fichier cloud-init et permettent de vérifier ou de refaire la configuration manuellement.

Les exemples ci-dessous supposent que:

- `eth0` est l'interface LAN de la VM, connectée au réseau de la Freebox;
- `usb0` est l'interface du modem 4G USB;
- `192.168.100.254` est l'adresse IPv4 de la Freebox;
- `fd00:1234::/64` est le préfixe IPv6 annoncé par `freebox_failover` pendant le failover.

Adaptez ces valeurs à votre configuration, ainsi que les mêmes champs dans `freebox_failover.conf`.

### Interface LAN

La VM doit être joignable sur le LAN Freebox, mais `cloud-init-user-data.yaml` ne fixe pas son adresse IPv4 car elle dépend de votre réseau. Elle ne doit pas installer de route par défaut apprise côté LAN: la route par défaut utile pendant le failover doit venir du modem 4G sur `usb0`.

Si `usb0` n'apparaît pas après avoir attaché le modem 4G à la VM, installez les modules noyau et chargez le pilote USB Ethernet:

```
sudo dnf install -y kernel-modules-$(uname -r)
sudo modprobe cdc_ether
```

Sur une image Fedora provisionnée par `cloud-init`, la connexion NetworkManager s'appelle généralement `cloud-init eth0`. `cloud-init-user-data.yaml` configure IPv6 sur cette connexion:

```
sudo nmcli con mod "cloud-init eth0" ipv4.never-default yes
sudo nmcli con mod "cloud-init eth0" ipv6.never-default yes
sudo nmcli con mod "cloud-init eth0" +ipv6.addresses fd00:1234::1/64
sudo nmcli con down "cloud-init eth0"
sudo nmcli con up "cloud-init eth0"
```

### Forward IPv4 et IPv6

Le noyau doit router les paquets entre le LAN et le modem 4G. Créez `/etc/sysctl.d/99-ipforward.conf`:

```
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.usb0.accept_ra = 2
net.ipv6.conf.eth0.accept_ra_defrtr = 0
```

Puis appliquez la configuration:

```
sudo sysctl --system
```

`net.ipv6.conf.all.forwarding=1` active le routage IPv6. Comme ce mode désactive normalement l'acceptation des Router Advertisements, `net.ipv6.conf.usb0.accept_ra=2` force la VM à accepter la route IPv6 fournie par le modem 4G sur `usb0`. `net.ipv6.conf.eth0.accept_ra_defrtr=0` évite d'apprendre une route par défaut depuis le LAN Freebox.

### NAT et forward avec nftables

Installez `nftables`:

```
sudo dnf install -y nftables
```

Sur Fedora, créez `/etc/sysconfig/nftables.conf` avec les règles suivantes:

```
flush ruleset

table ip nat {
        chain POSTROUTING {
                type nat hook postrouting priority srcnat; policy accept;
                oif "usb0" masquerade
        }
}

table ip6 nat {
        chain POSTROUTING {
                type nat hook postrouting priority srcnat; policy accept;
                oif "usb0" masquerade
        }
}

table inet filter {
        chain forward {
                type filter hook forward priority filter; policy drop;
                iif "eth0" oif "usb0" ct state established,related,new accept
                iif "usb0" oif "eth0" ct state established,related accept
                iif "eth0" oif "eth0" accept
        }
}
```

Activez ensuite le service, qui charge ce fichier au démarrage:

```
sudo systemctl enable --now nftables
sudo nft list ruleset
```

Ces règles font du masquerading IPv4 et IPv6 vers le modem 4G, et autorisent le forward du LAN vers `usb0` ainsi que les réponses en retour. Le script `freebox_failover` se charge ensuite d'annoncer la VM comme passerelle LAN lorsque la ligne Freebox tombe, via ARP en IPv4 et Router Advertisements/Neighbor Advertisements en IPv6.

## Installer depuis copr

1. Activer le dépot copr
   ```
   sudo dnf copr enable lvivier/freebox-failover
   ```
2. Installer les packages
   ```
   sudo dnf install freeboxvm freebox-failover
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
2. Construire directement depuis l'archive source :
   ```
   rpmbuild -ta dist/freebox_failover-0.0.1.tar.gz
   ```
   Les artefacts sont générés dans `~/rpmbuild/SRPMS/` et `~/rpmbuild/RPMS/noarch/`.
