# SPI TCTI LTT2GO
The SPI TCTI LTT2GO can be used for communication with LetsTrust-TPM2Go USB TPM.
The LTT2GO module utilizes the `tcti-spi-helper` library for PTP SPI protocol handling
and the `libusb-1.0-0-dev` library for USB communication.

# EXAMPLES

You should see the following after plugging in the LetsTrust-TPM2Go:
```console
dmesg
 [ 1019.115823] usb 3-2: new full-speed USB device number 5 using xhci_hcd
 [ 1019.480333] usb 3-2: New USB device found, idVendor=365d, idProduct=1337, bcdDevice= 0.00
 [ 1019.480360] usb 3-2: New USB device strings: Mfr=1, Product=2, SerialNumber=3
 [ 1019.480382] usb 3-2: Product: LetsTrust-TPM2Go
 [ 1019.480405] usb 3-2: Manufacturer: www.pi3g.com
 [ 1019.480426] usb 3-2: SerialNumber: Y23CW29NR00000RND987654321012

sudo udevadm info -e | grep LetsTrust
 E: ID_MODEL=LetsTrust-TPM2Go
 E: ID_MODEL_ENC=LetsTrust-TPM2Go
 E: ID_SERIAL=www.pi3g.com_LetsTrust-TPM2Go_Y23CW29NR00000RND987654321012
```

After plugging in the LetsTrust-TPM2Go, the USB interface access permission is granted to the user `tss`. The `tcti-spi-ltt2go` can now be used to communicate with the TPM.
```console
sudo -u tss tpm2_startup -Tspi-ltt2go -c
sudo -u tss tpm2_getrandom -Tspi-ltt2go 8 --hex
```

If multiple LetsTrust-TPM2Go devices are plugged in, it is possible to choose which one to address by specifying the serial number. The input format supports regex.
```console
sudo -u tss tpm2_getrandom -Tspi-ltt2go:Y23CW29NR00000RND987654321012 8 --hex
sudo -u tss tpm2_getrandom -Tspi-ltt2go:RND98765 8 --hex
sudo -u tss tpm2_getrandom -Tspi-ltt2go:21012$ 8 --hex
```

## ABRMD (Alone)

Manually launch the abrmd (log in as root user):
```console
sudo su

export DBUS_SESSION_BUS_ADDRESS=`dbus-daemon --session --print-address --fork`
tpm2-abrmd --allow-root --session --tcti=spi-ltt2go &

export TPM2TOOLS_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd,bus_type=session"
tpm2_startup -c
tpm2_getrandom 8 --hex
```

## ABRMD (As a Systemd Service)

Launch the abrmd as a service (supports only **a single** LetsTrust-TPM2Go at a time).

Edit the service file using `systemctl edit --full tpm2-abrmd`. Then, update the service file content to:
```
[Unit]
Description=TPM2 Access Broker and Resource Management Daemon
# These settings are needed when using the device TCTI. If the
# TCP mssim is used then the settings should be commented out.
#After=dev-tpm0.device
#Requires=dev-tpm0.device

[Service]
Type=dbus
BusName=com.intel.tss2.Tabrmd
ExecStart=/usr/local/sbin/tpm2-abrmd --tcti=spi-ltt2go
User=tss

[Install]
WantedBy=multi-user.target
```

After editing the service file, the TPM is accessible by:
```console
sudo systemctl start tpm2-abrmd

export TPM2TOOLS_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd"
sudo -u tss tpm2_startup -c
sudo -u tss tpm2_getrandom 8 --hex
```

## ABRMD (Udev + Systemd Service)

By configuring the udev rules to automatically start the abrmd service when a LetsTrust-TPM2Go is plugged in and stop the service upon removal (supports only **a single** LetsTrust-TPM2Go at a time).

Make the following modifications to `tpm2-abrmd/dist/tpm2-abrmd.service.in`:
```
[Unit]
Description=TPM2 Access Broker and Resource Management Daemon
# These settings are needed when using the device TCTI. If the
# TCP mssim is used then the settings should be commented out.
#After=dev-tpm0.device
#Requires=dev-tpm0.device

[Service]
Type=dbus
BusName=com.intel.tss2.Tabrmd
ExecStart=@SBINDIR@/tpm2-abrmd --tcti=spi-ltt2go:%i
User=tss

[Install]
WantedBy=multi-user.target
```

After (re)installing the tpm2-abrmd, rename the service file on your host from `tpm2-abrmd.service` to `tpm2-abrmd@.service`.

Make the following modifications to `tpm2-tss/dist/ltt2go-udev.rules`:
```
SUBSYSTEM=="usb", ATTRS{idVendor}=="365d", ATTRS{idProduct}=="1337", ACTION=="add", TAG+="systemd", MODE="0600", OWNER="tss", RUN+="/bin/ltt2go_add.sh $env{DEVNAME}"
SUBSYSTEM=="usb", ACTION=="remove", TAG+="systemd", ENV{PRODUCT}=="365d/1337/0", RUN+="/bin/ltt2go_remove.sh $env{DEVNAME}"
```

Create a script at `/bin/ltt2go_add.sh` and make it executable.
```
#!/bin/sh

DEVNAME=$1

ID_SERIAL_SHORT=$(udevadm info --query=env --name=$DEVNAME | grep ID_SERIAL_SHORT | cut -d= -f2)

if [ -z "${ID_SERIAL_SHORT}" ]; then
    exit 1
fi

mkdir -p /run/ltt2go/$DEVNAME
echo $ID_SERIAL_SHORT > /run/ltt2go/${DEVNAME}/sn

systemctl start tpm2-abrmd@${ID_SERIAL_SHORT}.service

exit 0
```

Create a script at `/bin/ltt2go_remove.sh` and make it executable:
```
#!/bin/sh

DEVNAME=$1

SN_DIR=/run/ltt2go/$DEVNAME

if [ -f ${SN_DIR}/sn ]; then
    SERIAL_NUMBER=$(cat ${SN_DIR}/sn)

    systemctl stop tpm2-abrmd@${SERIAL_NUMBER}.service

    rm -f ${SN_DIR}/sn
    find /run/ltt2go -type d -empty -not -path /run/ltt2go -delete
else
    exit 1
fi

exit 0
```

After (re)installing the tpm2-tss, reload the udev rules and systemd:
```console
sudo udevadm control --reload-rules
sudo udevadm trigger
sudo systemctl daemon-reload
```

Now, plug in the LetsTrust-TPM2Go and access it by:
```console
export TPM2TOOLS_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd"
sudo -u tss tpm2_startup -c
sudo -u tss tpm2_getrandom 8 --hex
```