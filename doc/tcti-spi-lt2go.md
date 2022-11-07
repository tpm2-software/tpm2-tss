# SPI TCTI LT2GO
The SPI TCTI LT2GO can be used for communication with LetsTrust-TPM2Go USB TPM.
The LT2GO module utilizes the `tcti-spi-helper` library for PTP SPI protocol handling
and the `libusb-1.0-0-dev` library for USB communication.

# EXAMPLES

Set udev rules for LetsTrust-TPM2Go by creating a file `/etc/udev/rules.d/60-tpm2go.rules`:
```
ATTRS{idVendor}=="04b4", ATTRS{idProduct}=="0004", TAG+="uaccess"
```

Activate the udev rules:
```console
sudo udevadm control --reload
```

You should see the following after plugging in the LetsTrust-TPM2Go:
```
dmesg
 [ 1019.115823] usb 3-2: new full-speed USB device number 5 using xhci_hcd
 [ 1019.480333] usb 3-2: New USB device found, idVendor=04b4, idProduct=0004, bcdDevice= 0.00
 [ 1019.480360] usb 3-2: New USB device strings: Mfr=1, Product=2, SerialNumber=3
 [ 1019.480382] usb 3-2: Product: LetsTrust-TPM2Go
 [ 1019.480405] usb 3-2: Manufacturer: www.pi3g.com
 [ 1019.480426] usb 3-2: SerialNumber: 000010

sudo udevadm info -e | grep LetsTrust
 E: ID_MODEL=LetsTrust-TPM2Go
 E: ID_MODEL_ENC=LetsTrust-TPM2Go
 E: ID_SERIAL=www.pi3g.com_LetsTrust-TPM2Go_000010
```

Use tcti-spi-lt2go to communicate with LetsTrust-TPM2Go:
```console
tpm2_startup -Tspi-lt2go -c
tpm2_getrandom -Tspi-lt2go 8 --hex
```

Enable abrmd:
```console
export DBUS_SESSION_BUS_ADDRESS=`dbus-daemon --session --print-address --fork`
tpm2-abrmd --allow-root --session --tcti=spi-lt2go &

export TPM2TOOLS_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd,bus_type=session"
tpm2_startup -c
tpm2_getrandom 8 --hex
```