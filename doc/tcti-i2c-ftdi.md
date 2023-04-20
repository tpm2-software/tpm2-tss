# I2C TCTI FTDI

The I2C TCTI FTDI can be used for communication with an I2C-based TPM over the FTDI MPSSE
USB to I2C bridge. The FTDI module utilizes the `tcti-i2c-helper` library for handling the
PTP I2C protocol and the `libftdi-dev` library for handling the USB to I2C communication.

Example of a FTDI MPSSE USB to I2C bridge is the product "USB 2.0 Hi-Speed to MPSSE
Cable (SPI/I2C/JTAG master) with +3.3V digital level signals", part no: C232HM-DDHSL-0.
Connect the cable to your TPM as specified in the table below:

|   C232HM-DDHSL-0   | Description |
|--------------------|-------------|
| pin 1, red, VCC    |     VCC     |
| pin 2, orange, SCL |     SCL     |
| pin 3, yellow, SDA |     SDA     |
| pin 4, green, SDA  |     SDA     |
| pin 10, black, GND |     GND     |

**Important: both yellow and green wires need to be shorted together to create bidirectional data.**

# EXAMPLES

Set udev rules for the C232HM-DDHSL-0 cable by creating a file `/etc/udev/rules.d/60-c232hm.rules`:
```
ATTRS{idVendor}=="0403", ATTRS{idProduct}=="6014", TAG+="uaccess"
```

Activate the udev rules:
```console
sudo udevadm control --reload
```

You should see the following after plugging in the C232HM-DDHSL-0 cable:
```
dmesg
 [74386.091721] usb 3-2: new high-speed USB device number 18 using xhci_hcd
 [74386.439103] usb 3-2: New USB device found, idVendor=0403, idProduct=6014, bcdDevice= 9.00
 [74386.439117] usb 3-2: New USB device strings: Mfr=1, Product=2, SerialNumber=3
 [74386.439129] usb 3-2: Product: C232HM-DDHSL-0
 [74386.439140] usb 3-2: Manufacturer: FTDI
 [74386.439151] usb 3-2: SerialNumber: FT1UGJKF
 [74386.443996] ftdi_sio 3-2:1.0: FTDI USB Serial Device converter detected
 [74386.444030] usb 3-2: Detected FT232H
 [74386.446370] usb 3-2: FTDI USB Serial Device converter now attached to ttyUSB0
```

Use tcti-i2c-ftdi to communicate with a I2C-based TPM:
```console
tpm2_startup -Ti2c-ftdi -c
tpm2_getrandom -Ti2c-ftdi 8 --hex
```

Enable abrmd:
```console
export DBUS_SESSION_BUS_ADDRESS=`dbus-daemon --session --print-address --fork`
tpm2-abrmd --allow-root --session --tcti=i2c-ftdi &

export TPM2TOOLS_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd,bus_type=session"
tpm2_startup -c
tpm2_getrandom 8 --hex
```