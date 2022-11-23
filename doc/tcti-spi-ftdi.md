# SPI TCTI FTDI

The SPI TCTI FTDI can be used for communication with a SPI-based TPM over the FTDI MPSSE
USB to SPI bridge. The FTDI module utilizes the `tcti-spi-helper` library for handling the
PTP SPI protocol and the `libftdi-dev` library for handling the USB to SPI communication.

Example of a FTDI MPSSE USB to SPI bridge is the product "USB 2.0 Hi-Speed to MPSSE
Cable (SPI/I2C/JTAG master) with +3.3V digital level signals", part no: C232HM-DDHSL-0.
Connect the cable to your TPM as specified in the table below:

|    C232HM-DDHSL-0   | Description |
|---------------------|-------------|
|  VCC, red, pin 1    |     VCC     |
|  SK, orange, pin 2  |     SCLK    |
|  DO, yellow, pin 3  |     MOSI    |
|  DI, green, pin 4   |     MISO    |
|  CS, brown, pin 5   |     CS      |
|  GND, black, pin 10 |     GND     |

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

Use tcti-spi-ftdi to communicate with a SPI-based TPM:
```console
tpm2_startup -Tspi-ftdi -c
tpm2_getrandom -Tspi-ftdi 8 --hex
```

Enable abrmd:
```console
export DBUS_SESSION_BUS_ADDRESS=`dbus-daemon --session --print-address --fork`
tpm2-abrmd --allow-root --session --tcti=spi-ftdi &

export TPM2TOOLS_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd,bus_type=session"
tpm2_startup -c
tpm2_getrandom 8 --hex
```