# P-nucleo-wb55 build & burn instructions    {#getStart}

The Nucleo pack (P-NUCLEO-WB55) with a Nucleo-68 board and a USB dongle provides
an affordable and flexible way for users to try out new concepts and build prototypes using
STM32WB microcontrollers with a 2.4 GHz radio interface.
This circuit block provides various combinations of performance, power consumption and
features. A 2.4 GHz RF transceiver supporting Bluetooth ® specification v5.0 and IEEE
802.15.4-2011 PHY and MAC is supported

# steps to build blink project: 

1. Clone the STM32WB repository

2. switch to last Branch

3. go to ST_link and run make

4. go to build/Release and move st-flash & st-info to parent folder (ST_link)

5. in .bashrc add the next lines

*dont forget to update the links for your setup

export PATH=$PATH:/home/efi/projects/Arad/gcc-arm-none-eabi-10.3-2021.07-x86_64-linux/gcc-arm-none-eabi-10.3-2021.07/bin

export PATH=$PATH:/home/efi/projects/Arad/stlink-1.7.0/
	
6. run in terminal : source .bashrc

7. run in terminal : st-info -- probe

8. the “com” led supposed to blink on your board and in the terminal you should get information about the device 

9. go to the project folder and in the Makefile validate the links for your environment

10. run in terminal: make

11. make sure you got 3 new files :

	.hex
	.elf
	.bin
12. run in terminal: make burn

	
