# Path to stlink folder for uploading code to board --efi notes : ok
STLINK=/home/efi/projects/Arad/stlink-1.7.0

# Put your source files here (*.c) --efi notes : system_stm32f4xx.c  
SRCS=main.c system_stm32wbxx.c stm32wbxx_hal_msp.c stm32wbxx_it.c stm32wbxx_nucleo.c stm32wbxx_hal_flash.c software_imp_st.c nl_host.c 
 
# Libraries source files, add ones that you intent to use --efi notes : couldnt find the same , we have ll and hal
SRCS += stm32wbxx_ll_rcc.c
SRCS += stm32wbxx_ll_gpio.c
SRCS += stm32wbxx_ll_usart.c
SRCS += stm32wbxx_ll_usart.c
SRCS += stm32wbxx_hal.c
SRCS += stm32wbxx_hal_gpio.c
SRCS += stm32wbxx_hal_rcc.c
SRCS += stm32wbxx_hal_pwr.c		
SRCS += stm32wbxx_hal_pwr_ex.c	
SRCS += stm32wbxx_hal_cortex.c	
SRCS += stm32wbxx_hal_flash_ex.c
SRCS += stm32wbxx_hal_uart.c	
SRCS += stm32wbxx_hal_uart_ex.c
SRCS += stm32wbxx_hal_usart.c
SRCS += stm32wbxx_hal_usart_ex.c
SRCS += stm32wbxx_hal_dma.c
SRCS += /home/efi/projects/Arad/Arad_demo/nl_library/kernel/software_logic.c
SRCS += /home/efi/projects/Arad/Arad_demo/nl_library/kernel/crypto/sha2.c
SRCS += /home/efi/projects/Arad/Arad_demo/nl_library/kernel/crypto/hmac_sha2.c
SRCS += /home/efi/projects/Arad/Arad_demo/nl_library/src/nl_api.c
SRCS += /home/efi/projects/Arad/Arad_demo/nl_library/src/nl_lib.c
SRCS += /home/efi/projects/Arad/Arad_demo/nl_library/src/fw.c
SRCS += /home/efi/projects/Arad/Arad_demo/nl_library/src/communication.c
SRCS += /home/efi/projects/Arad/Arad_demo/nl_library/src/nl_serial_helper.c





# Binaries will be generated with this name (.elf, .bin, .hex) -- efi notes : ok
PROJ_NAME=template

# Put your STM32F4 library code directory here, change YOURUSERNAME to yours --efi notes : recheck , prob wb folder
STM_COMMON=/home/efi/projects/Arad/stm32cubeWB

# Compiler settings. Only edit CFLAGS to include other header files. --efi notes : ok
CC=arm-none-eabi-gcc -specs=nosys.specs $(OTHER_LINK_OPTIONS)
OBJCOPY=arm-none-eabi-objcopy



# Compiler flags --efi notes : not sure need to be check (key word wb instead of f4)
CFLAGS  = -g -O2 -Wall -TSTM32WB55RGVX_FLASH.ld
CFLAGS += -DUSE_STDPERIPH_DRIVER
CFLAGS += -mlittle-endian -mthumb -mcpu=cortex-m4 -mthumb-interwork
CFLAGS += -mfloat-abi=hard -mfpu=fpv4-sp-d16
CFLAGS += -I.

# Include files from STM libraries --efi notes : should find this folders in my case
CFLAGS += -I$(STM_COMMON)/en.stm32cubewb_v1-12-0_v1.12.0/STM32Cube_FW_WB_V1.12.0/Drivers/CMSIS/Include
CFLAGS += -I$(STM_COMMON)/en.stm32cubewb_v1-12-0_v1.12.0/STM32Cube_FW_WB_V1.12.0/Drivers/CMSIS/Device/ST/STM32WBxx/Include
CFLAGS += -I$(STM_COMMON)/en.stm32cubewb_v1-12-0_v1.12.0/STM32Cube_FW_WB_V1.12.0/Drivers/STM32WBxx_HAL_Driver/Inc
CFLAGS += -I/home/efi/projects/Arad/Arad_demo/inc
CFLAGS += -I/home/efi/projects/Arad/Arad_demo/nl_library/inc
CFLAGS += -I/home/efi/projects/Arad/Arad_demo/nl_library/contrib
CFLAGS += -I/home/efi/projects/Arad/Arad_demo/nl_library/kernel
CFLAGS += -I/home/efi/projects/Arad/Arad_demo/nl_library/kernel/crypto
CFLAGS += -DNL_PROJECT_stm32WB55
CFLAGS += -DNL_SOFTWARE_ONLY
CFLAGS += -DNL_BAREMETAL
CFLAGS += -DNL_CHIP_AND_HOST
CFLAGS += -DNL_SERIAL_COMMUNICATION
     
	



# add startup file to build --efi notes : should find this folder in my case
SRCS += $(STM_COMMON)/en.stm32cubewb_v1-12-0_v1.12.0/STM32Cube_FW_WB_V1.12.0/Projects/P-NUCLEO-WB55.Nucleo/Templates/STM32CubeIDE/Application/Startup/startup_stm32wb55rgvx.s
OBJS = $(SRCS:.c=.o)

vpath %.c $(STM_COMMON)/en.stm32cubewb_v1-12-0_v1.12.0/STM32Cube_FW_WB_V1.12.0/Drivers/STM32WBxx_HAL_Driver/Src  \

.PHONY: proj

# Commands
all: proj

proj: $(PROJ_NAME).elf

$(PROJ_NAME).elf: $(SRCS)
	$(CC) $(CFLAGS) $^ -o $@
	$(OBJCOPY) -O ihex $(PROJ_NAME).elf $(PROJ_NAME).hex
	$(OBJCOPY) -O binary $(PROJ_NAME).elf $(PROJ_NAME).bin

clean:
	rm -f *.o $(PROJ_NAME).elf $(PROJ_NAME).hex $(PROJ_NAME).bin

# Flash the STM32F4
burn: proj
	$(STLINK)/st-flash write $(PROJ_NAME).bin 0x8000000
